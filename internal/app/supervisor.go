package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"sync"
	"time"

	"my-zerotier/internal/agent"
	"my-zerotier/internal/core"
)

type tunnelOpener func(name string, addresses []string) (io.ReadWriteCloser, error)
type configFetcher func(context.Context, core.Credential) (core.Config, string, error)
type agentRunner func(context.Context, core.Credential, core.Config, string, io.ReadWriteCloser) error

type fetchResult struct {
	config core.Config
	id     string
	err    error
}

type ownedTunnel struct {
	io.ReadWriteCloser
	once sync.Once
	err  error
}

func (d *ownedTunnel) Close() error {
	d.once.Do(func() { d.err = d.ReadWriteCloser.Close() })
	return d.err
}

// supervise fails closed on refresh errors and recreates the tunnel on change.
func supervise(ctx context.Context, cred core.Credential, iface string, initial core.Config, initialID string, interval time.Duration, open tunnelOpener, fetch configFetcher, run agentRunner) (result error) {
	var cancel context.CancelFunc
	var done chan error
	var revision string
	stop := func() error {
		if cancel == nil {
			return nil
		}
		cancel()
		err := <-done
		cancel, done = nil, nil
		return err
	}
	defer func() { result = errors.Join(result, stop()) }()
	start := func(cfg core.Config, id string) error {
		self, ok := cfg.Peer(id)
		if !ok {
			return fmt.Errorf("local peer missing from configuration")
		}
		prefix, err := netip.ParsePrefix(cfg.Network)
		if err != nil {
			return err
		}
		addresses := []string{fmt.Sprintf("%s/%d", self.IP, prefix.Bits())}
		if self.IPv6 != "" {
			prefix6, err := netip.ParsePrefix(cfg.Network6)
			if err != nil {
				return err
			}
			addresses = append(addresses, fmt.Sprintf("%s/%d", self.IPv6, prefix6.Bits()))
		}
		newRevision, err := cfg.Revision()
		if err != nil {
			return err
		}
		rawDevice, err := open(iface, addresses)
		if err != nil {
			return fmt.Errorf("open tunnel: %w", err)
		}
		dev := &ownedTunnel{ReadWriteCloser: rawDevice}
		child, childCancel := context.WithCancel(ctx)
		cancel = childCancel
		done = make(chan error, 1)
		revision = newRevision
		go func() {
			err := run(child, cred, cfg, id, dev)
			if closeErr := dev.Close(); closeErr != nil && !errors.Is(err, closeErr) {
				err = errors.Join(err, fmt.Errorf("close tunnel: %w", closeErr))
			}
			done <- err
		}()
		log.Printf("interface %s active for %s (%v)", iface, id, addresses)
		return nil
	}
	if err := start(initial, initialID); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var fetched <-chan fetchResult
	var cancelFetch context.CancelFunc
	defer func() {
		if cancelFetch != nil {
			cancelFetch()
		}
	}()
	unavailable := false
	for {
		select {
		case <-ctx.Done():
			return stop()
		case err := <-done:
			cancel()
			cancel, done = nil, nil
			if ctx.Err() != nil {
				return err
			}
			if err == nil {
				return fmt.Errorf("tunnel stopped unexpectedly")
			}
			return fmt.Errorf("tunnel stopped: %w", err)
		case <-ticker.C:
			if fetched != nil {
				continue
			}
			fetchCtx, stopFetch := context.WithCancel(ctx)
			cancelFetch = stopFetch
			results := make(chan fetchResult, 1)
			fetched = results
			go func() {
				cfg, id, err := fetch(fetchCtx, cred)
				results <- fetchResult{cfg, id, err}
			}()
		case result := <-fetched:
			cancelFetch()
			cancelFetch, fetched = nil, nil
			cfg, id, err := result.config, result.id, result.err
			if ctx.Err() != nil {
				return stop()
			}
			if err != nil {
				if stopErr := stop(); stopErr != nil {
					return stopErr
				}
				if !unavailable {
					log.Printf("controller refresh failed; tunnel closed: %v", err)
				}
				unavailable = true
				continue
			}
			next, err := cfg.Revision()
			if err != nil {
				return err
			}
			if cancel != nil && revision == next && id == initialID {
				continue
			}
			if err := stop(); err != nil {
				return err
			}
			if err := start(cfg, id); err != nil {
				return err
			}
			initialID = id
			unavailable = false
		}
	}
}

func runSupervised(ctx context.Context, cred core.Credential, cfg core.Config, id, iface string) error {
	return supervise(ctx, cred, iface, cfg, id, 2*time.Second, agent.OpenTunnel, agent.FetchConfig, agent.Run)
}
