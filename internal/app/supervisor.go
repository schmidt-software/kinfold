package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
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

// supervise keeps the tunnel in line with the controller configuration. A
// failed fetch is tolerated for up to grace (see decision D-013); after that
// the tunnel is closed (fail closed) until the controller answers again. A
// failed tunnel start after a configuration change is retried on the next
// tick instead of terminating the client.
func supervise(ctx context.Context, cred core.Credential, iface string, initial core.Config, initialID string, interval, grace time.Duration, open tunnelOpener, fetch configFetcher, run agentRunner) (result error) {
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
		slog.Info("tunnel active", "interface", iface, "peer", id, "addresses", addresses)
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
	var failingSince time.Time // zero while the controller answers
	startFailed := false
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
				now := time.Now()
				if failingSince.IsZero() {
					failingSince = now
					slog.Warn("controller refresh failed; keeping tunnel during grace period", "error", err, "grace", grace)
				}
				if cancel != nil && now.Sub(failingSince) >= grace {
					if stopErr := stop(); stopErr != nil {
						return stopErr
					}
					slog.Warn("controller unreachable beyond grace period; tunnel closed", "error", err, "since", failingSince)
				}
				continue
			}
			if !failingSince.IsZero() {
				slog.Info("controller reachable again", "outage", time.Since(failingSince).Round(time.Second))
				failingSince = time.Time{}
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
				if !startFailed {
					slog.Warn("tunnel start failed; retrying", "error", err)
				}
				startFailed = true
				continue
			}
			if startFailed {
				slog.Info("tunnel start recovered")
				startFailed = false
			}
			initialID = id
		}
	}
}

// fetchGrace is how long the client keeps its tunnel while the controller
// cannot be reached. It is bounded because a client that cannot fetch also
// cannot learn about policy changes; the relay enforces membership and the
// current revision independently (D-013).
const fetchGrace = 30 * time.Second

// runSupervised runs the tunnel and, when autoRenew is set, renews the
// device certificate in the background. A renewal restarts the tunnel with
// the new credential.
func runSupervised(ctx context.Context, path string, cred core.Credential, cfg core.Config, id, iface string, autoRenew bool) error {
	for {
		client := agent.NewConfigClient(cred)
		runCtx, cancel := context.WithCancel(ctx)
		renewed := make(chan core.Credential, 1)
		if autoRenew {
			go func() {
				renewLoop(runCtx, path, cred, client, renewed)
				if len(renewed) > 0 {
					cancel() // stop the tunnel; it restarts below with the new credential
				}
			}()
		}
		fetch := func(ctx context.Context, _ core.Credential) (core.Config, string, error) { return client.Fetch(ctx) }
		err := supervise(runCtx, cred, iface, cfg, id, 2*time.Second, fetchGrace, agent.OpenTunnel, fetch, agent.Run)
		cancel()
		client.Close()
		select {
		case next := <-renewed:
			if err != nil {
				return err
			}
			cred = next
			if cfg, id, err = fetchAfterRenewal(ctx, cred); err != nil {
				return err
			}
			slog.Info("restarting tunnel with renewed certificate", "peer", id)
		default:
			return err
		}
	}
}
