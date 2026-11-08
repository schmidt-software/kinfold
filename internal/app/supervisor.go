package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
)

type tunnelOpener func(name string, addresses []string) (io.ReadWriteCloser, error)
type configFetcher func(context.Context, core.Credential) (core.Config, string, error)
type agentRunner func(context.Context, core.Credential, core.Config, string, io.ReadWriteCloser, <-chan core.Config) error

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
func supervise(ctx context.Context, cred core.Credential, iface string, initial core.Config, initialID string, interval, grace time.Duration, leaseUntil func() time.Time, open tunnelOpener, fetch configFetcher, run agentRunner) (result error) {
	var cancel context.CancelFunc
	var done chan error
	var revision, tunnel string
	var updates chan core.Config
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
		revision, tunnel = newRevision, tunnelKey(cfg, id)
		updates = make(chan core.Config, 1)
		pending := updates
		go func() {
			err := run(child, cred, cfg, id, dev, pending)
			if closeErr := dev.Close(); closeErr != nil && !errors.Is(err, closeErr) {
				err = errors.Join(err, fmt.Errorf("close tunnel: %w", closeErr))
			}
			done <- err
		}()
		slog.Info("tunnel active", "interface", iface, "peer", id, "addresses", addresses)
		agent.Metrics.Counter("kinfold_tunnel_starts_total", "TUN device (re)creations.", nil).Inc()
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
			// A signed configuration may only be used until its lease ends;
			// without a fresh one the tunnel closes (D-025).
			if leaseUntil != nil && cancel != nil {
				if until := leaseUntil(); !until.IsZero() && !time.Now().Before(until) {
					if err := stop(); err != nil {
						return err
					}
					slog.Warn("configuration lease expired; tunnel closed until a fresh configuration arrives", "lease_until", until)
				}
			}
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
			reachable := agent.Metrics.Gauge("kinfold_controller_reachable", "1 while the last configuration fetch succeeded.", nil)
			if err != nil && errors.Is(err, agent.ErrRefused) {
				// The controller answered and refused: close at once, the
				// grace period only covers an unreachable controller.
				reachable.Set(1)
				if cancel != nil {
					if stopErr := stop(); stopErr != nil {
						return stopErr
					}
					slog.Warn("controller refused the configuration; tunnel closed", "error", err)
				}
				failingSince = time.Time{}
				continue
			}
			if err != nil {
				reachable.Set(0)
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
			reachable.Set(1)
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
			if cancel != nil && id == initialID && tunnelKey(cfg, id) == tunnel {
				// Same device addresses: hand the change to the running
				// agent instead of recreating the tunnel (review R-09).
				select {
				case <-updates: // replace an update the agent has not taken yet
				default:
				}
				updates <- cfg
				revision = next
				agent.Metrics.Counter("kinfold_config_updates_applied_total", "Configuration changes applied to the running tunnel.", nil).Inc()
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
func runSupervised(ctx context.Context, path string, cred core.Credential, cfg core.Config, id, iface string, autoRenew bool, direct directOptions) error {
	for {
		if cert, err := credentialCertificate(cred); err == nil {
			expiry := float64(cert.NotAfter.Unix())
			agent.Metrics.GaugeFunc("kinfold_certificate_expiry_timestamp_seconds", "Expiry of the device certificate in use (Unix time).", nil, func() float64 { return expiry })
		}
		client := agent.NewConfigClient(cred)
		runCtx, cancel := context.WithCancel(ctx)
		renewed := make(chan core.Credential, 1)
		var renewing sync.WaitGroup
		if autoRenew {
			renewing.Add(1)
			go func() {
				defer renewing.Done()
				renewLoop(runCtx, path, cred, client, renewed)
				if len(renewed) > 0 {
					cancel() // stop the tunnel; it restarts below with the new credential
				}
			}()
		}
		fetch := func(ctx context.Context, _ core.Credential) (core.Config, string, error) { return client.Fetch(ctx) }
		client.SetNotBefore(readSeen(path))
		persistDone := make(chan struct{})
		go func() {
			defer close(persistDone)
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-runCtx.Done():
					writeSeen(path, client.NotBefore())
					return
				case <-ticker.C:
					writeSeen(path, client.NotBefore())
				}
			}
		}()
		var runOpts []agent.Option
		if direct.dial || direct.listen != "" {
			runOpts = append(runOpts, agent.WithDirect(direct.listen, client.Endpoints))
		}
		if direct.port > 0 {
			client.SetDirect(direct.port, direct.addrs)
		}
		runner := func(ctx context.Context, cred core.Credential, cfg core.Config, id string, dev io.ReadWriteCloser, updates <-chan core.Config) error {
			return agent.RunWithUpdates(ctx, cred, cfg, id, dev, updates, runOpts...)
		}
		err := supervise(runCtx, cred, iface, cfg, id, 2*time.Second, fetchGrace, client.LeaseUntil, agent.OpenTunnel, fetch, runner)
		cancel()
		<-persistDone
		// Never exit while a renewal is between request and storage
		// (change review finding 2); an interrupted one resumes at start.
		renewing.Wait()
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

// tunnelKey covers what the TUN device is configured with; a change that
// keeps it can be applied to the running agent.
func tunnelKey(cfg core.Config, id string) string {
	self, _ := cfg.Peer(id)
	return strings.Join([]string{id, self.IP, self.IPv6, cfg.Network, cfg.Network6}, "|")
}

// The rollback watermark (newest accepted configuration issue time) is
// persisted next to the credential so a restart cannot be fed an older,
// validly signed configuration (D-025).
func seenPath(credential string) string { return credential + ".seen" }

func readSeen(credential string) time.Time {
	data, err := os.ReadFile(seenPath(credential))
	if err != nil {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(data)))
	if err != nil {
		slog.Warn("ignoring unreadable configuration watermark", "path", seenPath(credential), "error", err)
		return time.Time{}
	}
	return t
}

func writeSeen(credential string, t time.Time) {
	if t.IsZero() || !t.After(readSeen(credential)) {
		return
	}
	if err := writeFileAtomic(seenPath(credential), []byte(t.UTC().Format(time.RFC3339Nano)+"\n")); err != nil {
		slog.Warn("could not persist configuration watermark", "error", err)
	}
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// directOptions configures the direct path (D-026).
type directOptions struct {
	dial   bool     // dial peers that advertise direct endpoints
	listen string   // accept direct sessions on this address ("" = no)
	port   int      // advertised port (from listen)
	addrs  []string // advertised local addresses
}

// localAddresses lists this host's addresses that a peer might reach:
// global and private unicast, excluding loopback and link-local.
func localAddresses() []string {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range ifaces {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := prefix.Addr()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}
