package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

// Standby replication (D-028): a standby controller pulls the complete
// state from the primary over mutual TLS with its replica certificate,
// checks it as LoadState would and stores it; its watcher then serves it.

const replicationInterval = 2 * time.Second

// defaultStandbyMaxAge bounds how long a standby serves a state it could
// not refresh from the primary (D-031).
const defaultStandbyMaxAge = time.Hour

type replicator struct {
	cred   core.ReplicaCredential
	dir    string
	client *http.Client
	maxAge time.Duration
	// setStale is told whether the standby must stop serving; lastOK is the
	// time of the last successful replication (stored as the state file's
	// modification time so it survives restarts).
	setStale func(bool)
	mu       sync.Mutex
	lastOK   time.Time
	stale    bool
	// lock is the data directory lock a running standby holds for its whole
	// lifetime, so replica-promote cannot run against a live standby.
	lock *os.File
}

// Close releases the data directory lock.
func (r *replicator) Close() {
	if r.lock != nil {
		r.lock.Close()
		r.lock = nil
	}
}

// primaryAnswer is a non-200 answer of the primary: it was reachable.
type primaryAnswer struct{ status int }

func (e primaryAnswer) Error() string {
	return fmt.Sprintf("primary: %d %s", e.status, http.StatusText(e.status))
}

// unreachable wraps network errors: only these let a standby start from its
// last stored state.
type unreachable struct{ err error }

func (e unreachable) Error() string { return e.err.Error() }
func (e unreachable) Unwrap() error { return e.err }

func newReplicator(cred core.ReplicaCredential, dir string) (*replicator, error) {
	pair, err := tls.X509KeyPair(cred.Cert, cred.Key)
	if err != nil {
		return nil, fmt.Errorf("replica certificate: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cred.CA) {
		return nil, fmt.Errorf("replica credential has no valid CA")
	}
	transport := &http.Transport{
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots, NextProtos: []string{"http/1.1"}},
		MaxResponseHeaderBytes: 16 << 10,
		MaxIdleConns:           1,
		IdleConnTimeout:        30 * time.Second,
	}
	return &replicator{cred: cred, dir: dir, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}, maxAge: defaultStandbyMaxAge, setStale: func(bool) {}}, nil
}

// pull fetches, checks and stores the primary's state; it reports whether
// the stored state changed.
func (r *replicator) pull(ctx context.Context) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+r.cred.Primary+"/replica/state", nil)
	if err != nil {
		return false, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return false, unreachable{err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, primaryAnswer{resp.StatusCode}
	}
	var state core.State
	if err := core.DecodeJSON(resp.Body, &state); err != nil {
		return false, fmt.Errorf("replicated state: %w", err)
	}
	if err := state.CheckStandby(); err != nil {
		return false, fmt.Errorf("replicated state is invalid: %w", err)
	}
	if !bytes.Equal(state.CA, r.cred.CA) {
		return false, fmt.Errorf("replicated state belongs to another CA")
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return false, err
	}
	path := filepath.Join(r.dir, "state.json")
	if current, err := os.ReadFile(path); err == nil && bytes.Equal(bytes.TrimSpace(current), data) {
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil {
			return false, err
		}
		r.succeeded(now)
		return false, nil
	}
	if r.lock == nil {
		lock, err := core.LockState(r.dir)
		if err != nil {
			return false, err
		}
		defer lock.Close()
	}
	if err := core.WriteJSON(path, &state); err != nil {
		return false, err
	}
	r.succeeded(time.Now())
	return true, nil
}

func (r *replicator) succeeded(now time.Time) {
	r.mu.Lock()
	r.lastOK = now
	r.mu.Unlock()
	r.markStale(false, "")
}

// lastReplication is the time of the last successful replication.
func (r *replicator) lastReplication() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastOK
}

func (r *replicator) markStale(stale bool, reason string) {
	r.mu.Lock()
	changed := r.stale != stale
	r.stale = stale
	r.mu.Unlock()
	if !changed {
		return
	}
	r.setStale(stale)
	if stale {
		slog.Error("standby stopped serving devices", "reason", reason, "primary", r.cred.Primary)
	} else {
		slog.Info("standby serving devices again", "primary", r.cred.Primary)
	}
}

// failed decides after a failed pull whether the standby may keep serving:
// not once the primary refuses it (removed replica), and not when its state
// is older than maxAge (D-031).
func (r *replicator) failed(err error, now time.Time) {
	var answer primaryAnswer
	switch {
	case errors.As(err, &answer) && answer.status == http.StatusForbidden:
		r.markStale(true, "the primary no longer accepts this standby")
	case now.Sub(r.lastReplication()) > r.maxAge:
		r.markStale(true, fmt.Sprintf("no successful replication for more than %s", r.maxAge))
	}
}

// run replicates until ctx ends, logging state changes once.
func (r *replicator) run(ctx context.Context) {
	ticker := time.NewTicker(replicationInterval)
	defer ticker.Stop()
	failing := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := r.pull(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			r.failed(err, time.Now())
			if !failing {
				slog.Warn("replication from the primary failed; serving the last replicated state", "primary", r.cred.Primary, "error", err)
			}
			failing = true
		case err == nil:
			if failing {
				slog.Info("replication from the primary restored", "primary", r.cred.Primary)
			}
			failing = false
			if changed {
				slog.Debug("replicated a new controller state")
			}
		}
	}
}

func readReplicaCredential(path string) (core.ReplicaCredential, error) {
	var cred core.ReplicaCredential
	if err := core.CheckPrivate(path); err != nil {
		return cred, err
	}
	if err := core.ReadJSON(path, &cred); err != nil {
		return cred, err
	}
	if err := core.ValidateServerAddress(cred.Primary); err != nil {
		return cred, fmt.Errorf("replica credential: %w", err)
	}
	return cred, nil
}

// prepareStandby makes sure the standby has a replicated state before it
// starts serving: it pulls once, and falls back to the last stored state
// only if the primary cannot be reached and that state is not older than
// maxAge. A primary that answers but refuses, or sends an invalid state,
// stops the start.
func prepareStandby(ctx context.Context, cred core.ReplicaCredential, dir string, maxAge time.Duration) (*replicator, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r, err := newReplicator(cred, dir)
	if err != nil {
		return nil, err
	}
	r.maxAge = maxAge
	if r.lock, err = core.LockState(dir); err != nil {
		return nil, fmt.Errorf("standby data directory is in use (another standby or an administrative command): %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			r.Close()
		}
	}()
	if _, err := r.pull(ctx); err != nil {
		var down unreachable
		if !errors.As(err, &down) {
			return nil, fmt.Errorf("initial replication from %s: %w", cred.Primary, err)
		}
		info, statErr := os.Stat(filepath.Join(dir, "state.json"))
		if statErr != nil {
			return nil, fmt.Errorf("initial replication from %s: %w", cred.Primary, err)
		}
		if age := time.Since(info.ModTime()); age > maxAge {
			return nil, fmt.Errorf("primary unreachable (%w) and the last replicated state is %s old (maximum %s)", err, age.Round(time.Second), maxAge)
		}
		r.lastOK = info.ModTime()
		slog.Warn("primary unreachable; starting with the last replicated state", "error", err, "replicated", info.ModTime().UTC().Format(time.RFC3339))
	}
	ok = true
	return r, nil
}

// controllersPath stores the controller list a client learned from its
// signed configuration, so it can reach a standby after a restart.
func controllersPath(credential string) string { return credential + ".controllers" }

func readControllers(credential string) []string {
	data, err := os.ReadFile(controllersPath(credential))
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && core.ValidateServerAddress(line) == nil {
			out = append(out, line)
		}
	}
	return out
}

func writeControllers(credential string, list []string) {
	if len(list) == 0 || strings.Join(list, "\n") == strings.Join(readControllers(credential), "\n") {
		return
	}
	if err := core.WriteFileAtomic(controllersPath(credential), []byte(strings.Join(list, "\n")+"\n")); err != nil {
		slog.Warn("could not persist the controller list", "error", err)
	}
}
