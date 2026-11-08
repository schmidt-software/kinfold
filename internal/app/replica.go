package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

// Standby replication (D-028): a standby controller pulls the complete
// state from the primary over mutual TLS with its replica certificate,
// checks it as LoadState would and stores it; its watcher then serves it.

const replicationInterval = 2 * time.Second

type replicator struct {
	cred   core.ReplicaCredential
	dir    string
	client *http.Client
}

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
	return &replicator{cred: cred, dir: dir, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}, nil
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
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("primary: %q", resp.Status)
	}
	var state core.State
	if err := core.DecodeJSON(resp.Body, &state); err != nil {
		return false, fmt.Errorf("replicated state: %w", err)
	}
	if err := state.Check(); err != nil {
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
		return false, nil
	}
	lock, err := core.LockState(r.dir)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	return true, core.WriteJSON(path, &state)
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
// only if the primary cannot be reached.
func prepareStandby(ctx context.Context, cred core.ReplicaCredential, dir string) (*replicator, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	r, err := newReplicator(cred, dir)
	if err != nil {
		return nil, err
	}
	if _, err := r.pull(ctx); err != nil {
		if _, statErr := os.Stat(filepath.Join(dir, "state.json")); statErr != nil {
			return nil, fmt.Errorf("initial replication from %s: %w", cred.Primary, err)
		}
		slog.Warn("primary unreachable; starting with the last replicated state", "error", err)
	}
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
	if err := writeFileAtomic(controllersPath(credential), []byte(strings.Join(list, "\n")+"\n")); err != nil {
		slog.Warn("could not persist the controller list", "error", err)
	}
}
