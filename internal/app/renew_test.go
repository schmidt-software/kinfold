package app

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

// renewalController runs a controller on a real state directory whose clock
// for renewal decisions is controller().
func renewalController(t *testing.T, now func() time.Time) (dir, credPath string, cred core.Credential) {
	t.Helper()
	dir = filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	credDir := t.TempDir()
	credPath = filepath.Join(credDir, "alice.json")
	if err := Run([]string{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", credPath}); err != nil {
		t.Fatal(err)
	}
	state, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	handler.SetRenewer(controllerRenewer(dir, now))
	tlsCfg, err := relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := listenController(ctx, "127.0.0.1:0", relay.DefaultListenerLimits)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := newControllerServer(handler, tlsCfg, defaultServerTimeouts)
	done := make(chan error, 1)
	go func() {
		done <- serveController(ctx, server, ln, handler, func(ctx context.Context) {
			handler.Watch(ctx.Done(), state, func() (*core.State, error) { return core.LoadState(dir) }, 20*time.Millisecond)
		}, time.Second)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("controller: %v", err)
		}
	})
	if err := core.ReadJSON(credPath, &cred); err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	cred.Server = "localhost:" + port
	if err := os.Remove(credPath); err != nil {
		t.Fatal(err)
	}
	if err := core.WriteJSON(credPath, cred); err != nil {
		t.Fatal(err)
	}
	return dir, credPath, cred
}

func TestCertificateRenewalEndToEnd(t *testing.T) {
	var late time.Time
	_, credPath, cred := renewalController(t, func() time.Time { return late })
	cert, err := credentialCertificate(cred)
	if err != nil {
		t.Fatal(err)
	}
	late = cert.NotAfter.Add(-7 * 24 * time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client := agent.NewConfigClient(cred)
	defer client.Close()

	if _, ok, err := renewCredential(ctx, credPath, cred, client, time.Now()); ok || err != nil {
		t.Fatalf("fresh certificate: renewed=%v err=%v", ok, err)
	}
	renewed, ok, err := renewCredential(ctx, credPath, cred, client, late)
	if err != nil || !ok {
		t.Fatalf("renewal: renewed=%v err=%v", ok, err)
	}
	var onDisk core.Credential
	if err := core.ReadJSON(credPath, &onDisk); err != nil {
		t.Fatal(err)
	}
	if string(onDisk.Cert) != string(renewed.Cert) || string(onDisk.Key) == string(cred.Key) {
		t.Fatal("credential file was not replaced with the new key and certificate")
	}
	if info, err := os.Stat(credPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("credential mode after renewal: %v %v", info.Mode(), err)
	}
	if _, id, err := fetchAfterRenewal(ctx, renewed); err != nil || id != "alice" {
		t.Fatalf("renewed credential not accepted: id=%q err=%v", id, err)
	}
	if _, _, err := agent.FetchConfig(ctx, cred); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("old credential still accepted: %v", err)
	}
}

func TestRenewalRejectedOutsideControllerWindow(t *testing.T) {
	_, credPath, cred := renewalController(t, time.Now)
	cert, err := credentialCertificate(cred)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := agent.NewConfigClient(cred)
	defer client.Close()
	// The client believes renewal is due (skewed clock), the controller does not.
	_, ok, err := renewCredential(ctx, credPath, cred, client, cert.NotAfter.Add(-time.Hour))
	if ok || err != core.ErrRenewalNotDue {
		t.Fatalf("renewed=%v err=%v, want ErrRenewalNotDue", ok, err)
	}
	var onDisk core.Credential
	if err := core.ReadJSON(credPath, &onDisk); err != nil {
		t.Fatal(err)
	}
	if string(onDisk.Cert) != string(cred.Cert) {
		t.Fatal("credential changed although renewal was refused")
	}
}

func TestRenewCommandReportsNotDue(t *testing.T) {
	_, credPath, _ := renewalController(t, time.Now)
	if err := Run([]string{"renew", "-credential", credPath}); err != nil {
		t.Fatalf("renew on a fresh certificate: %v", err)
	}
}
