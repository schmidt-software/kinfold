package agent

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/metrics"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func pathGauge(peer, path string) int64 {
	return Metrics.Gauge("kinfold_peer_path", "1 for the path currently used to reach the peer.", metrics.Labels{"peer": peer, "path": path}).Value()
}

func TestDirectPathCarriesTrafficAndEndsOnRevocation(t *testing.T) {
	cfg, a, b := setup(t)
	bobAddr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	ta, tb := newFakeTun(), newFakeTun()
	bobUpdates := make(chan core.Config, 1)
	done := make(chan error, 2)
	endpoints := func(peer string) []string {
		if peer == "bob" {
			return []string{bobAddr}
		}
		return nil
	}
	go func() {
		done <- RunWithUpdates(ctx, a, cfg.ForPeer("alice"), "alice", ta, nil, WithDirect("", endpoints))
	}()
	go func() {
		done <- RunWithUpdates(ctx, b, cfg.ForPeer("bob"), "bob", tb, bobUpdates, WithDirect(bobAddr, func(string) []string { return nil }))
	}()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			if err := <-done; err != nil {
				t.Errorf("agent stopped: %v", err)
			}
		}
	}()
	if !waitDelivered(t, ta, tb, ipv4(1, 2), 8*time.Second) {
		t.Fatal("no traffic between the agents")
	}
	if pathGauge("bob", "direct") != 1 || pathGauge("bob", "relay") != 0 {
		t.Fatalf("alice reaches bob via direct=%d relay=%d, want the direct path", pathGauge("bob", "direct"), pathGauge("bob", "relay"))
	}

	// Bob's configuration withdraws every rule with alice: bob drops the
	// link and with it the direct session, without involving the relay.
	revoked := cfg.Clone()
	revoked.SetRule("alice", "bob", false)
	revoked.SetRule("bob", "alice", false)
	bobUpdates <- revoked.ForPeer("bob")
	deadline := time.Now().Add(5 * time.Second)
	for pathGauge("bob", "direct") != 0 {
		if time.Now().After(deadline) {
			t.Fatal("direct session survived the revocation on the accepting side")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDirectListenerRejectsUnknownCertificate(t *testing.T) {
	cfg, _, b := setup(t)
	_, stranger, _ := setup(t) // a device of another network (other CA)
	bobAddr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunWithUpdates(ctx, b, cfg.ForPeer("bob"), "bob", newFakeTun(), nil, WithDirect(bobAddr, nil))
	}()
	bob, _ := cfg.Peer("bob")
	var err error
	for i := 0; i < 50; i++ {
		if _, err = dialDirect(ctx, stranger, bob, bobAddr); err != nil && strings.Contains(err.Error(), "connection refused") {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		break
	}
	if err == nil {
		t.Fatal("a certificate from another CA got a direct session")
	}
	cancel()
	<-done
}
