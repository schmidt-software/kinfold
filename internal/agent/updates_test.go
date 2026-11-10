package agent

import (
	"context"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func waitDelivered(t *testing.T, from, to *fakeTun, packet []byte, within time.Duration) bool {
	t.Helper()
	deadline := time.After(within)
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			from.in <- packet
		case p := <-to.out:
			if string(p) == string(packet) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestUpdatesApplyWithoutRecreatingTunnel(t *testing.T) {
	cfg, a, b := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	ta, tb := newFakeTun(), newFakeTun()
	updates := make(chan core.Config, 1)
	done := make(chan error, 2)
	go func() { done <- RunWithUpdates(ctx, a, cfg.ForPeer("alice"), "alice", ta, updates) }()
	go func() { done <- RunWithUpdates(ctx, b, cfg.ForPeer("bob"), "bob", tb, nil) }()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			if err := <-done; err != nil {
				t.Errorf("agent stopped: %v", err)
			}
		}
	}()
	if !waitDelivered(t, ta, tb, ipv4(1, 2), 8*time.Second) {
		t.Fatal("initial session not established")
	}

	// An identical configuration keeps the session: the next packet goes
	// through immediately, without a reconnect window.
	updates <- cfg.ForPeer("alice")
	time.Sleep(100 * time.Millisecond)
	if !waitDelivered(t, ta, tb, ipv4(1, 2), 300*time.Millisecond) {
		t.Fatal("unchanged link lost its session after an update")
	}

	// Withdrawing alice->bob stops forwarding at once, still without
	// closing the TUN device.
	revoked := cfg.Clone()
	if err := revoked.SetRule("alice", "bob", false); err != nil {
		t.Fatal(err)
	}
	updates <- revoked.ForPeer("alice")
	time.Sleep(100 * time.Millisecond)
	for len(tb.out) > 0 {
		<-tb.out
	}
	if waitDelivered(t, ta, tb, ipv4(1, 2), 400*time.Millisecond) {
		t.Fatal("packet forwarded after the rule was withdrawn")
	}
	select {
	case <-ta.closed:
		t.Fatal("update closed the TUN device")
	default:
	}
}

func TestUpdateChangingOwnAddressStopsAgent(t *testing.T) {
	cfg, a, _ := setup(t)
	ta := newFakeTun()
	updates := make(chan core.Config, 1)
	done := make(chan error, 1)
	go func() { done <- RunWithUpdates(context.Background(), a, cfg, "alice", ta, updates) }()
	moved := cfg.Clone()
	moved.Peers[0].IP = "10.77.0.9"
	updates <- moved
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("agent accepted an update that moves its own address")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent kept running with a changed own address")
	}
}
