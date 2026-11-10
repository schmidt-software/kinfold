package agent

import (
	"context"
	"testing"
	"time"
)

func TestDirectionalPolicyBetweenAgents(t *testing.T) {
	cfg, alice, bob := setupWithReverse(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	a, b := newFakeTun(), newFakeTun()
	done := make(chan error, 2)
	go func() { done <- RunWithUpdates(ctx, alice, cfg, "alice", a, nil) }()
	go func() { done <- RunWithUpdates(ctx, bob, cfg, "bob", b, nil) }()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("agent error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("agent did not stop")
			}
		}
	}()
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.in <- ipv4(1, 2)
		case <-b.out:
			goto connected
		case <-deadline.C:
			t.Fatal("allowed direction did not deliver")
		}
	}
connected:
	b.in <- ipv4(2, 1)
	select {
	case <-a.out:
		t.Fatal("blocked direction delivered a packet")
	case <-time.After(300 * time.Millisecond):
	}
}
