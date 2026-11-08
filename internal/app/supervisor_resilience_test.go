package app

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type resilienceHarness struct {
	mu      sync.Mutex
	cfg     core.Config
	failing bool
	openErr error
	opens   atomic.Int32
	stops   atomic.Int32
}

func (h *resilienceHarness) open(string, []string) (io.ReadWriteCloser, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.openErr != nil {
		return nil, h.openErr
	}
	h.opens.Add(1)
	return testDevice{}, nil
}

func (h *resilienceHarness) fetch(context.Context, core.Credential) (core.Config, string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failing {
		return core.Config{}, "", errors.New("controller unreachable")
	}
	return h.cfg, "alice", nil
}

func (h *resilienceHarness) run(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser, _ <-chan core.Config) error {
	<-ctx.Done()
	h.stops.Add(1)
	return nil
}

func (h *resilienceHarness) set(f func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f()
}

func newResilienceHarness(t *testing.T) (*resilienceHarness, core.Credential) {
	t.Helper()
	s, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return &resilienceHarness{cfg: s.Config}, cred
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func runHarness(t *testing.T, h *resilienceHarness, cred core.Credential, grace time.Duration) (cancel func()) {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- supervise(ctx, cred, "kf0", h.cfg, "alice", 5*time.Millisecond, grace, h.open, h.fetch, h.run)
	}()
	return func() {
		stop()
		select {
		case err := <-result:
			if err != nil {
				t.Errorf("supervise: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("supervisor did not stop")
		}
	}
}

func TestSuperviseKeepsTunnelDuringShortOutage(t *testing.T) {
	h, cred := newResilienceHarness(t)
	stop := runHarness(t, h, cred, time.Hour)
	defer stop()
	eventually(t, "initial tunnel", func() bool { return h.opens.Load() == 1 })
	h.set(func() { h.failing = true })
	time.Sleep(100 * time.Millisecond) // many failed polls, well within grace
	if h.stops.Load() != 0 {
		t.Fatal("tunnel was closed during a short controller outage")
	}
	h.set(func() { h.failing = false })
	time.Sleep(50 * time.Millisecond)
	if h.opens.Load() != 1 || h.stops.Load() != 0 {
		t.Fatalf("tunnel was recreated after recovery with unchanged config: opens=%d stops=%d", h.opens.Load(), h.stops.Load())
	}
}

func TestSuperviseFailsClosedAfterGrace(t *testing.T) {
	h, cred := newResilienceHarness(t)
	stop := runHarness(t, h, cred, 50*time.Millisecond)
	defer stop()
	eventually(t, "initial tunnel", func() bool { return h.opens.Load() == 1 })
	h.set(func() { h.failing = true })
	eventually(t, "fail closed after grace", func() bool { return h.stops.Load() == 1 })
	time.Sleep(30 * time.Millisecond)
	if h.opens.Load() != 1 {
		t.Fatal("tunnel reopened while the controller was unreachable")
	}
	h.set(func() { h.failing = false })
	eventually(t, "tunnel restored", func() bool { return h.opens.Load() == 2 })
}

func TestSuperviseRetriesFailedTunnelStart(t *testing.T) {
	h, cred := newResilienceHarness(t)
	stop := runHarness(t, h, cred, time.Hour)
	defer stop()
	eventually(t, "initial tunnel", func() bool { return h.opens.Load() == 1 })
	changed := h.cfg
	changed.Network = "10.77.0.0/25"
	h.set(func() { h.openErr = errors.New("interface kf0 already exists"); h.cfg = changed })
	eventually(t, "old tunnel stopped for the change", func() bool { return h.stops.Load() == 1 })
	time.Sleep(30 * time.Millisecond)
	h.set(func() { h.openErr = nil })
	eventually(t, "tunnel started after transient failure", func() bool { return h.opens.Load() == 2 })
}

func TestSuperviseHandsPolicyChangesToRunningAgent(t *testing.T) {
	s, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	current := s.Config.Clone()
	var opens atomic.Int32
	received := make(chan core.Config, 4)
	open := func(string, []string) (io.ReadWriteCloser, error) { opens.Add(1); return testDevice{}, nil }
	fetch := func(context.Context, core.Credential) (core.Config, string, error) {
		mu.Lock()
		defer mu.Unlock()
		return current, "alice", nil
	}
	run := func(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser, updates <-chan core.Config) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case c := <-updates:
				received <- c
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- supervise(ctx, cred, "kf0", s.Config, "alice", 5*time.Millisecond, time.Hour, open, fetch, run) }()
	defer func() { cancel(); <-result }()
	eventually(t, "initial tunnel", func() bool { return opens.Load() == 1 })
	mu.Lock()
	if err := current.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	mu.Unlock()
	select {
	case c := <-received:
		if !c.Permits("alice", "bob") {
			t.Fatal("agent received a stale configuration")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("policy change did not reach the running agent")
	}
	if opens.Load() != 1 {
		t.Fatalf("tunnel reopened %d times for a policy-only change", opens.Load()-1)
	}
}
