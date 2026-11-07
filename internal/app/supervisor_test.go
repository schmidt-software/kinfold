package app

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type testDevice struct{}

func (testDevice) Read([]byte) (int, error)    { return 0, io.EOF }
func (testDevice) Write(p []byte) (int, error) { return len(p), nil }
func (testDevice) Close() error                { return nil }

func TestSuperviseRefreshAndFailClosed(t *testing.T) {
	s, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	initial := s.Config
	changed := initial
	changed.Network = "10.77.0.0/25"
	var mu sync.Mutex
	current, fail := initial, false
	opened, stopped := make(chan string, 10), make(chan struct{}, 10)
	open := func(_ string, addresses []string) (io.ReadWriteCloser, error) {
		opened <- addresses[0]
		return testDevice{}, nil
	}
	fetch := func(context.Context, core.Credential) (core.Config, string, error) {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			return core.Config{}, "", errors.New("offline")
		}
		return current, "alice", nil
	}
	run := func(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser) error {
		<-ctx.Done()
		stopped <- struct{}{}
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- supervise(ctx, cred, "kf0", initial, "alice", 10*time.Millisecond, open, fetch, run)
	}()
	waitAddress := func(expected string) {
		t.Helper()
		select {
		case addr := <-opened:
			if addr != expected {
				t.Fatalf("address %q, want %q", addr, expected)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("tunnel was not started")
		}
	}
	waitStop := func() {
		t.Helper()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Fatal("tunnel was not stopped")
		}
	}
	waitAddress("10.77.0.1/24")
	mu.Lock()
	current = changed
	mu.Unlock()
	waitStop()
	waitAddress("10.77.0.1/25")
	mu.Lock()
	fail = true
	mu.Unlock()
	waitStop()
	select {
	case <-opened:
		t.Fatal("tunnel restarted while controller unavailable")
	case <-time.After(50 * time.Millisecond):
	}
	mu.Lock()
	fail = false
	mu.Unlock()
	waitAddress("10.77.0.1/25")
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor failed to stop")
	}
}
