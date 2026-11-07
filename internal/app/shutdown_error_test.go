package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestSuperviseReportsShutdownError(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	open := func(string, []string) (io.ReadWriteCloser, error) { return testDevice{}, nil }
	fetch := func(context.Context, core.Credential) (core.Config, string, error) {
		return state.Config, "alice", nil
	}
	run := func(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser) error {
		close(started)
		<-ctx.Done()
		return errors.New("tunnel shutdown failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervise(ctx, cred, "kf0", state.Config, "alice", time.Hour, 0, open, fetch, run) }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "tunnel shutdown failed") {
			t.Fatalf("shutdown error lost: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("supervisor did not stop")
	}
}
