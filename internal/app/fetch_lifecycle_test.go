package app

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestSuperviseReportsAgentFailureDuringFetch(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	started, fetchStopped, fail := make(chan struct{}), make(chan struct{}), make(chan struct{})
	runErr := errors.New("injected tunnel failure")
	open := func(string, []string) (io.ReadWriteCloser, error) { return testDevice{}, nil }
	fetch := func(ctx context.Context, _ core.Credential) (core.Config, string, error) {
		close(started)
		<-ctx.Done()
		close(fetchStopped)
		return core.Config{}, "", ctx.Err()
	}
	run := func(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser, _ <-chan core.Config) error {
		select {
		case <-fail:
			return runErr
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- supervise(ctx, cred, "kf0", state.Config, "alice", time.Millisecond, 0, open, fetch, run)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not begin")
	}
	close(fail)
	select {
	case err := <-done:
		if !errors.Is(err, runErr) {
			t.Fatalf("agent error lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fetch blocked agent error")
	}
	select {
	case <-fetchStopped:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch was not canceled")
	}
}

func TestSuperviseCancelsSingleOutstandingFetchOnShutdown(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	started, stopped := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	open := func(string, []string) (io.ReadWriteCloser, error) { return testDevice{}, nil }
	fetch := func(ctx context.Context, _ core.Credential) (core.Config, string, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-ctx.Done()
		if calls.Load() == 1 {
			close(stopped)
		}
		return core.Config{}, "", ctx.Err()
	}
	run := func(ctx context.Context, _ core.Credential, _ core.Config, _ string, _ io.ReadWriteCloser, _ <-chan core.Config) error {
		<-ctx.Done()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- supervise(ctx, cred, "kf0", state.Config, "alice", time.Millisecond, 0, open, fetch, run)
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch did not begin")
	}
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("shutdown: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("shutdown blocked")
	}
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("fetch not canceled")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("concurrent fetches started: %d", got)
	}
}
