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

type countedTunnel struct {
	testDevice
	closes atomic.Int32
	err    error
}

func (d *countedTunnel) Close() error {
	d.closes.Add(1)
	return d.err
}

func TestSuperviseClosesTunnelOnceAndReportsCloseError(t *testing.T) {
	for _, runnerCloses := range []bool{false, true} {
		name := "runner returns early"
		if runnerCloses {
			name = "runner closes tunnel"
		}
		t.Run(name, func(t *testing.T) {
			state, err := core.NewState("localhost:8443", "10.77.0.0/24")
			if err != nil {
				t.Fatal(err)
			}
			cred, err := state.AddPeer("alice", "10.77.0.1")
			if err != nil {
				t.Fatal(err)
			}
			closeErr := errors.New("tunnel close failure")
			runErr := errors.New("runner failure")
			device := &countedTunnel{err: closeErr}
			open := func(string, []string) (io.ReadWriteCloser, error) { return device, nil }
			fetch := func(context.Context, core.Credential) (core.Config, string, error) {
				return state.Config, "alice", nil
			}
			run := func(_ context.Context, _ core.Credential, _ core.Config, _ string, tunnel io.ReadWriteCloser) error {
				if runnerCloses {
					return errors.Join(runErr, tunnel.Close())
				}
				return runErr
			}
			err = supervise(context.Background(), cred, "kf0", state.Config, "alice", time.Hour, 0, open, fetch, run)
			if !errors.Is(err, runErr) || !errors.Is(err, closeErr) {
				t.Fatalf("runner or close failure lost: %v", err)
			}
			if got := device.closes.Load(); got != 1 {
				t.Fatalf("tunnel closed %d times, want 1", got)
			}
		})
	}
}
