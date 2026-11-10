package agent

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type delayedCloseDevice struct {
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	err     error
}

func (d *delayedCloseDevice) Read([]byte) (int, error) {
	<-d.closed
	return 0, io.EOF
}

func (d *delayedCloseDevice) Write(p []byte) (int, error) { return len(p), nil }

func (d *delayedCloseDevice) Close() error {
	close(d.entered)
	<-d.release
	close(d.closed)
	return d.err
}

func TestRunWaitsForTunnelCloseAndReportsFailure(t *testing.T) {
	for _, closeErr := range []error{nil, errors.New("injected close error")} {
		state, err := core.NewState("localhost:8443", "10.77.0.0/24")
		if err != nil {
			t.Fatal(err)
		}
		credential, err := state.AddPeer("alice", "10.77.0.1")
		if err != nil {
			t.Fatal(err)
		}
		device := &delayedCloseDevice{
			entered: make(chan struct{}), release: make(chan struct{}),
			closed: make(chan struct{}), err: closeErr,
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- RunWithUpdates(ctx, credential, state.Config, "alice", device, nil) }()
		cancel()
		select {
		case <-device.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("tunnel close did not start")
		}
		select {
		case err := <-done:
			t.Fatalf("run returned before close completed: %v", err)
		default:
		}
		close(device.release)
		select {
		case err := <-done:
			if closeErr == nil && err != nil {
				t.Fatal(err)
			}
			if closeErr != nil && (err == nil || !strings.Contains(err.Error(), closeErr.Error())) {
				t.Fatalf("missing close failure: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("run did not stop after tunnel close")
		}
	}
}
