package relay

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestWatchFailsClosedOnInvalidPKIAndRecovers(t *testing.T) {
	dir := t.TempDir()
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.json")
	if err := core.WriteJSON(path, state); err != nil {
		t.Fatal(err)
	}
	server, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	left, right := net.Pipe()
	defer right.Close()
	if err := right.SetReadDeadline(time.Now().Add(4 * time.Second)); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	server.active[left] = endpoint{from: "a", to: "b"}
	server.mu.Unlock()
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		server.Watch(done, state, func() (*core.State, error) { return core.LoadState(dir) }, 10*time.Millisecond)
	}()
	defer func() { close(done); <-stopped }()
	bad := *state
	bad.CAKey = state.ServerKey
	if err := core.WriteJSON(path, &bad); err != nil {
		t.Fatal(err)
	}
	waitAvailable := func(want bool) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			server.mu.Lock()
			got := server.available
			server.mu.Unlock()
			if got == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("relay availability did not become %v", want)
	}
	waitAvailable(false)
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Fatal("relay session survived invalid PKI")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("relay session was not closed")
	}
	if err := core.WriteJSON(path, state); err != nil {
		t.Fatal(err)
	}
	waitAvailable(true)
}
