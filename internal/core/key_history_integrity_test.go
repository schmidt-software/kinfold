package core

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingActiveKeyIsRejected(t *testing.T) {
	state, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	state.UsedPeerKeys = []string{strings.Repeat("a", 64)}
	dir := privateTempDir(t)
	if err := WriteJSON(filepath.Join(dir, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected missing key error: %v", err)
	}
}
