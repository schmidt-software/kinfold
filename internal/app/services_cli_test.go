package app

import (
	"path/filepath"
	"testing"

	"my-zerotier/internal/core"
)

func TestServiceCLIAndPeerRemoval(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	commands := [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"add-peer", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-out", filepath.Join(dir, "alice")},
		{"add-peer", "-data", state, "-id", "bob", "-ip", "10.77.0.2", "-out", filepath.Join(dir, "bob")},
		{"allow", "-data", state, "-from", "alice", "-to", "bob"},
		{"service-enable", "-data", state},
		{"service-allow", "-data", state, "-from", "alice", "-to", "bob", "-protocol", "udp", "-port", "53"},
	}
	for _, cmd := range commands {
		if err := Run(cmd); err != nil {
			t.Fatalf("%v: %v", cmd, err)
		}
	}
	if err := Run([]string{"service-allow", "-data", state, "-from", "alice", "-to", "bob", "-protocol", "tcp", "-port", "65536"}); err == nil {
		t.Fatal("accepted oversized port")
	}
	s, err := core.LoadState(state)
	if err != nil || len(s.Config.Policy.Services.Allowed) != 1 {
		t.Fatalf("service policy not saved: %v", err)
	}
	if err := Run([]string{"remove-peer", "-data", state, "-id", "bob"}); err != nil {
		t.Fatal(err)
	}
	s, err = core.LoadState(state)
	if err != nil || len(s.Config.Policy.Services.Allowed) != 0 {
		t.Fatalf("removing peer did not clean up service policy: %v", err)
	}
}
