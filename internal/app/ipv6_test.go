package app

import (
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestIPv6Commands(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	commands := [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"add-peer", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-out", filepath.Join(dir, "a")},
		{"ipv6-network", "-data", state, "-network", "fd77::/64"},
		{"ipv6-assign", "-data", state, "-id", "alice", "-ip", "fd77::1"},
	}
	for _, args := range commands {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := Run([]string{"ipv6-network", "-data", state, "-network", "none"}); err == nil {
		t.Fatal("disabled IPv6 while an assignment exists")
	}
	s, err := core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	if s.Config.Network6 != "fd77::/64" || s.Config.Peers[0].IPv6 != "fd77::1" {
		t.Fatal("failed update changed persisted state")
	}
	if err := Run([]string{"ipv6-assign", "-data", state, "-id", "alice", "-ip", "none"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"ipv6-network", "-data", state, "-network", "none"}); err != nil {
		t.Fatal(err)
	}
}
