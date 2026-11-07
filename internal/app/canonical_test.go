package app

import (
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestIPv6CommandsStoreCanonicalForm(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", filepath.Join(t.TempDir(), "alice.json")}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"ipv6-network", "-data", dir, "-network", "FD77:0::/64"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"ipv6-assign", "-data", dir, "-id", "alice", "-ip", "FD77:0:0:0:0:0:0:1"}); err != nil {
		t.Fatal(err)
	}
	s, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Config.Network6 != "fd77::/64" || s.Config.Peers[0].IPv6 != "fd77::1" {
		t.Fatalf("stored %q / %q, want canonical fd77::/64 / fd77::1", s.Config.Network6, s.Config.Peers[0].IPv6)
	}
	if err := Run([]string{"ipv6-network", "-data", dir, "-network", "fd78::1/64"}); err == nil {
		t.Fatal("non-masked IPv6 prefix accepted")
	}
}
