package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPeersAndPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "controller")
	if err := InitState(dir, "127.0.0.1:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := InitState(dir, "127.0.0.1:8443", "10.77.0.0/24"); err == nil {
		t.Fatal("init overwrote state")
	}
	s, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ id, ip string }{
		{"alice", "10.77.0.2"}, {"bob", "10.77.0.1"}, {"bad/id", "10.77.0.2"},
		{"bob", "10.77.0.0"}, {"bob", "10.77.0.255"}, {"bob", "10.78.0.1"},
	} {
		if _, err := s.AddPeer(test.id, test.ip); err == nil {
			t.Errorf("accepted invalid peer %+v", test)
		}
	}
	if len(s.Config.Peers) != 1 {
		t.Fatal("invalid AddPeer changed state")
	}
	path := filepath.Join(dir, "state.json")
	if err := WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe state permissions: %o", info.Mode().Perm())
	}
	reloaded, err := LoadState(dir)
	if err != nil || len(reloaded.Config.Peers) != 1 {
		t.Fatalf("reloading state: %v", err)
	}
}

func TestNetworkValidation(t *testing.T) {
	for _, network := range []string{"10.0.0.1/24", "10.0.0.0/31", "::/64", "invalid"} {
		if err := (Config{Network: network}).Validate(); err == nil {
			t.Errorf("accepted %q", network)
		}
	}
}

func TestDirectionalPolicy(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	if s.Config.Permits("alice", "bob") {
		t.Fatal("default policy allowed traffic")
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	if !s.Config.Permits("alice", "bob") || s.Config.Permits("bob", "alice") {
		t.Fatal("directional policy did not work")
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	if len(s.Config.Policy.Allowed) != 1 {
		t.Fatal("duplicate rule")
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Config.Policy.Allowed = append(s.Config.Policy.Allowed, Rule{From: "missing", To: "bob"})
	if err := s.Config.Validate(); err == nil {
		t.Fatal("accepted invalid rule")
	}
	s.Config.Policy.Allowed = s.Config.Policy.Allowed[:1]
	if err := s.Config.SetRule("alice", "bob", false); err != nil {
		t.Fatal(err)
	}
	if s.Config.Permits("alice", "bob") {
		t.Fatal("removed rule still allows traffic")
	}
	s.Config.Policy = nil
	if !s.Config.Permits("alice", "bob") {
		t.Fatal("legacy behavior changed")
	}
	if err := s.Config.SetRule("alice", "bob", true); err == nil {
		t.Fatal("modified legacy policy")
	}
}
