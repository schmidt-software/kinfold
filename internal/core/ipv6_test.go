package core

import "testing"

func TestIPv6ConfigValidation(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	s.Config.Network6 = "fd77::/64"
	s.Config.Peers[0].IPv6 = "fd77::1"
	s.Config.Peers[1].IPv6 = "fd77::2"
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"::/64", "fd77::1/64", "fd77::/48", "2001:db8::/64", "fd77::/65", ""} {
		cfg := s.Config
		cfg.Network6 = invalid
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted IPv6 prefix %q", invalid)
		}
	}
	for _, invalid := range []string{"fd77::", "fd78::1", "fe80::1%lo", "::ffff:10.77.0.1", "fd77:0:0:0:0:0:0:1"} {
		cfg := s.Config
		cfg.Peers = append([]Peer(nil), s.Config.Peers...)
		cfg.Peers[1].IPv6 = invalid
		if err := cfg.Validate(); err == nil {
			t.Errorf("accepted IPv6 address %q", invalid)
		}
	}
}
