package core

import "testing"

func TestValidateRestrictsIPv4NetworkToPrivateSpace(t *testing.T) {
	for _, network := range []string{"10.0.0.0/8", "10.77.0.0/24", "172.16.5.0/24", "172.31.255.0/30", "192.168.1.0/24", "100.64.0.0/16"} {
		if err := (Config{Network: network}).Validate(); err != nil {
			t.Errorf("rejected private network %s: %v", network, err)
		}
	}
	for _, network := range []string{"0.0.0.0/0", "10.0.0.0/7", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "8.8.8.0/24", "172.32.0.0/24", "100.128.0.0/16"} {
		if err := (Config{Network: network}).Validate(); err == nil {
			t.Errorf("accepted non-private network %s", network)
		}
	}
}

func TestValidateRequiresCanonicalIPv6(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		network, address string
		ok               bool
	}{
		{"fd77::/64", "fd77::1", true},
		{"FD77::/64", "fd77::1", false},
		{"fd77:0::/64", "fd77::1", false},
		{"fd77::/64", "FD77::1", false},
		{"fd77::/64", "fd77:0:0:0:0:0:0:1", false},
	} {
		cfg := s.Config
		cfg.Peers = append([]Peer(nil), s.Config.Peers...)
		cfg.Network6, cfg.Peers[0].IPv6 = tc.network, tc.address
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("network %s address %s: err=%v, want ok=%v", tc.network, tc.address, err, tc.ok)
		}
	}
}

// signWithCA issues a certificate from the state's CA for an arbitrary template.
