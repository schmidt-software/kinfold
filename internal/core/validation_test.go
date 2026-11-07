package core

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestRevisionIsStableAcrossJSONRoundTrip(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	first, err := s.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Config.Revision(); again != first {
		t.Fatal("revision is not deterministic")
	}
	data, err := json.Marshal(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := DecodeJSON(strings.NewReader(string(data)), &decoded); err != nil {
		t.Fatal(err)
	}
	if got, _ := decoded.Revision(); got != first {
		t.Fatal("controller and client would compute different revisions for the same configuration")
	}
	if err := s.Config.SetRule("bob", "alice", true); err != nil {
		t.Fatal(err)
	}
	if changed, _ := s.Config.Revision(); changed == first {
		t.Fatal("revision did not change with the policy")
	}
}

func TestSetRuleDoesNotMutateSharedSlices(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}, {"carol", "10.77.0.3"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]string{{"alice", "bob"}, {"bob", "carol"}} {
		if err := s.Config.SetRule(r[0], r[1], true); err != nil {
			t.Fatal(err)
		}
	}
	s.Config.Policy.Services = &ServicePolicy{Allowed: []ServiceRule{{From: "bob", To: "carol", Protocol: "icmp"}, {From: "alice", To: "bob", Protocol: "icmp"}}}
	rules, services := s.Config.Policy.Allowed, s.Config.Policy.Services.Allowed
	if err := s.Config.SetRule("alice", "bob", false); err != nil {
		t.Fatal(err)
	}
	if rules[0] != (Rule{From: "alice", To: "bob"}) || rules[1] != (Rule{From: "bob", To: "carol"}) {
		t.Fatalf("SetRule edited a previously shared rule slice: %v", rules)
	}
	if services[0].From != "bob" || services[1].From != "alice" {
		t.Fatalf("SetRule edited a previously shared service slice: %v", services)
	}
}
