package core

import "testing"

func TestServicePolicyValidationAndLifecycle(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Config.SetServiceRule("alice", "bob", "tcp", 443, true); err == nil {
		t.Fatal("enabled service without policy")
	}
	s.Config.Policy.Services = &ServicePolicy{}
	if err := s.Config.SetServiceRule("alice", "bob", "tcp", 443, true); err == nil {
		t.Fatal("enabled service without directional permission")
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		proto string
		port  uint16
	}{{"tcp", 0}, {"udp", 0}, {"icmp", 1}, {"icmp6", 1}, {"sctp", 80}} {
		if err := s.Config.SetServiceRule("alice", "bob", tc.proto, tc.port, true); err == nil {
			t.Errorf("accepted %s/%d", tc.proto, tc.port)
		}
	}
	for _, tc := range []struct {
		proto string
		port  uint16
	}{{"tcp", 443}, {"udp", 53}, {"icmp", 0}, {"icmp6", 0}} {
		if err := s.Config.SetServiceRule("alice", "bob", tc.proto, tc.port, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	s.Config.Policy.Services.Allowed = append(s.Config.Policy.Services.Allowed, s.Config.Policy.Services.Allowed[0])
	if err := s.Config.Validate(); err == nil {
		t.Fatal("duplicate service accepted")
	}
	s.Config.Policy.Services.Allowed = s.Config.Policy.Services.Allowed[:4]
	if err := s.Config.SetRule("alice", "bob", false); err != nil {
		t.Fatal(err)
	}
	if len(s.Config.Policy.Services.Allowed) != 0 {
		t.Fatal("revoked direction retained service rules")
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
}
