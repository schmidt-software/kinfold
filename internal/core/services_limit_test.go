package core

import "testing"

func TestServiceRuleLimit(t *testing.T) {
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
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	s.Config.Policy.Services = &ServicePolicy{}
	for i := 1; i <= MaxServiceRules; i++ {
		if err := s.Config.SetServiceRule("alice", "bob", "udp", uint16(i), true); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := s.Config.SetServiceRule("alice", "bob", "udp", MaxServiceRules+1, true); err == nil {
		t.Fatal("accepted rule above limit")
	}
	if err := s.Config.SetServiceRule("alice", "bob", "udp", 1, true); err != nil {
		t.Fatalf("idempotent existing rule rejected: %v", err)
	}
	s.Config.Policy.Services.Allowed = append(s.Config.Policy.Services.Allowed, ServiceRule{From: "alice", To: "bob", Protocol: "udp", Port: MaxServiceRules + 1})
	if err := s.Config.Validate(); err == nil {
		t.Fatal("accepted oversized configuration")
	}
}
