package core

import "testing"

func threePeerConfig(t *testing.T) Config {
	t.Helper()
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}, {"carol", "10.77.0.3"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]string{{"alice", "bob"}, {"bob", "alice"}, {"bob", "carol"}} {
		if err := s.Config.SetRule(r[0], r[1], true); err != nil {
			t.Fatal(err)
		}
	}
	return s.Config
}

func TestForPeerDisclosesOnlyRelatedDevicesAndRules(t *testing.T) {
	cfg := threePeerConfig(t)
	alice := cfg.ForPeer("alice")
	if err := alice.Validate(); err != nil {
		t.Fatalf("view does not validate: %v", err)
	}
	if len(alice.Peers) != 2 || len(alice.Policy.Allowed) != 2 {
		t.Fatalf("alice sees %d peers and %d rules, want 2 and 2", len(alice.Peers), len(alice.Policy.Allowed))
	}
	if _, ok := alice.Peer("carol"); ok {
		t.Fatal("alice learned about carol")
	}
	bob := cfg.ForPeer("bob")
	if len(bob.Peers) != 3 || len(bob.Policy.Allowed) != 3 {
		t.Fatalf("bob sees %d peers and %d rules", len(bob.Peers), len(bob.Policy.Allowed))
	}
	// A change between bob and carol does not change alice's view.
	before, _ := alice.Revision()
	if err := cfg.SetRule("carol", "bob", true); err != nil {
		t.Fatal(err)
	}
	if after, _ := cfg.ForPeer("alice").Revision(); after != before {
		t.Fatal("unrelated rule changed alice's revision")
	}
	if lone := cfg.ForPeer("dave"); len(lone.Peers) != 0 {
		t.Fatal("unknown device sees peers")
	}
}

func TestPairSignature(t *testing.T) {
	cfg := threePeerConfig(t)
	ab := cfg.PairSignature("alice", "bob")
	if ab == "" || ab != cfg.PairSignature("bob", "alice") {
		t.Fatal("signature empty or direction-dependent")
	}
	if cfg.PairSignature("alice", "carol") != "" {
		t.Fatal("unauthorized pair has a signature")
	}
	if err := cfg.SetRule("carol", "bob", true); err != nil {
		t.Fatal(err)
	}
	if cfg.PairSignature("alice", "bob") != ab {
		t.Fatal("unrelated change altered the pair signature")
	}
	if err := cfg.SetRule("bob", "alice", false); err != nil {
		t.Fatal(err)
	}
	if cfg.PairSignature("alice", "bob") == ab {
		t.Fatal("rule change between the pair did not alter its signature")
	}
}
