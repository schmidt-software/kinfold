package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func threePeerState(t *testing.T) *core.State {
	t.Helper()
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}, {"carol", "10.77.0.3"}} {
		if _, err := state.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]string{{"alice", "bob"}, {"bob", "alice"}, {"bob", "carol"}} {
		if err := state.Config.SetRule(r[0], r[1], true); err != nil {
			t.Fatal(err)
		}
	}
	return state
}

func TestUpdateClosesOnlyAffectedPairs(t *testing.T) {
	state := threePeerState(t)
	s, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ab, abPeer := net.Pipe()
	bc, bcPeer := net.Pipe()
	defer abPeer.Close()
	defer bcPeer.Close()
	s.mu.Lock()
	s.active[ab] = endpoint{from: "alice", to: "bob"}
	s.active[bc] = endpoint{from: "bob", to: "carol"}
	s.mu.Unlock()
	isActive := func(c net.Conn) bool { s.mu.Lock(); defer s.mu.Unlock(); _, ok := s.active[c]; return ok }

	if err := state.Config.SetRule("carol", "bob", true); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(state.Config, nil); err != nil {
		t.Fatal(err)
	}
	if !isActive(ab) {
		t.Fatal("unrelated change closed the alice-bob session")
	}
	if isActive(bc) {
		t.Fatal("the bob-carol session survived a rule change between bob and carol")
	}
}

func TestUpdateClosesChangedPair(t *testing.T) {
	state := threePeerState(t)
	s, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ab, abPeer := net.Pipe()
	bc, bcPeer := net.Pipe()
	defer abPeer.Close()
	defer bcPeer.Close()
	s.mu.Lock()
	s.active[ab] = endpoint{from: "alice", to: "bob"}
	s.active[bc] = endpoint{from: "bob", to: "carol"}
	s.mu.Unlock()
	if err := state.Config.SetRule("bob", "alice", false); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(state.Config, nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	_, abOK := s.active[ab]
	_, bcOK := s.active[bc]
	s.mu.Unlock()
	if abOK || !bcOK {
		t.Fatalf("after changing alice<->bob: alice-bob active=%v (want false), bob-carol active=%v (want true)", abOK, bcOK)
	}
}

func TestConfigEndpointServesPerDeviceView(t *testing.T) {
	state := threePeerState(t)
	s, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cert, err := x509.ParseCertificate(state.Config.Peers[0].Cert) // alice
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/config", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	var got core.Config
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got.Peer("carol"); ok || len(got.Policy.Allowed) != 2 {
		t.Fatalf("alice's view leaks other devices or rules: %d peers, %d rules", len(got.Peers), len(got.Policy.Allowed))
	}
}
