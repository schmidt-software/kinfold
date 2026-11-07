package relay

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestRelayPeerPairAdmission(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(state.Config.Peers[0].Cert)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := func(cfg core.Config, revision string) int {
		t.Helper()
		if err := server.Update(cfg, nil); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodConnect, "/relay?peer=bob", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		req.Header.Set("X-Kinfold-Config-Revision", revision)
		recorder := httptest.NewRecorder()
		server.ServeHTTP(recorder, req)
		return recorder.Code
	}
	revision, err := state.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if got := request(state.Config, revision); got != http.StatusForbidden {
		t.Fatalf("default-deny pair: %d", got)
	}
	if err := state.Config.SetRule("bob", "alice", true); err != nil {
		t.Fatal(err)
	}
	revision, err = state.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	// A recorder cannot hijack: 500 means the pair passed authorization.
	if got := request(state.Config, revision); got != http.StatusInternalServerError {
		t.Fatalf("reverse-only rule did not permit session: %d", got)
	}
	if got := request(state.Config, "stale"); got != http.StatusConflict {
		t.Fatalf("stale revision: %d", got)
	}
	state.Config.Policy = nil
	revision, err = state.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if got := request(state.Config, ""); got != http.StatusConflict {
		t.Fatalf("missing revision accepted without policy: %d", got)
	}
	if got := request(state.Config, revision); got != http.StatusForbidden {
		t.Fatalf("configuration without policy did not deny the pair: %d", got)
	}
}
