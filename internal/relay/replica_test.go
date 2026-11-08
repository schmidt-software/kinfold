package relay

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReplicaStateAndStandby(t *testing.T) {
	state := threePeerState(t)
	repl, err := state.AddReplica("standby", "standby.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	block, _ := pem.Decode(repl.Cert)
	replicaCert, _ := x509.ParseCertificate(block.Bytes)
	peerCert, _ := x509.ParseCertificate(state.Config.Peers[0].Cert)
	get := func(cert *x509.Certificate) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/replica/state", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, r)
		return rec
	}
	rec := get(replicaCert)
	if rec.Code != http.StatusOK {
		t.Fatalf("replica state: %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got["ca_key"] == nil {
		t.Fatal("replica did not receive the full state")
	}
	if rec := get(peerCert); rec.Code != http.StatusForbidden {
		t.Fatalf("a member device received the controller state: %d", rec.Code)
	}
	if s.controllers[1] != "standby.example.com:8443" {
		t.Fatalf("controller list %v", s.controllers)
	}

	standby, err := NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer standby.Close()
	standby.SetStandby()
	standby.SetRenewer(func(string, *x509.Certificate, []byte) ([]byte, error) { t.Fatal("standby renewed"); return nil, nil })
	r := httptest.NewRequest(http.MethodPost, "/renew", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
	rec = httptest.NewRecorder()
	standby.ServeHTTP(rec, r)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("X-Kinfold-Standby") != "1" {
		t.Fatalf("standby renewal: %d %q", rec.Code, rec.Header().Get("X-Kinfold-Standby"))
	}
	r = httptest.NewRequest(http.MethodGet, "/replica/state", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{replicaCert}}
	rec = httptest.NewRecorder()
	standby.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("standby replicated further: %d", rec.Code)
	}

	config := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/config", nil)
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
		rec := httptest.NewRecorder()
		standby.ServeHTTP(rec, r)
		return rec
	}
	if rec := config(); rec.Code != http.StatusOK {
		t.Fatalf("standby config: %d", rec.Code)
	}
	standby.SetStale(true)
	if rec := config(); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("X-Kinfold-Standby") != "1" {
		t.Fatalf("stale standby config: %d %q", rec.Code, rec.Header().Get("X-Kinfold-Standby"))
	}
	standby.SetStale(false)
	if rec := config(); rec.Code != http.StatusOK {
		t.Fatalf("standby config after recovery: %d", rec.Code)
	}
}
