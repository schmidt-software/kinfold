package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRenewalWindows(t *testing.T) {
	start := time.Unix(0, 0)
	cert := &x509.Certificate{NotBefore: start, NotAfter: start.Add(300 * time.Hour)}
	for _, tc := range []struct {
		at            time.Duration
		due, accepted bool
	}{
		{0, false, false},
		{149 * time.Hour, false, false},
		{150 * time.Hour, false, true},
		{201 * time.Hour, true, true},
		{299 * time.Hour, true, true},
		{300 * time.Hour, true, false},
	} {
		now := start.Add(tc.at)
		if got := RenewalDue(cert, now); got != tc.due {
			t.Errorf("at %v: due=%v, want %v", tc.at, got, tc.due)
		}
		if got := RenewalAccepted(cert, now); got != tc.accepted {
			t.Errorf("at %v: accepted=%v, want %v", tc.at, got, tc.accepted)
		}
	}
}

func TestRenewPeer(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cred.Cert)
	presented, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, request, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RenewPeer("alice", presented, request, time.Now()); !errors.Is(err, ErrRenewalNotDue) {
		t.Fatalf("fresh certificate renewed: %v", err)
	}
	late := presented.NotAfter.Add(-24 * time.Hour)
	if _, _, err := s.RenewPeer("bob", presented, request, late); err == nil {
		t.Fatal("unknown peer renewed")
	}
	_, wrongID, _ := NewEnrollment("bob")
	if _, _, err := s.RenewPeer("alice", presented, wrongID, late); err == nil {
		t.Fatal("request for another ID accepted")
	}
	certPEM, changed, err := s.RenewPeer("alice", presented, request, late)
	if err != nil || !changed {
		t.Fatalf("renewal in window failed: changed=%v err=%v", changed, err)
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	// A retry with the old certificate and the same request (lost response)
	// returns the same certificate without changing the state, also when the
	// relay no longer knows the ID of the old certificate.
	for _, id := range []string{"alice", ""} {
		again, changed, err := s.RenewPeer(id, presented, request, late)
		if err != nil || changed || string(again) != string(certPEM) {
			t.Fatalf("retry (id %q): changed=%v err=%v same=%v", id, changed, err, string(again) == string(certPEM))
		}
	}
	_, otherKey, _ := NewEnrollment("alice")
	if _, _, err := s.RenewPeer("alice", presented, otherKey, late); err == nil {
		t.Fatal("old certificate obtained a certificate for a different key")
	}
	block, _ = pem.Decode(certPEM)
	renewed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(renewed) == Fingerprint(presented) {
		t.Fatal("certificate unchanged")
	}
	if _, _, err := s.RenewPeer("alice", renewed, request, renewed.NotAfter.Add(-time.Hour)); err == nil {
		t.Fatal("previously used key accepted again")
	}
}

func TestRenewPeerRefusesNearCAExpiry(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	caBlock, _ := pem.Decode(s.CA)
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der := signWithCA(t, s, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "alice"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		NotAfter:    ca.NotAfter.Add(-time.Hour),
	}, pub)
	s.Config.Peers = []Peer{{ID: "alice", IP: "10.77.0.1", Cert: der}}
	presented, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	_, request, _ := NewEnrollment("alice")
	_, changed, err := s.RenewPeer("alice", presented, request, presented.NotAfter.Add(-2*time.Hour))
	if !errors.Is(err, ErrRenewalNotDue) || changed || !strings.Contains(err.Error(), "rotate the CA") {
		t.Fatalf("renewal capped by CA expiry was not refused: changed=%v err=%v", changed, err)
	}
}

func TestRemovedPeerRenewalRecordIsRejected(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	s.RenewedFrom = map[string]string{"bob": strings.Repeat("ab", 32)}
	if err := s.validateRenewedFrom(); err == nil {
		t.Fatal("renewal record for an unknown peer accepted")
	}
	s.RenewedFrom = map[string]string{"alice": "zz"}
	if err := s.validateRenewedFrom(); err == nil {
		t.Fatal("malformed renewal record accepted")
	}
	s.RenewedFrom = map[string]string{"alice": strings.Repeat("ab", 32)}
	if err := s.validateRenewedFrom(); err != nil {
		t.Fatal(err)
	}
	s.ForgetPeer("alice")
	if len(s.RenewedFrom) != 0 {
		t.Fatal("ForgetPeer kept the record")
	}
}
