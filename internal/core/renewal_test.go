package core

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	if _, err := s.RenewPeer("alice", presented, request, time.Now()); !errors.Is(err, ErrRenewalNotDue) {
		t.Fatalf("fresh certificate renewed: %v", err)
	}
	late := presented.NotAfter.Add(-24 * time.Hour)
	if _, err := s.RenewPeer("bob", presented, request, late); err == nil {
		t.Fatal("unknown peer renewed")
	}
	_, wrongID, _ := NewEnrollment("bob")
	if _, err := s.RenewPeer("alice", presented, wrongID, late); err == nil {
		t.Fatal("request for another ID accepted")
	}
	certPEM, err := s.RenewPeer("alice", presented, request, late)
	if err != nil {
		t.Fatalf("renewal in window failed: %v", err)
	}
	if err := s.Config.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RenewPeer("alice", presented, request, late); err == nil {
		t.Fatal("old certificate could renew a second time")
	}
	block, _ = pem.Decode(certPEM)
	renewed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(renewed) == Fingerprint(presented) {
		t.Fatal("certificate unchanged")
	}
	if _, err := s.RenewPeer("alice", renewed, request, renewed.NotAfter.Add(-time.Hour)); err == nil {
		t.Fatal("previously used key accepted again")
	}
}
