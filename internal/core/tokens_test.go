package core

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentTokenLifecycle(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, bad := range []struct {
		id, ip string
		ttl    time.Duration
	}{
		{"alice", "10.77.0.1", 0},
		{"alice", "10.77.0.1", 8 * 24 * time.Hour},
		{"a!ice", "10.77.0.1", time.Hour},
		{"alice", "10.78.0.1", time.Hour},
		{"alice", "10.77.0.0", time.Hour},
		{"alice", "10.77.0.255", time.Hour},
	} {
		if _, err := s.IssueToken(bad.id, bad.ip, bad.ttl, now); err == nil {
			t.Errorf("accepted token %+v", bad)
		}
	}
	secret, err := s.IssueToken("alice", "10.77.0.1", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.IssueToken("alice", "10.77.0.2", time.Hour, now); err == nil {
		t.Fatal("second token for the same ID accepted")
	}
	if s.EnrollmentTokens[0].Hash == secret || len(secret) < 40 {
		t.Fatal("token secret stored or too short")
	}
	if err := s.validateTokens(now); err != nil {
		t.Fatal(err)
	}
	_, request, _ := NewEnrollment("alice")
	_, wrongID, _ := NewEnrollment("mallory")
	if _, _, _, err := s.EnrollWithToken("guess", request, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong token: %v", err)
	}
	if _, _, _, err := s.EnrollWithToken(secret, wrongID, now); err == nil {
		t.Fatal("token enrolled a request for another ID")
	}
	if _, _, _, err := s.EnrollWithToken(secret, request, now.Add(2*time.Hour)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token: %v", err)
	}
	secret, _ = s.IssueToken("alice", "10.77.0.1", time.Hour, now)
	id, cert, changed, err := s.EnrollWithToken(secret, request, now)
	if err != nil || id != "alice" || len(cert) == 0 || !changed {
		t.Fatalf("enroll: %q changed=%v %v", id, changed, err)
	}
	if p, ok := s.Config.Peer("alice"); !ok || p.IP != "10.77.0.1" {
		t.Fatal("device not added with the token's address")
	}
	// A lost response: the same token and key collect the same certificate.
	again, _, changed, err := s.EnrollWithToken(secret, request, now)
	if err != nil || changed || again != "alice" {
		t.Fatalf("retry with the same key: changed=%v err=%v", changed, err)
	}
	_, otherKey, _ := NewEnrollment("alice")
	if _, _, _, err := s.EnrollWithToken(secret, otherKey, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("used token enrolled a second key")
	}
	s.ForgetPeer("alice")
	if len(s.EnrollmentTokens) != 0 {
		t.Fatal("removing the peer kept its token")
	}
	if _, err := s.IssueToken("bob", "10.77.0.2", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !s.RevokeToken("bob") || s.RevokeToken("bob") {
		t.Fatal("revoke did not remove exactly one token")
	}
}

func TestDropTokensAndValidation(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.IssueToken("laptop", "10.77.0.5", MaxTokenTTL, now); err != nil {
		t.Fatal(err)
	}
	s.DropTokens("laptop", "")
	if len(s.EnrollmentTokens) != 0 {
		t.Fatal("token for a device authorized offline was kept")
	}
	if _, err := s.IssueToken("phone", "10.77.0.6", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	s.DropTokens("other", "10.77.0.6")
	if len(s.EnrollmentTokens) != 0 {
		t.Fatal("token for an address authorized offline was kept")
	}
	s.EnrollmentTokens = []EnrollmentToken{{ID: "x", IP: "10.77.0.7", Hash: strings.Repeat("ab", 32), NotAfter: now.Add(30 * 24 * time.Hour)}}
	if err := s.validateTokens(now); err == nil {
		t.Fatal("token beyond the maximum lifetime accepted")
	}
	s.EnrollmentTokens[0].NotAfter, s.EnrollmentTokens[0].IP = now.Add(time.Hour), "010.77.0.7"
	if err := s.validateTokens(now); err == nil {
		t.Fatal("non-canonical token address accepted")
	}
}
