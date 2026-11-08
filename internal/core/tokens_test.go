package core

import (
	"errors"
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
	if err := s.validateTokens(); err != nil {
		t.Fatal(err)
	}
	_, request, _ := NewEnrollment("alice")
	_, wrongID, _ := NewEnrollment("mallory")
	if _, _, err := s.EnrollWithToken("guess", request, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong token: %v", err)
	}
	if _, _, err := s.EnrollWithToken(secret, wrongID, now); err == nil {
		t.Fatal("token enrolled a request for another ID")
	}
	if _, _, err := s.EnrollWithToken(secret, request, now.Add(2*time.Hour)); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("expired token: %v", err)
	}
	secret, _ = s.IssueToken("alice", "10.77.0.1", time.Hour, now)
	id, cert, err := s.EnrollWithToken(secret, request, now)
	if err != nil || id != "alice" || len(cert) == 0 {
		t.Fatalf("enroll: %q %v", id, err)
	}
	if p, ok := s.Config.Peer("alice"); !ok || p.IP != "10.77.0.1" {
		t.Fatal("device not added with the token's address")
	}
	if _, _, err := s.EnrollWithToken(secret, request, now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatal("token used twice")
	}
	if len(s.EnrollmentTokens) != 0 {
		t.Fatal("token not consumed")
	}
	if _, err := s.IssueToken("bob", "10.77.0.2", time.Hour, now); err != nil {
		t.Fatal(err)
	}
	if !s.RevokeToken("bob") || s.RevokeToken("bob") {
		t.Fatal("revoke did not remove exactly one token")
	}
}
