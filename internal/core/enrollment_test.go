package core

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"testing"
)

func TestLocalEnrollment(t *testing.T) {
	s, err := NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	key, request, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(request, []byte("PRIVATE KEY")) {
		t.Fatal("private key in request")
	}
	if _, err := s.ApproveEnrollment("bob", "10.77.0.1", request); err == nil {
		t.Fatal("approved different identity")
	}
	block, _ := pem.Decode(request)
	block.Bytes[len(block.Bytes)-1] ^= 1
	tampered := pem.EncodeToMemory(block)
	if _, err := s.ApproveEnrollment("alice", "10.77.0.1", tampered); err == nil {
		t.Fatal("approved tampered CSR")
	}
	if len(s.Config.Peers) != 0 {
		t.Fatal("invalid request changed config")
	}
	cert, err := s.ApproveEnrollment("alice", "10.77.0.1", request)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := CompleteEnrollment(s.Server, s.CA, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(cred.Cert, cred.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveEnrollment("alice", "10.77.0.2", request); err == nil {
		t.Fatal("approved duplicate identity")
	}
	if _, err := s.ApproveEnrollment("bob", "10.77.0.2", request); err == nil {
		t.Fatal("approved CSR under wrong identity")
	}
	otherKey, _, err := NewEnrollment("bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteEnrollment(s.Server, s.CA, cert, otherKey); err == nil {
		t.Fatal("accepted incorrect key")
	}
	other, err := NewState("127.0.0.1:8443", "10.78.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteEnrollment(s.Server, other.CA, cert, key); err == nil {
		t.Fatal("accepted untrusted CA")
	}
	if _, err := CompleteEnrollment(s.Server, append([]byte("garbage"), s.CA...), cert, key); err == nil {
		t.Fatal("accepted invalid CA PEM")
	}
}
