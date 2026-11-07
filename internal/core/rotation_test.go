package core

import (
	"bytes"
	"encoding/pem"
	"reflect"
	"testing"
)

func TestRotatePeerEnrollment(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	oldKey, oldRequest, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	oldCert, err := s.ApproveEnrollment("alice", "10.77.0.1", oldRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	s.Config.Network6 = "fd77::/64"
	s.Config.Peers[0].IPv6 = "fd77::1"
	before := s.Config
	before.Peers = append([]Peer(nil), s.Config.Peers...)
	key, request, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(request)
	block.Bytes[len(block.Bytes)-1] ^= 1
	for _, invalid := range [][]byte{oldRequest, pem.EncodeToMemory(block), []byte("invalid")} {
		if _, err := s.RotatePeerEnrollment("alice", invalid); err == nil {
			t.Fatal("accepted invalid or reused key")
		}
		if !reflect.DeepEqual(before, s.Config) {
			t.Fatal("failed rotation modified configuration")
		}
	}
	if _, err := s.RotatePeerEnrollment("missing", request); err == nil {
		t.Fatal("accepted wrong identity")
	}
	cert, err := s.RotatePeerEnrollment("alice", request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldCert, cert) || bytes.Equal(oldKey, key) {
		t.Fatal("identity did not rotate")
	}
	if _, err := CompleteEnrollment(s.Server, s.CA, cert, key); err != nil {
		t.Fatal(err)
	}
	if _, err := CompleteEnrollment(s.Server, s.CA, cert, oldKey); err == nil {
		t.Fatal("new certificate accepted old key")
	}
	before.Peers[0].Cert = s.Config.Peers[0].Cert
	if !reflect.DeepEqual(before, s.Config) {
		t.Fatal("rotation changed address, rules or other peer")
	}
}
