package core

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidPeerKeyHistoryIsRejected(t *testing.T) {
	state, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, history := range [][]string{
		{"bad"},
		{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{strings.Repeat("A", 64)},
	} {
		state.UsedPeerKeys = history
		if err := WriteJSON(filepath.Join(dir, "state.json"), state); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(dir); err == nil {
			t.Fatal("accepted invalid key history")
		}
	}
}

func TestNewRequestWithPreviouslyUsedKeyIsRejected(t *testing.T) {
	state, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}

	key, firstRequest, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.ApproveEnrollment("alice", "10.77.0.1", firstRequest); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(key)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	newCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "bob"},
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	request := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: newCSR})
	if _, err := state.ApproveEnrollment("bob", "10.77.0.2", request); err == nil || !strings.Contains(err.Error(), "previously authorized") {
		t.Fatalf("reused key in a different request: %v", err)
	}
}
