package core

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
)

func TestDistinctCertificatesCannotSharePeerKey(t *testing.T) {
	state, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	alice, err := ParseCert(state.Config.Peers[0].Cert)
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(state.CA, state.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template := *alice
	template.SerialNumber = new(big.Int).Add(alice.SerialNumber, big.NewInt(1))
	template.Subject.CommonName = "bob"
	cert, err := x509.CreateCertificate(rand.Reader, &template, ca, alice.PublicKey, caPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(cert) == string(alice.Raw) {
		t.Fatal("certificates must differ")
	}
	state.Config.Peers = append(state.Config.Peers, Peer{ID: "bob", IP: "10.77.0.2", Cert: cert})
	if err := state.Config.Validate(); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("configuration accepted shared peer key: %v", err)
	}
	dir := t.TempDir()
	if err := WriteJSON(filepath.Join(dir, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "public key") {
		t.Fatalf("persisted state accepted shared peer key: %v", err)
	}
}
