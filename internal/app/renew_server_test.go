package app

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"my-zerotier/internal/core"
)

func TestRenewExpiredServerCertificate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	s, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	serverPair, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	server, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	server.NotBefore = time.Now().Add(-40 * time.Second)
	server.NotAfter = time.Now().Add(-10 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, server, ca, server.PublicKey, caPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	s.ServerCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(dir, "state.json")
	if err := core.WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadState(dir); err == nil {
		t.Fatal("expired server accepted for service")
	}
	oldKey := append([]byte(nil), s.ServerKey...)
	if err := Run([]string{"renew-server", "-data", dir}); err != nil {
		t.Fatal(err)
	}
	renewed, err := core.LoadState(dir)
	if err != nil {
		t.Fatalf("renewed state invalid: %v", err)
	}
	if bytes.Equal(oldKey, renewed.ServerKey) {
		t.Fatal("server key was not rotated")
	}
	if !bytes.Equal(s.CA, renewed.CA) || !bytes.Equal(s.CAKey, renewed.CAKey) || len(renewed.Config.Peers) != 1 {
		t.Fatal("renewal changed CA or membership")
	}
}
