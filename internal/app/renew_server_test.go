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

	"github.com/schmidt-software/kinfold/internal/core"
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

func TestRenewServerChangesControllerAddress(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "old.example.com:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(t.TempDir(), "alice.json")
	if err := Run([]string{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", cred}); err != nil {
		t.Fatal(err)
	}
	before, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"renew-server", "-data", dir, "-server", "alice:9443"}); err == nil {
		t.Fatal("controller host equal to a device ID accepted")
	}
	if err := Run([]string{"renew-server", "-data", dir, "-server", "new.example.com"}); err == nil {
		t.Fatal("address without port accepted")
	}
	if err := Run([]string{"renew-server", "-data", dir, "-server", "new.example.com:9443"}); err != nil {
		t.Fatal(err)
	}
	after, err := core.LoadState(dir)
	if err != nil {
		t.Fatalf("moved state does not load: %v", err)
	}
	if after.Server != "new.example.com:9443" || string(after.CA) != string(before.CA) || after.Config.Peers[0].IP != "10.77.0.1" {
		t.Fatalf("unexpected state after move: server=%s", after.Server)
	}
	if string(after.Config.Peers[0].Cert) != string(before.Config.Peers[0].Cert) {
		t.Fatal("device certificate changed by the controller move")
	}
}
