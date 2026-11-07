package app

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestRemovePeerWithExpiredServerCertificate(t *testing.T) {
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
	if _, err := s.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
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
	cert, err := x509.CreateCertificate(rand.Reader, server, ca, server.PublicKey, caPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	s.ServerCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	path := filepath.Join(dir, "state.json")
	if err := core.WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadState(dir); err == nil {
		t.Fatal("expired server accepted for service")
	}
	if err := Run([]string{"remove-peer", "-data", dir, "-id", "alice"}); err != nil {
		t.Fatal(err)
	}
	offline, err := core.LoadStateForOfflineMaintenance(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := offline.Config.Peer("alice"); exists || len(offline.Config.Policy.Allowed) != 0 || len(offline.UsedPeerKeys) != 2 {
		t.Fatal("peer, rules or key history not preserved correctly")
	}
	if _, err := core.LoadState(dir); err == nil {
		t.Fatal("offline removal unexpectedly enabled service")
	}
	if err := Run([]string{"renew-server", "-data", dir}); err != nil {
		t.Fatal(err)
	}
	renewed, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := renewed.Config.Peer("alice"); exists {
		t.Fatal("removed peer reappeared after renewal")
	}
}

func TestOfflineRevocationRejectsOtherInvalidPKI(t *testing.T) {
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
	s.Server = "example.invalid:8443"
	path := filepath.Join(dir, "state.json")
	if err := core.WriteJSON(path, s); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"remove-peer", "-data", dir, "-id", "alice"}); err == nil {
		t.Fatal("accepted invalid server identity")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("rejected removal changed state: %v", err)
	}
}
