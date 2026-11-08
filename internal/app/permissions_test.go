package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestClientCommandsRefuseAccessibleCredential(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	cred := filepath.Join(t.TempDir(), "alice.json")
	if err := Run([]string{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", cred}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cred, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"status", "-credential", cred},
		{"run", "-credential", cred},
		{"check-config", "-data", dir, "-credential", cred},
	} {
		if err := Run(args); err == nil || !strings.Contains(err.Error(), "accessible by other users") {
			t.Errorf("%s accepted a world-readable credential: %v", args[0], err)
		}
	}
}

func TestEnrollValidatesServerAndKeyPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	key, req, crt, ca := filepath.Join(work, "k"), filepath.Join(work, "r"), filepath.Join(work, "c"), filepath.Join(work, "ca")
	for _, args := range [][]string{
		{"keygen", "-id", "alice", "-key", key, "-request", req},
		{"approve", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-request", req, "-out", crt},
		{"export-ca", "-data", dir, "-out", ca},
	} {
		if err := Run(args); err != nil {
			t.Fatalf("%s: %v", args[0], err)
		}
	}
	enroll := func(server string) error {
		return Run([]string{"enroll", "-server", server, "-key", key, "-cert", crt, "-ca", ca, "-out", filepath.Join(work, "out-"+strings.ReplaceAll(server, ":", "_"))})
	}
	if err := enroll("localhost"); err == nil || !strings.Contains(err.Error(), "host:port") {
		t.Fatalf("server without port accepted: %v", err)
	}
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := enroll("localhost:8443"); err == nil || !strings.Contains(err.Error(), "accessible by other users") {
		t.Fatalf("group-readable private key accepted: %v", err)
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := enroll("localhost:8443"); err != nil {
		t.Fatalf("valid enroll failed: %v", err)
	}
}
