package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"my-zerotier/internal/core"
)

func TestRotatePeerCLI(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	old := filepath.Join(dir, "old.json")
	key, request := filepath.Join(dir, "key"), filepath.Join(dir, "request")
	cert := filepath.Join(dir, "cert")
	for _, args := range [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"add-peer", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-out", old},
		{"keygen", "-id", "alice", "-key", key, "-request", request},
	} {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	before, err := os.ReadFile(filepath.Join(state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cert, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"rotate-peer", "-data", state, "-id", "alice", "-request", request, "-out", cert}
	if err := Run(args); err == nil {
		t.Fatal("overwrote certificate")
	}
	after, err := os.ReadFile(filepath.Join(state, "state.json"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("state changed despite output failure: %v", err)
	}
	newCert := filepath.Join(dir, "new-cert")
	args[len(args)-1] = newCert
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	s, err := core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(newCert)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.CompleteEnrollment(s.Server, s.CA, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
}
