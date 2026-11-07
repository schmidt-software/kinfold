package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"my-zerotier/internal/core"
)

func TestAddPeerDoesNotOverwriteCredentialOrUpdateStateOnOutputFailure(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	if err := Run([]string{"init", "-data", state, "-server", "localhost:8443"}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "credential.json")
	original := []byte("existing credential")
	if err := os.WriteFile(output, original, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"add-peer", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-out", output}
	if err := Run(args); err == nil {
		t.Fatal("overwrote credential")
	}
	got, err := os.ReadFile(output)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("existing file changed: %q, %v", got, err)
	}
	s, err := core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Config.Peer("alice"); ok {
		t.Fatal("peer authorized despite output failure")
	}
	output = filepath.Join(dir, "alice.json")
	args[len(args)-1] = output
	if err := Run(args); err != nil {
		t.Fatal(err)
	}
	var cred core.Credential
	if err := core.ReadJSON(output, &cred); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(output)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credential permissions: %v, %v", info, err)
	}
	s, err = core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Config.Peer("alice"); !ok || len(cred.Key) == 0 {
		t.Fatal("credential and authorized peer not persisted")
	}
}
