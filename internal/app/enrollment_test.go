package app

import (
	"os"
	"path/filepath"
	"testing"

	"my-zerotier/internal/core"
)

func TestOfflineEnrollmentCLI(t *testing.T) {
	dir := t.TempDir()
	path := func(name string) string { return filepath.Join(dir, name) }
	state, key, csr := path("state"), path("key"), path("request")
	cert, ca, credential := path("cert"), path("ca"), path("credential")
	commands := [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"keygen", "-id", "alice", "-key", key, "-request", csr},
		{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", csr, "-out", cert},
		{"export-ca", "-data", state, "-out", ca},
		{"enroll", "-server", "localhost:8443", "-key", key, "-cert", cert, "-ca", ca, "-out", credential},
	}

	for _, args := range commands {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}

	}
	for _, name := range []string{key, csr, cert, ca, credential} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("permissions %s: %v", name, err)
		}
	}
	var cred core.Credential
	if err := core.ReadJSON(credential, &cred); err != nil || len(cred.Key) == 0 {
		t.Fatalf("credential: %v", err)
	}
	if err := Run(commands[4]); err == nil {
		t.Fatal("overwrote credential")
	}
}

func TestPolicyCLIAndPeerRemoval(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	commands := [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"add-peer", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-out", filepath.Join(dir, "a")},
		{"add-peer", "-data", state, "-id", "bob", "-ip", "10.77.0.2", "-out", filepath.Join(dir, "b")},
		{"allow", "-data", state, "-from", "alice", "-to", "bob"},
		{"allow", "-data", state, "-from", "bob", "-to", "alice"},
		{"remove-peer", "-data", state, "-id", "bob"},
	}

	for _, args := range commands {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}

	}
	s, err := core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Config.Policy.Allowed) != 0 {
		t.Fatal("removed peer left policy rules")
	}
}
