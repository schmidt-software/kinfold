package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestEnrollmentKeyHistoryAfterRotationAndRemoval(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	path := func(name string) string { return filepath.Join(dir, name) }
	commands := [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"keygen", "-id", "alice", "-key", path("old.key"), "-request", path("old.csr")},
		{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", path("old.csr"), "-out", path("old.crt")},
		{"keygen", "-id", "alice", "-key", path("new.key"), "-request", path("new.csr")},
		{"rotate-peer", "-data", state, "-id", "alice", "-request", path("new.csr"), "-out", path("new.crt")},
	}
	for _, args := range commands {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	checkReject := func(args []string) {
		t.Helper()
		before, err := os.ReadFile(filepath.Join(state, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := Run(args); err == nil || !strings.Contains(err.Error(), "previously authorized") {
			t.Fatalf("expected reused-key rejection: %v", err)
		}
		after, err := os.ReadFile(filepath.Join(state, "state.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("rejected request changed state: %v", err)
		}
	}
	checkReject([]string{"rotate-peer", "-data", state, "-id", "alice", "-request", path("old.csr"), "-out", path("replay.crt")})
	if err := Run([]string{"remove-peer", "-data", state, "-id", "alice"}); err != nil {
		t.Fatal(err)
	}
	checkReject([]string{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", path("new.csr"), "-out", path("replay.crt")})
}

func TestLegacyStateRemembersKeysBeforeRemoval(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	key, csr, cert := filepath.Join(dir, "key"), filepath.Join(dir, "csr"), filepath.Join(dir, "cert")
	for _, args := range [][]string{
		{"init", "-data", state, "-server", "localhost:8443"},
		{"keygen", "-id", "alice", "-key", key, "-request", csr},
		{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", csr, "-out", cert},
	} {
		if err := Run(args); err != nil {
			t.Fatal(err)
		}
	}
	s, err := core.LoadState(state)
	if err != nil {
		t.Fatal(err)
	}
	s.UsedPeerKeys = nil
	if err := core.WriteJSON(filepath.Join(state, "state.json"), s); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"remove-peer", "-data", state, "-id", "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", csr, "-out", filepath.Join(dir, "replay")}); err == nil {
		t.Fatal("legacy active key was not retained")
	}
}
