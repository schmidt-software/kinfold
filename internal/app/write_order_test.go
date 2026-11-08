package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

// A command that cannot write its output must not change the state first:
// otherwise a member or standby exists without its credential.
func TestOutputProblemsLeaveStateUnchanged(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "controller")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(existing, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-dir", "out.json")
	for _, args := range [][]string{
		{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", existing},
		{"add-peer", "-data", dir, "-id", "alice", "-ip", "10.77.0.1", "-out", missing},
		{"replica-add", "-data", dir, "-id", "standby", "-address", "standby.example.com:8443", "-out", existing},
	} {
		if err := Run(args); err == nil {
			t.Fatalf("%v succeeded", args)
		}
		s, err := core.LoadState(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Config.Peers) != 0 || len(s.Replicas) != 0 {
			t.Fatalf("%v changed the state although its output failed", args)
		}
	}
	if data, _ := os.ReadFile(existing); string(data) != "keep" {
		t.Fatal("existing output file was overwritten")
	}
}
