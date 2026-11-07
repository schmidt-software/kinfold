//go:build linux || darwin

package app

import (
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestConcurrentMutationCommandsAreRejected(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	lock, err := core.LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"policy-enable", "-data", dir},
		{"allow", "-data", dir, "-from", "a", "-to", "b"},
		{"deny", "-data", dir, "-from", "a", "-to", "b"},
		{"approve", "-data", dir, "-id", "a", "-ip", "10.77.0.1", "-request", "missing", "-out", "missing"},
		{"add-peer", "-data", dir, "-id", "a", "-ip", "10.77.0.1", "-out", filepath.Join(t.TempDir(), "credential")},
		{"remove-peer", "-data", dir, "-id", "a"},
	} {
		if err := Run(args); err == nil {
			t.Errorf("mutation %v bypassed lock", args)
		}
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"add-peer", "-data", dir, "-id", "a", "-ip", "10.77.0.1", "-out", filepath.Join(t.TempDir(), "credential")}); err != nil {
		t.Fatalf("mutation after unlock: %v", err)
	}
}
