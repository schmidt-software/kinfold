//go:build linux || darwin

package core

import (
	"path/filepath"
	"testing"
)

func TestLockStatePreventsConcurrentWriters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	first, err := LockState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := LockState(dir); err == nil {
		second.Close()
		t.Fatal("second writer acquired lock")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := LockState(dir)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	next.Close()
}
