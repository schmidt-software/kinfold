package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitStateLeavesNothingBehindOnFailure(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	orig := writeStateHook
	writeStateHook = func(string, any) error { return os.ErrPermission }
	defer func() { writeStateHook = orig }()
	if err := InitState(dir, "localhost:8443", "10.77.0.0/24"); err == nil {
		t.Fatal("InitState reported success")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("failed init left %s behind: %v", dir, err)
	}
	writeStateHook = orig
	if err := InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatalf("retry after failed init: %v", err)
	}
}
