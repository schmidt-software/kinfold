package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadStateRefusesAccessibleFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("private state rejected: %v", err)
	}
	state := filepath.Join(dir, "state.json")
	if err := os.Chmod(state, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable state.json accepted: %v", err)
	}
	t.Setenv(InsecurePermissionsEnv, "1")
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("override did not apply: %v", err)
	}
	t.Setenv(InsecurePermissionsEnv, "")
	if err := os.Chmod(state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("group-accessible data directory accepted: %v", err)
	}
}
