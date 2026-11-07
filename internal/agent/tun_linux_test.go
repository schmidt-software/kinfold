//go:build linux

package agent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindIPUsesOnlyFixedCandidates(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	notExec := filepath.Join(dir, "plain")
	executable := filepath.Join(dir, "ip")
	if err := os.WriteFile(notExec, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	got, err := findIP([]string{missing, notExec, dir, executable})
	if err != nil || got != executable {
		t.Fatalf("findIP = %q, %v; want %q", got, err, executable)
	}
	if _, err := findIP([]string{missing, notExec}); err == nil {
		t.Fatal("found ip without an executable candidate")
	}
}

func TestOpenTunnelRejectsInvalidNames(t *testing.T) {
	for _, name := range []string{"", "a-very-long-interface-name"} {
		if _, err := OpenTunnel(name, nil); err == nil {
			t.Errorf("accepted interface name %q", name)
		}
	}
}
