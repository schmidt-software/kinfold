package core

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteJSONReportsUncertainDurabilityAfterRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	syncFailure := errors.New("injected directory sync failure")
	err := writeJSON(path, map[string]int{"version": 2}, func(got string) error {
		if got != path {
			t.Fatalf("sync path = %q, want %q", got, path)
		}
		var actual map[string]int
		if err := ReadJSON(path, &actual); err != nil || actual["version"] != 2 {
			t.Fatalf("rename not visible before sync: %v, %v", actual, err)
		}
		return syncFailure
	})
	if !errors.Is(err, syncFailure) || !strings.Contains(err.Error(), "durability is uncertain") {
		t.Fatalf("uncertain update not reported: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "state.json" {
		t.Fatalf("unexpected temporary files: %v, %v", entries, err)
	}
}

func TestWriteJSONPersistsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := WriteJSON(path, map[string]int{"version": 1}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(path, map[string]int{"version": 2}); err != nil {
		t.Fatal(err)
	}
	var actual map[string]int
	if err := ReadJSON(path, &actual); err != nil || actual["version"] != 2 {
		t.Fatalf("replacement: %v, %v", actual, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v, %v", info, err)
	}
}

func TestWriteFileAtomicReplacesPrivately(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watermark")
	for _, want := range []string{"first\n", "second\n"} {
		if err := WriteFileAtomic(path, []byte(want)); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != want {
			t.Fatalf("content %q, %v; want %q", got, err, want)
		}
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v; want 0600", info.Mode().Perm(), err)
	}
}
