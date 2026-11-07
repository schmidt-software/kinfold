package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEnrollmentFileSizeLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	for _, size := range []int{0, maxEnrollmentFileSize, maxEnrollmentFileSize + 1} {
		data := bytes.Repeat([]byte("x"), size)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readEnrollmentFile(path)
		if size > maxEnrollmentFileSize {
			if err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("size %d: expected limit error, got %v", size, err)
			}
		} else if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("size %d: %v", size, err)
		}
	}
}

func TestEnrollmentCommandsRejectOversizedInputBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	large := filepath.Join(dir, "large")
	if err := Run([]string{"init", "-data", state, "-server", "localhost:8443"}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(large, make([]byte, maxEnrollmentFileSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	key, request := filepath.Join(dir, "key"), filepath.Join(dir, "request")
	if err := Run([]string{"keygen", "-id", "alice", "-key", key, "-request", request}); err != nil {
		t.Fatal(err)
	}
	cert, ca := filepath.Join(dir, "cert"), filepath.Join(dir, "ca")
	if err := Run([]string{"approve", "-data", state, "-id", "alice", "-ip", "10.77.0.1", "-request", request, "-out", cert}); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"export-ca", "-data", state, "-out", ca}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(state, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"approve", []string{"approve", "-data", state, "-id", "bob", "-ip", "10.77.0.2", "-request", large}},
		{"rotate", []string{"rotate-peer", "-data", state, "-id", "alice", "-request", large}},
		{"key", []string{"enroll", "-server", "localhost:8443", "-key", large, "-cert", cert, "-ca", ca}},
		{"certificate", []string{"enroll", "-server", "localhost:8443", "-key", key, "-cert", large, "-ca", ca}},
		{"ca", []string{"enroll", "-server", "localhost:8443", "-key", key, "-cert", cert, "-ca", large}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(dir, "output-"+tc.name)
			args := append(append([]string(nil), tc.args...), "-out", out)
			if err := Run(args); err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("expected size error, got %v", err)
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("unexpected output file: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(state, "state.json"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("state changed: %v", err)
			}
		})
	}
}
