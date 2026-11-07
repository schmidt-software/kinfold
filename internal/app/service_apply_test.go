package app

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestServiceApplyReplacesWholePolicyAndRejectsInvalidInput(t *testing.T) {
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	commands := [][]string{
		{"init", "-data", stateDir, "-server", "localhost:8443"},
		{"add-peer", "-data", stateDir, "-id", "alice", "-ip", "10.77.0.1", "-out", filepath.Join(dir, "alice")},
		{"add-peer", "-data", stateDir, "-id", "bob", "-ip", "10.77.0.2", "-out", filepath.Join(dir, "bob")},
		{"allow", "-data", stateDir, "-from", "alice", "-to", "bob"},
	}
	for _, args := range commands {
		if err := Run(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	path := filepath.Join(dir, "rules.json")
	apply := func(input string) error {
		t.Helper()
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		return Run([]string{"service-apply", "-data", stateDir, "-rules", path})
	}
	valid := `{"allowed":[{"from":"alice","to":"bob","protocol":"tcp","port":443},{"from":"alice","to":"bob","protocol":"udp","port":53}]}`
	if err := apply(valid); err != nil {
		t.Fatal(err)
	}
	state, err := core.LoadState(stateDir)
	if err != nil || state.Config.Policy.Services == nil || len(state.Config.Policy.Services.Allowed) != 2 {
		t.Fatalf("complete policy not installed: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		`null`,
		`{}`,
		`{"allowed":null}`,
		`{"allowed":[],"unknown":true}`,
		`{"allowed":[],"ALLOWED":[]}`,
		`{"allowed":[{"from":"bob","to":"alice","protocol":"tcp","port":443}]}`,
		`{"allowed":[{"from":"alice","to":"bob","protocol":"tcp","port":0}]}`,
		`{"allowed":[{"from":"alice","to":"bob","protocol":"tcp","port":443},{"from":"alice","to":"bob","protocol":"tcp","port":443}]}`,
		`{"allowed":[]} trailing`,
	} {
		if err := apply(input); err == nil {
			t.Errorf("accepted invalid policy: %s", input)
		}
		after, err := os.ReadFile(filepath.Join(stateDir, "state.json"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("state changed after invalid policy %s: %v", input, err)
		}
	}
	if err := apply(`{"allowed":[]}`); err != nil {
		t.Fatal(err)
	}
	state, err = core.LoadState(stateDir)
	if err != nil || state.Config.Policy.Services == nil || len(state.Config.Policy.Services.Allowed) != 0 {
		t.Fatalf("empty policy did not deny all: %v", err)
	}
}
