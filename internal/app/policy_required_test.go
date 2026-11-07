package app

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestServeRefusesStateWithoutPolicy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	s, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Config.Policy = nil
	if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
		t.Fatal(err)
	}
	err = Run([]string{"serve", "-data", dir, "-listen", "127.0.0.1:0"})
	if err == nil || !strings.Contains(err.Error(), "policy-enable") {
		t.Fatalf("serve accepted state without policy: %v", err)
	}
	if err := Run([]string{"policy-enable", "-data", dir}); err != nil {
		t.Fatalf("policy-enable: %v", err)
	}
	s, err = core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Config.Policy == nil || len(s.Config.Policy.Allowed) != 0 {
		t.Fatalf("policy-enable did not add an empty default-deny policy: %+v", s.Config.Policy)
	}
}
