package relay

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

// pairConfig returns a valid configuration in which alice and bob may
// exchange traffic in both directions.
func pairConfig(t *testing.T) core.Config {
	t.Helper()
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}} {
		if _, err := state.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]string{{"alice", "bob"}, {"bob", "alice"}} {
		if err := state.Config.SetRule(r[0], r[1], true); err != nil {
			t.Fatal(err)
		}
	}
	return state.Config
}

// relayRequest builds a CONNECT request carrying the revision of cfg.
func relayRequest(t *testing.T, cfg core.Config) *http.Request {
	t.Helper()
	revision, err := cfg.Revision()
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodConnect, "/relay", nil)
	r.Header.Set("X-Kinfold-Config-Revision", revision)
	return r
}

// privateTempDir returns a temporary directory with mode 0700 so the state
// permission check accepts it.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}
