package app

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestCheckConfig(t *testing.T) {
	server := httptest.NewUnstartedServer(nil)
	state, err := core.NewState(server.Listener.Addr().String(), "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	server.Config.Handler = handler
	server.TLS, err = relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()

	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	credentialPath := filepath.Join(dir, "credential.json")
	if err := core.WriteJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := core.WriteJSON(credentialPath, cred); err != nil {
		t.Fatal(err)
	}
	args := []string{"check-config", "-data", dir, "-credential", credentialPath}
	if err := Run(args); err != nil {
		t.Fatalf("matching state: %v", err)
	}
	state.Config.Network = "10.77.0.0/25"
	if err := core.WriteJSON(statePath, state); err != nil {
		t.Fatal(err)
	}
	if err := Run(args); err == nil {
		t.Fatal("outdated controller configuration reported as current")
	}
	if err := handler.Update(state.Config, nil); err != nil {
		t.Fatal(err)
	}
	if err := Run(args); err != nil {
		t.Fatalf("updated state: %v", err)
	}
	cred.Server = "example.invalid:8443"
	if err := core.WriteJSON(credentialPath, cred); err != nil {
		t.Fatal(err)
	}
	if err := Run(args); err == nil {
		t.Fatal("different controller address accepted")
	}
}
