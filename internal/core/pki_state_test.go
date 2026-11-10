package core

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStateValidatesControllerPKI(t *testing.T) {
	state, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	other, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.AddPeer("mallory", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		edit func(*State)
		want string
	}{
		{"mismatched CA key", func(s *State) { s.CAKey = other.CAKey }, "CA certificate and private key"},
		{"mismatched server key", func(s *State) { s.ServerKey = other.ServerKey }, "server certificate and private key"},
		{"foreign server", func(s *State) { s.ServerCert, s.ServerKey = other.ServerCert, other.ServerKey }, "server certificate verification"},
		{"wrong server name", func(s *State) { s.Server = "example.invalid:8443" }, "server certificate verification"},
		{"invalid port", func(s *State) { s.Server = "localhost:0" }, "server port must be between 1 and 65535"},
		{"foreign peer", func(s *State) { s.Config.Peers[0].Cert = other.Config.Peers[0].Cert; s.UsedPeerKeys = nil }, "not signed by the controller CA"},
	}
	dir := privateTempDir(t)
	path := filepath.Join(dir, "state.json")
	if err := WriteJSON(path, state); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := *state
			changed.Config.Peers = append([]Peer(nil), state.Config.Peers...)
			tt.edit(&changed)
			if err := WriteJSON(path, &changed); err != nil {
				t.Fatal(err)
			}
			_, err := LoadState(dir)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}
