package core

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestServicePolicyRejectedByLegacyStrictDecoder(t *testing.T) {
	type legacyPolicy struct {
		Allowed []Rule `json:"allowed"`
	}
	type legacyConfig struct {
		Network  string        `json:"network"`
		Network6 string        `json:"network6,omitempty"`
		Peers    []Peer        `json:"peers"`
		Policy   *legacyPolicy `json:"policy,omitempty"`
	}
	cfg := Config{Network: "10.77.0.0/24", Policy: &Policy{}}
	encoded, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var old legacyConfig
	if err := DecodeJSON(bytes.NewReader(encoded), &old); err != nil {
		t.Fatalf("legacy policy unexpectedly incompatible: %v", err)
	}
	cfg.Policy.Services = &ServicePolicy{}
	encoded, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeJSON(bytes.NewReader(encoded), &old); err == nil {
		t.Fatal("legacy strict decoder silently accepted service policy")
	}
}
