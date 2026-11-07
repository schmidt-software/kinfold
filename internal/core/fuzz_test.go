package core

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzDecodeConfig(f *testing.F) {
	for _, seed := range []string{
		`{"network":"10.77.0.0/24","peers":[]}`,
		`{"network":"10.77.0.0/24","network6":"fd77::/64","peers":[],"policy":{"allowed":[]}}`,
		`{"policy":null,"Policy":{"allowed":[]}}`,
		`{"policy":{"allowed":[],"\u0061llowed":[]}}`,
		`{"network":`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg Config
		if err := DecodeJSON(bytes.NewReader(data), &cfg); err != nil {
			return
		}
		if len(data) > MaxJSONSize || !json.Valid(data) {
			t.Fatal("accepted oversized or invalid JSON")
		}
		encoded, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var roundTrip Config
		if err := DecodeJSON(bytes.NewReader(encoded), &roundTrip); err != nil {
			t.Fatalf("rejected encoded configuration: %v", err)
		}
		if !reflect.DeepEqual(cfg, roundTrip) {
			t.Fatal("configuration changed on JSON round trip")
		}
	})
}
