package core

import (
	"strings"
	"testing"
)

func TestDecodeJSONStrict(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid", `{"network":"10.77.0.0/24","peers":[],"policy":{"allowed":[]}}`, true},
		{"legacy", `{"network":"10.77.0.0/24","peers":[]}`, true},
		{"unknown", `{"network":"10.77.0.0/24","polciy":{"allowed":[]}}`, false},
		{"unknown nested", `{"network":"10.77.0.0/24","policy":{"allowd":[]}}`, false},
		{"duplicate", `{"network":"10.77.0.0/24","network":"10.78.0.0/24"}`, false},
		{"case duplicate", `{"policy":{"allowed":[]},"Policy":null}`, false},
		{"unicode case folding", `{"peers":[],"peer\u017f":[]}`, false},
		{"escaped duplicate", `{"policy":{"allowed":[],"\u0061llowed":[]}}`, false},
		{"trailing", `{"network":"10.77.0.0/24"} {}`, false},
		{"truncated", `{"network":`, false},
		{"oversized", `{"network":"` + strings.Repeat("x", MaxJSONSize) + `"}`, false},
		{"deep", `{"unknown":` + strings.Repeat("[", 70) + "0" + strings.Repeat("]", 70) + "}", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg Config
			err := DecodeJSON(strings.NewReader(tt.input), &cfg)
			if (err == nil) != tt.valid {
				t.Fatalf("valid=%v, error=%v", tt.valid, err)
			}
		})
	}
}
