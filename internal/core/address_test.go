package core

import "testing"

func TestValidateServerAddress(t *testing.T) {
	for _, ok := range []string{"vpn.example.com:8443", "10.0.0.1:1", "[fd00::1]:65535"} {
		if err := ValidateServerAddress(ok); err != nil {
			t.Errorf("%s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "vpn.example.com", ":8443", "host:0", "host:65536", "host:http"} {
		if err := ValidateServerAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
