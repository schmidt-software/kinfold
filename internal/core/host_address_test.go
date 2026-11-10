package core

import (
	"net/netip"
	"testing"
)

func TestNetworkOrBroadcast(t *testing.T) {
	for _, tt := range []struct {
		prefix, ip string
		want       bool
	}{
		{"10.77.0.0/24", "10.77.0.0", true},
		{"10.77.0.0/24", "10.77.0.255", true},
		{"10.77.0.0/24", "10.77.0.1", false},
		{"10.77.0.0/24", "10.77.0.254", false},
		{"10.77.0.0/30", "10.77.0.3", true},
		{"10.77.0.0/30", "10.77.0.2", false},
		{"172.16.0.0/12", "172.31.255.255", true},
		{"172.16.0.0/12", "172.16.255.255", false},
	} {
		got := networkOrBroadcast(netip.MustParsePrefix(tt.prefix), netip.MustParseAddr(tt.ip))
		if got != tt.want {
			t.Errorf("networkOrBroadcast(%s, %s) = %v, want %v", tt.prefix, tt.ip, got, tt.want)
		}
	}
}
