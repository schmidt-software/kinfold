package core

import "testing"

func TestSourceKeyAggregatesIPv6By64(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:1:2::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"fe80::1%eth0":         "fe80::/64",
		"not-an-address":       "not-an-address",
	} {
		if got := SourceKey(in); got != want {
			t.Errorf("SourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}
