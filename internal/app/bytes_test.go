package app

import "testing"

func TestParseBytes(t *testing.T) {
	for in, want := range map[string]float64{"0": 0, "1500": 1500, "10k": 10e3, "2.5M": 2.5e6, "1G": 1e9} {
		if got, err := parseBytes(in); err != nil || got != want {
			t.Errorf("parseBytes(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "1T", "M", "Inf", "NaN", "1e400"} {
		if _, err := parseBytes(in); err == nil {
			t.Errorf("parseBytes(%q) accepted", in)
		}
	}
}
