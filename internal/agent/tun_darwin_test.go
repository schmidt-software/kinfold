//go:build darwin

package agent

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestUtunFamilyHeader(t *testing.T) {
	v4 := ipv4(1, 2)
	frame, err := addFamily(nil, v4)
	if err != nil || binary.BigEndian.Uint32(frame) != 2 || string(frame[4:]) != string(v4) {
		t.Fatalf("IPv4 frame %x, %v", frame[:4], err)
	}
	v6 := ipv6("fd77::1", "fd77::2")
	frame, err = addFamily(nil, v6)
	if err != nil || binary.BigEndian.Uint32(frame) != darwinAFInet6 {
		t.Fatalf("IPv6 frame %x, %v", frame[:4], err)
	}
	buf := make([]byte, 2000)
	if n, _ := stripFamily(frame, buf); string(buf[:n]) != string(v6) {
		t.Fatal("stripFamily did not return the packet")
	}
	if n, _ := stripFamily([]byte{0, 0}, buf); n != 0 {
		t.Fatal("short frame not ignored")
	}
	if _, err := addFamily(nil, []byte{0x10}); err == nil {
		t.Fatal("non-IP packet accepted")
	}
	for bits, want := range map[int]string{24: "255.255.255.0", 16: "255.255.0.0", 30: "255.255.255.252", 8: "255.0.0.0"} {
		if got := netmaskString(bits); got != want {
			t.Errorf("netmask /%d = %s, want %s", bits, got, want)
		}
	}
}

func TestRouteExists(t *testing.T) {
	if !routeExists(errors.New("route [-q -n add -inet6 fd88::/64 -interface utun4]: exit status 1: route: writing to routing socket: File exists")) {
		t.Fatal("existing route not recognised")
	}
	if routeExists(errors.New("route [...]: exit status 1: route: writing to routing socket: Network is unreachable")) {
		t.Fatal("other route error treated as existing route")
	}
}
