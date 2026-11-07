package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"my-zerotier/internal/core"
)

func ipv6(src, dst string) []byte {
	p := make([]byte, 44)
	p[0] = 0x60
	binary.BigEndian.PutUint16(p[4:6], 4)
	a, b := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(p[8:24], a[:])
	copy(p[24:40], b[:])
	return p
}

func TestIPv6PacketValidation(t *testing.T) {
	p := ipv6("fd77::2", "fd77::1")
	src, dst, err := packetAddresses(p)
	if err != nil || src.String() != "fd77::2" || dst.String() != "fd77::1" {
		t.Fatalf("bad IPv6 addresses: %s %s %v", src, dst, err)
	}
	for _, invalid := range [][]byte{p[:39], p[:40], p[:43], append(append([]byte(nil), p...), 1)} {
		if _, _, err := packetAddresses(invalid); err == nil {
			t.Errorf("accepted malformed IPv6 packet %x", invalid)
		}
	}
}

func TestIPv6IncomingSession(t *testing.T) {
	for _, tc := range []struct {
		name, src, dst             string
		allow, delivered, rejected bool
	}{
		{"allowed", "fd77::2", "fd77::1", true, true, false},
		{"denied", "fd77::2", "fd77::1", false, false, false},
		{"spoofed source", "fd77::3", "fd77::1", true, false, true},
		{"wrong destination", "fd77::2", "fd77::3", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			l := &link{
				peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1),
				localIPv6: netip.MustParseAddr("fd77::1"), peerIPv6: netip.MustParseAddr("fd77::2"),
				allowIncoming: tc.allow,
			}

			var output bytes.Buffer
			var mu sync.Mutex
			result := make(chan error, 1)
			go func() {
				result <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), &output, &mu)
			}()
			packet := ipv6(tc.src, tc.dst)
			if err := WritePacket(right, packet); err != nil {
				t.Fatal(err)
			}
			if !tc.rejected {
				right.Close()
			}
			select {
			case err := <-result:
				if tc.rejected && (err == nil || !bytes.Contains([]byte(err.Error()), []byte("spoofed"))) {
					t.Fatalf("expected spoof rejection: %v", err)
				}
				if got := bytes.Equal(output.Bytes(), packet); got != tc.delivered {
					t.Fatalf("delivered = %v, output %x", got, output.Bytes())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("session did not terminate")
			}
			right.Close()
		})
	}
}
