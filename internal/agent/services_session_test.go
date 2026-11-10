package agent

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestIncomingServicePolicyEnforcedIndependently(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		name := "ipv4"
		if v6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			l := &link{
				peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1),
				allowIncoming: true, servicesOn: true,
				inServices: compileServices([]core.ServiceRule{{From: "bob", To: "alice", Protocol: "udp", Port: 53}}, "bob", "alice"),
				localIPv6:  netip.MustParseAddr("fd77::1"), peerIPv6: netip.MustParseAddr("fd77::2"),
			}
			output := newFakeTun()
			var mu sync.Mutex
			done := make(chan error, 1)
			go func() { done <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), output, &mu) }()
			packet := func(port uint16) []byte {
				p := serviceTestPacket(v6, 17, port)
				if v6 {
					src, dst := netip.MustParseAddr("fd77::2").As16(), netip.MustParseAddr("fd77::1").As16()
					copy(p[8:24], src[:])
					copy(p[24:40], dst[:])
				} else {
					copy(p[12:16], []byte{10, 77, 0, 2})
					copy(p[16:20], []byte{10, 77, 0, 1})
				}
				return p
			}
			if err := writePacket(right, packet(22)); err != nil {
				t.Fatal(err)
			}
			if err := writePacket(right, packet(53)); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-output.out:
				offset := 20
				if v6 {
					offset = 40
				}
				if port := binary.BigEndian.Uint16(got[offset+2:]); port != 53 {
					t.Fatalf("denied packet delivered to port %d", port)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("allowed packet not delivered")
			}
			right.Close()
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("session did not stop")
			}
		})
	}
}
