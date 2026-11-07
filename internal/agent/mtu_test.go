package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestPacketSizeLimitBeforeReadingBody(t *testing.T) {
	for _, size := range []int{tunnelMTU - 1, tunnelMTU, tunnelMTU + 1, 65535} {
		frame := make([]byte, 2+size)
		binary.BigEndian.PutUint16(frame, uint16(size))
		input := bytes.NewReader(frame)
		packet, err := readPacketLimited(input, tunnelMTU)
		if size > tunnelMTU {
			if err == nil || !strings.Contains(err.Error(), "exceeds limit") || input.Len() != size {
				t.Fatalf("size %d: error %v, unread bytes %d", size, err, input.Len())
			}
		} else if err != nil || len(packet) != size || input.Len() != 0 {
			t.Fatalf("size %d: error %v, got %d bytes", size, err, len(packet))
		}
	}
}

func TestPeerRejectsOversizeFrame(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	l := &link{
		peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1),
		allowIncoming: true,
	}
	var output bytes.Buffer
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		done <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), &output, &mu)
	}()
	header := []byte{byte((tunnelMTU + 1) >> 8), byte((tunnelMTU + 1) & 255)}
	if _, err := right.Write(header); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exceeds limit") || output.Len() != 0 {
			t.Fatalf("oversize frame: output %d, error %v", output.Len(), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("oversize frame did not terminate session")
	}
}

func TestPeerAcceptsPacketAtMTU(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	l := &link{
		peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1),
		allowIncoming: true,
	}
	var output bytes.Buffer
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() {
		done <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), &output, &mu)
	}()
	packet := make([]byte, tunnelMTU)
	copy(packet, ipv4(2, 1))
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	if err := WritePacket(right, packet); err != nil {
		t.Fatal(err)
	}
	right.Close()
	select {
	case <-done:
		if !bytes.Equal(output.Bytes(), packet) {
			t.Fatalf("packet at MTU was not delivered: %d bytes", output.Len())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not terminate")
	}
}
