package agent

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestPacketValidationAndFraming(t *testing.T) {
	p := ipv4(1, 2)
	src, dst, err := packetAddresses(p)
	if err != nil || src.String() != "10.77.0.1" || dst.String() != "10.77.0.2" {
		t.Fatalf("bad addresses: %s %s %v", src, dst, err)
	}
	for _, invalid := range [][]byte{nil, p[:19], append([]byte{0x60}, p[1:]...), p[:21]} {
		if _, _, err := packetAddresses(invalid); err == nil {
			t.Errorf("accepted malformed packet %x", invalid)
		}
	}
	var b bytes.Buffer
	if err := WritePacket(&b, p); err != nil {
		t.Fatal(err)
	}
	roundTrip, err := ReadPacket(&b)
	if err != nil || !bytes.Equal(roundTrip, p) {
		t.Fatalf("framing round-trip: %x %v", roundTrip, err)
	}
	if err := WritePacket(&b, nil); err == nil {
		t.Fatal("accepted empty packet")
	}
	if _, err := ReadPacket(bytes.NewReader([]byte{0, 3, 1})); err == nil {
		t.Fatal("accepted truncated packet")
	}
}

func TestIncomingSpoofIsRejected(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	l := &link{peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1)}
	var output bytes.Buffer
	var mu sync.Mutex
	result := make(chan error, 1)
	go func() {
		result <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), &output, &mu)
	}()
	if err := WritePacket(right, ipv4(3, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err == nil || output.Len() != 0 {
			t.Fatalf("spoof accepted: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("spoofed session did not terminate")
	}
}

func TestControllerRejectsUnlistedCertificate(t *testing.T) {
	s, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.NewForState(s)
	if err != nil {
		t.Fatal(err)
	}
	outsider, err := s.AddPeer("outsider", "10.77.0.3")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := relay.TLSConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()
	outsider.Server = server.Listener.Addr().String()
	if _, _, err := FetchConfig(context.Background(), outsider); err == nil {
		t.Fatal("unlisted but CA-signed certificate was accepted")
	}
}

func setup(t *testing.T) (core.Config, core.Credential, core.Credential) {
	return setupWithReverse(t, true)
}

func setupWithReverse(t *testing.T, reverse bool) (core.Config, core.Credential, core.Credential) {
	t.Helper()
	s, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.AddPeer("bob", "10.77.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	if reverse {
		if err := s.Config.SetRule("bob", "alice", true); err != nil {
			t.Fatal(err)
		}
	}
	handler, err := relay.NewForState(s)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := relay.TLSConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsCfg
	server.StartTLS()
	t.Cleanup(server.Close)
	a.Server, b.Server = server.Listener.Addr().String(), server.Listener.Addr().String()
	return s.Config, a, b
}

func TestIncomingPolicyBlocksUnauthorizedPeer(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	l := &link{peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1)}
	var output bytes.Buffer
	var mu sync.Mutex
	result := make(chan error, 1)
	go func() {
		result <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), &output, &mu)
	}()
	if err := WritePacket(right, ipv4(2, 1)); err != nil {
		t.Fatal(err)
	}
	right.Close()
	select {
	case <-result:
		if output.Len() != 0 {
			t.Fatal("unauthorized peer delivered packet")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session did not terminate")
	}
}

func TestRelayPeerTLSAndPinning(t *testing.T) {
	cfg, a, b := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	got, id, err := FetchConfig(ctx, a)
	if err != nil || id != "alice" || len(got.Peers) != 2 {
		t.Fatalf("fetch config: id=%q err=%v", id, err)
	}

	peerA, _ := cfg.Peer("alice")
	peerB, _ := cfg.Peer("bob")
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 2)
	go func() { c, err := Connect(ctx, a, cfg, "alice", peerB); ch <- result{c, err} }()
	go func() { c, err := Connect(ctx, b, cfg, "bob", peerA); ch <- result{c, err} }()
	first, second := <-ch, <-ch
	if first.err != nil || second.err != nil {
		t.Fatalf("connect: %v / %v", first.err, second.err)
	}
	defer first.c.Close()
	defer second.c.Close()
	msg := []byte{1, 2, 3, 4}
	go func() { _ = WritePacket(first.c, msg) }()
	read, err := ReadPacket(second.c)
	if err != nil || string(read) != string(msg) {
		t.Fatalf("packet: %v %v", read, err)
	}

	// A controller-provided wrong certificate must not authenticate Bob as
	// Alice: Bob pins "alice" to Bob's own certificate, so Bob must reject
	// Alice's real certificate with the pin error, and no payload may pass.
	peerA.Cert = peerB.Cert
	aliceCh, bobCh := make(chan result, 1), make(chan result, 1)
	go func() { c, err := Connect(ctx, a, cfg, "alice", peerB); aliceCh <- result{c, err} }()
	go func() { c, err := Connect(ctx, b, cfg, "bob", peerA); bobCh <- result{c, err} }()
	aliceRes, bobRes := <-aliceCh, <-bobCh
	if bobRes.c != nil {
		bobRes.c.Close()
	}
	if bobRes.err == nil || !strings.Contains(bobRes.err.Error(), "does not match authorized peer alice") {
		t.Fatalf("bob did not reject the mismatched pin: %v", bobRes.err)
	}
	if aliceRes.c != nil {
		defer aliceRes.c.Close()
		aliceRes.c.SetDeadline(time.Now().Add(time.Second))
		_ = WritePacket(aliceRes.c, msg)
		if _, err := ReadPacket(aliceRes.c); err == nil {
			t.Fatal("payload passed over a session with a pin mismatch")
		}
	}
}

func TestRelayRejectsStaleRevision(t *testing.T) {
	cfg, alice, _ := setup(t)
	stale := cfg
	stale.Policy = &core.Policy{}
	bob, _ := cfg.Peer("bob")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := Connect(ctx, alice, stale, "alice", bob)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("relay accepted stale policy")
	}
}

type fakeTun struct {
	in     chan []byte
	out    chan []byte
	closed chan struct{}
	once   sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{in: make(chan []byte, 32), out: make(chan []byte, 32), closed: make(chan struct{})}
}
func (t *fakeTun) Read(b []byte) (int, error) {
	select {
	case p := <-t.in:
		return copy(b, p), nil
	case <-t.closed:
		return 0, io.EOF
	}
}
func (t *fakeTun) Write(b []byte) (int, error) {
	select {
	case t.out <- append([]byte(nil), b...):
		return len(b), nil
	case <-t.closed:
		return 0, io.EOF
	}
}
func (t *fakeTun) Close() error { t.once.Do(func() { close(t.closed) }); return nil }

func ipv4(src, dst byte) []byte {
	p := make([]byte, 24)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	copy(p[12:16], []byte{10, 77, 0, src})
	copy(p[16:20], []byte{10, 77, 0, dst})
	return p
}

func TestAgentsTransferAndRejectSpoofedPackets(t *testing.T) {
	cfg, a, b := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	ta, tb := newFakeTun(), newFakeTun()
	done := make(chan error, 2)
	go func() { done <- Run(ctx, a, cfg, "alice", ta) }()
	go func() { done <- Run(ctx, b, cfg, "bob", tb) }()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("agent stopped: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("agent did not stop")
			}
		}
	}()
	deadline := time.After(8 * time.Second)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ta.in <- ipv4(1, 2)
		case p := <-tb.out:
			if string(p) != string(ipv4(1, 2)) {
				t.Fatal("wrong packet")
			}
			goto connected
		case <-deadline:
			t.Fatal("packet not delivered")
		}
	}
connected:
	ta.in <- ipv4(3, 2)
	time.Sleep(200 * time.Millisecond)
	for len(tb.out) > 0 {
		if p := <-tb.out; string(p) == string(ipv4(3, 2)) {
			t.Fatal("forwarded spoofed source")
		}
	}
	tb.in <- ipv4(2, 1)
	select {
	case p := <-ta.out:
		if string(p) != string(ipv4(2, 1)) {
			t.Fatal("wrong return packet")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("return packet not delivered")
	}
}
