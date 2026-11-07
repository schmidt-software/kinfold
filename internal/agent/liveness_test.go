package agent

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

func TestSessionEndsWhenPeerStopsReading(t *testing.T) {
	old := peerWriteTimeout
	peerWriteTimeout = 100 * time.Millisecond
	defer func() { peerWriteTimeout = old }()
	left, right := net.Pipe() // right never reads: every write blocks
	defer right.Close()
	l := &link{peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1), allowOutgoing: true}
	l.queue <- ipv4(1, 2)
	var mu sync.Mutex
	result := make(chan error, 1)
	go func() {
		result <- l.session(context.Background(), left, netip.MustParseAddr("10.77.0.1"), io.Discard, &mu)
	}()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("session ended without error")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("session kept blocking on a peer that does not read")
	}
}

type deadlineRecorder struct {
	net.Conn
	read, write time.Time
	closed      bool
}

func (c *deadlineRecorder) SetReadDeadline(t time.Time) error  { c.read = t; return nil }
func (c *deadlineRecorder) SetWriteDeadline(t time.Time) error { c.write = t; return nil }
func (c *deadlineRecorder) SetDeadline(t time.Time) error {
	c.read, c.write = t, t
	return nil
}
func (c *deadlineRecorder) Close() error { c.closed = true; return nil }

func TestCertificateConnClampsDeadlinesToExpiry(t *testing.T) {
	expiry := time.Now().Add(time.Minute)
	inner := &deadlineRecorder{}
	c := &certificateConn{Conn: inner, deadline: expiry, expiry: expiry}
	soon := time.Now().Add(time.Second)
	if err := c.SetWriteDeadline(soon); err != nil || !inner.write.Equal(soon) {
		t.Fatalf("earlier write deadline not kept: %v", inner.write)
	}
	if err := c.SetWriteDeadline(time.Now().Add(time.Hour)); err != nil || !inner.write.Equal(expiry) {
		t.Fatalf("write deadline extended past certificate expiry: %v", inner.write)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil || !inner.read.Equal(expiry) {
		t.Fatalf("clearing the read deadline removed the certificate deadline: %v", inner.read)
	}
	if err := c.SetDeadline(time.Time{}); err != nil || !inner.read.Equal(expiry) || !inner.write.Equal(expiry) {
		t.Fatal("SetDeadline removed the certificate deadline")
	}
}

func TestCertificateConnCloseClosesSocketFirst(t *testing.T) {
	socket, inner := &deadlineRecorder{}, &deadlineRecorder{}
	c := &certificateConn{Conn: inner, socket: socket}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if !socket.closed || !inner.closed {
		t.Fatalf("socket closed %v, inner closed %v", socket.closed, inner.closed)
	}
}

// A device certificate is CA-signed and carries the server-auth EKU, but no
// SAN; it must not be accepted as the controller's certificate.
func TestFetchConfigRejectsDeviceCertificateAsController(t *testing.T) {
	state, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := state.AddPeer("mallory", "10.77.0.2")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(mallory.Cert, mallory.Key)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("request reached the impostor controller")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	alice.Server = server.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := FetchConfig(ctx, alice); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("device certificate accepted as controller: %v", err)
	}
}

func TestConfigClientReusesConnection(t *testing.T) {
	_, alice, _ := setup(t)
	var dials atomic.Int32
	c := NewConfigClient(alice)
	defer c.Close()
	base := c.transport.DialContext
	c.transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return base(ctx, network, addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 3; i++ {
		if _, id, err := c.Fetch(ctx); err != nil || id != "alice" {
			t.Fatalf("fetch %d: id=%q err=%v", i, id, err)
		}
	}
	if n := dials.Load(); n != 1 {
		t.Fatalf("three fetches used %d connections, want 1", n)
	}
}
