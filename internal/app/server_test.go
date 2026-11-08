package app

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

type testController struct {
	addr  string
	state *core.State
	cred  core.Credential
}

// startTestController runs the production server and listener configuration
// with short timeouts.
func startTestController(t *testing.T, timeouts serverTimeouts) testController {
	t.Helper()
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := listenController(ctx, "127.0.0.1:0", relay.DefaultListenerLimits)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	server := newControllerServer(handler, tlsCfg, timeouts)
	done := make(chan error, 1)
	go func() {
		done <- serveController(ctx, server, ln, handler, func(context.Context) {}, time.Second)
	}()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("controller: %v", err)
		}
	})
	return testController{addr: ln.Addr().String(), state: state, cred: cred}
}

func (c testController) clientTLS(t *testing.T, cred *core.Credential, protos ...string) *tls.Config {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.state.CA) {
		t.Fatal("invalid CA")
	}
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: protos}
	if cred != nil {
		pair, err := tls.X509KeyPair(cred.Cert, cred.Key)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	return cfg
}

// closedWithin reports whether the server closes conn within d.
func closedWithin(conn net.Conn, d time.Duration) bool {
	conn.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, conn)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestControllerClosesIdleKeepAliveConnections(t *testing.T) {
	c := startTestController(t, serverTimeouts{Handshake: time.Second, Read: time.Second, Write: time.Second, Idle: 200 * time.Millisecond})
	conn, err := tls.Dial("tcp", c.addr, c.clientTLS(t, &c.cred, "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /config HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Close {
		t.Fatalf("unexpected first response: %s close=%v", resp.Status, resp.Close)
	}
	if !closedWithin(conn, 2*time.Second) {
		t.Fatal("idle keep-alive connection was not closed")
	}
}

func TestControllerClosesConnectionAfterRejection(t *testing.T) {
	c := startTestController(t, defaultServerTimeouts)
	// A certificate signed by the CA but not in the member list, like a
	// device removed with remove-peer.
	other := *c.state
	removed, err := other.AddPeer("mallory", "10.77.0.9")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", c.addr, c.clientTLS(t, &removed, "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /config HTTP/1.1\r\nHost: localhost\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !resp.Close {
		t.Fatalf("got %s close=%v, want 403 with Connection: close", resp.Status, resp.Close)
	}
	if !closedWithin(conn, 2*time.Second) {
		t.Fatal("rejected connection stayed open")
	}
}

func TestControllerBoundsUnauthenticatedHandshake(t *testing.T) {
	c := startTestController(t, serverTimeouts{Handshake: 200 * time.Millisecond, Read: time.Second, Write: time.Second, Idle: time.Second})
	conn, err := net.Dial("tcp", c.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !closedWithin(conn, 2*time.Second) {
		t.Fatal("silent TCP connection was not closed by the handshake timeout")
	}
}

func TestControllerDoesNotNegotiateHTTP2(t *testing.T) {
	c := startTestController(t, defaultServerTimeouts)
	conn, err := tls.Dial("tcp", c.addr, c.clientTLS(t, &c.cred, "h2", "http/1.1"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if got := conn.ConnectionState().NegotiatedProtocol; got == "h2" {
		t.Fatal("controller negotiated HTTP/2")
	}
	if _, err := tls.Dial("tcp", c.addr, c.clientTLS(t, &c.cred, "h2")); err == nil || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("h2-only client was not refused: %v", err)
	}
}

func TestProductionServerConfiguration(t *testing.T) {
	s := newControllerServer(http.NotFoundHandler(), &tls.Config{}, defaultServerTimeouts)
	if s.IdleTimeout <= 0 || s.ReadTimeout <= 0 || s.WriteTimeout <= 0 || s.ReadHeaderTimeout <= 0 {
		t.Fatalf("all server timeouts must be set: %+v", s)
	}
	if s.ReadHeaderTimeout > 5*time.Second {
		t.Fatalf("handshake/header timeout %v allows slow unauthenticated clients to hold slots", s.ReadHeaderTimeout)
	}
	if s.Protocols == nil || s.Protocols.HTTP2() || !s.Protocols.HTTP1() {
		t.Fatal("server must speak HTTP/1.1 only")
	}
	if s.MaxHeaderBytes != maxRequestHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d", s.MaxHeaderBytes)
	}
	if !controllerKeepAlive.Enable || controllerKeepAlive.Idle+controllerKeepAlive.Interval*time.Duration(controllerKeepAlive.Count) > time.Minute {
		t.Fatalf("keepalive detects dead peers too slowly: %+v", controllerKeepAlive)
	}
}
