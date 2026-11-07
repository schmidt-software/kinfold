package relay

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type blockingHijacker struct {
	conn   net.Conn
	header http.Header
}

func (w *blockingHijacker) Header() http.Header         { return w.header }
func (w *blockingHijacker) Write(p []byte) (int, error) { return len(p), nil }
func (w *blockingHijacker) WriteHeader(int)             {}
func (w *blockingHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestSlowRelayResponseDoesNotBlockRevocation(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	writer := &blockingHijacker{conn: left, header: make(http.Header)}
	done := make(chan struct{})
	go func() {
		s.connect(writer, relayRequest(t, cfg), "alice", "bob", 0)
		close(done)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		registered := len(s.active) == 1
		s.mu.Unlock()
		if registered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("connection not registered")
		}
		time.Sleep(time.Millisecond)
	}
	updated := make(chan error, 1)
	go func() { updated <- s.Update(core.Config{}, errors.New("state unavailable")) }()
	select {
	case err := <-updated:
		if err == nil {
			t.Fatal("expected invalid state error")
		}
	case <-time.After(time.Second):
		t.Fatal("slow client blocked configuration update")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closed connection did not terminate")
	}
}

func TestAdmissionLimitsAndRelease(t *testing.T) {
	s, err := New(core.Config{Network: "10.77.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	add := func(from, to string) {
		t.Helper()
		a, b := net.Pipe()
		conns = append(conns, a, b)
		s.active[a] = endpoint{from: from, to: to}
	}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	add("alice", "bob")
	if got := s.admissionStatus("alice", "bob"); got != http.StatusConflict {
		t.Fatalf("duplicate endpoint: %d", got)
	}
	for i := 1; i < maxPeerEndpoints; i++ {
		add("alice", fmt.Sprintf("peer-%d", i))
	}
	if got := s.admissionStatus("alice", "charlie"); got != http.StatusTooManyRequests {
		t.Fatalf("per-peer limit: %d", got)
	}
	if got := s.admissionStatus("bob", "alice"); got != 0 {
		t.Fatalf("unrelated endpoint rejected: %d", got)
	}
	for len(s.active) < maxRelayEndpoints {
		add("other", fmt.Sprint(len(s.active)))
	}
	if got := s.admissionStatus("bob", "alice"); got != http.StatusTooManyRequests {
		t.Fatalf("global limit: %d", got)
	}
	s.forget(conns[0])
	if got := s.admissionStatus("bob", "alice"); got != 0 {
		t.Fatalf("capacity was not released: %d", got)
	}
}

func TestDuplicateRelayRequestIsRejected(t *testing.T) {
	state, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddPeer("bob", "10.77.0.2"); err != nil {
		t.Fatal(err)
	}
	if err := state.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	handler, err := New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()
	defer handler.Close()
	cert, err := tls.X509KeyPair(alice.Cert, alice.Key)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(alice.CA) {
		t.Fatal("invalid CA")
	}
	revision, err := state.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	connect := func() (net.Conn, int) {
		t.Helper()
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", server.Listener.Addr().String(), &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{cert},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Path: "/relay", RawQuery: "peer=bob"},
			Host:   server.Listener.Addr().String(),
			Header: http.Header{"X-Kinfold-Config-Revision": {revision}},
		}
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			t.Fatal(err)
		}
		return conn, resp.StatusCode
	}
	first, status := connect()
	defer first.Close()
	if status != http.StatusOK {
		t.Fatalf("first request: %d", status)
	}
	second, status := connect()
	defer second.Close()
	if status != http.StatusConflict {
		t.Fatalf("duplicate request: %d", status)
	}
}
