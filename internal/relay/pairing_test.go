package relay

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func activeEndpoints(s *Server) (active, waiting int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.active), len(s.waiting)
}

func TestWaitingEndpointTimesOutAndReleasesSlot(t *testing.T) {
	old := pairingTimeout
	pairingTimeout = 100 * time.Millisecond
	defer func() { pairingTimeout = old }()
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan struct{})
	go func() {
		s.connect(&blockingHijacker{conn: left, header: make(http.Header)}, relayRequest(t, cfg), "alice", "bob", 0)
		close(done)
	}()
	reader := bufio.NewReader(right)
	if line, err := reader.ReadString('\n'); err != nil || !strings.Contains(line, "200") {
		t.Fatalf("no 200 response: %q %v", line, err)
	}
	// The 200 response is written before the endpoint is queued as waiting.
	registered := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if active, waiting := activeEndpoints(s); active == 1 && waiting == 1 {
			registered = true
			break
		}
	}
	if !registered {
		<-done
		t.Fatal("endpoint was never queued as waiting")
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting endpoint did not time out")
	}
	if active, waiting := activeEndpoints(s); active != 0 || waiting != 0 {
		t.Fatalf("slot not released after timeout: active=%d waiting=%d", active, waiting)
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAll(reader); err != nil {
		t.Fatalf("connection not closed after timeout: %v", err)
	}
}

// earlyDataHijacker returns a reader that already buffered client bytes,
// as if the client sent tunnel data before the relay's 200 response.
type earlyDataHijacker struct {
	blockingHijacker
}

func (w *earlyDataHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r := bufio.NewReader(io.MultiReader(strings.NewReader("early"), w.conn))
	if _, err := r.Peek(1); err != nil {
		return nil, nil, err
	}
	return w.conn, bufio.NewReadWriter(r, bufio.NewWriter(w.conn)), nil
}

func TestRelayRejectsEarlyData(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan struct{})
	go func() {
		s.connect(&earlyDataHijacker{blockingHijacker{conn: left, header: make(http.Header)}}, relayRequest(t, cfg), "alice", "bob", 0)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection with early data was not rejected")
	}
	if active, waiting := activeEndpoints(s); active != 0 || waiting != 0 {
		t.Fatalf("early-data connection kept a slot: active=%d waiting=%d", active, waiting)
	}
}

func TestPairedEndpointsBridgeAndRelease(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	aliceRelay, alice := net.Pipe()
	bobRelay, bob := net.Pipe()
	defer alice.Close()
	defer bob.Close()
	done := make(chan struct{}, 2)
	go func() {
		s.connect(&blockingHijacker{conn: aliceRelay, header: make(http.Header)}, relayRequest(t, cfg), "alice", "bob", 0)
		done <- struct{}{}
	}()
	aliceReader := bufio.NewReader(alice)
	if _, err := aliceReader.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	aliceReader.ReadString('\n') // blank line ending the response
	go func() {
		s.connect(&blockingHijacker{conn: bobRelay, header: make(http.Header)}, relayRequest(t, cfg), "bob", "alice", 0)
		done <- struct{}{}
	}()
	bobReader := bufio.NewReader(bob)
	bobReader.ReadString('\n')
	bobReader.ReadString('\n')
	go alice.Write([]byte("ping"))
	buf := make([]byte, 4)
	bob.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(bobReader, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("bridge did not forward data: %q %v", buf, err)
	}
	alice.Close()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("bridge did not end after one side closed")
		}
	}
	if active, waiting := activeEndpoints(s); active != 0 || waiting != 0 {
		t.Fatalf("bridged endpoints not released: active=%d waiting=%d", active, waiting)
	}
}
