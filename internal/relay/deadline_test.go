package relay

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

type failingDeadlineConn struct {
	net.Conn
	failClear bool
}

func (c *failingDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if deadline.IsZero() == c.failClear {
		return errors.New("injected deadline failure")
	}
	return c.Conn.SetWriteDeadline(deadline)
}

func TestRelayResponseDeadlineErrorsReleaseEndpoint(t *testing.T) {
	for _, failClear := range []bool{false, true} {
		name := "set"
		if failClear {
			name = "clear"
		}
		t.Run(name, func(t *testing.T) {
			cfg := pairConfig(t)
			server, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			left, right := net.Pipe()
			defer right.Close()
			w := &blockingHijacker{conn: &failingDeadlineConn{Conn: left, failClear: failClear}, header: make(http.Header)}
			done := make(chan struct{})
			go func() {
				server.connect(w, relayRequest(t, cfg, "alice"), "alice", "bob", 0)
				close(done)
			}()
			if failClear {
				if err := right.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(right), &http.Request{Method: http.MethodConnect})
				if err != nil || resp.StatusCode != http.StatusOK {
					t.Fatalf("read response: %v, %v", resp, err)
				}
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay handler did not exit after deadline error")
			}
			server.mu.Lock()
			active, waiting := len(server.active), len(server.waiting)
			server.mu.Unlock()
			if active != 0 || waiting != 0 {
				t.Fatalf("deadline failure leaked relay endpoint: %d active, %d waiting", active, waiting)
			}
			if err := right.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
				_, err = right.Read(make([]byte, 1))
				if err == nil || strings.Contains(err.Error(), "timeout") {
					t.Fatalf("connection not closed: %v", err)
				}
			}
		})
	}
}
