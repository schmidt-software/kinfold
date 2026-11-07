package agent

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

type delayedReadConn struct {
	net.Conn
	ready   chan struct{}
	release chan struct{}
}

func (c *delayedReadConn) Read(p []byte) (int, error) {
	close(c.ready)
	<-c.release
	p[0] = 42
	return 1, nil
}

func TestCertificateConnDiscardsReadCompletingAfterExpiry(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	source := &delayedReadConn{Conn: left, ready: make(chan struct{}), release: make(chan struct{})}
	conn := &certificateConn{Conn: source, deadline: time.Now().Add(100 * time.Millisecond), expiry: time.Now().Add(time.Hour)}
	result := make(chan error, 1)
	go func() {
		n, err := conn.Read(make([]byte, 1))
		if n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
			result <- errors.New("returned bytes read after expiry")
			return
		}
		result <- nil
	}()
	<-source.ready
	time.Sleep(time.Until(conn.deadline) + 10*time.Millisecond)
	close(source.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if n, err := conn.Write([]byte{1}); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write after expiry: %d, %v", n, err)
	}
}

func TestCertificateConnChecksWallExpiry(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	conn := &certificateConn{Conn: left, deadline: time.Now().Add(time.Hour), expiry: time.Now().Add(-time.Second)}
	if n, err := conn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after wall-clock expiry: %d, %v", n, err)
	}
}
