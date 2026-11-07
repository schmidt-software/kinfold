package agent

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type failingWriteTun struct {
	*fakeTun
	short bool
}

type blockedWriteDevice struct {
	entered chan struct{}
	release chan struct{}
	err     error
}

func (d *blockedWriteDevice) Write([]byte) (int, error) {
	close(d.entered)
	<-d.release
	return 0, d.err
}

type closeNotifyingConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyingConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestSessionWriteFailureDuringConcurrentStop(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		name := "network failure"
		if shutdown {
			name = "agent shutdown"
		}
		t.Run(name, func(t *testing.T) {
			left, right := net.Pipe()
			defer right.Close()
			conn := &closeNotifyingConn{Conn: left, closed: make(chan struct{})}
			writeFailure := errors.New("tunnel write failed")
			device := &blockedWriteDevice{entered: make(chan struct{}), release: make(chan struct{}), err: writeFailure}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			l := &link{peer: core.Peer{ID: "bob", IP: "10.77.0.2"}, queue: make(chan []byte, 1), allowIncoming: true}
			var mu sync.Mutex
			done := make(chan error, 1)
			go func() { done <- l.session(ctx, conn, netip.MustParseAddr("10.77.0.1"), device, &mu) }()
			if err := WritePacket(right, ipv4(2, 1)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-device.entered:
			case <-time.After(3 * time.Second):
				t.Fatal("write did not start")
			}
			if shutdown {
				cancel()
			} else {
				right.Close()
				l.queue <- ipv4(1, 2)
			}
			select {
			case <-conn.closed:
			case <-time.After(3 * time.Second):
				close(device.release)
				t.Fatal("session did not start closing")
			}
			close(device.release)
			select {
			case err := <-done:
				var writeErr *tunnelWriteError
				if shutdown && errors.As(err, &writeErr) {
					t.Fatalf("shutdown-induced write failure reported as fatal: %v", err)
				}
				if !shutdown && (!errors.As(err, &writeErr) || !errors.Is(err, writeFailure)) {
					t.Fatalf("concurrent tunnel failure lost: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("session did not stop")
			}
		})
	}
}

func (d *failingWriteTun) Write(p []byte) (int, error) {
	if d.short {
		return len(p) - 1, nil
	}
	return 0, errors.New("injected tunnel write failure")
}

func TestAgentStopsOnTunnelWriteFailure(t *testing.T) {
	for _, short := range []bool{false, true} {
		name := "error"
		want := "injected tunnel write failure"
		if short {
			name, want = "short-write", io.ErrShortWrite.Error()
		}
		t.Run(name, func(t *testing.T) {
			cfg, alice, bob := setup(t)
			ctx, cancel := context.WithCancel(context.Background())
			sender := newFakeTun()
			receiver := &failingWriteTun{fakeTun: newFakeTun(), short: short}
			senderDone := make(chan error, 1)
			receiverDone := make(chan error, 1)
			go func() { senderDone <- Run(ctx, alice, cfg, "alice", sender) }()
			go func() { receiverDone <- Run(ctx, bob, cfg, "bob", receiver) }()
			defer func() {
				cancel()
				select {
				case err := <-senderDone:
					if err != nil {
						t.Errorf("sender shutdown: %v", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("sender did not stop")
				}
			}()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			timeout := time.NewTimer(8 * time.Second)
			defer timeout.Stop()
			for {
				select {
				case <-ticker.C:
					select {
					case sender.in <- ipv4(1, 2):
					default:
					}
				case err := <-receiverDone:
					if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "write tunnel") {
						t.Fatalf("tunnel error not propagated: %v", err)
					}
					select {
					case <-receiver.closed:
					default:
						t.Fatal("tunnel was not closed")
					}
					return
				case <-timeout.C:
					cancel()
					t.Fatal("write error did not stop receiver")
				}
			}
		})
	}
}
