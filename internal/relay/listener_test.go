package relay

import (
	"errors"
	"net"
	"testing"
	"time"
)

func TestLimitedListenerCapacityAndClose(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := LimitListener(raw, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	next := make(chan net.Conn, 1)
	errs := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			errs <- err
			return
		}
		next <- c
	}()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	select {
	case c := <-next:
		c.Close()
		t.Fatal("accepted over capacity")
	case <-time.After(100 * time.Millisecond):
	}
	accepted.Close()
	accepted.Close()
	var secondAccepted net.Conn
	select {
	case secondAccepted = <-next:
	case <-time.After(time.Second):
		t.Fatal("slot was not released")
	}
	go func() {
		_, err := listener.Accept()
		errs <- err
	}()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("unexpected accept error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("accept did not unblock after close")
	}
	secondAccepted.Close()
}

func TestLimitListenerRejectsInvalidLimits(t *testing.T) {
	if _, err := LimitListener(nil, 1); err == nil {
		t.Fatal("accepted nil listener")
	}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := LimitListener(raw, 0); err == nil {
		t.Fatal("accepted zero limit")
	}
}
