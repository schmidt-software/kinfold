package relay

import (
	"errors"
	"fmt"
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

func newTestLimitedListener(t *testing.T, limits ListenerLimits) *limitedListener {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewLimitedListener(raw, limits)
	if err != nil {
		raw.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l.(*limitedListener)
}

// acceptAsync returns accepted connections; the listener closes rejected ones itself.
func acceptAsync(l net.Listener) <-chan net.Conn {
	out := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				close(out)
				return
			}
			out <- c
		}
	}()
	return out
}

func dialClosedByPeer(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func TestLimitedListenerPerSourceCap(t *testing.T) {
	l := newTestLimitedListener(t, ListenerLimits{Total: 10, PerSource: 2})
	accepted := acceptAsync(l)
	var held []net.Conn
	for i := 0; i < 2; i++ {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		select {
		case a := <-accepted:
			held = append(held, a)
		case <-time.After(time.Second):
			t.Fatal("connection within per-source cap was not accepted")
		}
	}
	if !dialClosedByPeer(t, l.Addr().String()) {
		t.Fatal("connection over the per-source cap was not closed")
	}
	held[0].Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case a := <-accepted:
		a.Close()
	case <-time.After(time.Second):
		t.Fatal("per-source slot was not released")
	}
	held[1].Close()
}

func TestLimitedListenerRateLimitRefills(t *testing.T) {
	l := newTestLimitedListener(t, ListenerLimits{Total: 10, RatePerSource: 1, BurstPerSource: 2})
	now := time.Unix(1000, 0)
	l.mu.Lock()
	l.now = func() time.Time { return now }
	l.mu.Unlock()
	for i := 0; i < 2; i++ {
		if !l.admit("192.0.2.1") {
			t.Fatalf("burst connection %d rejected", i)
		}
	}
	if l.admit("192.0.2.1") {
		t.Fatal("connection over burst admitted")
	}
	if !l.admit("192.0.2.2") {
		t.Fatal("other source was affected by rate limit")
	}
	now = now.Add(1100 * time.Millisecond)
	if !l.admit("192.0.2.1") {
		t.Fatal("bucket did not refill")
	}
}

func TestLimitedListenerForgetsIdleSources(t *testing.T) {
	l := newTestLimitedListener(t, ListenerLimits{Total: 10, PerSource: 4, RatePerSource: 10, BurstPerSource: 2})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	if !l.admit("192.0.2.1") {
		t.Fatal("rejected")
	}
	l.releaseSource("192.0.2.1")
	if len(l.sources) != 1 {
		t.Fatal("source with a partially used bucket was forgotten too early")
	}
	now = now.Add(time.Second)
	if !l.admit("192.0.2.1") {
		t.Fatal("rejected after refill")
	}
	now = now.Add(time.Second)
	l.releaseSource("192.0.2.1")
	if len(l.sources) != 0 {
		t.Fatalf("idle source state kept: %d entries", len(l.sources))
	}
}

func TestNewLimitedListenerRejectsInvalidLimits(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	for _, limits := range []ListenerLimits{
		{Total: 1, PerSource: -1},
		{Total: 1, RatePerSource: -1},
		{Total: 1, RatePerSource: 1, BurstPerSource: 0},
	} {
		if _, err := NewLimitedListener(raw, limits); err == nil {
			t.Errorf("accepted invalid limits %+v", limits)
		}
	}
}

func TestSourceKeyAggregatesIPv6By64(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:1:2::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9": "2001:db8:1:2::/64",
		"2001:db8:1:3::1":      "2001:db8:1:3::/64",
		"fe80::1%eth0":         "fe80::/64",
	} {
		if got := sourceKey(in); got != want {
			t.Errorf("sourceKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLimitedListenerSourceMapIsBounded(t *testing.T) {
	l := newTestLimitedListener(t, ListenerLimits{Total: 10, PerSource: 4, RatePerSource: 1, BurstPerSource: 4})
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	for i := 0; i < maxTrackedSources+100; i++ {
		source := fmt.Sprintf("2001:db8:%x::/64", i)
		if !l.admit(source) {
			t.Fatalf("source %d rejected", i)
		}
		l.releaseSource(source) // one-shot connection, bucket only partly refilled
	}
	if n := len(l.sources); n > maxTrackedSources {
		t.Fatalf("source map grew to %d entries", n)
	}
}
