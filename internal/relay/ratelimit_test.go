package relay

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/metrics"
)

func TestBucketCharge(t *testing.T) {
	limit := RelayLimit{Rate: 1000, Burst: 2000}
	var b bucket
	now := time.Now()
	if wait := b.charge(limit, 2000, now); wait != 0 {
		t.Fatalf("burst was not available: %s", wait)
	}
	if wait := b.charge(limit, 500, now); wait != 500*time.Millisecond {
		t.Fatalf("overdraft wait %s, want 500ms", wait)
	}
	// One second later 1000 bytes were refilled, paying the 500-byte debt.
	if wait := b.charge(limit, 500, now.Add(time.Second)); wait != 0 {
		t.Fatalf("refill not applied: %s", wait)
	}
	// Refill never exceeds the burst.
	if wait := b.charge(limit, 2001, now.Add(time.Hour)); wait != time.Millisecond {
		t.Fatalf("bucket grew beyond its burst: %s", wait)
	}
}

// The limit is shared by all sessions of one device and slows down only
// that device's direction.
func TestRelayLimitThrottlesDevice(t *testing.T) {
	s := &Server{metrics: metrics.New(), buckets: map[string]*bucket{}}
	s.SetRelayLimit(RelayLimit{Rate: 64 << 10, Burst: 16 << 10})
	run := func(id string) (time.Duration, uint64) {
		aliceSide, aliceRelay := net.Pipe()
		bobRelay, bobSide := net.Pipe()
		done := make(chan struct{})
		s.mu.Lock()
		a, b := s.limitedEnd(aliceRelay, id, done), s.limitedEnd(bobRelay, "bob", done)
		s.mu.Unlock()
		go bridge(a, b, done)
		payload := make([]byte, 80<<10)
		start := time.Now()
		go func() { _, _ = aliceSide.Write(payload); aliceSide.Close() }()
		n, _ := io.Copy(io.Discard, bobSide)
		bobSide.Close()
		if n != int64(len(payload)) {
			t.Fatalf("received %d of %d bytes", n, len(payload))
		}
		return time.Since(start), s.metrics.Counter("kinfold_relay_throttle_delay_milliseconds_total", "", metrics.Labels{"peer": id}).Value()
	}
	// 80 KiB with a 16 KiB burst at 64 KiB/s takes about one second.
	elapsed, delayed := run("alice")
	if elapsed < 800*time.Millisecond || elapsed > 5*time.Second || delayed == 0 {
		t.Fatalf("alice took %s, throttled %d ms", elapsed, delayed)
	}
	// The same device's bucket is empty now: a second session starts slow.
	if elapsed, _ := run("alice"); elapsed < 900*time.Millisecond {
		t.Fatalf("second session of the same device was not limited: %s", elapsed)
	}
	unlimited := &Server{metrics: metrics.New(), buckets: map[string]*bucket{}}
	unlimited.mu.Lock()
	if e := unlimited.limitedEnd(nil, "alice", nil); e.reader != nil {
		t.Fatal("reader wrapped without a limit")
	}
	unlimited.mu.Unlock()
}
