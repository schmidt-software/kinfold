package relay

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/metrics"
)

// Per-device relay bandwidth limit (D-035): every byte a device sends
// through the relay, over all of its sessions, is charged to one token
// bucket. A read that overdraws the bucket is followed by a pause long
// enough to pay the debt, so the long-term rate never exceeds the limit
// and bursts never exceed the bucket size plus one read.

const relayCopyBuffer = 16 << 10

// RelayLimit configures the per-device bandwidth limit; a zero Rate
// disables it.
type RelayLimit struct {
	Rate  float64 // bytes per second per device
	Burst float64 // bucket size in bytes
}

type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// charge takes n bytes from the bucket and returns how long the caller has
// to wait before reading more.
func (b *bucket) charge(limit RelayLimit, n int, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.last.IsZero() {
		b.tokens, b.last = limit.Burst, now
	}
	b.tokens = min(limit.Burst, b.tokens+now.Sub(b.last).Seconds()*limit.Rate)
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / limit.Rate * float64(time.Second))
}

// SetRelayLimit sets the per-device relay bandwidth limit. It applies to
// sessions bridged afterwards.
func (s *Server) SetRelayLimit(limit RelayLimit) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit.Rate > 0 && limit.Burst < relayCopyBuffer {
		limit.Burst = relayCopyBuffer
	}
	s.relayLimit = limit
}

// bucketFor returns the device's bucket, or nil without a limit. Caller
// holds s.mu.
func (s *Server) bucketFor(id string) *bucket {
	if s.relayLimit.Rate <= 0 || id == "" {
		return nil
	}
	b := s.buckets[id]
	if b == nil {
		b = &bucket{}
		s.buckets[id] = b
	}
	return b
}

// limitedReader charges what a device sends to its bucket and pauses when
// the bucket is overdrawn; done ends a pause early when the bridge closes.
type limitedReader struct {
	src     net.Conn
	limit   RelayLimit
	bucket  *bucket
	done    <-chan struct{}
	delayed *metrics.Counter
}

func (r *limitedReader) Read(p []byte) (int, error) {
	if len(p) > relayCopyBuffer {
		p = p[:relayCopyBuffer]
	}
	n, err := r.src.Read(p)
	if n > 0 {
		if wait := r.bucket.charge(r.limit, n, time.Now()); wait > 0 {
			r.delayed.Add(uint64(wait / time.Millisecond))
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-r.done:
				timer.Stop()
			}
		}
	}
	return n, err
}

// bridgeEnd is one side of a bridge: its connection and, with a limit,
// the reader that charges its device.
type bridgeEnd struct {
	conn   net.Conn
	reader io.Reader
}

// limitedEnd prepares one side of a bridge. Caller holds s.mu.
func (s *Server) limitedEnd(conn net.Conn, id string, done <-chan struct{}) bridgeEnd {
	b := s.bucketFor(id)
	if b == nil {
		return bridgeEnd{conn: conn, reader: conn}
	}
	delayed := s.metrics.Counter("kinfold_relay_throttle_delay_milliseconds_total", "Time relayed reads were paused by the per-device bandwidth limit.", metrics.Labels{"peer": id})
	return bridgeEnd{conn: conn, reader: &limitedReader{src: conn, limit: s.relayLimit, bucket: b, done: done, delayed: delayed}}
}
