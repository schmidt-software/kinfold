package agent

import (
	"testing"
	"time"
)

func TestRetryBackoffBoundsAndReset(t *testing.T) {
	var b retryBackoff
	for _, ceiling := range []time.Duration{2, 4, 8, 16, 30, 30} {
		delay := b.next()
		expected := ceiling * time.Second
		if b.ceiling != expected || delay < expected/2 || delay > expected {
			t.Fatalf("ceiling %s delay %s, expected %s", b.ceiling, delay, expected)
		}
	}
	b.reset()
	delay := b.next()
	if b.ceiling != initialRetry || delay < initialRetry/2 || delay > initialRetry {
		t.Fatalf("backoff did not reset: ceiling %s, delay %s", b.ceiling, delay)
	}
}
