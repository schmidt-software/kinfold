package agent

import (
	"math/rand/v2"
	"time"
)

const (
	initialRetry = 2 * time.Second
	maxRetry     = 30 * time.Second
	stableLink   = 30 * time.Second
)

type retryBackoff struct {
	ceiling time.Duration
}

func (b *retryBackoff) reset() { b.ceiling = 0 }

// next uses equal jitter to avoid synchronized retries and busy loops.
func (b *retryBackoff) next() time.Duration {
	if b.ceiling == 0 {
		b.ceiling = initialRetry
	} else if b.ceiling >= maxRetry/2 {
		b.ceiling = maxRetry
	} else {
		b.ceiling *= 2
	}
	half := b.ceiling / 2
	return half + time.Duration(rand.Int64N(int64(b.ceiling-half)+1))
}
