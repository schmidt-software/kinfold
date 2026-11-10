package app

import (
	"testing"

	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestSourceBurst(t *testing.T) {
	if got := sourceBurst(0); got != relay.DefaultListenerLimits.BurstPerSource {
		t.Fatalf("disabled per-source limit: burst %d, want the default %d", got, relay.DefaultListenerLimits.BurstPerSource)
	}
	if got := sourceBurst(8); got != 8 {
		t.Fatalf("burst %d, want the per-source limit 8", got)
	}
}
