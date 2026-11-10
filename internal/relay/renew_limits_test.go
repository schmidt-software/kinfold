package relay

import (
	"fmt"
	"testing"
	"time"
)

// The failed-attempt table is filled by unauthenticated callers and read
// under the relay lock, so it must stay bounded and must not be walked on
// every request (#145).
func TestFailedAttemptTableIsBounded(t *testing.T) {
	s, err := New(pairConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// An expired entry stops blocking at once, although the table is only
	// walked once a second.
	s.noteRenewalFailure("enroll:early")
	if !s.renewalBlocked("enroll:early") {
		t.Fatal("a recent failure does not block its caller")
	}
	s.mu.Lock()
	s.renewFailures["enroll:early"] = time.Now().Add(-2 * s.renewInterval)
	pruned := s.renewPruned
	s.mu.Unlock()
	if s.renewalBlocked("enroll:early") {
		t.Fatal("an expired entry still blocks its caller")
	}
	if !s.renewPruned.Equal(pruned) || len(s.renewFailures) != 1 {
		t.Fatal("the table was walked again within a second")
	}

	for i := 0; len(s.renewFailures) < maxRenewFailures; i++ {
		s.noteRenewalFailure(fmt.Sprintf("enroll:source-%d", i))
	}
	if !s.renewalBlocked("enroll:newcomer") {
		t.Fatal("a full table must refuse unknown callers")
	}
	s.noteRenewalFailure("enroll:newcomer")
	if got := len(s.renewFailures); got != maxRenewFailures {
		t.Fatalf("table has %d entries, want the bound %d", got, maxRenewFailures)
	}

	// The periodic walk drops expired entries and frees the table.
	s.mu.Lock()
	old := time.Now().Add(-2 * s.renewInterval)
	for key := range s.renewFailures {
		s.renewFailures[key] = old
	}
	s.renewPruned = time.Time{}
	s.mu.Unlock()
	if s.renewalBlocked("enroll:newcomer") || len(s.renewFailures) != 0 {
		t.Fatalf("expired entries were not dropped: %d left", len(s.renewFailures))
	}
}
