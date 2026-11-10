package app

import (
	"testing"
	"time"
)

func TestWarningsDueOncePerInterval(t *testing.T) {
	var last time.Time
	start := time.Now()
	if !warningsDue(&last, start) {
		t.Fatal("first check must warn (startup)")
	}
	if warningsDue(&last, start.Add(certificateWarningInterval-time.Second)) {
		t.Fatal("warned again within the interval")
	}
	if !warningsDue(&last, start.Add(certificateWarningInterval)) {
		t.Fatal("no warning after a full interval")
	}
	if warningsDue(&last, start.Add(certificateWarningInterval+time.Second)) {
		t.Fatal("interval did not restart after a warning")
	}
}
