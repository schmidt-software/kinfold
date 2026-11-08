package relay

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDeviceStatusMetrics(t *testing.T) {
	state := threePeerState(t)
	s, err := NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	scrape := func() string {
		var out strings.Builder
		if err := s.Metrics().WritePrometheus(&out); err != nil {
			t.Fatal(err)
		}
		return out.String()
	}
	if out := scrape(); !strings.Contains(out, `kinfold_device_last_seen_timestamp_seconds{peer="alice"} 0`) || !strings.Contains(out, `kinfold_device_relay_endpoints{peer="carol"} 0`) {
		t.Fatalf("initial status series missing:\n%s", out)
	}
	alice, _ := x509.ParseCertificate(state.Config.Peers[0].Cert)
	r := httptest.NewRequest(http.MethodGet, "/config", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{alice}}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("config: %d", rec.Code)
	}
	ab, abPeer := net.Pipe()
	defer abPeer.Close()
	s.mu.Lock()
	s.active[ab] = endpoint{from: "alice", to: "bob"}
	s.mu.Unlock()
	out := scrape()
	if strings.Contains(out, `kinfold_device_last_seen_timestamp_seconds{peer="alice"} 0`) || !strings.Contains(out, `kinfold_device_last_seen_timestamp_seconds{peer="bob"} 0`) {
		t.Fatalf("last seen not recorded for alice only:\n%s", out)
	}
	if !strings.Contains(out, `kinfold_device_relay_endpoints{peer="alice"} 1`) {
		t.Fatalf("relay endpoint not counted:\n%s", out)
	}
	next := state.Config.Clone()
	if err := next.SetRule("bob", "carol", false); err != nil {
		t.Fatal(err)
	}
	next.Peers = next.Peers[:2]
	if err := s.Update(next, nil); err != nil {
		t.Fatal(err)
	}
	if out := scrape(); strings.Contains(out, `peer="carol"`) {
		t.Fatalf("removed device still has status series:\n%s", out)
	}
}

// Scrapes take a family lock and then s.mu; updates must not take them in
// the opposite order.
func TestStatusMetricsScrapeDuringUpdates(t *testing.T) {
	state := threePeerState(t)
	s, err := NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	without := state.Config.Clone()
	if err := without.SetRule("bob", "carol", false); err != nil {
		t.Fatal(err)
	}
	without.Peers = without.Peers[:2]
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			var out strings.Builder
			_ = s.Metrics().WritePrometheus(&out)
		}
	}()
	for i := 0; i < 200; i++ {
		cfg := state.Config
		if i%2 == 0 {
			cfg = without
		}
		if err := s.Update(cfg, nil); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("scrape deadlocked with updates")
	}
}

// Removing a device frees its bucket, throttle series and status, and a
// configuration fetch racing with the removal does not bring them back
// (v0.6 review findings 2 and 3).
func TestRemovedDeviceStatusIsFreed(t *testing.T) {
	state := threePeerState(t)
	s, err := NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetRelayLimit(RelayLimit{Rate: 1 << 20, Burst: 1 << 20})
	s.mu.Lock()
	s.limitedEnd(nil, "carol", nil)
	s.mu.Unlock()
	next := state.Config.Clone()
	if err := next.SetRule("bob", "carol", false); err != nil {
		t.Fatal(err)
	}
	next.Peers = next.Peers[:2]
	if err := s.Update(next, nil); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.seen("carol", time.Now())
	_, bucket := s.buckets["carol"]
	_, seen := s.lastSeen["carol"]
	s.mu.Unlock()
	if bucket || seen {
		t.Fatalf("removed device kept bucket=%v lastSeen=%v", bucket, seen)
	}
	var out strings.Builder
	if err := s.Metrics().WritePrometheus(&out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), `peer="carol"`) {
		t.Fatalf("removed device still has series:\n%s", out.String())
	}
}
