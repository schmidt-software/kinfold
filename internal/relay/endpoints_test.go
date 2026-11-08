package relay

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegisterFiltersAdvertisedAddresses(t *testing.T) {
	s, err := New(pairConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := httptest.NewRequest("GET", "/config", nil)
	r.RemoteAddr = "203.0.113.7:40000"
	r.Header.Set(directPortHeader, "51900")
	r.Header.Set(directAddrsHeader, "192.168.1.20, 8.8.8.8, 127.0.0.1, 10.77.0.1, fe80::1, fd12::5, 100.64.3.4")
	now := time.Now()
	s.mu.Lock()
	s.register("bob", r, now)
	got := s.endpointsFor("alice", s.config, now)["bob"]
	s.mu.Unlock()
	want := []string{"203.0.113.7:51900", "192.168.1.20:51900", "[fd12::5]:51900", "100.64.3.4:51900"}
	if len(got) != len(want) {
		t.Fatalf("endpoints %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoints %v, want %v", got, want)
		}
	}
	s.mu.Lock()
	expired := s.endpointsFor("alice", s.config, now.Add(endpointTTL))
	s.mu.Unlock()
	if len(expired) != 0 {
		t.Fatal("endpoint registration did not expire")
	}
}

func TestShutdownAnswerIsMarked(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, renewRequest(t, cfg, ""))
	if rec.Code != 503 || rec.Header().Get("X-Kinfold-Shutdown") != "1" {
		t.Fatalf("shutdown answer: %d %q", rec.Code, rec.Header().Get("X-Kinfold-Shutdown"))
	}
}
