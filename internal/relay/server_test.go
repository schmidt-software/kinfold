package relay

import (
	"errors"
	"net"
	"testing"
	"time"

	"my-zerotier/internal/core"
)

func TestUpdateInvalidatesAndFailsClosed(t *testing.T) {
	cfg := core.Config{Network: "10.77.0.0/24", Policy: &core.Policy{}}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	left, right := net.Pipe()
	defer right.Close()
	p := &pending{conn: left, match: make(chan net.Conn, 1), cancel: make(chan struct{})}
	s.waiting["a"] = p
	s.active[left] = endpoint{from: "a", to: "b"}
	if err := s.Update(cfg, nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.cancel:
		t.Fatal("unchanged configuration disconnected session")
	default:
	}
	if err := s.Update(core.Config{}, errors.New("unreadable state")); err == nil {
		t.Fatal("ignored state error")
	}
	if s.available || len(s.waiting) != 0 || len(s.active) != 0 {
		t.Fatal("relay remained available")
	}
	select {
	case <-p.cancel:
	default:
		t.Fatal("pending connection was not cancelled")
	}
	right.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection was not closed")
	}
	if err := s.Update(cfg, nil); err != nil || !s.available {
		t.Fatalf("configuration did not recover: %v", err)
	}
	s.Close()
	if err := s.Update(cfg, nil); err == nil || s.available {
		t.Fatal("closed relay was reopened")
	}
}
