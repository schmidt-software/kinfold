package agent

import (
	"context"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestRotationInvalidatesSessionAndOldCredential(t *testing.T) {
	s, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.AddPeer("bob", "10.77.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	handler, err := relay.New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS, err = relay.TLSConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	defer handler.Close()
	old.Server, bob.Server = server.Listener.Addr().String(), server.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	alicePeer, _ := s.Config.Peer("alice")
	bobPeer, _ := s.Config.Peer("bob")
	go func() { c, e := Connect(ctx, old, s.Config, "alice", bobPeer); results <- result{c, e} }()
	go func() { c, e := Connect(ctx, bob, s.Config, "bob", alicePeer); results <- result{c, e} }()
	first, second := <-results, <-results
	if first.conn != nil {
		defer first.conn.Close()
	}
	if second.conn != nil {
		defer second.conn.Close()
	}
	if first.err != nil || second.err != nil {
		t.Fatalf("connect: %v / %v", first.err, second.err)
	}
	key, request, err := core.NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := s.RotatePeerEnrollment("alice", request)
	if err != nil {
		t.Fatal(err)
	}
	newCred, err := core.CompleteEnrollment(old.Server, s.CA, cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := handler.Update(s.Config, nil); err != nil {
		t.Fatal(err)
	}
	if err := first.conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := first.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("old session survived rotation")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("old session was not actively invalidated")
	}
	if _, _, err := FetchConfig(ctx, old); err == nil {
		t.Fatal("old certificate remains authorized")
	}
	if _, id, err := FetchConfig(ctx, newCred); err != nil || id != "alice" {
		t.Fatalf("new identity not authorized: %q, %v", id, err)
	}
}
