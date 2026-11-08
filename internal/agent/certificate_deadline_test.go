package agent

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestCertificateDeadlineClosesIdleRead(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	now := time.Now()
	if _, _, err := setCertificateDeadline(left, []*x509.Certificate{
		{NotAfter: now.Add(time.Hour)}, {NotAfter: now.Add(100 * time.Millisecond)},
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { _, err := left.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("expected deadline error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection outlived certificate")
	}
}

func TestPeerSessionExpiresWithLocalCertificate(t *testing.T) {
	state, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	alice, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := state.AddPeer("bob", "10.77.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	alicePair, err := tls.X509KeyPair(alice.Cert, alice.Key)
	if err != nil {
		t.Fatal(err)
	}
	template, err := x509.ParseCertificate(alicePair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(state.CA, state.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template.NotAfter = time.Now().Add(4 * time.Second)
	shortCert, err := x509.CreateCertificate(rand.Reader, template, ca, template.PublicKey, caPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	state.Config.Peers[0].Cert = shortCert
	alice.Cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: shortCert})
	handler, err := relay.NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS, err = relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	defer handler.Close()
	alice.Server, bob.Server = server.Listener.Addr().String(), server.Listener.Addr().String()
	peerAlice, _ := state.Config.Peer("alice")
	peerBob, _ := state.Config.Peer("bob")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	results := make(chan result, 2)
	go func() { c, e := Connect(ctx, alice, state.Config, "alice", peerBob); results <- result{c, e} }()
	go func() { c, e := Connect(ctx, bob, state.Config, "bob", peerAlice); results <- result{c, e} }()
	first, second := <-results, <-results
	if first.err != nil || second.err != nil {
		if first.conn != nil {
			first.conn.Close()
		}
		if second.conn != nil {
			second.conn.Close()
		}
		t.Fatalf("connect: %v / %v", first.err, second.err)
	}
	defer first.conn.Close()
	defer second.conn.Close()
	if _, err := second.conn.Write([]byte("buffered plaintext")); err != nil {
		t.Fatal(err)
	}
	var firstByte [1]byte
	if _, err := first.conn.Read(firstByte[:]); err != nil || firstByte[0] != 'b' {
		t.Fatalf("read before expiry: %q, %v", firstByte, err)
	}
	parsed, err := x509.ParseCertificate(shortCert)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(parsed.NotAfter) + 50*time.Millisecond)
	var rest [32]byte
	n, err := first.conn.Read(rest[:])
	var netErr net.Error
	if n != 0 || !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("buffered plaintext after expiry: %d bytes, %v", n, err)
	}
}

func TestCertificateDeadlineRejectsInvalidInputs(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	for _, certs := range [][]*x509.Certificate{
		nil, {nil}, {{NotAfter: time.Now().Add(-time.Second)}},
	} {
		if _, _, err := setCertificateDeadline(left, certs); err == nil {
			t.Fatal("accepted missing or expired certificate")
		}
	}
	left.Close()
	if _, _, err := setCertificateDeadline(left, []*x509.Certificate{{NotAfter: time.Now().Add(time.Hour)}}); err == nil {
		t.Fatal("ignored deadline-setting error")
	}
}
