package relay

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

// A plain tls.Conn.Close writes close_notify and waits up to 5 s when the
// peer does not read (net.Pipe is unbuffered, so any write blocks until
// read). forceClose must return immediately.
func TestForceCloseDoesNotWaitForUnreadCloseNotify(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(state.ServerCert, state.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	server := tls.Server(serverSide, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13})
	client := tls.Client(clientSide, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-handshake; err != nil {
		t.Fatal(err)
	}
	// The client no longer reads from here on.
	start := time.Now()
	forceClose(server)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("forceClose blocked for %v", elapsed)
	}
}
