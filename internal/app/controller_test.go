package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"my-zerotier/internal/core"
	"my-zerotier/internal/relay"
)

func TestControllerWaitsForShutdownAndReportsTimeout(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		name := "graceful"
		if timeout {
			name = "timeout"
		}
		t.Run(name, func(t *testing.T) {
			state, err := core.NewState("localhost:8443", "10.77.0.0/24")
			if err != nil {
				t.Fatal(err)
			}
			handler, err := relay.New(state.Config)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := tls.X509KeyPair(state.ServerCert, state.ServerKey)
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(state.CA) {
				t.Fatal("invalid CA")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			entered, release, watched := make(chan struct{}), make(chan struct{}), make(chan struct{})
			server := &http.Server{
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					close(entered)
					<-release
					w.WriteHeader(http.StatusNoContent)
				}),
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			grace := 3 * time.Second
			if timeout {
				grace = 100 * time.Millisecond
			}
			done := make(chan error, 1)
			go func() {
				done <- serveController(ctx, server, listener, handler, func(ctx context.Context) {
					<-ctx.Done()
					close(watched)
				}, grace)
			}()
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			requestDone := make(chan error, 1)
			go func() {
				resp, err := client.Get("https://" + listener.Addr().String())
				if err == nil {
					resp.Body.Close()
				}
				requestDone <- err
			}()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				close(release)
				t.Fatal("request did not start")
			}
			cancel()
			<-watched
			if !timeout {
				select {
				case err := <-done:
					close(release)
					t.Fatalf("returned before active request ended: %v", err)
				default:
				}
				close(release)
			}
			select {
			case err := <-done:
				if timeout && !errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("shutdown timeout not reported: %v", err)
				}
				if !timeout && err != nil {
					t.Errorf("graceful shutdown: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("controller failed to stop")
			}
			if timeout {
				close(release)
			}
			select {
			case err := <-requestDone:
				if !timeout && err != nil {
					t.Errorf("graceful request: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("request did not stop")
			}
		})
	}
}

func TestControllerStartupFailureClosesListenerAndWatcher(t *testing.T) {
	state, err := core.NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := relay.New(state.Config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	watched := make(chan struct{})
	err = serveController(context.Background(), &http.Server{}, listener, handler, func(ctx context.Context) {
		<-ctx.Done()
		close(watched)
	}, time.Second)
	if err == nil {
		t.Fatal("missing TLS certificate accepted")
	}
	select {
	case <-watched:
	default:
		t.Fatal("watcher not stopped")
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second); err == nil {
		conn.Close()
		t.Fatal("listener still open")
	}
}
