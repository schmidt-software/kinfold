package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"my-zerotier/internal/core"
	"my-zerotier/internal/relay"
)

func TestFetchConfigRejectsOversizeResponseHeaders(t *testing.T) {
	state, err := core.NewState("127.0.0.1:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := state.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", maxControllerResponseHeaderBytes+1))
		_, _ = w.Write([]byte(`{}`))
	}))
	server.TLS, err = relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	server.StartTLS()
	defer server.Close()
	cred.Server = server.Listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, _, err := FetchConfig(ctx, cred); err == nil || !strings.Contains(err.Error(), "response headers exceeded") {
		t.Fatalf("expected response-header limit error, got %v", err)
	}
}
