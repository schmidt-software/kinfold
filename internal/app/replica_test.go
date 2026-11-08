package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

// runTestController serves dir on addr (standby when replica is set) until
// the returned stop function is called.
func runTestController(t *testing.T, dir, addr string, replica *core.ReplicaCredential) (stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	load := core.LoadState
	var rep *replicator
	if replica != nil {
		var err error
		rep, err = prepareStandby(ctx, *replica, dir, defaultStandbyMaxAge)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		load = core.LoadStandbyState
	}
	state, err := load(dir)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	handler, err := relay.NewForState(state)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	tlsCfg, err := relay.TLSConfig(state)
	if replica != nil {
		handler.SetStandby()
		rep.setStale = handler.SetStale
		tlsCfg, err = relay.TLSConfigWithServer(state, replica.ServerCert, replica.ServerKey)
	}
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	ln, err := listenController(ctx, addr, relay.DefaultListenerLimits)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if rep != nil {
		go rep.run(ctx)
	}
	done := make(chan error, 1)
	go func() {
		done <- serveController(ctx, newControllerServer(handler, tlsCfg, defaultServerTimeouts), ln, handler, func(ctx context.Context) {
			handler.Watch(ctx.Done(), state, func() (*core.State, error) { return load(dir) }, 50*time.Millisecond)
		}, time.Second)
	}()
	stopped := false
	stop = func() {
		if !stopped {
			stopped = true
			cancel()
			<-done
			if rep != nil {
				rep.Close()
			}
		}
	}
	t.Cleanup(stop)
	return stop
}

func TestStandbyServesWhenPrimaryIsDown(t *testing.T) {
	primaryDir := filepath.Join(t.TempDir(), "primary")
	if err := core.InitState(primaryDir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	credPath := filepath.Join(t.TempDir(), "alice.json")
	if err := Run([]string{"add-peer", "-data", primaryDir, "-id", "alice", "-ip", "10.77.0.1", "-out", credPath}); err != nil {
		t.Fatal(err)
	}
	primaryAddr, standbyAddr := freeLocal(t), freeLocal(t)
	_, standbyPort, _ := net.SplitHostPort(standbyAddr)
	replicaPath := filepath.Join(t.TempDir(), "standby.json")
	if err := Run([]string{"replica-add", "-data", primaryDir, "-id", "standby", "-address", "localhost:" + standbyPort, "-out", replicaPath}); err != nil {
		t.Fatal(err)
	}
	replica, err := readReplicaCredential(replicaPath)
	if err != nil {
		t.Fatal(err)
	}
	_, primaryPort, _ := net.SplitHostPort(primaryAddr)
	replica.Primary = "localhost:" + primaryPort
	stopPrimary := runTestController(t, primaryDir, primaryAddr, nil)
	standbyDir := filepath.Join(t.TempDir(), "standby")
	stopStandby := runTestController(t, standbyDir, standbyAddr, &replica)
	// A change on the primary reaches the standby within a few seconds.
	if err := Run([]string{"add-peer", "-data", primaryDir, "-id", "bob", "-ip", "10.77.0.2", "-out", filepath.Join(t.TempDir(), "bob.json")}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		if st, err := core.LoadState(standbyDir); err == nil {
			if _, ok := st.Config.Peer("bob"); ok {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("standby did not replicate a change on the primary")
		}
		time.Sleep(100 * time.Millisecond)
	}

	var cred core.Credential
	if err := core.ReadJSON(credPath, &cred); err != nil {
		t.Fatal(err)
	}
	cred.Server = "localhost:" + primaryPort
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := agent.NewConfigClient(cred)
	defer client.Close()
	if _, id, err := client.Fetch(ctx); err != nil || id != "alice" {
		t.Fatalf("fetch from primary: %q %v", id, err)
	}
	if got := client.Controllers(); len(got) != 2 || !strings.HasSuffix(got[1], ":"+standbyPort) {
		t.Fatalf("controller list %v", got)
	}

	// A primary without a valid state answers with an unmarked 503; the
	// device must use the standby instead of closing its tunnel.
	statePath := filepath.Join(primaryDir, "state.json")
	original, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for {
		_, _, err := client.Fetch(ctx)
		if err == nil && client.Current() == "localhost:"+standbyPort {
			break
		}
		if errorsIsRefused(err) || time.Now().After(deadline) {
			t.Fatalf("no failover from a primary without valid state: %v (current %s)", err, client.Current())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := os.WriteFile(statePath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	stopPrimary()
	cfg, id, err := client.Fetch(ctx)
	if err != nil || id != "alice" || len(cfg.Peers) != 1 {
		t.Fatalf("fetch after primary failure: %q %v", id, err)
	}
	if got := client.Current(); got != "localhost:"+standbyPort {
		t.Fatalf("client uses %s, want the standby", got)
	}
	if _, err := client.Renew(ctx, []byte("csr")); err == nil || errorsIsRefused(err) {
		t.Fatalf("standby renewal: %v (must fail, but not as a refusal)", err)
	}

	// Promotion: the stopped standby becomes the primary at its own address.
	stopStandby()
	if err := Run([]string{"replica-promote", "-data", standbyDir, "-standby", replicaPath}); err != nil {
		t.Fatal(err)
	}
	promoted, err := core.LoadState(standbyDir)
	if err != nil {
		t.Fatal(err)
	}
	if promoted.Server != "localhost:"+standbyPort || promoted.Replicas != nil {
		t.Fatalf("promoted state: server %s, replicas %v", promoted.Server, promoted.Replicas)
	}
	runTestController(t, standbyDir, standbyAddr, nil)
	if _, id, err := client.Fetch(ctx); err != nil || id != "alice" {
		t.Fatalf("fetch from the promoted controller: %q %v", id, err)
	}
	if got := client.Controllers(); len(got) != 1 || got[0] != "localhost:"+standbyPort {
		t.Fatalf("controller list after promotion %v", got)
	}
}

func freeLocal(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func errorsIsRefused(err error) bool {
	return err != nil && strings.Contains(err.Error(), agent.ErrRefused.Error())
}

func TestStandbyStopsServingStaleState(t *testing.T) {
	primaryDir := filepath.Join(t.TempDir(), "primary")
	if err := core.InitState(primaryDir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	primaryAddr := freeLocal(t)
	_, primaryPort, _ := net.SplitHostPort(primaryAddr)
	replicaPath := filepath.Join(t.TempDir(), "standby.json")
	if err := Run([]string{"replica-add", "-data", primaryDir, "-id", "standby", "-address", "standby.example.com:8443", "-out", replicaPath}); err != nil {
		t.Fatal(err)
	}
	replica, err := readReplicaCredential(replicaPath)
	if err != nil {
		t.Fatal(err)
	}
	replica.Primary = "localhost:" + primaryPort
	standbyDir := filepath.Join(t.TempDir(), "standby")
	ctx := context.Background()

	// No stored state and no primary: the standby cannot start.
	if _, err := prepareStandby(ctx, replica, standbyDir, time.Hour); err == nil {
		t.Fatal("standby started without any state")
	}
	stopPrimary := runTestController(t, primaryDir, primaryAddr, nil)
	rep, err := prepareStandby(ctx, replica, standbyDir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer rep.Close()
	if _, err := prepareStandby(ctx, replica, standbyDir, time.Hour); err == nil {
		t.Fatal("second standby started on a data directory in use")
	}
	if err := Run([]string{"replica-promote", "-data", standbyDir, "-standby", replicaPath}); err == nil {
		t.Fatal("promoted a running standby")
	}
	var stale []bool
	rep.setStale = func(v bool) { stale = append(stale, v) }

	// Network errors are tolerated up to the maximum age.
	now := time.Now()
	rep.failed(unreachable{net.ErrClosed}, now.Add(30*time.Minute))
	if len(stale) != 0 {
		t.Fatalf("stale after 30 minutes: %v", stale)
	}
	rep.failed(unreachable{net.ErrClosed}, now.Add(61*time.Minute))
	if len(stale) != 1 || !stale[0] {
		t.Fatalf("not stale after the maximum age: %v", stale)
	}
	if _, err := rep.pull(ctx); err != nil {
		t.Fatal(err)
	}
	if len(stale) != 2 || stale[1] {
		t.Fatalf("successful replication did not resume serving: %v", stale)
	}

	// A removed standby stops at once and does not start from its old state.
	if err := Run([]string{"replica-remove", "-data", primaryDir, "-id", "standby"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := rep.pull(ctx)
		var answer primaryAnswer
		if errors.As(err, &answer) && answer.status == http.StatusForbidden {
			rep.failed(err, time.Now())
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("primary did not refuse the removed standby: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(stale) != 3 || !stale[2] {
		t.Fatalf("removed standby keeps serving: %v", stale)
	}
	rep.Close()
	if _, err := prepareStandby(ctx, replica, standbyDir, time.Hour); err == nil {
		t.Fatal("removed standby started from its stored state")
	}

	// With the primary down, a recent stored state is used, an old one not.
	stopPrimary()
	again, err := prepareStandby(ctx, replica, standbyDir, time.Hour)
	if err != nil {
		t.Fatalf("standby did not start from a recent state: %v", err)
	}
	again.Close()
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(standbyDir, "state.json"), old, old); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareStandby(ctx, replica, standbyDir, time.Hour); err == nil {
		t.Fatal("standby started from a state older than the maximum age")
	}
}
