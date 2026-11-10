package agent

import (
	"context"
	"encoding/binary"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

func TestServicePolicyBetweenAgents(t *testing.T) {
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
	state.Config.Network6 = "fd77::/64"
	state.Config.Peers[0].IPv6, state.Config.Peers[1].IPv6 = "fd77::1", "fd77::2"
	if err := state.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	state.Config.Policy.Services = &core.ServicePolicy{}
	if err := state.Config.SetServiceRule("alice", "bob", "udp", 53, true); err != nil {
		t.Fatal(err)
	}
	handler, err := relay.NewForState(state)
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Close()
	tlsCfg, err := relay.TLSConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = tlsCfg
	server.StartTLS()
	defer server.Close()
	alice.Server, bob.Server = server.Listener.Addr().String(), server.Listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	a, b := newFakeTun(), newFakeTun()
	done := make(chan error, 2)
	go func() { done <- RunWithUpdates(ctx, alice, state.Config, "alice", a, nil) }()
	go func() { done <- RunWithUpdates(ctx, bob, state.Config, "bob", b, nil) }()
	defer func() {
		cancel()
		for i := 0; i < 2; i++ {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("agent stopped: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("agent did not stop")
			}
		}
	}()
	packet := func(v6 bool, port uint16) []byte {
		p := serviceTestPacket(v6, 17, port)
		if v6 {
			src, dst := netip.MustParseAddr("fd77::1").As16(), netip.MustParseAddr("fd77::2").As16()
			copy(p[8:24], src[:])
			copy(p[24:40], dst[:])
		} else {
			copy(p[12:16], []byte{10, 77, 0, 1})
			copy(p[16:20], []byte{10, 77, 0, 2})
		}
		return p
	}
	for _, v6 := range []bool{false, true} {
		ticker := time.NewTicker(50 * time.Millisecond)
		timeout := time.NewTimer(8 * time.Second)
		received := false
		for !received {
			select {
			case <-ticker.C:
				a.in <- packet(v6, 22)
				a.in <- packet(v6, 53)
			case got := <-b.out:
				offset := 20
				if got[0]>>4 == 6 {
					offset = 40
				}
				if binary.BigEndian.Uint16(got[offset+2:]) != 53 {
					t.Fatal("blocked service delivered")
				}
				received = got[0]>>4 == 4 && !v6 || got[0]>>4 == 6 && v6
			case <-timeout.C:
				t.Fatal("allowed service not delivered")
			}
		}
		ticker.Stop()
		timeout.Stop()
	}
}
