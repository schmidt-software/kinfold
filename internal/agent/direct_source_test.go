package agent

import (
	"net"
	"testing"
)

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// Callers from one IPv6 /64 share the handshake limit of the direct
// listener, as they do on the controller (#150).
func TestRemoteSourceGroupsIPv6By64(t *testing.T) {
	key := func(addr string) string {
		tcp, err := net.ResolveTCPAddr("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		return remoteSource(addrConn{remote: tcp})
	}
	if a, b := key("[2001:db8:1:2::1]:4000"), key("[2001:db8:1:2:ffff::9]:5000"); a != b {
		t.Fatalf("same /64 counted as two sources: %q and %q", a, b)
	}
	if a, b := key("[2001:db8:1:2::1]:4000"), key("[2001:db8:1:3::1]:4000"); a == b {
		t.Fatalf("different /64 networks share the key %q", a)
	}
	if a, b := key("192.0.2.7:4000"), key("192.0.2.8:4000"); a == b {
		t.Fatalf("different IPv4 addresses share the key %q", a)
	}
}
