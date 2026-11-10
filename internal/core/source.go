package core

import "net/netip"

// SourceKey is the accounting key for a remote host in per-source limits:
// the IPv4 address, or the /64 prefix for IPv6, because a single IPv6 host
// usually controls a whole /64 and could otherwise bypass the limits. Text
// that is not an IP address is returned unchanged.
func SourceKey(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, _ := addr.WithZone("").Prefix(64)
	return prefix.String()
}
