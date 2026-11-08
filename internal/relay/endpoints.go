package relay

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

// Direct-path endpoint registry (D-026). Devices that accept direct sessions
// report their listening port and local addresses on every configuration
// fetch; the controller adds the address it observed and keeps the result in
// memory only, for endpointTTL.

const (
	endpointTTL        = 30 * time.Second
	maxAdvertisedAddrs = 4
	directPortHeader   = "X-Kinfold-Direct-Port"
	directAddrsHeader  = "X-Kinfold-Direct-Addrs"
)

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

type registration struct {
	addrs   []string
	expires time.Time
}

// usableEndpointIP filters addresses a peer could plausibly reach: no
// loopback, unspecified, multicast or link-local addresses, and nothing
// inside the overlay networks themselves.
func usableEndpointIP(ip netip.Addr, cfg core.Config) bool {
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, network := range []string{cfg.Network, cfg.Network6} {
		if prefix, err := netip.ParsePrefix(network); err == nil && prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// register records the direct endpoints a device reports with a request.
// Caller holds s.mu.
func (s *Server) register(id string, r *http.Request, now time.Time) {
	port, err := strconv.Atoi(r.Header.Get(directPortHeader))
	if err != nil || port < 1 || port > 65535 {
		delete(s.endpoints, id)
		return
	}
	seen := map[netip.Addr]bool{}
	var addrs []string
	add := func(ip netip.Addr) {
		ip = ip.Unmap()
		if len(addrs) < maxAdvertisedAddrs && !seen[ip] && usableEndpointIP(ip, s.config) {
			seen[ip] = true
			addrs = append(addrs, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			add(ip) // observed address first: works for public and NAT-forwarded setups
		}
	}
	// Advertised addresses serve the LAN case, so only private ones are
	// taken; a public address must be the one the controller observed. This
	// limits how far a device can make its peers dial arbitrary hosts
	// (v0.4 review finding 8).
	for _, field := range strings.Split(r.Header.Get(directAddrsHeader), ",") {
		if ip, err := netip.ParseAddr(strings.TrimSpace(field)); err == nil && (ip.Unmap().IsPrivate() || cgnat.Contains(ip.Unmap())) {
			add(ip)
		}
	}
	if len(addrs) == 0 {
		delete(s.endpoints, id)
		return
	}
	if s.endpoints == nil {
		s.endpoints = make(map[string]registration)
	}
	s.endpoints[id] = registration{addrs: addrs, expires: now.Add(endpointTTL)}
}

// endpointsFor returns the current direct endpoints of the peers in view.
// Caller holds s.mu.
func (s *Server) endpointsFor(id string, view core.Config, now time.Time) map[string][]string {
	var out map[string][]string
	for _, p := range view.Peers {
		reg, ok := s.endpoints[p.ID]
		if p.ID == id || !ok {
			continue
		}
		if !now.Before(reg.expires) {
			delete(s.endpoints, p.ID)
			continue
		}
		if out == nil {
			out = make(map[string][]string)
		}
		out[p.ID] = append([]string(nil), reg.addrs...)
	}
	return out
}
