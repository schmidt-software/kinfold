package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// ForPeer returns the part of the configuration a device needs: itself, the
// devices it has a rule with in either direction, and those rules. Other
// devices and the rules between them are not disclosed (review R-10). The
// result validates on its own and has its own Revision.
func (c Config) ForPeer(id string) Config {
	view := Config{Network: c.Network, Network6: c.Network6}
	related := map[string]bool{id: true}
	if c.Policy != nil {
		policy := &Policy{Allowed: []Rule{}}
		for _, r := range c.Policy.Allowed {
			if r.From == id || r.To == id {
				policy.Allowed = append(policy.Allowed, r)
				related[r.From], related[r.To] = true, true
			}
		}
		if c.Policy.Services != nil {
			services := &ServicePolicy{Allowed: []ServiceRule{}}
			for _, r := range c.Policy.Services.Allowed {
				if r.From == id || r.To == id {
					services.Allowed = append(services.Allowed, r)
				}
			}
			policy.Services = services
		}
		view.Policy = policy
	}
	view.Peers = []Peer{}
	for _, p := range c.Peers {
		if related[p.ID] {
			p.Cert = append([]byte(nil), p.Cert...)
			view.Peers = append(view.Peers, p)
		}
	}
	return view
}

// PairSignature summarises everything that authorizes traffic between two
// devices: both certificates and addresses, the IPv6 network, the directional
// rules and the service rules between them. A configuration change that
// leaves it unchanged does not need to interrupt the pair's relay session.
// The empty string means the pair is not authorized.
func (c Config) PairSignature(a, b string) string {
	pa, okA := c.Peer(a)
	pb, okB := c.Peer(b)
	if !okA || !okB || a == b || (!c.Permits(a, b) && !c.Permits(b, a)) {
		return ""
	}
	if a > b {
		a, b, pa, pb = b, a, pb, pa
	}
	var services []ServiceRule
	if c.Policy != nil && c.Policy.Services != nil {
		for _, r := range c.Policy.Services.Allowed {
			if (r.From == a && r.To == b) || (r.From == b && r.To == a) {
				services = append(services, r)
			}
		}
		sort.Slice(services, func(i, j int) bool {
			x, y := services[i], services[j]
			if x.From != y.From {
				return x.From < y.From
			}
			if x.Protocol != y.Protocol {
				return x.Protocol < y.Protocol
			}
			return x.Port < y.Port
		})
	}
	summary := struct {
		A, B            Peer
		Network6        string
		AToB, BToA      bool
		ServicesEnabled bool
		Services        []ServiceRule
	}{pa, pb, c.Network6, c.Permits(a, b), c.Permits(b, a), c.Policy != nil && c.Policy.Services != nil, services}
	data, _ := json.Marshal(summary)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
