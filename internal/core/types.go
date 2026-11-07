package core

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
)

type Peer struct {
	ID   string `json:"id"`
	IP   string `json:"ip"`
	IPv6 string `json:"ipv6,omitempty"`
	Cert []byte `json:"cert"`
}

type Config struct {
	Network  string  `json:"network"`
	Network6 string  `json:"network6,omitempty"`
	Peers    []Peer  `json:"peers"`
	Policy   *Policy `json:"policy,omitempty"`
}

type Rule struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type Policy struct {
	Allowed  []Rule         `json:"allowed"`
	Services *ServicePolicy `json:"services,omitempty"`
}

type ServiceRule struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port,omitempty"`
}

type ServicePolicy struct {
	Allowed []ServiceRule `json:"allowed"`
}

const MaxServiceRules = 4096

type Credential struct {
	Server string `json:"server"`
	CA     []byte `json:"ca"`
	Cert   []byte `json:"cert"`
	Key    []byte `json:"key"`
}

var validID = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}$`)

func ValidID(id string) bool { return validID.MatchString(id) }

func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func ParseCert(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %w", err)
	}
	return cert, nil
}

func (c Config) Validate() error {
	if len(c.Peers) > 32 {
		return errors.New("at most 32 peers are supported in the experimental full-mesh implementation")
	}
	prefix, err := netip.ParsePrefix(c.Network)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() || prefix.Bits() > 30 {
		return errors.New("network must be a canonical IPv4 prefix no smaller than /30")
	}
	var prefix6 netip.Prefix
	if c.Network6 != "" {
		prefix6, err = netip.ParsePrefix(c.Network6)
		ula := netip.MustParsePrefix("fd00::/8")
		if err != nil || !prefix6.Addr().Is6() || prefix6.Addr().Is4In6() || prefix6.Bits() != 64 || prefix6 != prefix6.Masked() || !ula.Contains(prefix6.Addr()) {
			return errors.New("IPv6 network must be a canonical fd00::/8 ULA /64 prefix")
		}
	}
	ids, ips, certs, keys := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	ips6 := map[netip.Addr]bool{}
	for _, p := range c.Peers {
		ip, err := netip.ParseAddr(p.IP)
		if !ValidID(p.ID) || err != nil || !ip.Is4() || !prefix.Contains(ip) {
			return fmt.Errorf("invalid peer %q or IP %q", p.ID, p.IP)
		}
		// Network and broadcast addresses are not usable by hosts.
		b := prefix.Addr().As4()
		base := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		a := ip.As4()
		n := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		if n == base || n == base|(^uint32(0)>>prefix.Bits()) {
			return fmt.Errorf("peer %s uses a network or broadcast address", p.ID)
		}
		if p.IPv6 != "" {
			ip6, err := netip.ParseAddr(p.IPv6)
			if err != nil || !prefix6.IsValid() || !ip6.Is6() || ip6.Is4In6() || ip6.Zone() != "" || !prefix6.Contains(ip6) || ip6 == prefix6.Addr() {
				return fmt.Errorf("invalid IPv6 address %q for peer %s", p.IPv6, p.ID)
			}
			if ips6[ip6] {
				return fmt.Errorf("duplicate IPv6 address %s", ip6)
			}
			ips6[ip6] = true
		}
		cert, err := ParseCert(p.Cert)
		if err != nil {
			return fmt.Errorf("peer %s: %w", p.ID, err)
		}
		fp := Fingerprint(cert)
		key, err := peerKeyFingerprint(cert.PublicKey)
		if err != nil {
			return fmt.Errorf("peer %s: %w", p.ID, err)
		}
		if ids[p.ID] || ips[p.IP] || certs[fp] || keys[key] {
			return fmt.Errorf("duplicate peer ID, IP, certificate or public key: %s", p.ID)
		}
		ids[p.ID], ips[p.IP], certs[fp] = true, true, true
		keys[key] = true
	}
	if c.Policy != nil {
		seen := map[Rule]bool{}
		for _, rule := range c.Policy.Allowed {
			if !ids[rule.From] || !ids[rule.To] || rule.From == rule.To || seen[rule] {
				return fmt.Errorf("invalid or duplicate policy rule %s -> %s", rule.From, rule.To)
			}
			seen[rule] = true
		}
		if c.Policy.Services != nil {
			if len(c.Policy.Services.Allowed) > MaxServiceRules {
				return fmt.Errorf("at most %d service rules are supported", MaxServiceRules)
			}
			services := map[ServiceRule]bool{}
			for _, rule := range c.Policy.Services.Allowed {
				if !ids[rule.From] || !ids[rule.To] || rule.From == rule.To ||
					!validService(rule.Protocol, rule.Port) || services[rule] || !seen[Rule{From: rule.From, To: rule.To}] {
					return fmt.Errorf("invalid or duplicate service rule %s -> %s %s/%d", rule.From, rule.To, rule.Protocol, rule.Port)
				}
				services[rule] = true
			}
		}
	}
	return nil
}

// Permits reports whether the static, directional member rule allows a packet.
// A configuration without a policy (pre-policy state format) denies all
// traffic; missing rules never mean allow-all (review C-01).
func (c Config) Permits(from, to string) bool {
	if c.Policy == nil {
		return false
	}
	for _, rule := range c.Policy.Allowed {
		if rule.From == from && rule.To == to {
			return true
		}
	}
	return false
}

func (c *Config) SetRule(from, to string, allow bool) error {
	if c.Policy == nil {
		return errors.New("configuration has no policy: run policy-enable first")
	}
	if _, ok := c.Peer(from); !ok {
		return fmt.Errorf("unknown peer %q", from)
	}
	if _, ok := c.Peer(to); !ok || from == to {
		return fmt.Errorf("invalid destination peer %q", to)
	}
	rule := Rule{From: from, To: to}
	index := -1
	for i, r := range c.Policy.Allowed {
		if r == rule {
			index = i
			break
		}
	}
	if allow && index < 0 {
		c.Policy.Allowed = append(c.Policy.Allowed, rule)
	} else if !allow && index >= 0 {
		c.Policy.Allowed = append(c.Policy.Allowed[:index], c.Policy.Allowed[index+1:]...)
		if c.Policy.Services != nil {
			services := c.Policy.Services.Allowed[:0]
			for _, s := range c.Policy.Services.Allowed {
				if s.From != from || s.To != to {
					services = append(services, s)
				}
			}
			c.Policy.Services.Allowed = services
		}
	}
	return nil
}

func validService(protocol string, port uint16) bool {
	switch protocol {
	case "tcp", "udp":
		return port != 0
	case "icmp", "icmp6":
		return port == 0
	}
	return false
}

func (c *Config) SetServiceRule(from, to, protocol string, port uint16, allow bool) error {
	if c.Policy == nil || c.Policy.Services == nil {
		return errors.New("service policy is not enabled")
	}
	if !c.Permits(from, to) || !validService(protocol, port) {
		return errors.New("service requires an existing directional allow and a valid protocol and port")
	}
	rule := ServiceRule{From: from, To: to, Protocol: protocol, Port: port}
	index := -1
	for i, existing := range c.Policy.Services.Allowed {
		if existing == rule {
			index = i
			break
		}
	}
	if allow && index < 0 {
		if len(c.Policy.Services.Allowed) >= MaxServiceRules {
			return fmt.Errorf("at most %d service rules are supported", MaxServiceRules)
		}
		c.Policy.Services.Allowed = append(c.Policy.Services.Allowed, rule)
	} else if !allow && index >= 0 {
		c.Policy.Services.Allowed = append(c.Policy.Services.Allowed[:index], c.Policy.Services.Allowed[index+1:]...)
	}
	return nil
}

func (c Config) Peer(id string) (Peer, bool) {
	for _, p := range c.Peers {
		if p.ID == id {
			return p, true
		}
	}
	return Peer{}, false
}

func (c Config) Revision() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func ReadJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := DecodeJSON(f, value); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// WriteJSON uses a same-directory atomic rename and synchronizes its directory.
func WriteJSON(path string, value any) error {
	return writeJSON(path, value, SyncParentDir)
}

func writeJSON(path string, value any, syncParent func(string) error) error {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	if err := syncParent(path); err != nil {
		return fmt.Errorf("%s was replaced but directory synchronization failed; durability is uncertain: %w", path, err)
	}
	return nil
}

// SyncParentDir persists a file's directory entry on supported filesystems.
func SyncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open parent directory: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if err := errors.Join(syncErr, closeErr); err != nil {
		return fmt.Errorf("sync or close parent directory: %w", err)
	}
	return nil
}

// Clone returns a deep copy, so a holder of the copy is not affected by
// later in-place changes to the original's slices or policy.
func (c Config) Clone() Config {
	out := c
	out.Peers = make([]Peer, len(c.Peers))
	for i, p := range c.Peers {
		p.Cert = append([]byte(nil), p.Cert...)
		out.Peers[i] = p
	}
	if c.Peers == nil {
		out.Peers = nil
	}
	if c.Policy != nil {
		policy := *c.Policy
		policy.Allowed = append([]Rule(nil), c.Policy.Allowed...)
		if c.Policy.Allowed != nil && policy.Allowed == nil {
			policy.Allowed = []Rule{}
		}
		if c.Policy.Services != nil {
			services := *c.Policy.Services
			services.Allowed = append([]ServiceRule(nil), c.Policy.Services.Allowed...)
			if c.Policy.Services.Allowed != nil && services.Allowed == nil {
				services.Allowed = []ServiceRule{}
			}
			policy.Services = &services
		}
		out.Policy = &policy
	}
	return out
}
