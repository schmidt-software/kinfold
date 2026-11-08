package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestValidateRestrictsIPv4NetworkToPrivateSpace(t *testing.T) {
	for _, network := range []string{"10.0.0.0/8", "10.77.0.0/24", "172.16.5.0/24", "172.31.255.0/30", "192.168.1.0/24", "100.64.0.0/16"} {
		if err := (Config{Network: network}).Validate(); err != nil {
			t.Errorf("rejected private network %s: %v", network, err)
		}
	}
	for _, network := range []string{"0.0.0.0/0", "10.0.0.0/7", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "8.8.8.0/24", "172.32.0.0/24", "100.128.0.0/16"} {
		if err := (Config{Network: network}).Validate(); err == nil {
			t.Errorf("accepted non-private network %s", network)
		}
	}
}

func TestValidateRequiresCanonicalIPv6(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		network, address string
		ok               bool
	}{
		{"fd77::/64", "fd77::1", true},
		{"FD77::/64", "fd77::1", false},
		{"fd77:0::/64", "fd77::1", false},
		{"fd77::/64", "FD77::1", false},
		{"fd77::/64", "fd77:0:0:0:0:0:0:1", false},
	} {
		cfg := s.Config
		cfg.Peers = append([]Peer(nil), s.Config.Peers...)
		cfg.Network6, cfg.Peers[0].IPv6 = tc.network, tc.address
		if err := cfg.Validate(); (err == nil) != tc.ok {
			t.Errorf("network %s address %s: err=%v, want ok=%v", tc.network, tc.address, err, tc.ok)
		}
	}
}

// signWithCA issues a certificate from the state's CA for an arbitrary template.
func signWithCA(t *testing.T, s *State, template *x509.Certificate, pub any) []byte {
	t.Helper()
	pair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	template.SerialNumber = big.NewInt(time.Now().UnixNano())
	template.NotBefore = time.Now().Add(-time.Minute)
	if template.NotAfter.IsZero() {
		template.NotAfter = time.Now().Add(time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestValidatePKIRejectsMalformedDeviceCertificates(t *testing.T) {
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := map[string]struct {
		template *x509.Certificate
		key      any
		want     string
	}{
		"CA":            {&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: both}, pub, "must not be a CA"},
		"common name":   {&x509.Certificate{Subject: pkix.Name{CommonName: "mallory"}, ExtKeyUsage: both}, pub, "common name"},
		"client only":   {&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, pub, "authentication usages"},
		"extra usage":   {&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, ExtKeyUsage: append(both, x509.ExtKeyUsageCodeSigning)}, pub, "authentication usages"},
		"non-Ed25519":   {&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, ExtKeyUsage: both}, &ecKey.PublicKey, "Ed25519"},
		"valid control": {&x509.Certificate{Subject: pkix.Name{CommonName: "alice"}, ExtKeyUsage: both}, pub, ""},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s, err := NewState("localhost:8443", "10.77.0.0/24")
			if err != nil {
				t.Fatal(err)
			}
			s.Config.Peers = []Peer{{ID: "alice", IP: "10.77.0.1", Cert: signWithCA(t, s, tc.template, tc.key)}}
			err = s.validatePKI(false)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("valid certificate rejected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestNewCertificatesCarryConstraints(t *testing.T) {
	s, err := NewState("vpn.example.com:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	parse := func(pemBytes []byte) *x509.Certificate {
		t.Helper()
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			t.Fatal("no PEM block")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	ca, server, peer := parse(s.CA), parse(s.ServerCert), parse(cred.Cert)
	if !ca.IsCA || !ca.MaxPathLenZero || ca.MaxPathLen != 0 {
		t.Fatalf("CA path length not limited: maxPathLen=%d zero=%v", ca.MaxPathLen, ca.MaxPathLenZero)
	}
	for name, cert := range map[string]*x509.Certificate{"server": server, "peer": peer} {
		if !cert.BasicConstraintsValid || cert.IsCA {
			t.Errorf("%s certificate lacks explicit leaf basic constraints", name)
		}
	}
}

func TestPeerIDMustDifferFromControllerHost(t *testing.T) {
	s, err := NewState("Gateway:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("gateway", "10.77.0.1"); err == nil {
		t.Fatal("peer ID equal to the controller host name was accepted")
	}
}

func TestCertificateWarnings(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	both := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	s.Config.Peers = []Peer{
		{ID: "soon", IP: "10.77.0.1", Cert: signWithCA(t, s, &x509.Certificate{Subject: pkix.Name{CommonName: "soon"}, ExtKeyUsage: both, NotAfter: time.Now().Add(24 * time.Hour)}, pub)},
	}
	warnings := s.CertificateWarnings(time.Now(), 30*24*time.Hour)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "device soon certificate expires") {
		t.Fatalf("warnings = %v", warnings)
	}
	if got := s.CertificateWarnings(time.Now().AddDate(20, 0, 0), time.Hour); len(got) != 3 {
		t.Fatalf("expected CA, controller and device to be reported as expired, got %v", got)
	}
}

func TestRevisionIsStableAcrossJSONRoundTrip(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Config.SetRule("alice", "bob", true); err != nil {
		t.Fatal(err)
	}
	first, err := s.Config.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := s.Config.Revision(); again != first {
		t.Fatal("revision is not deterministic")
	}
	data, err := json.Marshal(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := DecodeJSON(strings.NewReader(string(data)), &decoded); err != nil {
		t.Fatal(err)
	}
	if got, _ := decoded.Revision(); got != first {
		t.Fatal("controller and client would compute different revisions for the same configuration")
	}
	if err := s.Config.SetRule("bob", "alice", true); err != nil {
		t.Fatal(err)
	}
	if changed, _ := s.Config.Revision(); changed == first {
		t.Fatal("revision did not change with the policy")
	}
}

func TestSetRuleDoesNotMutateSharedSlices(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []struct{ id, ip string }{{"alice", "10.77.0.1"}, {"bob", "10.77.0.2"}, {"carol", "10.77.0.3"}} {
		if _, err := s.AddPeer(p.id, p.ip); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range [][2]string{{"alice", "bob"}, {"bob", "carol"}} {
		if err := s.Config.SetRule(r[0], r[1], true); err != nil {
			t.Fatal(err)
		}
	}
	s.Config.Policy.Services = &ServicePolicy{Allowed: []ServiceRule{{From: "bob", To: "carol", Protocol: "icmp"}, {From: "alice", To: "bob", Protocol: "icmp"}}}
	rules, services := s.Config.Policy.Allowed, s.Config.Policy.Services.Allowed
	if err := s.Config.SetRule("alice", "bob", false); err != nil {
		t.Fatal(err)
	}
	if rules[0] != (Rule{From: "alice", To: "bob"}) || rules[1] != (Rule{From: "bob", To: "carol"}) {
		t.Fatalf("SetRule edited a previously shared rule slice: %v", rules)
	}
	if services[0].From != "bob" || services[1].From != "alice" {
		t.Fatalf("SetRule edited a previously shared service slice: %v", services)
	}
}

func TestLoadStateCanonicalizesLegacyIPv6(t *testing.T) {
	dir := privateTempDir(t)
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPeer("alice", "10.77.0.1"); err != nil {
		t.Fatal(err)
	}
	s.Config.Network6, s.Config.Peers[0].IPv6 = "FD77:0001::/64", "FD77:1:0:0:0:0:0:1"
	if err := WriteJSON(dir+"/state.json", s); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadState(dir)
	if err != nil {
		t.Fatalf("v0.1-style IPv6 state did not load: %v", err)
	}
	if loaded.Config.Network6 != "fd77:1::/64" || loaded.Config.Peers[0].IPv6 != "fd77:1::1" {
		t.Fatalf("not canonicalised: %q %q", loaded.Config.Network6, loaded.Config.Peers[0].IPv6)
	}
}
