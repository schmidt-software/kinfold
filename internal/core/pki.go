package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type State struct {
	Server       string   `json:"server"`
	CA           []byte   `json:"ca"`
	CAKey        []byte   `json:"ca_key"`
	ServerCert   []byte   `json:"server_cert"`
	ServerKey    []byte   `json:"server_key"`
	Config       Config   `json:"config"`
	UsedPeerKeys []string `json:"used_peer_keys,omitempty"`
	// RenewedFrom maps a peer ID to the fingerprint of the certificate its
	// last online renewal replaced, so a device whose renewal response was
	// lost can collect the new certificate again (D-018).
	RenewedFrom map[string]string `json:"renewed_from,omitempty"`
	// EnrollmentTokens are pending single-use online enrollments (D-024).
	EnrollmentTokens []EnrollmentToken `json:"enrollment_tokens,omitempty"`
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func newKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func keyPEM(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// ValidateServerAddress checks a controller address as clients use it.
func ValidateServerAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("server must be a host:port address, got %q", address)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535, got %q", port)
	}
	return nil
}

func NewState(address, network string) (*State, error) {
	if err := ValidateServerAddress(address); err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(address)
	cfg := Config{Network: network, Policy: &Policy{}}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	pub, priv, err := newKey()
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: "Kinfold CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return nil, err
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	caKey, err := keyPEM(priv)
	if err != nil {
		return nil, err
	}
	serverPub, serverPriv, err := newKey()
	if err != nil {
		return nil, err
	}
	n, err = serial()
	if err != nil {
		return nil, err
	}
	server := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		server.IPAddresses = []net.IP{ip}
	} else {
		server.DNSNames = []string{host}
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, serverPub, priv)
	if err != nil {
		return nil, err
	}
	serverKey, err := keyPEM(serverPriv)
	if err != nil {
		return nil, err
	}
	return &State{Server: address, CA: certPEM(der), CAKey: caKey, ServerCert: certPEM(serverDER), ServerKey: serverKey, Config: cfg}, nil
}

func (s *State) AddPeer(id, ip string) (Credential, error) {
	pub, key, err := newKey()
	if err != nil {
		return Credential{}, err
	}
	der, err := s.addPeerPublicKey(id, ip, pub)
	if err != nil {
		return Credential{}, err
	}
	priv, err := keyPEM(key)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Server: s.Server, CA: s.CA, Cert: certPEM(der), Key: priv}, nil
}

func (s *State) addPeerPublicKey(id, ip string, pub ed25519.PublicKey) ([]byte, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid ID %q", id)
	}
	if _, exists := s.Config.Peer(id); exists {
		return nil, fmt.Errorf("peer %s already exists", id)
	}
	if host, _, err := net.SplitHostPort(s.Server); err == nil && strings.EqualFold(host, id) {
		return nil, fmt.Errorf("peer ID %q equals the controller host name", id)
	}
	history, err := s.historyWithNewKey(pub)
	if err != nil {
		return nil, err
	}
	der, err := s.issuePeerCertificate(id, pub)
	if err != nil {
		return nil, err
	}
	updated := s.Config
	updated.Peers = append(append([]Peer(nil), updated.Peers...), Peer{ID: id, IP: ip, Cert: der})
	if err := updated.Validate(); err != nil {
		return nil, err
	}
	s.Config = updated
	s.UsedPeerKeys = history
	return der, nil
}

func (s *State) issuePeerCertificate(id string, pub ed25519.PublicKey) ([]byte, error) {
	for _, peer := range s.Config.Peers {
		cert, err := ParseCert(peer.Cert)
		if err != nil {
			return nil, err
		}
		if existing, ok := cert.PublicKey.(ed25519.PublicKey); ok && existing.Equal(pub) {
			return nil, fmt.Errorf("public key already belongs to peer %s", peer.ID)
		}
	}
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		return nil, err
	}
	n, err := serial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	if !expires.After(now.Add(time.Minute)) {
		return nil, fmt.Errorf("CA expires too soon to issue a peer certificate")
	}
	template := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: id},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caPair.PrivateKey)
	if err != nil {
		return nil, err
	}
	return der, nil
}

func LoadState(dir string) (*State, error) {
	return loadState(dir, false)
}

// LoadStateForOfflineMaintenance permits an expired server certificate for
// narrowly scoped administrative operations; it must not be used to serve.
// The CA and all other checks remain valid.
func LoadStateForOfflineMaintenance(dir string) (*State, error) {
	return loadState(dir, true)
}

func loadState(dir string, renewServer bool) (*State, error) {
	path := filepath.Join(dir, "state.json")
	for _, p := range []string{dir, path} {
		if err := CheckPrivate(p); err != nil {
			return nil, err
		}
	}
	var s State
	if err := ReadJSON(path, &s); err != nil {
		return nil, err
	}
	// States written by v0.1 may hold IPv6 values as typed (upper case,
	// leading zeros); normalise them instead of refusing to load (change
	// review finding 9). The next write stores the canonical form.
	s.Config.canonicalizeIPv6()
	if err := s.Config.Validate(); err != nil {
		return nil, err
	}
	if err := s.validatePeerKeyHistory(); err != nil {
		return nil, err
	}
	if err := s.validateRenewedFrom(); err != nil {
		return nil, err
	}
	if err := s.validateTokens(); err != nil {
		return nil, err
	}
	if err := s.validatePKI(renewServer); err != nil {
		return nil, fmt.Errorf("invalid controller PKI: %w", err)
	}
	return &s, nil
}

func (s *State) validatePKI(renewServer bool) error {
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		return fmt.Errorf("CA certificate and private key: %w", err)
	}
	if len(caPair.Certificate) != 1 {
		return fmt.Errorf("expected exactly one CA certificate")
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse CA: %w", err)
	}
	if !ca.IsCA || ca.CheckSignatureFrom(ca) != nil {
		return fmt.Errorf("CA must be self-signed and able to sign certificates")
	}
	serverPair, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		return fmt.Errorf("server certificate and private key: %w", err)
	}
	if len(serverPair.Certificate) != 1 {
		return fmt.Errorf("expected exactly one server certificate")
	}
	server, err := x509.ParseCertificate(serverPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("parse server certificate: %w", err)
	}
	host, port, err := net.SplitHostPort(s.Server)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("invalid controller address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return fmt.Errorf("invalid controller port")
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := ca.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("CA certificate verification: %w", err)
	}
	verifyTime := time.Now()
	if renewServer && verifyTime.After(server.NotAfter) {
		verifyTime = server.NotAfter
	}
	if _, err := server.Verify(x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: verifyTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return fmt.Errorf("server certificate verification: %w", err)
	}
	for _, peer := range s.Config.Peers {
		cert, err := ParseCert(peer.Cert)
		if err != nil {
			return fmt.Errorf("peer %s: %w", peer.ID, err)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil {
			return fmt.Errorf("peer %s is not signed by the controller CA: %w", peer.ID, err)
		}
		if err := checkPeerCertificate(peer.ID, cert); err != nil {
			return fmt.Errorf("peer %s: %w", peer.ID, err)
		}
	}
	return nil
}

// checkPeerCertificate enforces the shape of device certificates beyond the
// CA signature (review C-02). Validity is deliberately not checked here: an
// expired device must not take the whole controller down; it is reported by
// CertificateWarnings and rejected by TLS.
func checkPeerCertificate(id string, cert *x509.Certificate) error {
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		return fmt.Errorf("device certificate must not be a CA")
	}
	if cert.Subject.CommonName != id {
		return fmt.Errorf("certificate common name %q does not match peer ID", cert.Subject.CommonName)
	}
	client, server := false, false
	for _, usage := range cert.ExtKeyUsage {
		client = client || usage == x509.ExtKeyUsageClientAuth
		server = server || usage == x509.ExtKeyUsageServerAuth
	}
	if !client || !server || len(cert.ExtKeyUsage) != 2 {
		return fmt.Errorf("device certificate must have exactly the client and server authentication usages")
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return fmt.Errorf("device certificate must use an Ed25519 key")
	}
	return nil
}

// CertificateWarnings lists device, server and CA certificates that are
// expired or expire within the given window.
func (s *State) CertificateWarnings(now time.Time, window time.Duration) []string {
	var warnings []string
	check := func(name string, cert *x509.Certificate) {
		switch {
		case !now.Before(cert.NotAfter):
			warnings = append(warnings, fmt.Sprintf("%s certificate expired on %s", name, cert.NotAfter.UTC().Format(time.DateOnly)))
		case cert.NotAfter.Sub(now) < window:
			warnings = append(warnings, fmt.Sprintf("%s certificate expires on %s", name, cert.NotAfter.UTC().Format(time.DateOnly)))
		}
	}
	if block, _ := pem.Decode(s.CA); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			check("CA", cert)
		}
	}
	if block, _ := pem.Decode(s.ServerCert); block != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			check("controller", cert)
		}
	}
	for _, peer := range s.Config.Peers {
		if cert, err := ParseCert(peer.Cert); err == nil {
			check("device "+peer.ID, cert)
		}
	}
	return warnings
}

// RenewServerCertificate creates a new controller key and certificate using the existing CA.
func (s *State) RenewServerCertificate() error {
	if err := s.validatePKI(true); err != nil {
		return fmt.Errorf("invalid controller PKI: %w", err)
	}
	return s.issueServerCertificate()
}

// ChangeServerAddress moves the controller to a new host:port and issues a
// server certificate for it. The CA, device certificates and keys stay
// valid; devices only need the new address in their credential file.
func (s *State) ChangeServerAddress(address string) error {
	if err := s.validatePKI(true); err != nil {
		return fmt.Errorf("invalid controller PKI: %w", err)
	}
	if err := ValidateServerAddress(address); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(address)
	for _, peer := range s.Config.Peers {
		if strings.EqualFold(peer.ID, host) {
			return fmt.Errorf("new controller host name %q equals the ID of a device", host)
		}
	}
	old := s.Server
	s.Server = address
	if err := s.issueServerCertificate(); err != nil {
		s.Server = old
		return err
	}
	return nil
}

func (s *State) issueServerCertificate() error {
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(s.Server)
	if err != nil {
		return err
	}
	pub, priv, err := newKey()
	if err != nil {
		return err
	}
	n, err := serial()
	if err != nil {
		return err
	}
	now := time.Now()
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	if !expires.After(now.Add(time.Minute)) {
		return fmt.Errorf("CA expires too soon to renew server certificate")
	}
	template := &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Minute), NotAfter: expires,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caPair.PrivateKey)
	if err != nil {
		return err
	}
	key, err := keyPEM(priv)
	if err != nil {
		return err
	}
	s.ServerCert, s.ServerKey = certPEM(der), key
	return nil
}

// writeStateHook lets tests inject a failing state write into InitState.
var writeStateHook = WriteJSON

func InitState(dir, server, network string) error {
	s, err := NewState(server, network)
	if err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("create new data directory: %w", err)
	}
	if err := SyncParentDir(dir); err != nil {
		return fmt.Errorf("data directory %s created but its durability is uncertain: %w", dir, err)
	}
	if err := writeStateHook(filepath.Join(dir, "state.json"), s); err != nil {
		// Leave nothing behind that would make a retry fail (review C-07).
		// Remove only succeeds for the empty directory created above.
		os.Remove(dir)
		return err
	}
	return nil
}
