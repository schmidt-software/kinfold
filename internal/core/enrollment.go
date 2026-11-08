package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// NewEnrollment creates a locally held key and a signed proof-of-possession request.
func NewEnrollment(id string) (key, request []byte, err error) {
	if !ValidID(id) {
		return nil, nil, fmt.Errorf("invalid ID %q", id)
	}
	_, priv, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: id},
	}, priv)
	if err != nil {
		return nil, nil, err
	}
	key, err = keyPEM(priv)
	if err != nil {
		return nil, nil, err
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func onePEM(data []byte, kind string) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----\n")) {
		return nil, fmt.Errorf("expected %s PEM block", kind)
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != kind || len(rest) != 0 || len(block.Headers) != 0 {
		return nil, fmt.Errorf("expected exactly one %s PEM block", kind)
	}
	return block.Bytes, nil
}

// ApproveEnrollment requires an administrator-selected ID and never trusts CSR extensions.
func (s *State) ApproveEnrollment(id, ip string, request []byte) ([]byte, error) {
	pub, err := enrollmentPublicKey(id, request)
	if err != nil {
		return nil, err
	}
	cert, err := s.addPeerPublicKey(id, ip, pub)
	if err != nil {
		return nil, err
	}
	return certPEM(cert), nil
}

func enrollmentPublicKey(id string, request []byte) (ed25519.PublicKey, error) {
	der, err := onePEM(request, "CERTIFICATE REQUEST")
	if err != nil {
		return nil, err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid request signature: %w", err)
	}
	pub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only Ed25519 enrollment keys are supported")
	}
	if csr.Subject.CommonName != id {
		return nil, fmt.Errorf("request ID does not match approved ID")
	}
	return pub, nil
}

// RotatePeerEnrollment replaces the certificate only after validating the new key and configuration.
func (s *State) RotatePeerEnrollment(id string, request []byte) ([]byte, error) {
	pub, err := enrollmentPublicKey(id, request)
	if err != nil {
		return nil, err
	}
	index := -1
	for i, peer := range s.Config.Peers {
		if peer.ID == id {
			index = i
		}
	}
	if index < 0 {
		return nil, fmt.Errorf("unknown peer %q", id)
	}
	history, err := s.historyWithNewKey(pub)
	if err != nil {
		return nil, err
	}
	cert, err := s.issuePeerCertificate(id, pub)
	if err != nil {
		return nil, err
	}
	updated := s.Config
	updated.Peers = append([]Peer(nil), s.Config.Peers...)
	updated.Peers[index].Cert = cert
	if err := updated.Validate(); err != nil {
		return nil, err
	}
	s.Config = updated
	s.UsedPeerKeys = history
	return certPEM(cert), nil
}

// CompleteEnrollment verifies both the private key and the explicitly trusted CA.
func CompleteEnrollment(server string, ca, cert, key []byte) (Credential, error) {
	if err := ValidateServerAddress(server); err != nil {
		return Credential{}, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return Credential{}, fmt.Errorf("certificate and key: %w", err)
	}
	if len(pair.Certificate) != 1 {
		return Credential{}, fmt.Errorf("expected one peer certificate")
	}
	rootDER, err := onePEM(ca, "CERTIFICATE")
	if err != nil {
		return Credential{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil || !root.IsCA {
		return Credential{}, fmt.Errorf("invalid trusted CA")
	}
	peer, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Credential{}, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if _, err := peer.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return Credential{}, fmt.Errorf("peer certificate verification: %w", err)
		}
	}
	return Credential{Server: server, CA: ca, Cert: cert, Key: key}, nil
}
