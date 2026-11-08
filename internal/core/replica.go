package core

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"strings"
	"time"
)

// Replica is a standby controller that copies the state from the primary
// (D-028). Its client certificate authenticates it for replication; it is
// not a network member.
type Replica struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Cert    []byte `json:"cert"`
}

// ReplicaCredential is everything a standby controller needs: the primary's
// address, the CA, a client certificate to pull the state, and the server
// certificate it presents to devices under its own address.
type ReplicaCredential struct {
	Primary    string `json:"primary"`
	Address    string `json:"address"`
	CA         []byte `json:"ca"`
	Cert       []byte `json:"cert"`
	Key        []byte `json:"key"`
	ServerCert []byte `json:"server_cert"`
	ServerKey  []byte `json:"server_key"`
}

const maxReplicas = 8

// AddReplica registers a standby controller reachable at address.
func (s *State) AddReplica(id, address string) (ReplicaCredential, error) {
	if !ValidID(id) {
		return ReplicaCredential{}, fmt.Errorf("invalid ID %q", id)
	}
	if err := ValidateServerAddress(address); err != nil {
		return ReplicaCredential{}, err
	}
	if address == s.Server {
		return ReplicaCredential{}, fmt.Errorf("a replica needs its own address")
	}
	for _, r := range s.Replicas {
		if strings.EqualFold(r.ID, id) || r.Address == address {
			return ReplicaCredential{}, fmt.Errorf("replica %s or address %s already exists", id, address)
		}
	}
	if len(s.Replicas) >= maxReplicas {
		return ReplicaCredential{}, fmt.Errorf("at most %d replicas", maxReplicas)
	}
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		return ReplicaCredential{}, err
	}
	ca, err := x509.ParseCertificate(caPair.Certificate[0])
	if err != nil {
		return ReplicaCredential{}, err
	}
	now := time.Now()
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	issue := func(template *x509.Certificate) (der, key []byte, err error) {
		pub, priv, err := newKey()
		if err != nil {
			return nil, nil, err
		}
		n, err := serial()
		if err != nil {
			return nil, nil, err
		}
		template.SerialNumber, template.NotBefore, template.NotAfter = n, now.Add(-time.Minute), expires
		template.BasicConstraintsValid, template.KeyUsage = true, x509.KeyUsageDigitalSignature
		der, err = x509.CreateCertificate(rand.Reader, template, ca, pub, caPair.PrivateKey)
		if err != nil {
			return nil, nil, err
		}
		key, err = keyPEM(priv)
		return der, key, err
	}
	clientDER, clientKey, err := issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "replica " + id},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return ReplicaCredential{}, err
	}
	host, _, _ := net.SplitHostPort(address)
	server := &x509.Certificate{Subject: pkix.Name{CommonName: host}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		server.IPAddresses = []net.IP{ip}
	} else {
		server.DNSNames = []string{host}
	}
	serverDER, serverKey, err := issue(server)
	if err != nil {
		return ReplicaCredential{}, err
	}
	s.Replicas = append(s.Replicas, Replica{ID: id, Address: address, Cert: clientDER})
	return ReplicaCredential{Primary: s.Server, Address: address, CA: s.CA, Cert: certPEM(clientDER), Key: clientKey, ServerCert: certPEM(serverDER), ServerKey: serverKey}, nil
}

// RemoveReplica unregisters a standby controller.
func (s *State) RemoveReplica(id string) bool {
	for i, r := range s.Replicas {
		if r.ID == id {
			s.Replicas = append(append([]Replica(nil), s.Replicas[:i]...), s.Replicas[i+1:]...)
			if len(s.Replicas) == 0 {
				s.Replicas = nil
			}
			return true
		}
	}
	return false
}

// Controllers lists the addresses devices may fetch their configuration
// from: the primary first, then the replicas.
func (s *State) Controllers() []string {
	out := []string{s.Server}
	for _, r := range s.Replicas {
		out = append(out, r.Address)
	}
	return out
}

func (s *State) validateReplicas(ca *x509.Certificate) error {
	if len(s.Replicas) > maxReplicas {
		return fmt.Errorf("more than %d replicas", maxReplicas)
	}
	seen := map[string]bool{}
	for _, r := range s.Replicas {
		if !ValidID(r.ID) || ValidateServerAddress(r.Address) != nil || r.Address == s.Server || seen[strings.ToLower(r.ID)] || seen["a:"+r.Address] {
			return fmt.Errorf("invalid or duplicate replica %q", r.ID)
		}
		seen[strings.ToLower(r.ID)], seen["a:"+r.Address] = true, true
		cert, err := ParseCert(r.Cert)
		if err != nil {
			return fmt.Errorf("replica %s: %w", r.ID, err)
		}
		if err := cert.CheckSignatureFrom(ca); err != nil || cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
			return fmt.Errorf("replica %s certificate is not a CA-signed client-only certificate", r.ID)
		}
	}
	return nil
}
