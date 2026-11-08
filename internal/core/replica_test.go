package core

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestReplicaLifecycle(t *testing.T) {
	s, err := NewState("primary.example.com:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddReplica("standby", "primary.example.com:8443"); err == nil {
		t.Fatal("replica with the primary's address accepted")
	}
	cred, err := s.AddReplica("standby", "standby.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddReplica("Standby", "other.example.com:8443"); err == nil {
		t.Fatal("replica ID differing only in case accepted")
	}
	if got := s.Controllers(); len(got) != 2 || got[0] != "primary.example.com:8443" || got[1] != "standby.example.com:8443" {
		t.Fatalf("controllers %v", got)
	}
	if err := s.validatePKI(false); err != nil {
		t.Fatalf("state with replica does not validate: %v", err)
	}
	server, err := tls.X509KeyPair(cred.ServerCert, cred.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(server.Certificate[0])
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.CA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "standby.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("replica server certificate: %v", err)
	}
	client, _ := tls.X509KeyPair(cred.Cert, cred.Key)
	clientLeaf, _ := x509.ParseCertificate(client.Certificate[0])
	if _, err := clientLeaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("replica client certificate is also valid for server authentication")
	}
	s.Replicas[0].Cert = s.Replicas[0].Cert[:10]
	if err := s.validatePKI(false); err == nil {
		t.Fatal("broken replica certificate accepted")
	}
	if !s.RemoveReplica("standby") || s.RemoveReplica("standby") || s.Replicas != nil {
		t.Fatal("remove did not remove exactly one replica")
	}
}

func TestReplicaPromotion(t *testing.T) {
	s, err := NewState("primary.example.com:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddReplica("standby", "standby.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.AddReplica("other", "other.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ChangeServerAddress("standby.example.com:8443"); err == nil {
		t.Fatal("moved the primary to a standby's address")
	}
	if err := s.Check(); err != nil || s.Server != "primary.example.com:8443" {
		t.Fatalf("failed address change modified the state: %s %v", s.Server, err)
	}
	foreign, err := NewState("primary.example.com:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if err := foreign.Promote(cred); err == nil {
		t.Fatal("promoted with a credential of another CA")
	}
	wrong := cred
	wrong.Cert, wrong.Key = other.Cert, other.Key
	if err := s.Promote(wrong); err == nil {
		t.Fatal("promoted with the certificate of another replica")
	}
	if err := s.Promote(cred); err != nil {
		t.Fatal(err)
	}
	if s.Server != "standby.example.com:8443" || len(s.Replicas) != 1 || s.Replicas[0].ID != "other" {
		t.Fatalf("promoted state: %s %v", s.Server, s.Replicas)
	}
	server, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(server.Certificate[0])
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(s.CA)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "standby.example.com", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("promoted server certificate: %v", err)
	}
	if err := s.Promote(cred); err == nil {
		t.Fatal("promoted twice")
	}
}

func TestStandbyToleratesExpiredPrimaryCertificate(t *testing.T) {
	s, err := NewState("primary.example.com:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddReplica("standby", "standby.example.com:8443")
	if err != nil {
		t.Fatal(err)
	}
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caPair.Certificate[0])
	pub, priv, _ := newKey()
	n, _ := serial()
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: n, Subject: pkix.Name{CommonName: "primary.example.com"}, DNSNames: []string{"primary.example.com"},
		NotBefore: ca.NotBefore, NotAfter: time.Now().Add(-time.Second),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, pub, caPair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	s.ServerCert = certPEM(der)
	if s.ServerKey, err = keyPEM(priv); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(); err == nil {
		t.Fatal("expired server certificate accepted for serving as primary")
	}
	if err := s.CheckStandby(); err != nil {
		t.Fatalf("standby rejects a state whose primary certificate expired: %v", err)
	}
	warnings := strings.Join(s.CertificateWarnings(time.Now(), 30*24*time.Hour), "\n")
	if !strings.Contains(warnings, "controller certificate expired") {
		t.Fatalf("warnings %q", warnings)
	}
	if strings.Contains(warnings, "standby standby") {
		t.Fatalf("fresh standby certificate reported: %q", warnings)
	}
	late := time.Now().AddDate(1, 0, 1)
	if w := strings.Join(s.CertificateWarnings(late, 0), "\n"); !strings.Contains(w, "standby standby certificate expired") {
		t.Fatalf("expired standby certificate not reported: %q", w)
	}
	if w := cred.CertificateWarnings(late, 0); len(w) != 2 {
		t.Fatalf("credential warnings %q", w)
	}
	if w := cred.CertificateWarnings(time.Now(), 24*time.Hour); len(w) != 0 {
		t.Fatalf("fresh credential reported: %q", w)
	}
}
