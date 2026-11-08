package core

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
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
