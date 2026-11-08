package core

import (
	"crypto/x509"
	"errors"
	"time"
)

// Renewal windows (D-015). The client asks for a new certificate once less
// than a third of the current lifetime remains; the controller accepts
// requests once at most half remains. The gap leaves room for clock skew and
// retries without letting a device churn certificates (and key history
// entries) at will.
const (
	clientRenewFraction     = 3 // renew when remaining < lifetime/3
	controllerRenewFraction = 2 // accept when remaining <= lifetime/2
)

// ErrRenewalNotDue is returned when a certificate is too fresh to renew.
var ErrRenewalNotDue = errors.New("certificate renewal is not due yet")

// RenewalDue reports whether a device should request a new certificate.
func RenewalDue(cert *x509.Certificate, now time.Time) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return cert.NotAfter.Sub(now) < lifetime/clientRenewFraction
}

// RenewalAccepted reports whether the controller accepts a renewal request
// authenticated with cert.
func RenewalAccepted(cert *x509.Certificate, now time.Time) bool {
	lifetime := cert.NotAfter.Sub(cert.NotBefore)
	return now.Before(cert.NotAfter) && cert.NotAfter.Sub(now) <= lifetime/controllerRenewFraction
}

// RenewPeer replaces the certificate of peer id with one for the key in
// request, authenticated by the certificate the device currently presents.
// It applies the same checks as rotate-peer (proof of possession, Ed25519,
// ID binding, key history) and additionally requires that the presented
// certificate is the one on record and inside the renewal window.
func (s *State) RenewPeer(id string, presented *x509.Certificate, request []byte, now time.Time) ([]byte, error) {
	peer, ok := s.Config.Peer(id)
	if !ok {
		return nil, errors.New("peer is not authorized")
	}
	current, err := ParseCert(peer.Cert)
	if err != nil {
		return nil, err
	}
	if Fingerprint(current) != Fingerprint(presented) {
		return nil, errors.New("presented certificate is no longer the one on record")
	}
	if !RenewalAccepted(current, now) {
		return nil, ErrRenewalNotDue
	}
	return s.RotatePeerEnrollment(id, request)
}
