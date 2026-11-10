package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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

// RenewPeer issues a new certificate for peer id for the key in request,
// authenticated by the certificate the device presents. id is empty when the
// presented certificate is no longer a member; it is then resolved through
// RenewedFrom. The returned bool reports whether the state changed and must
// be written.
//
// Normal renewal requires the presented certificate to be the one on record
// and inside the renewal window, and applies the rotate-peer checks (proof of
// possession, Ed25519, ID binding, key history).
//
// Retried renewal: if the presented certificate is the one the last renewal
// replaced and the request is signed by the key of the current certificate,
// the current certificate is returned again without changing the state. This
// lets a device recover when the response to its renewal was lost; a holder
// of only the old credential cannot use it, because it lacks the new key.
func (s *State) RenewPeer(id string, presented *x509.Certificate, request []byte, now time.Time) ([]byte, bool, error) {
	fp := Fingerprint(presented)
	if id == "" {
		for peer, previous := range s.RenewedFrom {
			if previous == fp {
				id = peer
			}
		}
		if id == "" {
			return nil, false, errors.New("peer is not authorized")
		}
	}
	peer, ok := s.Config.Peer(id)
	if !ok {
		return nil, false, errors.New("peer is not authorized")
	}
	current, err := ParseCert(peer.Cert)
	if err != nil {
		return nil, false, err
	}
	if s.RenewedFrom[id] == fp {
		pub, err := enrollmentPublicKey(id, request)
		if err != nil {
			return nil, false, err
		}
		if key, ok := current.PublicKey.(ed25519.PublicKey); !ok || !key.Equal(pub) {
			return nil, false, errors.New("retried renewal must use the key of the issued certificate")
		}
		return certPEM(current.Raw), false, nil
	}
	if Fingerprint(current) != fp {
		return nil, false, errors.New("presented certificate is no longer the one on record")
	}
	if !RenewalAccepted(current, now) {
		return nil, false, ErrRenewalNotDue
	}
	if expiry, err := s.peerCertificateExpiry(now); err != nil {
		return nil, false, err
	} else if !expiry.After(current.NotAfter.Add(minRenewalGain)) {
		// Near CA expiry every renewal would be capped at the CA's end and
		// renewals would come ever faster (change review finding 8).
		return nil, false, fmt.Errorf("%w: a new certificate would not outlive the current one because the CA expires on %s; rotate the CA", ErrRenewalNotDue, expiry.UTC().Format(time.DateOnly))
	}
	cert, err := s.RotatePeerEnrollment(id, request)
	if err != nil {
		return nil, false, err
	}
	if s.RenewedFrom == nil {
		s.RenewedFrom = make(map[string]string)
	}
	s.RenewedFrom[id] = fp
	return cert, true, nil
}

// minRenewalGain is how much longer a renewed certificate must live than the
// current one for a renewal to be worth its session reset.
const minRenewalGain = 7 * 24 * time.Hour

// peerCertificateExpiry is the NotAfter a peer certificate issued now gets.
func (s *State) peerCertificateExpiry(now time.Time) (time.Time, error) {
	ca, err := ParseCertPEM(s.CA)
	if err != nil {
		return time.Time{}, fmt.Errorf("CA certificate: %w", err)
	}
	expires := now.AddDate(1, 0, 0)
	if ca.NotAfter.Before(expires) {
		expires = ca.NotAfter
	}
	return expires, nil
}

func (s *State) validateRenewedFrom() error {
	for id, fp := range s.RenewedFrom {
		if _, ok := s.Config.Peer(id); !ok {
			return fmt.Errorf("renewal record for unknown peer %q", id)
		}
		data, err := hex.DecodeString(fp)
		if err != nil || len(data) != sha256.Size {
			return fmt.Errorf("invalid renewal record for peer %q", id)
		}
	}
	return nil
}

// ForgetPeer removes per-peer records that must not outlive the peer,
// including its enrollment tokens (v0.3 review finding 4).
func (s *State) ForgetPeer(id string) {
	delete(s.RenewedFrom, id)
	kept := s.EnrollmentTokens[:0:0]
	for _, t := range s.EnrollmentTokens {
		if t.ID != id {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		kept = nil
	}
	s.EnrollmentTokens = kept
}
