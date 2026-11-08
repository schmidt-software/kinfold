package core

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Signed configuration (D-025). The controller signs every configuration
// view it serves with a dedicated Ed25519 key (not the TLS CA key). The
// signature covers the device the view is for, the time it was issued and a
// lease end. Devices verify the signature with the public key pinned in
// their credential, reject anything older than what they have already
// accepted, and stop using a configuration once its lease has ended.

// DefaultLease is how long a signed configuration may be used.
const DefaultLease = 2 * time.Minute

// MaxLease bounds the lease a device accepts.
const MaxLease = 15 * time.Minute

// LeaseDuration is how long the configuration may be used after receipt.
func (p SignedPayload) LeaseDuration() time.Duration { return p.NotAfter.Sub(p.IssuedAt) }

// MaxClockSkew bounds how far in the future issued_at may lie.
const MaxClockSkew = 5 * time.Minute

const signedConfigContext = "kinfold signed configuration v1\n"

// SignedPayload is what the controller signs.
type SignedPayload struct {
	Peer     string    `json:"peer"`
	IssuedAt time.Time `json:"issued_at"`
	NotAfter time.Time `json:"not_after"`
	Config   Config    `json:"config"`
	// Endpoints lists direct-connection addresses (host:port) of peers in
	// the view that accept direct sessions (D-026). It is signed but kept
	// out of Config, so changing addresses do not change revisions.
	Endpoints map[string][]string `json:"endpoints,omitempty"`
	// Controllers lists the controller addresses (primary first, then
	// standbys) the device may fetch from (D-028).
	Controllers []string `json:"controllers,omitempty"`
}

// SignedConfig is the envelope served on GET /config.
type SignedConfig struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

// Errors returned by VerifyConfig.
var (
	ErrConfigSignature = errors.New("configuration signature is invalid")
	ErrConfigRollback  = errors.New("configuration is older than one already accepted")
	ErrConfigExpired   = errors.New("configuration lease has expired")
)

// NewConfigKey generates a configuration signing key (PKCS#8 PEM).
func NewConfigKey() ([]byte, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return keyPEM(priv)
}

// ParseConfigKey parses the PEM signing key.
func ParseConfigKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("configuration key is not a PEM private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("configuration key must be Ed25519")
	}
	return priv, nil
}

// ConfigPublicKey returns the public half of the state's signing key.
func (s *State) ConfigPublicKey() (ed25519.PublicKey, error) {
	priv, err := ParseConfigKey(s.ConfigKey)
	if err != nil {
		return nil, err
	}
	return priv.Public().(ed25519.PublicKey), nil
}

// SignConfig signs the view for peer with the given lease.
func SignConfig(key ed25519.PrivateKey, peer string, view Config, endpoints map[string][]string, controllers []string, now time.Time, lease time.Duration) (SignedConfig, error) {
	payload, err := json.Marshal(SignedPayload{Peer: peer, IssuedAt: now.UTC(), NotAfter: now.Add(lease).UTC(), Config: view, Endpoints: endpoints, Controllers: controllers})
	if err != nil {
		return SignedConfig{}, err
	}
	return SignedConfig{Payload: payload, Signature: ed25519.Sign(key, append([]byte(signedConfigContext), payload...))}, nil
}

// VerifyConfig checks the envelope for device peer: signature, device,
// freshness against notBefore (the newest issue time accepted so far; a
// configuration must be strictly newer), clock skew and staleness. It
// returns the payload. An empty peer skips the device check; the caller
// must then match the payload's device itself.
//
// The device's own clock only decides staleness with MaxClockSkew of
// tolerance in both directions; how long a verified configuration may be
// used is measured by the device from the moment it received it (see
// LeaseDuration), so a fast or slow device clock neither locks it out nor
// extends the lease (v0.4 review finding 3).
func VerifyConfig(env SignedConfig, pub ed25519.PublicKey, peer string, notBefore, now time.Time) (SignedPayload, error) {
	var p SignedPayload
	if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, append([]byte(signedConfigContext), env.Payload...), env.Signature) {
		return p, ErrConfigSignature
	}
	if err := DecodeJSON(bytes.NewReader(env.Payload), &p); err != nil {
		return p, fmt.Errorf("signed configuration: %w", err)
	}
	if peer != "" && p.Peer != peer {
		return p, fmt.Errorf("signed configuration is for device %q, not %q", p.Peer, peer)
	}
	if !notBefore.IsZero() && !p.IssuedAt.After(notBefore) {
		return p, ErrConfigRollback // strictly newer only: no replay of the newest (finding 4)
	}
	if p.IssuedAt.After(now.Add(MaxClockSkew)) {
		return p, fmt.Errorf("signed configuration issued %s in the future; check the clocks", p.IssuedAt.Sub(now).Round(time.Second))
	}
	if !p.NotAfter.After(p.IssuedAt) || p.NotAfter.Sub(p.IssuedAt) > MaxLease || !now.Before(p.NotAfter.Add(MaxClockSkew)) {
		return p, ErrConfigExpired
	}
	if err := p.Config.Validate(); err != nil {
		return p, err
	}
	return p, nil
}
