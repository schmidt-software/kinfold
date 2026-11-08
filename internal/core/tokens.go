package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// EnrollmentToken authorizes one online enrollment for a fixed device ID and
// address until NotAfter. Only the SHA-256 of the secret is stored (D-024).
type EnrollmentToken struct {
	ID       string    `json:"id"`
	IP       string    `json:"ip"`
	Hash     string    `json:"hash"`
	NotAfter time.Time `json:"not_after"`
}

const (
	DefaultTokenTTL = time.Hour
	MaxTokenTTL     = 7 * 24 * time.Hour
	tokenBytes      = 32
	maxTokens       = 256
)

// ErrTokenInvalid hides whether a token is unknown, expired or already used.
var ErrTokenInvalid = errors.New("enrollment token is invalid, expired or already used")

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// IssueToken creates a single-use token for device id with address ip and
// returns the secret, which is shown once and never stored.
func (s *State) IssueToken(id, ip string, ttl time.Duration, now time.Time) (string, error) {
	if ttl < time.Second || ttl > MaxTokenTTL {
		return "", fmt.Errorf("token lifetime must be between 1s and %s", MaxTokenTTL)
	}
	if !ValidID(id) {
		return "", fmt.Errorf("invalid ID %q", id)
	}
	if _, exists := s.Config.Peer(id); exists {
		return "", fmt.Errorf("peer %s already exists", id)
	}
	if err := s.addressAvailable(ip); err != nil {
		return "", err
	}
	s.PruneTokens(now)
	for _, t := range s.EnrollmentTokens {
		if t.ID == id || t.IP == ip {
			return "", fmt.Errorf("a pending token already exists for %s or %s; revoke it first", id, ip)
		}
	}
	if len(s.EnrollmentTokens) >= maxTokens {
		return "", fmt.Errorf("at most %d pending tokens", maxTokens)
	}
	raw := make([]byte, tokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	s.EnrollmentTokens = append(s.EnrollmentTokens, EnrollmentToken{ID: id, IP: ip, Hash: hashToken(secret), NotAfter: now.Add(ttl).UTC().Truncate(time.Second)})
	return secret, nil
}

// addressAvailable checks an IPv4 address as Validate would for a new peer.
func (s *State) addressAvailable(ip string) error {
	addr, err := netip.ParseAddr(ip)
	prefix, perr := netip.ParsePrefix(s.Config.Network)
	if err != nil || perr != nil || !addr.Is4() || addr.String() != ip || !prefix.Contains(addr) {
		return fmt.Errorf("invalid IPv4 address %q for network %s", ip, s.Config.Network)
	}
	last := prefix.Addr().As4()
	host := 32 - prefix.Bits()
	n := uint32(last[0])<<24 | uint32(last[1])<<16 | uint32(last[2])<<8 | uint32(last[3])
	a := addr.As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	if v == n || v == n|(1<<host-1) {
		return fmt.Errorf("%s is the network or broadcast address", ip)
	}
	for _, p := range s.Config.Peers {
		if p.IP == ip {
			return fmt.Errorf("address %s already belongs to peer %s", ip, p.ID)
		}
	}
	return nil
}

// PruneTokens drops expired tokens.
func (s *State) PruneTokens(now time.Time) {
	kept := s.EnrollmentTokens[:0:0]
	for _, t := range s.EnrollmentTokens {
		if now.Before(t.NotAfter) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		kept = nil
	}
	s.EnrollmentTokens = kept
}

// RevokeToken removes the pending token for device id.
func (s *State) RevokeToken(id string) bool {
	for i, t := range s.EnrollmentTokens {
		if t.ID == id {
			s.EnrollmentTokens = append(append([]EnrollmentToken(nil), s.EnrollmentTokens[:i]...), s.EnrollmentTokens[i+1:]...)
			if len(s.EnrollmentTokens) == 0 {
				s.EnrollmentTokens = nil
			}
			return true
		}
	}
	return false
}

// EnrollWithToken consumes a token and authorizes the key in request for the
// token's device ID and address, with the same checks as approve. It returns
// the device ID and the new certificate (PEM).
func (s *State) EnrollWithToken(secret string, request []byte, now time.Time) (string, []byte, error) {
	s.PruneTokens(now)
	hash := hashToken(secret)
	index := -1
	for i, t := range s.EnrollmentTokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(hash)) == 1 {
			index = i
		}
	}
	if index < 0 {
		return "", nil, ErrTokenInvalid
	}
	token := s.EnrollmentTokens[index]
	cert, err := s.ApproveEnrollment(token.ID, token.IP, request)
	if err != nil {
		return "", nil, err
	}
	s.RevokeToken(token.ID) // single use
	return token.ID, cert, nil
}

func (s *State) validateTokens() error {
	if len(s.EnrollmentTokens) > maxTokens {
		return fmt.Errorf("more than %d enrollment tokens", maxTokens)
	}
	seen := map[string]bool{}
	for _, t := range s.EnrollmentTokens {
		data, err := hex.DecodeString(t.Hash)
		if !ValidID(t.ID) || err != nil || len(data) != sha256.Size || seen[t.ID] || seen["ip:"+t.IP] || seen["h:"+t.Hash] {
			return fmt.Errorf("invalid or duplicate enrollment token for %q", t.ID)
		}
		seen[t.ID], seen["ip:"+t.IP], seen["h:"+t.Hash] = true, true, true
	}
	return nil
}
