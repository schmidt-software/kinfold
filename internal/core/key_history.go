package core

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

const maxPeerKeyHistory = 32768

func peerKeyFingerprint(publicKey any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal peer public key: %w", err)
	}
	hash := sha256.Sum256(der)
	return hex.EncodeToString(hash[:]), nil
}

func (s *State) validatePeerKeyHistory() error {
	if len(s.UsedPeerKeys) > maxPeerKeyHistory {
		return fmt.Errorf("peer key history exceeds %d entries", maxPeerKeyHistory)
	}
	seen := make(map[string]bool, len(s.UsedPeerKeys))
	for _, fingerprint := range s.UsedPeerKeys {
		data, err := hex.DecodeString(fingerprint)
		if err != nil || len(data) != sha256.Size || hex.EncodeToString(data) != fingerprint || seen[fingerprint] {
			return fmt.Errorf("invalid or duplicate peer key history entry")
		}
		seen[fingerprint] = true
	}
	if s.UsedPeerKeys != nil {
		for _, peer := range s.Config.Peers {
			cert, err := ParseCert(peer.Cert)
			if err != nil {
				return fmt.Errorf("peer %s: %w", peer.ID, err)
			}
			key, err := peerKeyFingerprint(cert.PublicKey)
			if err != nil {
				return err
			}
			if !seen[key] {
				return fmt.Errorf("peer %s is missing from peer key history", peer.ID)
			}
		}
	}
	return nil
}

func (s *State) activeKeyHistory() ([]string, error) {
	if err := s.validatePeerKeyHistory(); err != nil {
		return nil, err
	}
	history := append([]string(nil), s.UsedPeerKeys...)
	seen := make(map[string]bool, len(history))
	for _, key := range history {
		seen[key] = true
	}
	for _, peer := range s.Config.Peers {
		cert, err := ParseCert(peer.Cert)
		if err != nil {
			return nil, err
		}
		key, err := peerKeyFingerprint(cert.PublicKey)
		if err != nil {
			return nil, err
		}
		if !seen[key] {
			history = append(history, key)
			seen[key] = true
		}
	}
	if len(history) > maxPeerKeyHistory {
		return nil, fmt.Errorf("peer key history exceeds %d entries", maxPeerKeyHistory)
	}
	return history, nil
}

// RememberActivePeerKeys upgrades pre-history state before removing a peer.
func (s *State) RememberActivePeerKeys() error {
	history, err := s.activeKeyHistory()
	if err != nil {
		return err
	}
	s.UsedPeerKeys = history
	return nil
}

func (s *State) historyWithNewKey(publicKey any) ([]string, error) {
	history, err := s.activeKeyHistory()
	if err != nil {
		return nil, err
	}
	key, err := peerKeyFingerprint(publicKey)
	if err != nil {
		return nil, err
	}
	for _, existing := range history {
		if key == existing {
			return nil, fmt.Errorf("peer public key was previously authorized")
		}
	}
	if len(history) >= maxPeerKeyHistory {
		return nil, fmt.Errorf("peer key history limit reached")
	}
	return append(history, key), nil
}
