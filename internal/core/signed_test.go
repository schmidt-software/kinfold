package core

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestSignedConfigRoundTripAndRejections(t *testing.T) {
	s, err := NewState("localhost:8443", "10.77.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := s.AddPeer("alice", "10.77.0.1")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseConfigKey(s.ConfigKey)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := s.ConfigPublicKey()
	if string(cred.ConfigKey) != string(pub) {
		t.Fatal("credential does not carry the configuration key")
	}
	now := time.Now()
	view := s.Config.ForPeer("alice")
	env, err := SignConfig(priv, "alice", view, nil, nil, now, DefaultLease)
	if err != nil {
		t.Fatal(err)
	}
	p, err := VerifyConfig(env, pub, "alice", time.Time{}, now)
	if err != nil || p.Peer != "alice" || len(p.Config.Peers) != 1 {
		t.Fatalf("verify: %+v %v", p, err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyConfig(env, other, "alice", time.Time{}, now); !errors.Is(err, ErrConfigSignature) {
		t.Fatalf("wrong key: %v", err)
	}
	tampered := env
	tampered.Payload = append([]byte(nil), env.Payload...)
	tampered.Payload[len(tampered.Payload)-2] ^= 1
	if _, err := VerifyConfig(tampered, pub, "alice", time.Time{}, now); !errors.Is(err, ErrConfigSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	if _, err := VerifyConfig(env, pub, "bob", time.Time{}, now); err == nil {
		t.Fatal("view for alice accepted by bob")
	}
	if _, err := VerifyConfig(env, pub, "alice", now.Add(time.Second), now); !errors.Is(err, ErrConfigRollback) {
		t.Fatalf("older than accepted: %v", err)
	}
	if _, err := VerifyConfig(env, pub, "alice", time.Time{}, now.Add(DefaultLease+MaxClockSkew)); !errors.Is(err, ErrConfigExpired) {
		t.Fatalf("stale envelope: %v", err)
	}
	// A device clock up to MaxClockSkew fast still accepts a fresh envelope.
	if _, err := VerifyConfig(env, pub, "alice", time.Time{}, now.Add(DefaultLease+time.Minute)); err != nil {
		t.Fatalf("fresh envelope rejected on a fast device clock: %v", err)
	}
	if _, err := VerifyConfig(env, pub, "alice", p.IssuedAt, now); !errors.Is(err, ErrConfigRollback) {
		t.Fatalf("exact replay of the newest envelope: %v", err)
	}
	future, _ := SignConfig(priv, "alice", view, nil, nil, now.Add(time.Hour), DefaultLease)
	if _, err := VerifyConfig(future, pub, "alice", time.Time{}, now); err == nil {
		t.Fatal("configuration from the future accepted")
	}
}
