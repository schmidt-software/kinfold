package app

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
)

func issueToken(t *testing.T, dir, id, ip string) (secret, fingerprint string) {
	t.Helper()
	s, lock, err := loadWritableState(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	secret, err = s.IssueToken(id, ip, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
		t.Fatal(err)
	}
	fingerprint, err = caFingerprint(s)
	if err != nil {
		t.Fatal(err)
	}
	return secret, fingerprint
}

func TestJoinWithTokenEndToEnd(t *testing.T) {
	dir, _, alice := renewalController(t, time.Now)
	server := alice.Server
	secret, fp := issueToken(t, dir, "bob", "10.77.0.2")
	work := t.TempDir()
	out := filepath.Join(work, "bob.json")
	tokenFile := filepath.Join(work, "token")
	if err := os.WriteFile(tokenFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A wrong pin aborts before the token is sent: the token stays usable.
	wrong := strings.Repeat("0", 64)
	if err := Run([]string{"join", "-server", server, "-ca-sha256", wrong, "-id", "bob", "-token-file", tokenFile, "-out", out}); err == nil || !strings.Contains(err.Error(), "pinned fingerprint") {
		t.Fatalf("join with a wrong CA pin: %v", err)
	}
	os.Remove(joinPendingPath(out)) // the token was never sent; start over with the right pin
	if err := Run([]string{"join", "-server", server, "-ca-sha256", strings.ToUpper(fp), "-id", "bob", "-token-file", tokenFile, "-out", out}); err != nil {
		t.Fatalf("join: %v", err)
	}
	if _, err := os.Stat(joinPendingPath(out)); !os.IsNotExist(err) {
		t.Fatal("pending enrollment left behind after success")
	}
	var cred core.Credential
	if err := core.ReadJSON(out, &cred); err != nil {
		t.Fatal(err)
	}
	if len(cred.ConfigKey) != 32 {
		t.Fatal("token-enrolled credential lacks the configuration key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, id, err := fetchAfterRenewal(ctx, cred); err != nil || id != "bob" {
		t.Fatalf("enrolled credential not accepted: id=%q err=%v", id, err)
	}
	again := filepath.Join(t.TempDir(), "bob2.json")
	if err := Run([]string{"join", "-server", server, "-ca-sha256", fp, "-id", "bob", "-token-file", tokenFile, "-out", again}); err == nil {
		t.Fatal("used token enrolled a second key")
	}
}

func TestControllerRequiresCertificateOutsideEnroll(t *testing.T) {
	_, _, alice := renewalController(t, time.Now)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: 5 * time.Second}
	resp, err := client.Get("https://" + alice.Server + "/config")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("/config without a client certificate: %s", resp.Status)
	}
	if _, err := agent.NormalizeFingerprint("AB:CD"); err == nil {
		t.Fatal("short fingerprint accepted")
	}
}

func TestJoinResumesAfterLostResponse(t *testing.T) {
	dir, _, alice := renewalController(t, time.Now)
	secret, fp := issueToken(t, dir, "carol", "10.77.0.3")
	out := filepath.Join(t.TempDir(), "carol.json")
	key, request, err := core.NewEnrollment("carol")
	if err != nil {
		t.Fatal(err)
	}
	if err := core.WriteJSON(joinPendingPath(out), joinPending{Server: alice.Server, ID: "carol", Token: secret, Key: key, Request: request}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, _, err := agent.Join(ctx, alice.Server, fp, secret, request); err != nil {
		t.Fatalf("first request: %v", err)
	} // response "lost"
	if err := Run([]string{"join", "-server", alice.Server, "-ca-sha256", fp, "-id", "carol", "-token-file", "/nonexistent", "-out", out}); err != nil {
		t.Fatalf("resume: %v", err)
	}
	var cred core.Credential
	if err := core.ReadJSON(out, &cred); err != nil || string(cred.Key) != string(key) {
		t.Fatalf("resumed credential does not use the pending key: %v", err)
	}
}

func TestOfflineAuthorizationDropsPendingToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := core.InitState(dir, "localhost:8443", "10.77.0.0/24"); err != nil {
		t.Fatal(err)
	}
	issueToken(t, dir, "laptop", "10.77.0.5")
	if err := Run([]string{"add-peer", "-data", dir, "-id", "laptop", "-ip", "10.77.0.5", "-out", filepath.Join(t.TempDir(), "l.json")}); err != nil {
		t.Fatal(err)
	}
	s, err := core.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.EnrollmentTokens) != 0 {
		t.Fatal("token survived offline authorization of its device")
	}
}

func TestUnknownTokenIsRefusedWithoutTouchingState(t *testing.T) {
	cache := newTokenCache("/nonexistent/state", &core.State{})
	enroll := controllerEnroller("/nonexistent/state", time.Now, cache)
	if _, _, err := enroll("guess", nil); err != core.ErrTokenInvalid {
		t.Fatalf("unknown token: %v (the state must not be loaded or locked)", err)
	}
}

// The pending enrollment must survive every error except the controller's
// refusal of the token, even when the error text contains "403" (#122).
func TestJoinKeepsPendingUnlessTokenRefused(t *testing.T) {
	dir, _, alice := renewalController(t, time.Now)
	_, fp := issueToken(t, dir, "dave", "10.77.0.4")
	work := t.TempDir()
	out := filepath.Join(work, "dave.json")
	tokenFile := filepath.Join(work, "token")
	if err := os.WriteFile(tokenFile, []byte("not-the-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Nothing listens on the privileged port 403; the address is part of
	// the transport error.
	_, err := joinWithToken(ctx, "127.0.0.1:403", fp, "dave", tokenFile, out)
	if err == nil || !strings.Contains(err.Error(), "403") || errors.Is(err, agent.ErrTokenRefused) {
		t.Fatalf("join at an unreachable controller: %v", err)
	}
	if _, err := os.Stat(joinPendingPath(out)); err != nil {
		t.Fatalf("pending enrollment removed after a transport error: %v", err)
	}
	os.Remove(joinPendingPath(out))

	if _, err := joinWithToken(ctx, alice.Server, fp, "dave", tokenFile, out); !errors.Is(err, agent.ErrTokenRefused) {
		t.Fatalf("join with a wrong token: %v", err)
	}
	if _, err := os.Stat(joinPendingPath(out)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending enrollment kept after the controller refused the token: %v", err)
	}
}
