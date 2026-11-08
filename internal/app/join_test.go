package app

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
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
	out := filepath.Join(t.TempDir(), "bob.json")

	// A wrong pin aborts before the token is sent: the token stays usable.
	wrong := strings.Repeat("0", 64)
	if err := Run([]string{"join", "-server", server, "-ca-sha256", wrong, "-id", "bob", "-token", secret, "-out", out}); err == nil || !strings.Contains(err.Error(), "pinned fingerprint") {
		t.Fatalf("join with a wrong CA pin: %v", err)
	}
	if err := Run([]string{"join", "-server", server, "-ca-sha256", strings.ToUpper(fp), "-id", "bob", "-token", secret, "-out", out}); err != nil {
		t.Fatalf("join: %v", err)
	}
	var cred core.Credential
	if err := core.ReadJSON(out, &cred); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, id, err := fetchAfterRenewal(ctx, cred); err != nil || id != "bob" {
		t.Fatalf("enrolled credential not accepted: id=%q err=%v", id, err)
	}
	again := filepath.Join(t.TempDir(), "bob2.json")
	if err := Run([]string{"join", "-server", server, "-ca-sha256", fp, "-id", "bob", "-token", secret, "-out", again}); err == nil {
		t.Fatal("token used twice")
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
