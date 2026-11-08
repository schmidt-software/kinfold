package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/agent"
	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/relay"
)

// renewCheckInterval is how often the client checks whether its certificate
// is due; retryInterval applies after a failed attempt.
var (
	renewCheckInterval = time.Hour
	renewRetryInterval = 10 * time.Minute
)

// controllerRenewer issues renewed device certificates on the controller
// under the state lock, from the state on disk (not the possibly older copy
// in memory). The watcher then reloads the state like any other change.
func controllerRenewer(dir string, now func() time.Time) relay.Renewer {
	return func(id string, presented *x509.Certificate, request []byte) ([]byte, error) {
		// A current member outside its window is refused without touching
		// the state lock (change review finding 7).
		if id != "" && !core.RenewalAccepted(presented, now()) {
			return nil, core.ErrRenewalNotDue
		}
		s, lock, err := loadWritableState(dir)
		if errors.Is(err, core.ErrStateLocked) {
			return nil, relay.ErrBusy
		}
		if err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
		defer lock.Close()
		cert, changed, err := s.RenewPeer(id, presented, request, now())
		if err != nil {
			return nil, err
		}
		if changed {
			if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
				return nil, fmt.Errorf("persist renewed certificate: %w", err)
			}
		}
		return cert, nil
	}
}

func credentialCertificate(cred core.Credential) (*x509.Certificate, error) {
	block, _ := pem.Decode(cred.Cert)
	if block == nil {
		return nil, fmt.Errorf("credential certificate is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// checkWritable fails early if the credential cannot be replaced, before
// the controller switches the device to a new certificate.
func checkWritable(path string) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".renew-check-*")
	if err != nil {
		return fmt.Errorf("credential directory is not writable: %w", err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// pendingRenewal is stored next to the credential before a renewal request
// is sent. If the response is lost, the next attempt resends the same
// request and the controller returns the certificate it already issued
// (D-018). It contains the new private key and has mode 0600.
type pendingRenewal struct {
	Key     []byte `json:"key"`
	Request []byte `json:"request"`
}

func pendingPath(path string) string { return path + ".renewing" }

func loadPending(path string) (*pendingRenewal, error) {
	p := pendingPath(path)
	if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := core.CheckPrivate(p); err != nil {
		return nil, err
	}
	var pending pendingRenewal
	if err := core.ReadJSON(p, &pending); err != nil {
		return nil, err
	}
	return &pending, nil
}

// renewCredential renews the credential at path if it is due, or resumes an
// interrupted renewal. The new key never leaves the device; only a
// certificate request is sent over the mutual-TLS connection.
func renewCredential(ctx context.Context, path string, cred core.Credential, client *agent.ConfigClient, now time.Time) (core.Credential, bool, error) {
	cert, err := credentialCertificate(cred)
	if err != nil {
		return cred, false, err
	}
	pending, err := loadPending(path)
	if err != nil {
		return cred, false, fmt.Errorf("interrupted renewal: %w", err)
	}
	if pending == nil {
		if !core.RenewalDue(cert, now) {
			return cred, false, nil
		}
		if err := checkWritable(path); err != nil {
			return cred, false, err
		}
		key, request, err := core.NewEnrollment(cert.Subject.CommonName)
		if err != nil {
			return cred, false, err
		}
		pending = &pendingRenewal{Key: key, Request: request}
		if err := core.WriteJSON(pendingPath(path), pending); err != nil {
			return cred, false, fmt.Errorf("store pending renewal: %w", err)
		}
	}
	certPEM, err := client.Renew(ctx, pending.Request)
	if errors.Is(err, core.ErrRenewalNotDue) {
		// The controller has not issued anything for this request.
		os.Remove(pendingPath(path))
		return cred, false, err
	}
	if err != nil {
		return cred, false, err // keep the pending request for the retry
	}
	renewed, err := core.CompleteEnrollment(cred.Server, cred.CA, certPEM, pending.Key)
	if err != nil {
		return cred, false, fmt.Errorf("controller returned an unusable certificate: %w", err)
	}
	renewed.ConfigKey = cred.ConfigKey
	if err := core.WriteJSON(path, renewed); err != nil {
		return cred, false, fmt.Errorf("store renewed credential (the pending renewal in %s allows a retry): %w", pendingPath(path), err)
	}
	if err := os.Remove(pendingPath(path)); err != nil && !errors.Is(err, os.ErrNotExist) {
		slog.Warn("could not remove completed pending renewal", "path", pendingPath(path), "error", err)
	}
	return renewed, true, nil
}

// resumeRenewal completes an interrupted renewal before the client starts,
// because the old certificate may no longer be a member.
func resumeRenewal(ctx context.Context, path string, cred core.Credential) (core.Credential, error) {
	pending, err := loadPending(path)
	if err != nil || pending == nil {
		return cred, err
	}
	slog.Info("resuming interrupted certificate renewal")
	client := agent.NewConfigClient(cred)
	defer client.Close()
	renewed, _, err := renewCredential(ctx, path, cred, client, time.Now())
	if err != nil && !errors.Is(err, core.ErrRenewalNotDue) {
		return cred, fmt.Errorf("resume interrupted renewal: %w", err)
	}
	return renewed, nil
}

// renewLoop checks the certificate now and then periodically, and reports a
// renewed credential on done.
func renewLoop(ctx context.Context, path string, cred core.Credential, client *agent.ConfigClient, done chan<- core.Credential) {
	for {
		renewed, ok, err := renewCredential(ctx, path, cred, client, time.Now())
		wait := renewCheckInterval
		switch {
		case ok:
			if cert, err := credentialCertificate(renewed); err == nil {
				slog.Info("device certificate renewed", "valid_until", cert.NotAfter.UTC().Format(time.RFC3339))
			}
			done <- renewed
			return
		case errors.Is(err, core.ErrRenewalNotDue):
			// Clock skew between device and controller; try again later.
		case err != nil && ctx.Err() == nil:
			slog.Warn("certificate renewal failed; will retry", "error", err, "retry_in", renewRetryInterval)
			wait = renewRetryInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// fetchAfterRenewal waits until the controller has reloaded the state with
// the new certificate (the watcher polls about once per second).
func fetchAfterRenewal(ctx context.Context, cred core.Credential) (core.Config, string, error) {
	return fetchAfterRenewalAt(ctx, "", cred)
}

// fetchWithWatermark fetches the configuration once, honouring and updating
// the rollback watermark persisted next to the credential at path.
func fetchWithWatermark(ctx context.Context, path string, cred core.Credential) (core.Config, string, error) {
	client := agent.NewConfigClient(cred)
	defer client.Close()
	if path != "" {
		client.SetNotBefore(readSeen(path))
		client.SetControllers(readControllers(path))
	}
	cfg, id, err := client.Fetch(ctx)
	if err == nil && path != "" {
		writeSeen(path, client.NotBefore())
		writeControllers(path, client.Controllers())
	}
	return cfg, id, err
}

func fetchAfterRenewalAt(ctx context.Context, path string, cred core.Credential) (core.Config, string, error) {
	var lastErr error
	for i := 0; i < 30; i++ {
		var cfg core.Config
		var id string
		var err error
		if len(cred.ConfigKey) == 0 {
			cfg, id, err = agent.FetchConfig(ctx, cred)
		} else {
			cfg, id, err = fetchWithWatermark(ctx, path, cred)
		}
		if err == nil {
			return cfg, id, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return core.Config{}, "", ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return core.Config{}, "", fmt.Errorf("controller did not accept the renewed certificate: %w", lastErr)
}

// tokenCache holds the hashes of the pending tokens so that a request with
// an unknown token is refused without taking the state lock (v0.3 review
// finding 1). On a miss it checks whether state.json changed since the last
// load (a stat) and only then re-reads it, without the lock, so a token
// issued a moment ago works immediately while unknown tokens cost a stat.
type tokenCache struct {
	path   string
	mu     sync.Mutex
	hashes map[string]bool
	stamp  fileStamp
}

type fileStamp struct {
	mod  time.Time
	size int64
	ino  uint64
}

func stampOf(info os.FileInfo) fileStamp {
	s := fileStamp{mod: info.ModTime(), size: info.Size()}
	if st, ok := info.Sys().(interface{ Ino() uint64 }); ok {
		s.ino = st.Ino()
	}
	return s
}

func newTokenCache(dir string, s *core.State) *tokenCache {
	c := &tokenCache{path: filepath.Join(dir, "state.json")}
	if info, err := os.Stat(c.path); err == nil {
		c.stamp = stampOf(info)
	}
	c.set(s)
	return c
}

func (c *tokenCache) set(s *core.State) {
	m := make(map[string]bool, len(s.EnrollmentTokens))
	for _, t := range s.EnrollmentTokens {
		m[t.Hash] = true
	}
	c.hashes = m
}

// update records a state the caller has just loaded or written.
func (c *tokenCache) update(s *core.State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if info, err := os.Stat(c.path); err == nil {
		c.stamp = stampOf(info)
	}
	c.set(s)
}

func (c *tokenCache) has(secret string) bool {
	hash := core.TokenHash(secret)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.hashes[hash] {
		return true
	}
	info, err := os.Stat(c.path)
	if err != nil || stampOf(info) == c.stamp {
		return false
	}
	s, err := core.LoadState(filepath.Dir(c.path))
	if err != nil {
		return false
	}
	c.stamp = stampOf(info)
	c.set(s)
	return c.hashes[hash]
}

// controllerEnroller consumes enrollment tokens on the controller under the
// state lock (D-024).
func controllerEnroller(dir string, now func() time.Time, cache *tokenCache) relay.Enroller {
	return func(token string, request []byte) (string, []byte, error) {
		if !cache.has(token) {
			return "", nil, core.ErrTokenInvalid
		}
		s, lock, err := loadWritableState(dir)
		if errors.Is(err, core.ErrStateLocked) {
			return "", nil, relay.ErrBusy
		}
		if err != nil {
			return "", nil, fmt.Errorf("load state: %w", err)
		}
		defer lock.Close()
		id, cert, changed, err := s.EnrollWithToken(token, request, now())
		if err != nil {
			return "", nil, err
		}
		if changed {
			if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
				return "", nil, fmt.Errorf("persist enrollment: %w", err)
			}
		}
		cache.update(s)
		return id, cert, nil
	}
}

// caFingerprint returns the SHA-256 fingerprint of the controller CA.
func caFingerprint(s *core.State) (string, error) {
	block, _ := pem.Decode(s.CA)
	if block == nil {
		return "", fmt.Errorf("invalid CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	return core.Fingerprint(cert), nil
}

// joinPending is stored next to the future credential before an enrollment
// request is sent, so a lost response can be collected again with the same
// token and key (the controller keeps used tokens until they expire).
type joinPending struct {
	Server  string `json:"server"`
	ID      string `json:"id"`
	Token   string `json:"token"`
	Key     []byte `json:"key"`
	Request []byte `json:"request"`
}

func joinPendingPath(out string) string { return out + ".joining" }

const maxTokenFileBytes = 1024

func readToken(path string) (string, error) {
	var r io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		r = f
	}
	data, err := io.ReadAll(io.LimitReader(r, maxTokenFileBytes+1))
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if token == "" || len(data) > maxTokenFileBytes {
		return "", fmt.Errorf("token must be a single line of at most %d bytes", maxTokenFileBytes)
	}
	return token, nil
}

// joinWithToken enrolls the device, resuming an interrupted attempt from the
// pending file next to out when there is one.
func joinWithToken(ctx context.Context, server, fingerprint, id, tokenFile, out string) (core.Credential, error) {
	var pending joinPending
	path := joinPendingPath(out)
	if _, err := os.Stat(path); err == nil {
		if err := core.CheckPrivate(path); err != nil {
			return core.Credential{}, err
		}
		if err := core.ReadJSON(path, &pending); err != nil {
			return core.Credential{}, err
		}
		if pending.Server != server || pending.ID != id {
			return core.Credential{}, fmt.Errorf("%s belongs to an enrollment of %s at %s; remove it to start over", path, pending.ID, pending.Server)
		}
		slog.Info("resuming interrupted enrollment")
	} else {
		token, err := readToken(tokenFile)
		if err != nil {
			return core.Credential{}, err
		}
		if err := checkWritable(out); err != nil {
			return core.Credential{}, err
		}
		key, request, err := core.NewEnrollment(id)
		if err != nil {
			return core.Credential{}, err
		}
		pending = joinPending{Server: server, ID: id, Token: token, Key: key, Request: request}
		if err := core.WriteJSON(path, pending); err != nil {
			return core.Credential{}, fmt.Errorf("store pending enrollment: %w", err)
		}
	}
	cert, ca, configKey, err := agent.Join(ctx, server, fingerprint, pending.Token, pending.Request)
	if err != nil {
		if strings.Contains(err.Error(), "403") {
			os.Remove(path) // the controller refused the token; nothing was issued for this key
		}
		return core.Credential{}, err
	}
	cred, err := core.CompleteEnrollment(server, ca, cert, pending.Key)
	cred.ConfigKey = configKey
	return cred, err
}

// pinConfigKey fetches the controller's configuration key over the
// authenticated connection for a credential from before v0.4 and stores it
// in the credential, so later runs verify against the pinned key (D-025).
func pinConfigKey(ctx context.Context, path string, cred core.Credential) (core.Credential, error) {
	if len(cred.ConfigKey) != 0 {
		return cred, nil
	}
	client := agent.NewConfigClient(cred)
	defer client.Close()
	key, err := client.FetchConfigKey(ctx)
	if err != nil {
		return cred, fmt.Errorf("fetch configuration key: %w", err)
	}
	cred.ConfigKey = key
	if err := core.WriteJSON(path, cred); err != nil {
		// E.g. a credential bind-mounted as a single file cannot be replaced.
		// The key is still used for this run and fetched again next time.
		slog.Warn("could not store the configuration key in the credential; using it for this run only", "path", path, "error", err)
		return cred, nil
	}
	slog.Info("pinned the controller's configuration signing key in the credential")
	return cred, nil
}

// addConfigKey adds a configuration signing key to a state written before
// v0.4 (D-025).
func addConfigKey(dir string) (*core.State, error) {
	s, lock, err := loadWritableState(dir)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if s.ConfigKey == nil {
		if s.ConfigKey, err = core.NewConfigKey(); err != nil {
			return nil, err
		}
		if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
			return nil, err
		}
	}
	return s, nil
}
