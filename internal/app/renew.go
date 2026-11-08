package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	var lastErr error
	for i := 0; i < 30; i++ {
		cfg, id, err := agent.FetchConfig(ctx, cred)
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

// controllerEnroller consumes enrollment tokens on the controller under the
// state lock (D-024).
func controllerEnroller(dir string, now func() time.Time) relay.Enroller {
	return func(token string, request []byte) (string, []byte, error) {
		s, lock, err := loadWritableState(dir)
		if errors.Is(err, core.ErrStateLocked) {
			return "", nil, relay.ErrBusy
		}
		if err != nil {
			return "", nil, fmt.Errorf("load state: %w", err)
		}
		defer lock.Close()
		id, cert, err := s.EnrollWithToken(token, request, now())
		if err != nil {
			return "", nil, err
		}
		if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
			return "", nil, fmt.Errorf("persist enrollment: %w", err)
		}
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
