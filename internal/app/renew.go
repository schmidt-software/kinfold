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
		s, lock, err := loadWritableState(dir)
		if errors.Is(err, core.ErrStateLocked) {
			return nil, relay.ErrBusy
		}
		if err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
		defer lock.Close()
		cert, err := s.RenewPeer(id, presented, request, now())
		if err != nil {
			return nil, err
		}
		if err := core.WriteJSON(filepath.Join(dir, "state.json"), s); err != nil {
			return nil, fmt.Errorf("persist renewed certificate: %w", err)
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

// renewCredential renews the credential at path if it is due. The new key
// never leaves the device; only a certificate request is sent over the
// still-valid mutual-TLS connection.
func renewCredential(ctx context.Context, path string, cred core.Credential, client *agent.ConfigClient, now time.Time) (core.Credential, bool, error) {
	cert, err := credentialCertificate(cred)
	if err != nil {
		return cred, false, err
	}
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
	certPEM, err := client.Renew(ctx, request)
	if err != nil {
		return cred, false, err
	}
	renewed, err := core.CompleteEnrollment(cred.Server, cred.CA, certPEM, key)
	if err != nil {
		return cred, false, fmt.Errorf("controller returned an unusable certificate: %w", err)
	}
	if err := core.WriteJSON(path, renewed); err != nil {
		return cred, false, fmt.Errorf("certificate renewed but %s could not be updated; the device must be re-enrolled: %w", path, err)
	}
	return renewed, true, nil
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
