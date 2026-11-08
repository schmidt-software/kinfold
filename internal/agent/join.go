package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

// NormalizeFingerprint accepts SHA-256 fingerprints as printed by kinfold
// (hex) or openssl (colon-separated, upper case).
func NormalizeFingerprint(fp string) (string, error) {
	fp = strings.ToLower(strings.ReplaceAll(strings.TrimPrefix(strings.TrimSpace(fp), "sha256:"), ":", ""))
	if len(fp) != 64 || strings.Trim(fp, "0123456789abcdef") != "" {
		return "", fmt.Errorf("CA fingerprint must be a SHA-256 value (64 hex digits)")
	}
	return fp, nil
}

// Join enrolls a device online with a single-use token. The controller is
// authenticated before the token is sent: its certificate chain must
// contain the CA whose SHA-256 fingerprint is caFingerprint, and the server
// certificate must be valid for the server's host name under that CA. It
// returns the new certificate and the pinned CA (both PEM).
func Join(ctx context.Context, server, caFingerprint, token string, request []byte) ([]byte, []byte, error) {
	if err := core.ValidateServerAddress(server); err != nil {
		return nil, nil, err
	}
	pin, err := NormalizeFingerprint(caFingerprint)
	if err != nil {
		return nil, nil, err
	}
	host, _, _ := net.SplitHostPort(server)
	var ca *x509.Certificate
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: true, // replaced by the pinned verification below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("controller sent no certificate")
			}
			for _, c := range cs.PeerCertificates[1:] {
				if c.IsCA && core.Fingerprint(c) == pin {
					ca = c
				}
			}
			if ca == nil {
				return fmt.Errorf("controller CA does not match the pinned fingerprint")
			}
			roots := x509.NewCertPool()
			roots.AddCert(ca)
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: host, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg, MaxResponseHeaderBytes: maxControllerResponseHeaderBytes, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	body, err := json.Marshal(struct {
		Token   string `json:"token"`
		Request []byte `json:"request"`
	}{token, request})
	if err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+server+"/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRenewalResponseBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("controller: %q: %q", resp.Status, bytes.TrimSpace(data))
	}
	if len(data) > maxRenewalResponseBytes {
		return nil, nil, fmt.Errorf("enrollment response exceeds %d bytes", maxRenewalResponseBytes)
	}
	return data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}), nil
}
