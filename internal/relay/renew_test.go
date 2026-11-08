package relay

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/schmidt-software/kinfold/internal/core"
)

func renewRequest(t *testing.T, cfg core.Config, body string) *http.Request {
	t.Helper()
	cert, err := x509.ParseCertificate(cfg.Peers[0].Cert)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/renew", strings.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func TestRenewEndpoint(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	serve := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, renewRequest(t, cfg, body))
		return rec
	}
	if rec := serve("csr"); rec.Code != http.StatusNotFound {
		t.Fatalf("renewal without a renewer: %d", rec.Code)
	}
	var gotID string
	var result []byte
	var resultErr error
	s.SetRenewer(func(id string, presented *x509.Certificate, request []byte) ([]byte, error) {
		gotID = id
		return result, resultErr
	})
	result = []byte("CERT")
	if rec := serve("csr"); rec.Code != http.StatusOK || rec.Body.String() != "CERT" || gotID != "alice" {
		t.Fatalf("successful renewal: %d %q id=%q", rec.Code, rec.Body.String(), gotID)
	}
	for err, want := range map[error]int{
		core.ErrRenewalNotDue: http.StatusConflict,
		ErrBusy:               http.StatusServiceUnavailable,
		errors.New("bad key"): http.StatusBadRequest,
	} {
		resultErr = err
		if rec := serve("csr"); rec.Code != want || rec.Header().Get("Connection") != "close" {
			t.Errorf("%v: status %d, want %d", err, rec.Code, want)
		}
	}
	resultErr = nil
	if rec := serve(strings.Repeat("x", maxRenewalRequestBytes+1)); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized renewal request: %d", rec.Code)
	}
}
