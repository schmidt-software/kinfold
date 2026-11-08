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
	s.renewInterval = 0
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

func TestRenewRateLimitPerCertificate(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	calls := 0
	s.SetRenewer(func(string, *x509.Certificate, []byte) ([]byte, error) { calls++; return nil, core.ErrRenewalNotDue })
	for i, want := range []int{http.StatusConflict, http.StatusTooManyRequests} {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, renewRequest(t, cfg, "csr"))
		if rec.Code != want {
			t.Fatalf("attempt %d: status %d, want %d", i, rec.Code, want)
		}
	}
	if calls != 1 {
		t.Fatalf("renewer called %d times, want 1", calls)
	}
}

func TestRenewAcceptsNonMemberCertificateForRetry(t *testing.T) {
	cfg := pairConfig(t)
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var gotID = "unset"
	s.SetRenewer(func(id string, _ *x509.Certificate, _ []byte) ([]byte, error) { gotID = id; return []byte("CERT"), nil })
	other := pairConfig(t) // different CA run, so not a member of cfg
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, renewRequest(t, other, "csr"))
	if rec.Code != http.StatusOK || gotID != "" {
		t.Fatalf("non-member renewal retry: status %d id %q", rec.Code, gotID)
	}
	get := httptest.NewRequest(http.MethodGet, "/config", nil)
	get.TLS = renewRequest(t, other, "").TLS
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, get)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-member reached /config: %d", rec.Code)
	}
}
