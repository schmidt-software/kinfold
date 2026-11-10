package relay

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A busy controller blocks the source like a failed attempt, so the
// Retry-After header must name that time, not a shorter one (#149).
func TestEnrollBusyNamesTheBlockTime(t *testing.T) {
	s, err := New(pairConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetEnroller(func(string, []byte) (string, []byte, error) { return "", nil, ErrBusy })
	enroll := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enroll", strings.NewReader(`{"token":"t","request":"YQ=="}`)))
		return rec
	}
	if rec := enroll(); rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("busy controller: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	if rec := enroll(); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "30" {
		t.Fatalf("retry within the block: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
}
