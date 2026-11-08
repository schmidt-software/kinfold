package core

import (
	"strings"
	"testing"
)

func TestOnePEMToleratesLineEndings(t *testing.T) {
	_, request, err := NewEnrollment("alice")
	if err != nil {
		t.Fatal(err)
	}
	crlf := []byte(strings.ReplaceAll(string(request), "\n", "\r\n"))
	for name, input := range map[string][]byte{
		"LF":       request,
		"CRLF":     crlf,
		"trailing": append(append([]byte(nil), request...), '\n', '\n'),
	} {
		if _, err := onePEM(input, "CERTIFICATE REQUEST"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	two := append(append([]byte(nil), request...), request...)
	if _, err := onePEM(two, "CERTIFICATE REQUEST"); err == nil {
		t.Error("accepted two PEM blocks")
	}
	if _, err := onePEM([]byte("junk\n"+string(request)), "CERTIFICATE REQUEST"); err == nil {
		t.Error("accepted leading garbage")
	}
}
