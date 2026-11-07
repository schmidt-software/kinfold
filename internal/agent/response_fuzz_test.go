package agent

import (
	"bytes"
	"net/http"
	"testing"
)

func FuzzRelayResponse(f *testing.F) {
	f.Add([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("HTTP/1.1 200 OK\r\nX:"))
	f.Fuzz(func(t *testing.T, data []byte) {
		resp, reader, err := readRelayResponse(bytes.NewReader(data), &http.Request{Method: http.MethodConnect})
		if err == nil && (resp == nil || reader == nil) {
			t.Fatal("successful response has no response or reader")
		}
	})
}
