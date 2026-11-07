package agent

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRelayResponseHeaderLimit(t *testing.T) {
	req := &http.Request{Method: http.MethodConnect}
	prefix := "HTTP/1.1 200 Connection Established\r\nX-Test: "
	suffix := "\r\n\r\n"
	for _, size := range []int{maxControllerResponseHeaderBytes - 1, maxControllerResponseHeaderBytes, maxControllerResponseHeaderBytes + 1, maxControllerResponseHeaderBytes + 5000} {
		header := prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
		t.Run(strings.Repeat("x", size%7+1), func(t *testing.T) {
			payload := bytes.Repeat([]byte{42}, 10000)
			resp, reader, err := readRelayResponse(bytes.NewReader(append([]byte(header), payload...)), req)
			if size > maxControllerResponseHeaderBytes {
				if err == nil || !strings.Contains(err.Error(), "exceed") {
					t.Fatalf("size %d: expected limit error, got %v", size, err)
				}
				return
			}
			if err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("size %d: response %v, error %v", size, resp, err)
			}
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("size %d: buffered tunnel data lost: %v", size, err)
			}
		})
	}
}

func TestRelayResponseRejectsTruncatedHeader(t *testing.T) {
	_, _, err := readRelayResponse(strings.NewReader("HTTP/1.1 200 OK\r\nX: incomplete"), &http.Request{Method: http.MethodConnect})
	if err == nil {
		t.Fatal("accepted truncated response")
	}
}
