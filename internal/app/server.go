package app

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/schmidt-software/kinfold/internal/relay"
)

// serverTimeouts bound every phase of a controller connection before it is
// hijacked for relaying. Hijacking clears all deadlines, so established
// relay streams are not affected.
type serverTimeouts struct {
	// Handshake bounds the TLS handshake and reading the request header.
	// net/http derives the TLS handshake timeout from the smallest of
	// ReadHeaderTimeout, ReadTimeout and WriteTimeout.
	Handshake time.Duration
	Read      time.Duration
	Write     time.Duration
	// Idle closes keep-alive connections without a request. Without it,
	// net/http waits forever between requests (review R-01).
	Idle time.Duration
}

var defaultServerTimeouts = serverTimeouts{Handshake: 5 * time.Second, Read: 10 * time.Second, Write: 15 * time.Second, Idle: 60 * time.Second}

const maxRequestHeaderBytes = 16 << 10

// controllerKeepAlive detects dead peers in about 30 s instead of the
// default 15 s + 9 × 15 s (review R-04).
var controllerKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

func newControllerServer(handler http.Handler, tlsCfg *tls.Config, t serverTimeouts) *http.Server {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true) // relaying needs CONNECT hijacking; no implicit h2 (review R-03)
	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsCfg,
		Protocols:         protocols,
		ReadHeaderTimeout: t.Handshake,
		ReadTimeout:       t.Read,
		WriteTimeout:      t.Write,
		IdleTimeout:       t.Idle,
		MaxHeaderBytes:    maxRequestHeaderBytes,
	}
}

func listenController(ctx context.Context, address string, limits relay.ListenerLimits) (net.Listener, error) {
	lc := net.ListenConfig{KeepAliveConfig: controllerKeepAlive}
	ln, err := lc.Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	limited, err := relay.NewLimitedListener(ln, limits)
	if err != nil {
		ln.Close()
		return nil, err
	}
	return limited, nil
}
