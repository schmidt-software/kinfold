package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/metrics"
)

// Direct path (D-026). A device that accepts direct sessions listens on a
// TCP port; peers dial it with the same mutual TLS 1.3 and the same checks
// as the inner session through the relay (exact certificate pin, CA chain,
// role key usage, certificate deadlines). The dialing side is the TLS
// client. Authorization is checked against the acceptor's current signed
// configuration; configuration updates restart affected links and the lease
// ends the whole agent, so revocation does not depend on the relay.

const (
	directDialTimeout      = 3 * time.Second
	directHandshakeTimeout = 5 * time.Second
	maxPendingHandshakes   = 16
	maxPendingPerSource    = 2
	// acceptedMarker is written by the accepting side once it has taken the
	// session; in TLS 1.3 the dialer's handshake completes before the
	// acceptor has checked its certificate (v0.4 review finding 6).
	acceptedMarker = 0x01
)

// Option configures RunWithUpdates.
type Option func(*options)

type options struct {
	listenAddr string
	endpoints  func(peer string) []string
}

// WithDirect enables direct sessions: the agent accepts them on listenAddr
// (empty: dial only) and dials peers at the signed addresses that endpoints
// returns.
func WithDirect(listenAddr string, endpoints func(peer string) []string) Option {
	return func(o *options) { o.listenAddr, o.endpoints = listenAddr, endpoints }
}

func peerPath(peer, path string) *metrics.Gauge {
	return Metrics.Gauge("kinfold_peer_path", "1 for the path currently used to reach the peer.", metrics.Labels{"peer": peer, "path": path})
}

// verifyPeer pins the peer certificate and verifies its chain and usage; it
// records the verified chain for the certificate deadline.
func verifyPeer(roots *x509.CertPool, expected string, usage x509.ExtKeyUsage, chain *[]*x509.Certificate) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || core.Fingerprint(cs.PeerCertificates[0]) != expected {
			return fmt.Errorf("peer certificate does not match the authorized peer")
		}
		chains, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil {
			return err
		}
		*chain = chains[0]
		return nil
	}
}

// dialDirect opens a direct session to peer at addr.
func dialDirect(ctx context.Context, cred core.Credential, peer core.Peer, addr string) (net.Conn, error) {
	outer, err := outerTLS(cred)
	if err != nil {
		return nil, err
	}
	peerCert, err := core.ParseCert(peer.Cert)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       outer.Certificates,
		InsecureSkipVerify: true, // pin, chain and usage are verified in VerifyConnection
		VerifyConnection:   verifyPeer(outer.RootCAs, core.Fingerprint(peerCert), x509.ExtKeyUsageServerAuth, &chain),
	}
	dialCtx, cancel := context.WithTimeout(ctx, directDialTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{KeepAliveConfig: clientKeepAlive}, Config: cfg}
	raw, err := d.DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := raw.(*tls.Conn)
	marker := []byte{0}
	if err := conn.SetReadDeadline(time.Now().Add(directHandshakeTimeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := io.ReadFull(conn, marker); err != nil || marker[0] != acceptedMarker {
		conn.Close()
		if err == nil {
			err = fmt.Errorf("unexpected acceptance marker")
		}
		return nil, fmt.Errorf("peer did not accept the direct session: %w", err)
	}
	return withCertificateDeadline(conn, outer, chain)
}

func withCertificateDeadline(conn *tls.Conn, own *tls.Config, peerChain []*x509.Certificate) (net.Conn, error) {
	local, err := x509.ParseCertificate(own.Certificates[0].Certificate[0])
	if err != nil {
		conn.Close()
		return nil, err
	}
	deadline, expiry, err := setCertificateDeadline(conn.NetConn(), append([]*x509.Certificate{local}, peerChain...))
	if err != nil {
		conn.Close()
		return nil, err
	}
	return &certificateConn{Conn: conn, socket: conn, deadline: deadline, expiry: expiry}, nil
}

// acceptDirect serves direct sessions until ctx ends. lookup maps a peer
// certificate fingerprint to the link authorized for it right now.
func acceptDirect(ctx context.Context, ln net.Listener, cred core.Credential, lookup func(fingerprint string) *link) {
	own, err := outerTLS(cred)
	if err != nil {
		slog.Error("direct sessions disabled", "error", err)
		return
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	pending := make(chan struct{}, maxPendingHandshakes)
	var mu sync.Mutex
	perSource := map[string]int{}
	var handshakes sync.WaitGroup
	defer handshakes.Wait()
	for {
		raw, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("direct listener stopped", "error", err)
			}
			return
		}
		source := remoteHost(raw)
		mu.Lock()
		busy := perSource[source] >= maxPendingPerSource
		if !busy {
			perSource[source]++
		}
		mu.Unlock()
		if busy {
			raw.Close() // one source may not hold all handshake slots (finding 5)
			continue
		}
		select {
		case pending <- struct{}{}:
		default:
			mu.Lock()
			perSource[source]--
			mu.Unlock()
			raw.Close() // too many unauthenticated handshakes in flight
			continue
		}
		handshakes.Add(1)
		go func() {
			defer handshakes.Done()
			defer func() {
				<-pending
				mu.Lock()
				if perSource[source]--; perSource[source] <= 0 {
					delete(perSource, source)
				}
				mu.Unlock()
			}()
			var target *link
			var chain []*x509.Certificate
			cfg := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: own.Certificates,
				ClientAuth:   tls.RequireAnyClientCert,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return fmt.Errorf("no client certificate")
					}
					fp := core.Fingerprint(cs.PeerCertificates[0])
					if target = lookup(fp); target == nil {
						return fmt.Errorf("certificate is not authorized for a direct session")
					}
					return verifyPeer(own.RootCAs, fp, x509.ExtKeyUsageClientAuth, &chain)(cs)
				},
			}
			conn := tls.Server(raw, cfg)
			hsCtx, cancel := context.WithTimeout(ctx, directHandshakeTimeout)
			err := conn.HandshakeContext(hsCtx)
			cancel()
			if err != nil {
				raw.Close()
				return
			}
			session, err := withCertificateDeadline(conn, own, chain)
			if err != nil {
				return
			}
			if !deliver(target, session) {
				session.Close()
			}
		}()
	}
}

// deliver hands an established direct session to its link: it confirms
// acceptance to the peer and passes the session on, unless the link stopped.
func deliver(l *link, session net.Conn) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	if err := session.SetWriteDeadline(time.Now().Add(directHandshakeTimeout)); err != nil {
		return false
	}
	if _, err := session.Write([]byte{acceptedMarker}); err != nil {
		return false
	}
	if err := session.SetWriteDeadline(time.Time{}); err != nil {
		return false
	}
	select {
	case l.incoming <- session:
		return true
	case <-l.done:
		return false
	case <-time.After(directHandshakeTimeout):
		return false
	}
}

func remoteHost(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}
