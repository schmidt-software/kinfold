package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

const maxControllerResponseHeaderBytes = 16 << 10

// clientKeepAlive detects a dead relay connection in about 30 s instead of
// the default 15 s + 9 × 15 s (review R-04).
var clientKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 5 * time.Second, Count: 3}

func outerTLS(c core.Credential) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(c.CA) {
		return nil, fmt.Errorf("invalid CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots, NextProtos: []string{"http/1.1"}}, nil
}

// ConfigClient fetches the configuration over one reusable mutual-TLS
// connection instead of a new handshake per poll (review A-04).
type ConfigClient struct {
	cred      core.Credential
	transport *http.Transport
	client    *http.Client
	err       error
}

func NewConfigClient(cred core.Credential) *ConfigClient {
	tlsCfg, err := outerTLS(cred)
	if err != nil {
		return &ConfigClient{cred: cred, err: err}
	}
	transport := &http.Transport{
		TLSClientConfig:        tlsCfg,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: maxControllerResponseHeaderBytes,
		MaxIdleConns:           1,
		MaxIdleConnsPerHost:    1,
		IdleConnTimeout:        30 * time.Second,
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: clientKeepAlive}).DialContext,
	}
	return &ConfigClient{cred: cred, transport: transport, client: &http.Client{Transport: transport, Timeout: 10 * time.Second}}
}

// Close releases the idle connection.
func (c *ConfigClient) Close() {
	if c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

const maxRenewalResponseBytes = 64 << 10

// Renew sends a certificate request for the credential's own device and
// returns the new certificate (PEM). The controller answers 409 while the
// current certificate is outside its renewal window.
func (c *ConfigClient) Renew(ctx context.Context, request []byte) ([]byte, error) {
	if c.err != nil {
		return nil, c.err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.cred.Server+"/renew", bytes.NewReader(request))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRenewalResponseBytes+1))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusConflict:
		return nil, core.ErrRenewalNotDue
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("controller: %q: %q", resp.Status, bytes.TrimSpace(body))
	case len(body) > maxRenewalResponseBytes:
		return nil, fmt.Errorf("renewal response exceeds %d bytes", maxRenewalResponseBytes)
	}
	return body, nil
}

// FetchConfig performs a single fetch on a fresh connection.
func FetchConfig(ctx context.Context, cred core.Credential) (core.Config, string, error) {
	c := NewConfigClient(cred)
	defer c.Close()
	return c.Fetch(ctx)
}

// Fetch retrieves and validates the configuration and returns the local
// peer ID that the credential's certificate belongs to.
func (c *ConfigClient) Fetch(ctx context.Context) (core.Config, string, error) {
	if c.err != nil {
		return core.Config{}, "", c.err
	}
	cred, client := c.cred, c.client
	tlsCfg := c.transport.TLSClientConfig
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+cred.Server+"/config", nil)
	if err != nil {
		return core.Config{}, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return core.Config{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return core.Config{}, "", fmt.Errorf("controller: %q", resp.Status)
	}
	var cfg core.Config
	if err := core.DecodeJSON(resp.Body, &cfg); err != nil {
		return cfg, "", err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, "", err
	}
	own, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		return cfg, "", err
	}
	for _, p := range cfg.Peers {
		pc, err := core.ParseCert(p.Cert)
		if err == nil && core.Fingerprint(pc) == core.Fingerprint(own) {
			return cfg, p.ID, nil
		}
	}
	return cfg, "", fmt.Errorf("own certificate is not authorized")
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func readRelayResponse(raw io.Reader, req *http.Request) (*http.Response, *bufio.Reader, error) {
	// Allow buffered read-ahead without counting tunnel bytes as HTTP headers.
	const budget = maxControllerResponseHeaderBytes + 4096
	limited := &io.LimitedReader{R: raw, N: budget}
	reader := bufio.NewReader(limited)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		if limited.N == 0 {
			return nil, nil, fmt.Errorf("relay response headers exceed %d bytes", maxControllerResponseHeaderBytes)
		}
		return nil, nil, fmt.Errorf("read relay response: %w", err)
	}
	consumed := budget - limited.N - int64(reader.Buffered())
	if consumed > maxControllerResponseHeaderBytes {
		return nil, nil, fmt.Errorf("relay response headers exceed %d bytes", maxControllerResponseHeaderBytes)
	}
	limited.N = math.MaxInt64
	return resp, reader, nil
}

func Connect(ctx context.Context, cred core.Credential, cfg core.Config, ownID string, peer core.Peer) (net.Conn, error) {
	tlsCfg, err := outerTLS(cred)
	if err != nil {
		return nil, err
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAliveConfig: clientKeepAlive}, Config: tlsCfg}
	raw, err := dialer.DialContext(ctx, "tcp", cred.Server)
	if err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() { raw.Close() })
	success := false
	defer func() {
		stopCancel()
		if !success {
			raw.Close()
		}
	}()
	if err := raw.SetDeadline(time.Now().Add(40 * time.Second)); err != nil {
		return nil, fmt.Errorf("set handshake deadline: %w", err)
	}
	revision, err := cfg.Revision()
	if err != nil {
		return nil, err
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Path: "/relay", RawQuery: url.Values{"peer": {peer.ID}}.Encode()}, Host: cred.Server, Header: http.Header{"X-Kinfold-Config-Revision": {revision}}}
	if err := req.Write(raw); err != nil {
		return nil, err
	}
	resp, reader, err := readRelayResponse(raw, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay: %q", resp.Status)
	}
	underlying := &bufferedConn{Conn: raw, reader: reader}
	peerCert, err := core.ParseCert(peer.Cert)
	if err != nil {
		return nil, err
	}
	expected := core.Fingerprint(peerCert)
	roots := tlsCfg.RootCAs
	var peerChain []*x509.Certificate
	verify := func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 || core.Fingerprint(cs.PeerCertificates[0]) != expected {
			return fmt.Errorf("peer certificate does not match authorized peer %s", peer.ID)
		}
		usage := x509.ExtKeyUsageServerAuth
		if ownID > peer.ID {
			usage = x509.ExtKeyUsageClientAuth
		}
		chains, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil {
			return err
		}
		peerChain = chains[0]
		return nil
	}
	innerCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       tlsCfg.Certificates,
		InsecureSkipVerify: true, // Certificate chain and exact peer pin are verified in VerifyConnection.
		VerifyConnection:   verify,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	var conn *tls.Conn
	if ownID < peer.ID {
		conn = tls.Client(underlying, innerCfg)
	} else {
		conn = tls.Server(underlying, innerCfg)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("peer TLS: %w", err)
	}
	outer, ok := raw.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("controller connection is not TLS")
	}
	chains := outer.ConnectionState().VerifiedChains
	if len(chains) == 0 || len(peerChain) == 0 {
		return nil, fmt.Errorf("verified certificate chain missing")
	}
	localCert, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse local certificate: %w", err)
	}
	certificates := append([]*x509.Certificate{localCert}, chains[0]...)
	certificates = append(certificates, peerChain...)
	deadline, expiry, err := setCertificateDeadline(raw, certificates)
	if err != nil {
		return nil, err
	}
	success = true
	return &certificateConn{Conn: conn, socket: raw, deadline: deadline, expiry: expiry}, nil
}

// A socket deadline alone does not stop reads from TLS's plaintext buffer.
type certificateConn struct {
	net.Conn
	// socket is the outer controller connection carrying the inner session.
	socket   net.Conn
	deadline time.Time
	expiry   time.Time
}

// clamp keeps caller deadlines from extending past certificate expiry; the
// socket deadline set at connect time would otherwise be overwritten.
func (c *certificateConn) clamp(t time.Time) time.Time {
	if c.deadline.IsZero() {
		return t
	}
	if t.IsZero() || t.After(c.deadline) {
		return c.deadline
	}
	return t
}

func (c *certificateConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(c.clamp(t))
}

func (c *certificateConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(c.clamp(t))
}

func (c *certificateConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(c.clamp(t))
}

// Close tears down the TCP socket first. Closing the two stacked TLS
// connections gracefully writes two close_notify records with 5 s deadlines
// each, which a dead path turns into a 10 s shutdown stall (review A-07).
func (c *certificateConn) Close() error {
	if c.socket != nil {
		if tc, ok := c.socket.(interface{ NetConn() net.Conn }); ok {
			tc.NetConn().Close()
		} else {
			c.socket.Close()
		}
	}
	return c.Conn.Close()
}

func (c *certificateConn) expired() bool {
	now := time.Now()
	return !now.Before(c.deadline) || !now.Before(c.expiry)
}

func (c *certificateConn) Read(p []byte) (int, error) {
	if c.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.Conn.Read(p)
	if c.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	return n, err
}

func (c *certificateConn) Write(p []byte) (int, error) {
	if c.expired() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.Conn.Write(p)
	if c.expired() && err == nil {
		return n, os.ErrDeadlineExceeded
	}
	return n, err
}

func setCertificateDeadline(conn net.Conn, certificates []*x509.Certificate) (time.Time, time.Time, error) {
	if len(certificates) == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("certificate deadline requires a verified chain")
	}
	now := time.Now()
	var earliest time.Time
	for _, cert := range certificates {
		if cert == nil || !cert.NotAfter.After(now) {
			return time.Time{}, time.Time{}, fmt.Errorf("certificate has expired")
		}
		if earliest.IsZero() || cert.NotAfter.Before(earliest) {
			earliest = cert.NotAfter
		}
	}
	// Preserve the elapsed-time limit if the wall clock moves backwards.
	deadline := now.Add(earliest.Sub(now))
	if err := conn.SetDeadline(deadline); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("set certificate deadline: %w", err)
	}
	return deadline, earliest, nil
}

func WritePacket(w io.Writer, packet []byte) error {
	if len(packet) == 0 || len(packet) > 65535 {
		return fmt.Errorf("invalid packet size %d", len(packet))
	}
	buf := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(buf, uint16(len(packet)))
	copy(buf[2:], packet)
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		buf = buf[n:]
	}
	return nil
}

func ReadPacket(r io.Reader) ([]byte, error) {
	return readPacketLimited(r, 65535)
}

func readPacketLimited(r io.Reader, limit int) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(header[:])
	if n == 0 {
		return nil, fmt.Errorf("empty packet")
	}
	if int(n) > limit {
		return nil, fmt.Errorf("packet size %d exceeds limit %d", n, limit)
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}
