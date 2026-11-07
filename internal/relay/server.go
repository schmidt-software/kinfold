package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
)

type pending struct {
	from   string
	conn   net.Conn
	match  chan net.Conn
	cancel chan struct{}
}

type endpoint struct {
	from string
	to   string
}

const (
	maxRelayEndpoints = 1024
	maxPeerEndpoints  = 32
)

type Server struct {
	config     core.Config
	mu         sync.Mutex
	waiting    map[string]*pending
	active     map[net.Conn]endpoint
	available  bool
	generation uint64
	closed     bool
}

func New(config core.Config) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Server{config: config, waiting: make(map[string]*pending), active: make(map[net.Conn]endpoint), available: true}, nil
}

// Update invalidates all existing sessions on changes or invalid state.
func (s *Server) Update(config core.Config, err error) error {
	if err == nil {
		err = config.Validate()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("relay is closed")
	}
	if err != nil {
		if s.available {
			s.invalidate()
		}
		s.available = false
		return err
	}
	if !s.available || !reflect.DeepEqual(s.config, config) {
		s.invalidate()
		s.config = config
	}
	s.available = true
	return nil
}

// Caller holds s.mu.
func (s *Server) invalidate() {
	s.generation++
	for _, p := range s.waiting {
		close(p.cancel)
	}
	s.waiting = make(map[string]*pending)
	for conn := range s.active {
		// Avoid blocking a configuration update on TLS close notifications.
		_ = conn.SetDeadline(time.Now())
		conn.Close()
	}
	s.active = make(map[net.Conn]endpoint)
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.available = false
	s.closed = true
	s.invalidate()
}

// Watch periodically reloads configuration. PKI changes require a full restart.
func (s *Server) Watch(done <-chan struct{}, initial *core.State, load func() (*core.State, error), interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	failed := false
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			next, err := load()
			if err == nil && (!bytes.Equal(initial.CA, next.CA) || !bytes.Equal(initial.CAKey, next.CAKey) || !bytes.Equal(initial.ServerCert, next.ServerCert) || !bytes.Equal(initial.ServerKey, next.ServerKey)) {
				err = fmt.Errorf("controller TLS identity changed; restart required")
			}
			var cfg core.Config
			if err == nil {
				cfg = next.Config
			}
			if err = s.Update(cfg, err); err != nil {
				if !failed {
					slog.Error("controller configuration unavailable; relay closed", "error", err)
				}
				failed = true
			} else if failed {
				slog.Info("controller configuration restored")
				failed = false
			}
		}
	}
}

func TLSConfig(s *core.State) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CA) {
		return nil, fmt.Errorf("invalid CA")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots,
		NextProtos: []string{"http/1.1"},
	}, nil
}

func identity(r *http.Request, config core.Config) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	fp := core.Fingerprint(r.TLS.PeerCertificates[0])
	for _, peer := range config.Peers {
		cert, err := core.ParseCert(peer.Cert)
		if err == nil && core.Fingerprint(cert) == fp {
			return peer.ID, true
		}
	}
	return "", false
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	config, available, generation := s.config, s.available, s.generation
	s.mu.Unlock()
	if !available {
		reject(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	id, ok := identity(r, config)
	if !ok {
		reject(w, "not authorized", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/config":
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(config); err != nil {
			slog.Warn("config response failed", "error", err)
		}
	case r.Method == http.MethodConnect && r.URL.Path == "/relay":
		target := r.URL.Query().Get("peer")
		if _, ok := config.Peer(target); !ok || id == target {
			reject(w, "invalid target", http.StatusBadRequest)
			return
		}
		s.connect(w, r, id, target, generation)
	default:
		reject(w, "not found", http.StatusNotFound)
	}
}

// reject answers with an error and closes the connection afterwards. A
// rejected client (unknown, removed or misbehaving) must not keep an idle
// keep-alive connection and with it a listener slot (review R-01).
func reject(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request, from, to string, generation uint64) {
	key := from + "\x00" + to
	reverse := to + "\x00" + from
	s.mu.Lock()
	if !s.available || s.generation != generation {
		s.mu.Unlock()
		reject(w, "configuration changed", http.StatusServiceUnavailable)
		return
	}
	if s.config.Policy != nil {
		revision, err := s.config.Revision()
		if err != nil || r.Header.Get("X-Kinfold-Config-Revision") != revision {
			s.mu.Unlock()
			reject(w, "current policy configuration required", http.StatusConflict)
			return
		}
		if !s.config.Permits(from, to) && !s.config.Permits(to, from) {
			s.mu.Unlock()
			reject(w, "peer pair not authorized", http.StatusForbidden)
			return
		}
	}
	if s.waiting[key] != nil {
		s.mu.Unlock()
		reject(w, "relay busy", http.StatusConflict)
		return
	}
	if status := s.admissionStatus(from, to); status != 0 {
		s.mu.Unlock()
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "2")
		}
		reject(w, "relay connection limit reached", status)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.mu.Unlock()
		reject(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		s.mu.Unlock()
		slog.Warn("relay hijack failed", "error", err)
		return
	}
	if rw.Reader.Buffered() != 0 {
		s.mu.Unlock()
		conn.Close()
		return
	}
	s.active[conn] = endpoint{from: from, to: to}
	s.mu.Unlock()
	defer func() {
		if err != nil {
			conn.Close()
			s.forget(conn)
		}
	}()
	if err = conn.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		slog.Warn("relay response deadline failed", "error", err)
		return
	}
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err = rw.Flush(); err != nil {
		return
	}
	if err = conn.SetWriteDeadline(time.Time{}); err != nil {
		slog.Warn("clearing relay response deadline failed", "error", err)
		return
	}
	s.mu.Lock()
	if !s.available || s.generation != generation {
		s.mu.Unlock()
		conn.Close()
		s.forget(conn)
		return
	}
	other := s.waiting[reverse]
	if other != nil {
		delete(s.waiting, reverse)
		other.match <- conn
		s.mu.Unlock()
		return
	}
	p := &pending{from: from, conn: conn, match: make(chan net.Conn, 1), cancel: make(chan struct{})}
	s.waiting[key] = p
	s.mu.Unlock()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case peerConn := <-p.match:
		bridge(conn, peerConn)
		s.forget(conn, peerConn)
	case <-p.cancel:
		conn.Close()
	case <-timer.C:
		s.mu.Lock()
		if s.waiting[key] == p {
			delete(s.waiting, key)
			s.mu.Unlock()
			conn.Close()
			s.forget(conn)
			return
		}
		s.mu.Unlock()
		select {
		case peerConn := <-p.match:
			bridge(conn, peerConn)
			s.forget(conn, peerConn)
		case <-p.cancel:
			conn.Close()
		}
	}
}

// admissionStatus runs while holding s.mu. Counts include waiting and bridged endpoints.
func (s *Server) admissionStatus(from, to string) int {
	if len(s.active) >= maxRelayEndpoints {
		return http.StatusTooManyRequests
	}
	count := 0
	for _, current := range s.active {
		if current.from == from {
			count++
			if current.to == to {
				return http.StatusConflict
			}
		}
	}
	if count >= maxPeerEndpoints {
		return http.StatusTooManyRequests
	}
	return 0
}

func (s *Server) forget(conns ...net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range conns {
		delete(s.active, conn)
	}
}

func bridge(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	a.Close()
	b.Close()
	<-done
}
