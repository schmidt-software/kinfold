package relay

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/metrics"
)

type pending struct {
	from   string
	to     string
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

// Renewer issues a new device certificate for an authenticated member. It is
// called without the relay lock and performs its own state locking.
type Renewer func(id string, presented *x509.Certificate, request []byte) ([]byte, error)

// ErrBusy tells the relay to answer 503 so the device retries later.
var ErrBusy = errors.New("controller busy")

const maxRenewalRequestBytes = 64 << 10

// defaultPairingTimeout bounds how long a relay endpoint waits for its partner.
const defaultPairingTimeout = 30 * time.Second

type Server struct {
	metrics        *metrics.Registry
	renew          Renewer
	enroll         Enroller
	renewFailures  map[string]time.Time // certificate fingerprint -> last failed renewal
	renewInterval  time.Duration
	pairingTimeout time.Duration
	config         core.Config
	revision       string            // config.Revision(), computed once per update
	members        map[string]string // certificate fingerprint -> peer ID
	views          map[string]view   // peer ID -> configuration that peer sees
	mu             sync.Mutex
	waiting        map[string]*pending
	active         map[net.Conn]endpoint
	available      bool
	generation     uint64
	closed         bool
}

func New(config core.Config) (*Server, error) {
	config = config.Clone()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	revision, members, views, err := derive(config)
	if err != nil {
		return nil, err
	}
	s := &Server{metrics: metrics.New(), pairingTimeout: defaultPairingTimeout, renewInterval: defaultRenewalInterval, config: config, revision: revision, members: members, views: views, waiting: make(map[string]*pending), active: make(map[net.Conn]endpoint), available: true}
	s.registerMetrics()
	return s, nil
}

// Metrics returns the relay's metrics registry.
func (s *Server) Metrics() *metrics.Registry { return s.metrics }

func (s *Server) registerMetrics() {
	locked := func(fn func() float64) func() float64 {
		return func() float64 { s.mu.Lock(); defer s.mu.Unlock(); return fn() }
	}
	s.metrics.GaugeFunc("kinfold_relay_endpoints", "Relay endpoints currently waiting or bridged.", nil, locked(func() float64 { return float64(len(s.active)) }))
	s.metrics.GaugeFunc("kinfold_relay_waiting", "Relay endpoints waiting for their partner.", nil, locked(func() float64 { return float64(len(s.waiting)) }))
	s.metrics.GaugeFunc("kinfold_config_available", "1 while the controller serves a valid configuration.", nil, locked(func() float64 {
		if s.available {
			return 1
		}
		return 0
	}))
	s.metrics.GaugeFunc("kinfold_peers", "Authorized devices in the configuration.", nil, locked(func() float64 { return float64(len(s.config.Peers)) }))
}

func (s *Server) count(name, help string, labels metrics.Labels) {
	s.metrics.Counter(name, help, labels).Inc()
}

// view is the configuration one device receives and its revision, which the
// device presents when it opens a relay session.
type view struct {
	config   core.Config
	revision string
}

// derive precomputes the per-request lookups for a validated configuration
// so requests do not parse certificates or marshal the configuration under
// the relay lock (review R-07).
func derive(config core.Config) (string, map[string]string, map[string]view, error) {
	revision, err := config.Revision()
	if err != nil {
		return "", nil, nil, err
	}
	members := make(map[string]string, len(config.Peers))
	views := make(map[string]view, len(config.Peers))
	for _, peer := range config.Peers {
		cert, err := core.ParseCert(peer.Cert)
		if err != nil {
			return "", nil, nil, fmt.Errorf("peer %s: %w", peer.ID, err)
		}
		members[core.Fingerprint(cert)] = peer.ID
		v := config.ForPeer(peer.ID)
		r, err := v.Revision()
		if err != nil {
			return "", nil, nil, err
		}
		views[peer.ID] = view{config: v, revision: r}
	}
	return revision, members, views, nil
}

// Update applies a new configuration. Invalid state closes every session;
// a valid change closes only the sessions of device pairs whose
// authorization changed (review R-09).
func (s *Server) Update(config core.Config, err error) error {
	var revision string
	var members map[string]string
	var views map[string]view
	config = config.Clone()
	if err == nil {
		err = config.Validate()
	}
	if err == nil {
		revision, members, views, err = derive(config)
	}
	var stale []net.Conn
	defer func() { forceClose(stale...) }()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("relay is closed")
	}
	if err != nil {
		if s.available {
			stale = s.invalidate()
		}
		s.available = false
		s.count("kinfold_config_reloads_total", "Configuration reloads, by result.", metrics.Labels{"result": "failed"})
		s.metrics.Counter("kinfold_relay_sessions_closed_total", "Relay endpoints closed by the controller, by reason.", metrics.Labels{"reason": "unavailable"}).Add(uint64(len(stale)))
		return err
	}
	if s.revision == revision && s.available {
		s.count("kinfold_config_reloads_total", "Configuration reloads, by result.", metrics.Labels{"result": "unchanged"})
	} else {
		s.count("kinfold_config_reloads_total", "Configuration reloads, by result.", metrics.Labels{"result": "applied"})
	}
	defer func() {
		s.metrics.Counter("kinfold_relay_sessions_closed_total", "Relay endpoints closed by the controller, by reason.", metrics.Labels{"reason": "config_change"}).Add(uint64(len(stale)))
	}()
	if !s.available {
		stale = s.invalidate()
		s.config, s.revision, s.members, s.views = config, revision, members, views
	} else if s.revision != revision {
		stale = s.invalidatePairs(s.config, config)
		s.config, s.revision, s.members, s.views = config, revision, members, views
	}
	s.available = true
	return nil
}

// invalidate ends all pairings and returns the connections the caller must
// close with forceClose after releasing s.mu. Caller holds s.mu.
func (s *Server) invalidate() []net.Conn {
	s.generation++
	for _, p := range s.waiting {
		close(p.cancel)
	}
	s.waiting = make(map[string]*pending)
	stale := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		stale = append(stale, conn)
	}
	s.active = make(map[net.Conn]endpoint)
	return stale
}

// forceClose tears connections down without a TLS close_notify. Closing a
// *tls.Conn writes close_notify with its own 5 s deadline, which a peer that
// stops reading can exhaust (review R-05); the relay never needs a graceful
// TLS shutdown for a session it revokes.
func forceClose(conns ...net.Conn) {
	for _, conn := range conns {
		if tc, ok := conn.(interface{ NetConn() net.Conn }); ok {
			tc.NetConn().Close()
		}
		conn.Close()
	}
}

// defaultRenewalInterval is how long a certificate must wait after a failed
// renewal attempt; each attempt may take the controller's state lock
// (change review finding 7). Successful attempts are not limited, so a
// device can collect a certificate whose response was lost right away.
const defaultRenewalInterval = 30 * time.Second

func (s *Server) renewalBlocked(fingerprint string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for fp, last := range s.renewFailures {
		if now.Sub(last) >= s.renewInterval {
			delete(s.renewFailures, fp)
		}
	}
	_, blocked := s.renewFailures[fingerprint]
	return blocked
}

func (s *Server) noteRenewalFailure(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.renewFailures == nil {
		s.renewFailures = make(map[string]time.Time)
	}
	s.renewFailures[fingerprint] = time.Now()
}

// SetRenewer enables POST /renew. It must be called before serving.
func (s *Server) SetRenewer(r Renewer) { s.renew = r }

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, id string) {
	if s.renew == nil {
		s.reject(w, "not found", http.StatusNotFound)
		return
	}
	presented := r.TLS.PeerCertificates[0]
	fingerprint := core.Fingerprint(presented)
	if s.renewalBlocked(fingerprint) {
		w.Header().Set("Retry-After", "30")
		s.reject(w, "renewal recently failed; retry later", http.StatusTooManyRequests)
		return
	}
	request, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRenewalRequestBytes))
	if err != nil {
		s.reject(w, "renewal request too large or unreadable", http.StatusBadRequest)
		return
	}
	cert, err := s.renew(id, presented, request)
	if err != nil && !errors.Is(err, ErrBusy) {
		s.noteRenewalFailure(fingerprint)
	}
	switch {
	case errors.Is(err, core.ErrRenewalNotDue):
		s.reject(w, err.Error(), http.StatusConflict)
		return
	case errors.Is(err, ErrBusy):
		w.Header().Set("Retry-After", "5")
		s.reject(w, "controller busy; retry later", http.StatusServiceUnavailable)
		return
	case err != nil:
		slog.Warn("certificate renewal rejected", "peer", id, "error", err)
		s.reject(w, "renewal rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("device certificate renewed", "peer", id)
	s.count("kinfold_renewals_total", "Device certificates issued by online renewal.", nil)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Connection", "close")
	if _, err := w.Write(cert); err != nil {
		slog.Warn("renewal response failed", "peer", id, "error", err)
	}
}

// invalidatePairs ends the waiting and active endpoints of every pair whose
// PairSignature differs between old and next, and returns the connections to
// close after releasing s.mu. Caller holds s.mu.
func (s *Server) invalidatePairs(old, next core.Config) []net.Conn {
	changed := map[[2]string]bool{}
	pairChanged := func(from, to string) bool {
		key := [2]string{from, to}
		if from > to {
			key = [2]string{to, from}
		}
		c, ok := changed[key]
		if !ok {
			c = old.PairSignature(from, to) != next.PairSignature(from, to)
			changed[key] = c
		}
		return c
	}
	for key, p := range s.waiting {
		if pairChanged(p.from, p.to) {
			close(p.cancel)
			delete(s.waiting, key)
		}
	}
	var stale []net.Conn
	for conn, e := range s.active {
		if pairChanged(e.from, e.to) {
			delete(s.active, conn)
			stale = append(stale, conn)
		}
	}
	return stale
}

func (s *Server) Close() {
	s.mu.Lock()
	s.available = false
	s.closed = true
	stale := s.invalidate()
	s.mu.Unlock()
	forceClose(stale...)
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

// TLSConfig is the controller's TLS configuration. The CA certificate is
// sent with the server certificate so a device enrolling with a token can
// verify the controller against a pinned CA fingerprint before it reveals
// the token. Client certificates are verified when given; every endpoint
// except POST /enroll requires one (D-024).
func TLSConfig(s *core.State) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(s.ServerCert, s.ServerKey)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.CA) {
		return nil, fmt.Errorf("invalid CA")
	}
	caPair, err := tls.X509KeyPair(s.CA, s.CAKey)
	if err != nil {
		return nil, err
	}
	cert.Certificate = append(cert.Certificate, caPair.Certificate[0])
	return &tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: roots,
		NextProtos: []string{"http/1.1"},
	}, nil
}

// Enroller consumes an enrollment token for a certificate request and
// returns the new device's ID and certificate. It does its own locking.
type Enroller func(token string, request []byte) (string, []byte, error)

// SetEnroller enables POST /enroll. It must be called before serving.
func (s *Server) SetEnroller(e Enroller) { s.enroll = e }

type enrollRequest struct {
	Token   string `json:"token"`
	Request []byte `json:"request"`
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if s.enroll == nil {
		s.reject(w, "not found", http.StatusNotFound)
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	// Throttle per IPv4 address or IPv6 /64, like the listener limits
	// (v0.3 review finding 1).
	source := "enroll:" + sourceKey(host)
	if s.renewalBlocked(source) {
		w.Header().Set("Retry-After", "30")
		s.reject(w, "enrollment recently failed; retry later", http.StatusTooManyRequests)
		return
	}
	var req enrollRequest
	if err := core.DecodeJSON(http.MaxBytesReader(w, r.Body, maxRenewalRequestBytes), &req); err != nil {
		s.noteRenewalFailure(source)
		s.reject(w, "invalid enrollment request", http.StatusBadRequest)
		return
	}
	id, cert, err := s.enroll(req.Token, req.Request)
	switch {
	case errors.Is(err, ErrBusy):
		s.noteRenewalFailure(source) // unauthenticated callers must not keep the lock busy
		w.Header().Set("Retry-After", "5")
		s.reject(w, "controller busy; retry later", http.StatusServiceUnavailable)
		return
	case errors.Is(err, core.ErrTokenInvalid):
		s.noteRenewalFailure(source)
		slog.Warn("enrollment with an invalid token", "source", host)
		s.reject(w, err.Error(), http.StatusForbidden)
		return
	case err != nil:
		s.noteRenewalFailure(source)
		slog.Warn("enrollment rejected", "source", host, "error", err)
		s.reject(w, "enrollment rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("device enrolled with token", "peer", id, "source", host)
	s.count("kinfold_enrollments_total", "Devices enrolled with a token.", nil)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Connection", "close")
	_, _ = w.Write(cert)
}

func identity(r *http.Request, members map[string]string) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	id, ok := members[core.Fingerprint(r.TLS.PeerCertificates[0])]
	return id, ok
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	members, views, available, generation := s.members, s.views, s.available, s.generation
	s.mu.Unlock()
	if !available {
		s.reject(w, "configuration unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/enroll" && (r.TLS == nil || len(r.TLS.PeerCertificates) == 0) {
		s.handleEnroll(w, r)
		return
	}
	id, ok := identity(r, members)
	if !ok {
		// A device whose renewal response was lost presents its previous,
		// CA-signed certificate; the renewer decides whether it may collect
		// the certificate that was already issued (D-018).
		if r.Method == http.MethodPost && r.URL.Path == "/renew" && s.renew != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			s.handleRenew(w, r, "")
			return
		}
		s.reject(w, "not authorized", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/config":
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(views[id].config); err != nil {
			slog.Warn("config response failed", "error", err)
		}
	case r.Method == http.MethodPost && r.URL.Path == "/renew":
		s.handleRenew(w, r, id)
	case r.Method == http.MethodConnect && r.URL.Path == "/relay":
		target := r.URL.Query().Get("peer")
		// Devices outside the caller's view get the same answer as
		// unauthorized pairs, so their existence is not disclosed (D-023).
		if _, ok := views[id].config.Peer(target); !ok || id == target {
			s.reject(w, "peer pair not authorized", http.StatusForbidden)
			return
		}
		s.connect(w, r, id, target, generation)
	default:
		s.reject(w, "not found", http.StatusNotFound)
	}
}

// reject answers with an error and closes the connection afterwards. A
// rejected client (unknown, removed or misbehaving) must not keep an idle
// keep-alive connection and with it a listener slot (review R-01).
func (s *Server) reject(w http.ResponseWriter, message string, status int) {
	s.metrics.Counter("kinfold_relay_rejections_total", "Requests rejected by the controller, by HTTP status.", metrics.Labels{"status": strconv.Itoa(status)}).Inc()
	w.Header().Set("Connection", "close")
	http.Error(w, message, status)
}

func (s *Server) connect(w http.ResponseWriter, r *http.Request, from, to string, generation uint64) {
	key := from + "\x00" + to
	reverse := to + "\x00" + from
	s.mu.Lock()
	if !s.available || s.generation != generation {
		s.mu.Unlock()
		s.reject(w, "configuration changed", http.StatusServiceUnavailable)
		return
	}
	if r.Header.Get("X-Kinfold-Config-Revision") != s.views[from].revision {
		s.mu.Unlock()
		s.reject(w, "current configuration required", http.StatusConflict)
		return
	}
	if !s.config.Permits(from, to) && !s.config.Permits(to, from) {
		s.mu.Unlock()
		s.reject(w, "peer pair not authorized", http.StatusForbidden)
		return
	}
	// Remember the pair's authorization; if it changes before this endpoint
	// is queued, the endpoint must not be used (sessions of unchanged pairs
	// survive configuration changes, so the generation alone is not enough).
	pairSig := s.config.PairSignature(from, to)
	// The authenticated device reconnects for this ordered pair, so any
	// session it still holds for the pair is stale (crash, NAT timeout).
	// Supersede it instead of rejecting the reconnect until TCP keepalive
	// notices the dead connection (review R-06).
	superseded := s.supersede(from, to)
	if len(superseded) > 0 {
		s.metrics.Counter("kinfold_relay_sessions_closed_total", "Relay endpoints closed by the controller, by reason.", metrics.Labels{"reason": "superseded"}).Add(uint64(len(superseded)))
	}
	if status := s.admissionStatus(from); status != 0 {
		s.mu.Unlock()
		forceClose(superseded...)
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "2")
		}
		s.reject(w, "relay connection limit reached", status)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		s.mu.Unlock()
		forceClose(superseded...)
		s.reject(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		s.mu.Unlock()
		forceClose(superseded...)
		slog.Warn("relay hijack failed", "error", err)
		return
	}
	if rw.Reader.Buffered() != 0 {
		s.mu.Unlock()
		forceClose(superseded...)
		conn.Close()
		return
	}
	s.active[conn] = endpoint{from: from, to: to}
	s.mu.Unlock()
	forceClose(superseded...)
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
	// The 200 response was written without the lock. Meanwhile the
	// configuration may have changed, or a newer connection of the same
	// device may have superseded this one; then it must not become the
	// waiter (change review finding 3).
	_, stillActive := s.active[conn]
	if !s.available || s.generation != generation || !stillActive || s.config.PairSignature(from, to) != pairSig {
		s.mu.Unlock()
		forceClose(conn)
		s.forget(conn)
		return
	}
	other := s.waiting[reverse]
	if other != nil {
		s.count("kinfold_relay_pairings_total", "Relay endpoint pairs bridged.", nil)
		delete(s.waiting, reverse)
		other.match <- conn
		s.mu.Unlock()
		return
	}
	p := &pending{from: from, to: to, conn: conn, match: make(chan net.Conn, 1), cancel: make(chan struct{})}
	var replaced net.Conn
	if old := s.waiting[key]; old != nil {
		// Never overwrite a waiter without releasing it; its goroutine would
		// otherwise wait forever.
		close(old.cancel)
		delete(s.active, old.conn)
		replaced = old.conn
	}
	s.waiting[key] = p
	s.mu.Unlock()
	if replaced != nil {
		forceClose(replaced)
	}
	timer := time.NewTimer(s.pairingTimeout)
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

// supersede removes every waiting or active endpoint of the ordered pair and
// returns the connections to close after s.mu is released. Bridged partner
// connections end when their bridge sees the closed side. Caller holds s.mu.
func (s *Server) supersede(from, to string) []net.Conn {
	key := from + "\x00" + to
	if p := s.waiting[key]; p != nil {
		delete(s.waiting, key)
		close(p.cancel)
	}
	var stale []net.Conn
	for conn, current := range s.active {
		if current.from == from && current.to == to {
			delete(s.active, conn)
			stale = append(stale, conn)
		}
	}
	return stale
}

// admissionStatus runs while holding s.mu. Counts include waiting and bridged endpoints.
func (s *Server) admissionStatus(from string) int {
	if len(s.active) >= maxRelayEndpoints {
		return http.StatusTooManyRequests
	}
	count := 0
	for _, current := range s.active {
		if current.from == from {
			count++
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
