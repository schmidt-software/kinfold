package relay

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// ListenerLimits bounds the TCP connections the controller accepts. All
// limits apply before TLS, so they also protect against unauthenticated
// clients that never complete a handshake.
type ListenerLimits struct {
	// Total is the maximum number of concurrently open connections.
	Total int
	// PerSource is the maximum number of concurrently open connections from
	// one remote IP address. Zero disables the per-source limit.
	PerSource int
	// RatePerSource is the sustained number of new connections per second
	// accepted from one remote IP address. Zero disables rate limiting.
	RatePerSource float64
	// BurstPerSource is the number of new connections one remote IP address
	// may open at once before the rate applies. It must be at least 1 when
	// RatePerSource is set.
	BurstPerSource int
}

// DefaultListenerLimits fits the 32-device mesh: a client holds one control
// connection plus at most 31 relay connections, and opens them in a burst
// after a controller restart. A single device therefore needs up to 32
// connections; 128 leaves room for four devices behind one NAT address.
var DefaultListenerLimits = ListenerLimits{Total: 1152, PerSource: 128, RatePerSource: 20, BurstPerSource: 128}

// maxTrackedSources bounds the per-source state. Sources without open
// connections are dropped when the map is full, so an attacker cycling
// addresses cannot grow it without limit (change review finding 4).
const maxTrackedSources = 8192

// LimitListener bounds accepted TCP connections, including TLS handshakes and
// hijacked relay connections. Close unblocks an Accept waiting for capacity.
func LimitListener(inner net.Listener, limit int) (net.Listener, error) {
	return NewLimitedListener(inner, ListenerLimits{Total: limit})
}

// NewLimitedListener applies the given limits to inner. Connections over a
// per-source limit are accepted and closed immediately, so one source cannot
// fill the operating system backlog for everyone else; the global limit
// makes Accept wait as before.
func NewLimitedListener(inner net.Listener, limits ListenerLimits) (net.Listener, error) {
	if inner == nil || limits.Total <= 0 {
		return nil, fmt.Errorf("listener and positive connection limit required")
	}
	if limits.PerSource < 0 || limits.RatePerSource < 0 || (limits.RatePerSource > 0 && limits.BurstPerSource < 1) {
		return nil, fmt.Errorf("invalid per-source limits")
	}
	return &limitedListener{
		Listener: inner,
		limits:   limits,
		slots:    make(chan struct{}, limits.Total),
		done:     make(chan struct{}),
		sources:  make(map[string]*sourceState),
		now:      time.Now,
	}, nil
}

type sourceState struct {
	open   int
	tokens float64
	last   time.Time
}

type limitedListener struct {
	net.Listener
	limits ListenerLimits
	slots  chan struct{}
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	sources map[string]*sourceState
	now     func() time.Time
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		select {
		case <-l.done:
			return nil, net.ErrClosed
		case l.slots <- struct{}{}:
		}
		conn, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		source := remoteIP(conn)
		if !l.admit(source) {
			conn.Close()
			<-l.slots
			continue
		}
		return &limitedConn{Conn: conn, release: func() {
			l.releaseSource(source)
			<-l.slots
		}}, nil
	}
}

// admit applies the per-source limits and reserves a slot for source.
func (l *limitedListener) admit(source string) bool {
	if l.limits.PerSource == 0 && l.limits.RatePerSource == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	s := l.sources[source]
	if s == nil {
		if len(l.sources) >= maxTrackedSources {
			l.sweep()
			if len(l.sources) >= maxTrackedSources {
				return false
			}
		}
		s = &sourceState{tokens: float64(l.limits.BurstPerSource), last: now}
		l.sources[source] = s
	}
	if l.limits.RatePerSource > 0 {
		if elapsed := now.Sub(s.last); elapsed > 0 {
			s.tokens = min(float64(l.limits.BurstPerSource), s.tokens+elapsed.Seconds()*l.limits.RatePerSource)
		}
		s.last = now
		if s.tokens < 1 {
			l.forgetIdle(source, s)
			return false
		}
	}
	if l.limits.PerSource > 0 && s.open >= l.limits.PerSource {
		return false
	}
	if l.limits.RatePerSource > 0 {
		s.tokens--
	}
	s.open++
	return true
}

func (l *limitedListener) releaseSource(source string) {
	if l.limits.PerSource == 0 && l.limits.RatePerSource == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if s := l.sources[source]; s != nil {
		s.open--
		l.forgetIdle(source, s)
	}
}

// forgetIdle drops state for a source without open connections whose bucket
// would be full again, so the map stays bounded by the open connections.
// Caller holds l.mu.
func (l *limitedListener) forgetIdle(source string, s *sourceState) {
	if s.open > 0 {
		return
	}
	if l.limits.RatePerSource > 0 {
		refill := l.now().Sub(s.last).Seconds()*l.limits.RatePerSource + s.tokens
		if refill < float64(l.limits.BurstPerSource) {
			return
		}
	}
	delete(l.sources, source)
}

// sweep drops every source without open connections, forgetting its rate
// history. Caller holds l.mu.
func (l *limitedListener) sweep() {
	for source, s := range l.sources {
		if s.open == 0 {
			delete(l.sources, source)
		}
	}
}

func (l *limitedListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
}

// remoteIP returns the accounting key for a connection: the IPv4 address,
// or the /64 prefix for IPv6, because a single IPv6 host usually controls a
// whole /64 and could otherwise bypass the per-source limits (change review
// finding 5).
func remoteIP(conn net.Conn) string {
	var host string
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		host = tcp.IP.String()
	} else if h, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		host = h
	} else {
		return conn.RemoteAddr().String()
	}
	return sourceKey(host)
}

func sourceKey(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, _ := addr.WithZone("").Prefix(64)
	return prefix.String()
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}
