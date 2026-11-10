package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schmidt-software/kinfold/internal/core"
	"github.com/schmidt-software/kinfold/internal/metrics"
)

type link struct {
	peer core.Peer
	// incoming delivers accepted direct sessions to the link (D-026).
	incoming chan net.Conn
	// done is closed when the link stops; late deliveries are refused.
	done <-chan struct{}
	// dial reports whether this side dials the peer directly.
	dial      bool
	endpoints func(peer string) []string
	server    func() string // current controller for relay connections
	// queue is the send queue of the running session and holds frames
	// (framePacket); only that session reads it. outbox points to the same channel while a session is
	// connected and is nil otherwise. Each session gets a fresh channel, so
	// packets queued for an ended session are dropped with it instead of
	// leaking into the next one (review A-06).
	queue         chan []byte
	outbox        atomic.Pointer[chan []byte]
	allowIncoming bool
	allowOutgoing bool
	servicesOn    bool
	inServices    serviceSet
	outServices   serviceSet
	localIPv6     netip.Addr
	peerIPv6      netip.Addr
}

const (
	tunnelMTU      = 1280
	peerQueueDepth = 128
)

// Metrics is the client's metrics registry; one agent runs per process.
var Metrics = metrics.New()

var (
	droppedMTU     = droppedCounter("mtu")
	droppedSource  = droppedCounter("invalid_source")
	droppedNoRoute = droppedCounter("no_route_or_policy")
	droppedQueue   = droppedCounter("queue_full")
	droppedInbound = droppedCounter("inbound_policy")
)

func droppedCounter(reason string) *metrics.Counter {
	return Metrics.Counter("kinfold_packets_dropped_total", "Packets dropped by the client, by reason.", metrics.Labels{"reason": reason})
}

func peerConnected(peer string) *metrics.Gauge {
	return Metrics.Gauge("kinfold_peer_connected", "1 while a session to the peer is established.", metrics.Labels{"peer": peer})
}

func peerBytes(peer, direction string) *metrics.Counter {
	return Metrics.Counter("kinfold_peer_bytes_total", "Packet bytes exchanged with a peer.", metrics.Labels{"peer": peer, "direction": direction})
}

// peerWriteTimeout bounds a single frame write to a peer. Without it a dead
// path with data in flight blocks the sender until TCP gives up
// retransmitting, about 15 minutes on Linux (review A-01).
var peerWriteTimeout = 10 * time.Second

type tunnelWriteError struct{ err error }

func (e *tunnelWriteError) Error() string { return fmt.Sprintf("write tunnel: %v", e.err) }
func (e *tunnelWriteError) Unwrap() error { return e.err }

func packetAddresses(packet []byte) (netip.Addr, netip.Addr, error) {
	if len(packet) == 0 {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("empty packet")
	}
	if packet[0]>>4 == 6 {
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPv6 packet")
		}
		return netip.AddrFrom16([16]byte(packet[8:24])), netip.AddrFrom16([16]byte(packet[24:40])), nil
	}
	if len(packet) < 20 || packet[0]>>4 != 4 || int(packet[0]&15)*4 < 20 || int(packet[0]&15)*4 > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
		return netip.Addr{}, netip.Addr{}, fmt.Errorf("invalid IPv4 packet")
	}
	return netip.AddrFrom4([4]byte(packet[12:16])), netip.AddrFrom4([4]byte(packet[16:20])), nil
}

// RunWithUpdates forwards only exact member-to-member IP traffic and applies
// configuration updates in place (updates may be nil). An update must keep the device's own addresses (the supervisor recreates the
// tunnel otherwise). Peer links whose authorization is unchanged keep their
// sessions; changed links are restarted and removed links stopped, without
// touching the TUN device (review R-09).
func RunWithUpdates(ctx context.Context, cred core.Credential, cfg core.Config, ownID string, device io.ReadWriteCloser, updates <-chan core.Config, opts ...Option) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	var byFingerprint atomic.Pointer[map[string]*link]
	if err := cfg.Validate(); err != nil {
		return err
	}
	self, ok := cfg.Peer(ownID)
	if !ok {
		return fmt.Errorf("unknown local peer %s", ownID)
	}
	localIP, _ := netip.ParseAddr(self.IP)
	localIPv6, _ := netip.ParseAddr(self.IPv6)
	var current atomic.Pointer[core.Config]
	var routes atomic.Pointer[map[netip.Addr]*link]
	var writeMu sync.Mutex
	var workers sync.WaitGroup
	failure := make(chan error, 1)
	type runningLink struct {
		link   *link
		key    string
		cancel context.CancelFunc
	}
	running := map[string]*runningLink{}
	apply := func(cfg core.Config) error {
		if err := cfg.Validate(); err != nil {
			return err
		}
		self, ok := cfg.Peer(ownID)
		if !ok || self.IP != localIP.String() || (self.IPv6 != "") != localIPv6.IsValid() || (localIPv6.IsValid() && self.IPv6 != localIPv6.String()) {
			return fmt.Errorf("update changes the local peer's addresses")
		}
		current.Store(&cfg)
		next := map[string]*runningLink{}
		table := map[netip.Addr]*link{}
		for _, p := range cfg.Peers {
			if p.ID == ownID {
				continue
			}
			allowIncoming, allowOutgoing := cfg.Permits(p.ID, ownID), cfg.Permits(ownID, p.ID)
			if !allowIncoming && !allowOutgoing {
				continue
			}
			ip, _ := netip.ParseAddr(p.IP)
			peerIPv6, _ := netip.ParseAddr(p.IPv6)
			l := &link{peer: p, incoming: make(chan net.Conn, 1), endpoints: o.endpoints, server: o.server, allowIncoming: allowIncoming, allowOutgoing: allowOutgoing, localIPv6: localIPv6, peerIPv6: peerIPv6}
			// Only one side dials directly, so the two devices never build
			// two sessions: the side without a listener, or the lower ID.
			l.dial = o.endpoints != nil && (o.listenAddr == "" || ownID < p.ID)
			if cfg.Policy != nil && cfg.Policy.Services != nil {
				l.servicesOn = true
				l.inServices = compileServices(cfg.Policy.Services.Allowed, p.ID, ownID)
				l.outServices = compileServices(cfg.Policy.Services.Allowed, ownID, p.ID)
			}
			key := l.key()
			r := running[p.ID]
			if r != nil && r.key == key {
				delete(running, p.ID) // unchanged: keep the link and its session
			} else {
				linkCtx, linkCancel := context.WithCancel(ctx)
				l.done = linkCtx.Done()
				r = &runningLink{link: l, key: key, cancel: linkCancel}
				workers.Add(1)
				go func() {
					defer workers.Done()
					if err := l.run(linkCtx, cred, &current, ownID, localIP, device, &writeMu); err != nil {
						select {
						case failure <- err:
						default:
						}
						cancel()
					}
				}()
			}
			next[p.ID] = r
			table[ip] = r.link
			if peerIPv6.IsValid() && localIPv6.IsValid() {
				table[peerIPv6] = r.link
			}
		}
		// Publish the new links before stopping the old ones, so the
		// listener never hands a session to a link that is being stopped.
		routes.Store(&table)
		fps := make(map[string]*link, len(next))
		for _, r := range next {
			if cert, err := core.ParseCert(r.link.peer.Cert); err == nil {
				fps[core.Fingerprint(cert)] = r.link
			}
		}
		byFingerprint.Store(&fps)
		for _, r := range running {
			r.cancel() // removed or changed
		}
		running = next
		return nil
	}
	if err := apply(cfg); err != nil {
		return err
	}
	if o.listenAddr != "" {
		lc := net.ListenConfig{KeepAliveConfig: clientKeepAlive}
		ln, err := lc.Listen(ctx, "tcp", o.listenAddr)
		if err != nil {
			return fmt.Errorf("direct listener: %w", err)
		}
		slog.Info("accepting direct sessions", "address", ln.Addr().String())
		workers.Add(1)
		go func() {
			defer workers.Done()
			acceptDirect(ctx, ln, cred, func(fp string) *link { return (*byFingerprint.Load())[fp] })
		}()
	}
	if updates != nil {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case next := <-updates:
					if err := apply(next); err != nil {
						select {
						case failure <- fmt.Errorf("apply configuration update: %w", err):
						default:
						}
						cancel()
						return
					}
					slog.Info("configuration update applied without restarting the tunnel")
				}
			}
		}()
	}
	closed := make(chan error, 1)
	go func() {
		<-ctx.Done()
		closed <- device.Close()
	}()
	defer func() {
		cancel()
		closeErr := <-closed
		workers.Wait()
		select {
		case err := <-failure:
			result = errors.Join(result, err)
		default:
		}
		if closeErr != nil {
			result = errors.Join(result, fmt.Errorf("close tunnel: %w", closeErr))
		}
	}()
	buf := make([]byte, 65535)
	for {
		n, err := device.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read tunnel: %w", err)
		}
		packet := buf[:n]
		if len(packet) > tunnelMTU {
			droppedMTU.Inc()
			slog.Debug("packet exceeds tunnel MTU; dropped", "size", len(packet), "mtu", tunnelMTU)
			continue
		}
		src, dst, err := packetAddresses(packet)
		if err != nil || (src != localIP && (!localIPv6.IsValid() || src != localIPv6)) {
			droppedSource.Inc()
			continue
		}
		l := (*routes.Load())[dst]
		if l == nil || !l.allowOutgoing || (l.servicesOn && !servicePacket(packet, l.outServices)) {
			droppedNoRoute.Inc()
			continue
		}
		outbox := l.outbox.Load()
		if outbox == nil {
			droppedNoRoute.Inc()
			continue
		}
		// The read buffer is reused, so the packet is copied once, straight
		// into the frame the session writes.
		frame, err := framePacket(packet)
		if err != nil {
			droppedMTU.Inc()
			continue
		}
		select {
		case *outbox <- frame:
		default:
			droppedQueue.Inc()
			slog.Debug("peer queue full; packet dropped", "peer", l.peer.ID)
		}
	}
}

// key identifies everything a link's behaviour depends on; links with the
// same key can keep their session across configuration updates.
func (l *link) key() string {
	data, _ := json.Marshal(struct {
		Peer                    core.Peer
		In, Out, Services       bool
		InServices, OutServices []string
		LocalIPv6               string
	}{l.peer, l.allowIncoming, l.allowOutgoing, l.servicesOn, l.inServices.keys(), l.outServices.keys(), l.localIPv6.String()})
	return string(data)
}

func (l *link) run(ctx context.Context, cred core.Credential, cfg *atomic.Pointer[core.Config], ownID string, localIP netip.Addr, device io.Writer, writeMu *sync.Mutex) error {
	defer peerPath(l.peer.ID, "direct").Set(0)
	defer peerPath(l.peer.ID, "relay").Set(0)
	defer func() {
		for {
			select {
			case c := <-l.incoming:
				c.Close() // never leave an accepted session open behind a stopped link
			default:
				return
			}
		}
	}()
	var backoff retryBackoff
	failing := false  // the last connection attempt failed and was reported
	var next net.Conn // a direct session accepted while another one was running
	defer func() {
		if next != nil {
			next.Close()
		}
	}()
	for ctx.Err() == nil {
		conn, path, err := next, "direct", error(nil)
		next = nil
		if conn == nil {
			select {
			case conn = <-l.incoming:
			default:
				conn, path, err = l.connect(ctx, cred, cfg, ownID)
			}
		}
		if err != nil {
			// An offline peer is retried for as long as it stays offline:
			// report the first failure and keep the repeats at debug level,
			// so the log does not grow with every attempt (D-046).
			if ctx.Err() == nil && !failing {
				slog.Warn("peer connection failed; retrying", "peer", l.peer.ID, "error", err)
				failing = true
			} else if ctx.Err() == nil {
				slog.Debug("peer connection failed again", "peer", l.peer.ID, "error", err)
			}
		} else {
			failing = false
			slog.Info("peer connected", "peer", l.peer.ID, "path", path)
			var writeErr *tunnelWriteError
			next, err = l.runSession(ctx, cred, conn, path, localIP, device, writeMu, &backoff)
			if errors.As(err, &writeErr) {
				return fmt.Errorf("peer %s: %w", l.peer.ID, writeErr)
			}
			if next != nil {
				continue // upgrade to the direct session right away
			}
			if ctx.Err() == nil {
				slog.Warn("peer disconnected", "peer", l.peer.ID, "path", path, "error", err)
			}
		}
		timer := time.NewTimer(backoff.next())
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case next = <-l.incoming:
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

// connect dials the peer directly when this side dials and the peer has
// signed direct endpoints, and falls back to the relay.
func (l *link) connect(ctx context.Context, cred core.Credential, cfg *atomic.Pointer[core.Config], ownID string) (net.Conn, string, error) {
	if l.dial && l.endpoints != nil {
		for _, addr := range l.endpoints(l.peer.ID) {
			conn, err := dialDirect(ctx, cred, l.peer, addr)
			if err == nil {
				return conn, "direct", nil
			}
			slog.Debug("direct connection failed; trying next path", "peer", l.peer.ID, "address", addr, "error", err)
		}
	}
	// The relay is the fallback. While its pairing waits for the peer, a
	// direct session the peer opened to us takes precedence.
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		conn net.Conn
		err  error
	}
	relayed := make(chan result, 1)
	go func() {
		// Reconnects present the revision of the configuration in force now,
		// through the controller that answered last.
		c := cred
		if l.server != nil {
			c.Server = l.server()
		}
		conn, err := Connect(relayCtx, c, *cfg.Load(), ownID, l.peer)
		relayed <- result{conn, err}
	}()
	select {
	case r := <-relayed:
		return r.conn, "relay", r.err
	case direct := <-l.incoming:
		cancel()
		if r := <-relayed; r.conn != nil {
			r.conn.Close()
		}
		return direct, "direct", nil
	}
}

const (
	directUpgradeFirst = 3 * time.Second
	directUpgradeEvery = 30 * time.Second
)

// tryDirect dials the peer's direct endpoints and hands a session over as
// if it had been accepted, which makes runSession switch to it. It reports
// whether the peer had endpoints to try.
func (l *link) tryDirect(ctx context.Context, cred core.Credential) bool {
	endpoints := l.endpoints(l.peer.ID)
	for _, addr := range endpoints {
		conn, err := dialDirect(ctx, cred, l.peer, addr)
		if err != nil {
			slog.Debug("direct upgrade failed", "peer", l.peer.ID, "address", addr, "error", err)
			continue
		}
		select {
		case l.incoming <- conn:
		case <-ctx.Done():
			conn.Close()
		case <-l.done:
			conn.Close()
		}
		return true
	}
	return len(endpoints) > 0
}

// runSession runs one session. A direct session arriving while a relay
// session runs replaces it; that session is returned as next.
func (l *link) runSession(ctx context.Context, cred core.Credential, conn net.Conn, path string, localIP netip.Addr, device io.Writer, writeMu *sync.Mutex, backoff *retryBackoff) (next net.Conn, err error) {
	queue := make(chan []byte, peerQueueDepth)
	l.queue = queue
	l.outbox.Store(&queue)
	peerConnected(l.peer.ID).Set(1)
	peerPath(l.peer.ID, path).Set(1)
	defer func() {
		l.outbox.Store(nil)
		peerConnected(l.peer.ID).Set(0)
		peerPath(l.peer.ID, path).Set(0)
		conn.Close()
	}()
	started := time.Now()
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.session(sessCtx, conn, localIP, device, writeMu) }()
	// On the relay, the dialing side keeps trying the direct path (its
	// endpoints may only arrive with a later configuration fetch); a direct
	// session it opens arrives on l.incoming like an accepted one.
	if path == "relay" && l.dial && l.endpoints != nil {
		go func() {
			wait := directUpgradeFirst
			for {
				select {
				case <-sessCtx.Done():
					return
				case <-time.After(wait):
				}
				// Retry soon while no endpoint is known yet; back off once
				// an attempt was actually made.
				if l.tryDirect(sessCtx, cred) {
					wait = directUpgradeEvery
				}
			}
		}()
	}
	for {
		select {
		case err = <-done:
			if time.Since(started) >= stableLink {
				backoff.reset()
			}
			return next, err
		case incoming := <-l.incoming:
			if next != nil {
				incoming.Close()
				continue
			}
			// The newest direct session wins: the peer only dials again when
			// it considers the running session dead (finding 6).
			next = incoming
			slog.Info("switching peer to a new direct session", "peer", l.peer.ID, "from", path)
			cancel()
		}
	}
}

func (l *link) session(ctx context.Context, conn net.Conn, localIP netip.Addr, device io.Writer, writeMu *sync.Mutex) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	peerIP, _ := netip.ParseAddr(l.peer.IP)
	rx, tx := peerBytes(l.peer.ID, "rx"), peerBytes(l.peer.ID, "tx")
	go func() {
		for {
			packet, err := readPacketLimited(conn, tunnelMTU)
			if err != nil {
				done <- err
				return
			}
			src, dst, err := packetAddresses(packet)
			validIPv4 := src == peerIP && dst == localIP
			validIPv6 := l.peerIPv6.IsValid() && l.localIPv6.IsValid() && src == l.peerIPv6 && dst == l.localIPv6
			if err != nil || (!validIPv4 && !validIPv6) {
				done <- fmt.Errorf("invalid or spoofed packet from %s", l.peer.ID)
				return
			}
			if !l.allowIncoming || (l.servicesOn && !servicePacket(packet, l.inServices)) {
				droppedInbound.Inc()
				continue
			}
			rx.Add(uint64(len(packet)))
			writeMu.Lock()
			if ctx.Err() != nil {
				writeMu.Unlock()
				done <- ctx.Err()
				return
			}
			n, err := device.Write(packet)
			writeMu.Unlock()
			if err == nil && n != len(packet) {
				err = io.ErrShortWrite
			}
			if err != nil {
				if parent.Err() != nil {
					done <- parent.Err()
				} else {
					done <- &tunnelWriteError{err: err}
				}
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case frame := <-l.queue:
				if err := conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout)); err != nil {
					done <- err
					return
				}
				tx.Add(uint64(len(frame) - 2)) // packet bytes, without the length prefix
				if err := writeFrame(conn, frame); err != nil {
					done <- err
					return
				}
			case <-ctx.Done():
				done <- ctx.Err()
				return
			}
		}
	}()
	var result error
	completed := 0
	select {
	case err := <-done:
		result = err
		completed = 1
	case <-ctx.Done():
		result = ctx.Err()
	}
	cancel()
	conn.Close()
	for ; completed < 2; completed++ {
		err := <-done
		var writeErr *tunnelWriteError
		if errors.As(err, &writeErr) {
			result = writeErr
		}
	}
	return result
}
