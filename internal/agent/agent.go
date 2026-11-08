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
)

type link struct {
	peer core.Peer
	// queue is the send queue of the running session; only that session
	// reads it. outbox points to the same channel while a session is
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

// Run forwards only exact member-to-member IP traffic.
func Run(ctx context.Context, cred core.Credential, cfg core.Config, ownID string, device io.ReadWriteCloser) error {
	return RunWithUpdates(ctx, cred, cfg, ownID, device, nil)
}

// RunWithUpdates is Run with configuration updates applied in place. An
// update must keep the device's own addresses (the supervisor recreates the
// tunnel otherwise). Peer links whose authorization is unchanged keep their
// sessions; changed links are restarted and removed links stopped, without
// touching the TUN device (review R-09).
func RunWithUpdates(ctx context.Context, cred core.Credential, cfg core.Config, ownID string, device io.ReadWriteCloser, updates <-chan core.Config) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
			l := &link{peer: p, allowIncoming: allowIncoming, allowOutgoing: allowOutgoing, localIPv6: localIPv6, peerIPv6: peerIPv6}
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
		for _, r := range running {
			r.cancel() // removed or changed
		}
		running = next
		routes.Store(&table)
		return nil
	}
	if err := apply(cfg); err != nil {
		return err
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
			slog.Debug("packet exceeds tunnel MTU; dropped", "size", len(packet), "mtu", tunnelMTU)
			continue
		}
		src, dst, err := packetAddresses(packet)
		if err != nil || (src != localIP && (!localIPv6.IsValid() || src != localIPv6)) {
			continue
		}
		l := (*routes.Load())[dst]
		if l == nil || !l.allowOutgoing || (l.servicesOn && !servicePacket(packet, l.outServices)) {
			continue
		}
		outbox := l.outbox.Load()
		if outbox == nil {
			continue
		}
		clone := append([]byte(nil), packet...)
		select {
		case *outbox <- clone:
		default:
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
	var backoff retryBackoff
	for ctx.Err() == nil {
		// Reconnects present the revision of the configuration in force now.
		conn, err := Connect(ctx, cred, *cfg.Load(), ownID, l.peer)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("peer connection failed", "peer", l.peer.ID, "error", err)
			}
		} else {
			slog.Info("peer connected through relay", "peer", l.peer.ID)
			queue := make(chan []byte, peerQueueDepth)
			l.queue = queue
			l.outbox.Store(&queue)
			started := time.Now()
			err = l.session(ctx, conn, localIP, device, writeMu)
			if time.Since(started) >= stableLink {
				backoff.reset()
			}
			l.outbox.Store(nil)
			conn.Close()
			var writeErr *tunnelWriteError
			if errors.As(err, &writeErr) {
				return fmt.Errorf("peer %s: %w", l.peer.ID, writeErr)
			}
			if ctx.Err() == nil {
				slog.Warn("peer disconnected", "peer", l.peer.ID, "error", err)
			}
		}
		delay := backoff.next()
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

func (l *link) session(ctx context.Context, conn net.Conn, localIP netip.Addr, device io.Writer, writeMu *sync.Mutex) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	peerIP, _ := netip.ParseAddr(l.peer.IP)
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
				continue
			}
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
			case packet := <-l.queue:
				if err := conn.SetWriteDeadline(time.Now().Add(peerWriteTimeout)); err != nil {
					done <- err
					return
				}
				if err := WritePacket(conn, packet); err != nil {
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
