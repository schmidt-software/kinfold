package relay

import (
	"fmt"
	"net"
	"sync"
)

// LimitListener bounds accepted TCP connections, including TLS handshakes and
// hijacked relay connections. Close unblocks an Accept waiting for capacity.
func LimitListener(inner net.Listener, limit int) (net.Listener, error) {
	if inner == nil || limit <= 0 {
		return nil, fmt.Errorf("listener and positive connection limit required")
	}
	return &limitedListener{Listener: inner, slots: make(chan struct{}, limit), done: make(chan struct{})}, nil
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (l *limitedListener) Accept() (net.Conn, error) {
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
	return &limitedConn{Conn: conn, release: func() { <-l.slots }}, nil
}

func (l *limitedListener) Close() error {
	var err error
	l.once.Do(func() {
		close(l.done)
		err = l.Listener.Close()
	})
	return err
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
