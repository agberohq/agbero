package virtual

import (
	"errors"
	"net"
	"sync"
	"time"
)

var (
	ErrListenerClosed = errors.New("virtual listener closed")
)

// Listener implements net.Listener but accepts connections pushed via a channel.
// This allows bridging hijacked HTTP connections into an internal server (like FRP).
type Listener struct {
	ch     chan net.Conn
	done   chan struct{}
	addr   net.Addr
	mu     sync.Mutex
	closed bool
}

func NewListener(addr net.Addr) *Listener {
	if addr == nil {
		addr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	}
	return &Listener{
		ch:   make(chan net.Conn),
		done: make(chan struct{}),
		addr: addr,
	}
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, ErrListenerClosed
		}
		return c, nil
	case <-l.done:
		return nil, ErrListenerClosed
	}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return ErrListenerClosed.
func (l *Listener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}
	l.closed = true
	close(l.done)
	close(l.ch)
	return nil
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.addr
}

// HandleConn pushes a connection into the listener.
// This is called by the HTTP handler after hijacking the connection.
func (l *Listener) HandleConn(c net.Conn) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return ErrListenerClosed
	}
	l.mu.Unlock()

	// Push to channel or fail if listener is busy/blocking too long?
	// For a tunnel, we want to block until Accepted.
	select {
	case l.ch <- c:
		return nil
	case <-l.done:
		return ErrListenerClosed
	// Optional: Add timeout to prevent leaking hijacked conns if Accept stops
	case <-time.After(5 * time.Second):
		return errors.New("timeout waiting for virtual listener accept")
	}
}
