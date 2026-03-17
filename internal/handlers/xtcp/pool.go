package xtcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/raw/afs"
)

const (
	idleTimeoutLimit = 5 * time.Minute
	networkTypeIPv4  = "ip4"
)

var errPoolFull = fmt.Errorf("connection pool full")

type pooledConn struct {
	net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
	failed   atomic.Bool
}

type connPool struct {
	mu       sync.RWMutex
	conns    []*pooledConn
	maxSize  int
	timeout  time.Duration
	addr     string
	resolved netip.AddrPort
}

// newConnPool creates a managed pool for reusing TCP connections
// Configures bounds and timeouts to prevent socket exhaustion
func newConnPool(addr string, maxSize int, timeout time.Duration) *connPool {
	return &connPool{
		addr:    addr,
		maxSize: maxSize,
		timeout: timeout,
	}
}

// get acquires a healthy connection from the pool or establishes a new one
// Uses CAS-first pattern to avoid holding locks during syscalls
func (p *connPool) get(ctx context.Context) (*pooledConn, error) {
	for {
		p.mu.RLock()
		var candidate *pooledConn
		for _, c := range p.conns {
			if !c.inUse.Load() && !c.failed.Load() {
				candidate = c
				break
			}
		}
		p.mu.RUnlock()

		if candidate == nil {
			break
		}

		if !candidate.inUse.CompareAndSwap(false, true) {
			continue
		}

		if p.isAlive(candidate.Conn) {
			p.mu.Lock()
			candidate.lastUsed = time.Now()
			p.mu.Unlock()
			return candidate, nil
		}

		candidate.failed.Store(true)
		candidate.inUse.Store(false)
	}

	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{
		Conn:     conn,
		lastUsed: time.Now(),
	}
	pc.inUse.Store(true)

	p.mu.Lock()
	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, pc)
	} else {
		replaced := false
		for i, c := range p.conns {
			if c.failed.Load() || (!c.inUse.Load() && time.Since(c.lastUsed) > idleTimeoutLimit) {
				_ = c.Conn.Close()
				p.conns[i] = pc
				replaced = true
				break
			}
		}
		if !replaced {
			_ = pc.Conn.Close()
			p.mu.Unlock()
			return nil, errPoolFull
		}
	}
	p.mu.Unlock()

	return pc, nil
}

// dial negotiates a new network connection to the target backend
// Uses the parent context to securely terminate hanging DNS resolutions
func (p *connPool) dial(ctx context.Context) (net.Conn, error) {
	p.mu.RLock()
	resolved := p.resolved
	p.mu.RUnlock()

	dialer := net.Dialer{Timeout: p.timeout}

	if resolved.IsValid() {
		conn, err := dialer.DialContext(ctx, woos.TCP, resolved.String())
		if err == nil {
			return conn, nil
		}
		p.mu.Lock()
		p.resolved = netip.AddrPort{}
		p.mu.Unlock()
	}
	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		return nil, err
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(resCtx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(resCtx, network, address)
		},
	}
	addrs, err := resolver.LookupNetIP(ctx, networkTypeIPv4, host)
	if err != nil || len(addrs) == 0 {
		return dialer.DialContext(ctx, woos.TCP, p.addr)
	}
	var lastErr error
	for _, addr := range addrs {
		addrPort := netip.AddrPortFrom(addr, parsePort(port))
		conn, err := dialer.DialContext(ctx, woos.TCP, addrPort.String())
		if err == nil {
			p.mu.Lock()
			p.resolved = addrPort
			p.mu.Unlock()
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// put returns an active connection to the reusable pool
// Flags the object as available and refreshes its tracking timestamp
func (p *connPool) put(pc *pooledConn) {
	if pc == nil {
		return
	}
	pc.inUse.Store(false)
	p.mu.Lock()
	pc.lastUsed = time.Now()
	p.mu.Unlock()
}

// close terminates all active sockets within the pool
// Executed during graceful shutdown sweeps
func (p *connPool) close() {
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Conn.Close()
	}
	p.conns = p.conns[:0]
	p.mu.Unlock()
}

// isAlive checks the platform-specific socket status to ensure usability
// Filters out connections dropped silently by the remote peer
func (p *connPool) isAlive(conn net.Conn) bool {
	return afs.ConnAlive(conn)
}
