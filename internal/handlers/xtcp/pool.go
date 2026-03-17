// internal/handlers/xtcp/pool.go
package xtcp

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/raw/afs"
	"github.com/olekukonko/jack"
)

const (
	idleTimeoutLimit = 5 * time.Minute
	networkTypeIPv4  = "ip4"
	sweepInterval    = 30 * time.Second
	sweepRoutineName = "xtcp-conn-sweeper"
	sweepPoolSize    = 1
)

var errPoolFull = fmt.Errorf("connection pool full")

type pooledConn struct {
	net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
	failed   atomic.Bool
}

type connPool struct {
	mu        sync.RWMutex
	conns     []*pooledConn
	maxSize   int
	timeout   time.Duration
	addr      string
	resolved  netip.AddrPort
	scheduler *jack.Scheduler
	quit      chan struct{}
	once      sync.Once
}

// newConnPool creates a managed pool for reusing TCP connections
// Configures bounds and timeouts to prevent socket exhaustion
func newConnPool(addr string, maxSize int, timeout time.Duration) *connPool {
	p := &connPool{
		addr:    addr,
		maxSize: maxSize,
		timeout: timeout,
		conns:   make([]*pooledConn, 0, maxSize),
		quit:    make(chan struct{}),
	}

	sched, _ := jack.NewScheduler(sweepRoutineName, jack.NewPool(sweepPoolSize), jack.Routine{
		Interval: sweepInterval,
	})
	_ = sched.Do(jack.Do(p.sweep))
	p.scheduler = sched

	return p
}

// sweep periodically removes idle and failed connections that have exceeded timeout
// Runs in background to prevent file descriptor leaks during low traffic
func (p *connPool) sweep() {
	select {
	case <-p.quit:
		return
	default:
	}

	now := time.Now()
	var expired []*pooledConn

	p.mu.RLock()
	for _, c := range p.conns {
		if !c.inUse.Load() && (c.failed.Load() || now.Sub(c.lastUsed) > idleTimeoutLimit) {
			expired = append(expired, c)
		}
	}
	p.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	newConns := make([]*pooledConn, 0, len(p.conns))
	for _, c := range p.conns {
		shouldRemove := false
		for _, e := range expired {
			if c == e {
				shouldRemove = true
				break
			}
		}

		if shouldRemove {
			_ = c.Conn.Close()
		} else {
			newConns = append(newConns, c)
		}
	}
	p.conns = newConns
}

// get acquires a healthy connection from the pool or establishes a new one
// Uses CAS-first pattern to avoid holding locks during syscalls
func (p *connPool) get(ctx context.Context) (*pooledConn, error) {
	for {
		now := time.Now()
		p.mu.RLock()
		var candidate *pooledConn
		for _, c := range p.conns {
			if !c.inUse.Load() && !c.failed.Load() && now.Sub(c.lastUsed) <= idleTimeoutLimit {
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
	defer p.mu.Unlock()

	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, pc)
		return pc, nil
	}

	for i, c := range p.conns {
		if c.failed.Load() || (!c.inUse.Load() && time.Since(c.lastUsed) > idleTimeoutLimit) {
			_ = c.Conn.Close()
			p.conns[i] = pc
			return pc, nil
		}
	}

	_ = pc.Conn.Close()
	return nil, errPoolFull
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

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return dialer.DialContext(ctx, woos.TCP, p.addr)
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
		addrPort := netip.AddrPortFrom(addr, uint16(portNum))
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
	p.once.Do(func() {
		close(p.quit)
		if p.scheduler != nil {
			_ = p.scheduler.Stop()
		}
	})

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.conns {
		_ = c.Conn.Close()
	}
	p.conns = p.conns[:0]
}

// isAlive checks the platform-specific socket status to ensure usability
// Filters out connections dropped silently by the remote peer
func (p *connPool) isAlive(conn net.Conn) bool {
	return afs.ConnAlive(conn)
}
