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

	"github.com/agberohq/agbero/internal/core/def"
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

// pooledConn wraps a net.Conn with lifecycle tracking.
type pooledConn struct {
	net.Conn
	lastUsed atomic.Int64 // unix nanoseconds
	inUse    atomic.Bool
	failed   atomic.Bool
}

type connPool struct {
	// mu protects both the idle stack (free) and the ownership slice (all).
	// The Treiber lock-free stack was removed because reusing *pooledConn
	// pointers across push/pop cycles makes it vulnerable to the classic ABA
	// problem: a CAS on head can succeed with a stale "next" pointer, handing
	// the same connection to two concurrent callers and causing data corruption.
	// A plain mutex is correct and the critical section is tiny.
	mu      sync.Mutex
	free    []*pooledConn // idle connections (stack discipline: last-in, first-out)
	all     []*pooledConn // all connections ever created (for sweep and close)
	maxSize int
	timeout time.Duration
	addr    string

	resolved  atomic.Pointer[netip.AddrPort]
	scheduler *jack.Scheduler
	quit      chan struct{}
	once      sync.Once
}

// newConnPool creates a managed pool for reusing TCP connections.
func newConnPool(addr string, maxSize int, timeout time.Duration) *connPool {
	p := &connPool{
		addr:    addr,
		maxSize: maxSize,
		timeout: timeout,
		free:    make([]*pooledConn, 0, maxSize),
		all:     make([]*pooledConn, 0, maxSize),
		quit:    make(chan struct{}),
	}

	sched, _ := jack.NewScheduler(sweepRoutineName, jack.NewPool(sweepPoolSize), jack.Routine{
		Interval: sweepInterval,
	})
	_ = sched.Do(jack.Do(p.sweep))
	p.scheduler = sched

	return p
}

// pushFree returns a connection to the idle stack.
// Must be called only after inUse is cleared (put() handles this ordering).
func (p *connPool) pushFree(pc *pooledConn) {
	p.mu.Lock()
	p.free = append(p.free, pc)
	p.mu.Unlock()
}

// popFree removes and returns the most recently idle connection, or nil.
// The mutex eliminates the ABA problem that plagued the prior Treiber stack:
// because *pooledConn structs are reused (push after pop), a lock-free CAS
// on head could succeed with a stale "next" pointer after an A→B→A sequence,
// handing the same live connection to two goroutines simultaneously.
func (p *connPool) popFree() *pooledConn {
	p.mu.Lock()
	if len(p.free) == 0 {
		p.mu.Unlock()
		return nil
	}
	last := len(p.free) - 1
	pc := p.free[last]
	p.free[last] = nil // clear reference to avoid a GC-invisible retain
	p.free = p.free[:last]
	p.mu.Unlock()
	return pc
}

// sweep reaps idle and failed connections under one exclusive lock.
// The single-pass filter eliminates the prior RLock→Lock TOCTOU window.
// It also rebuilds the free slice, discarding entries for connections that
// have been closed so callers never pop a dead connection.
func (p *connPool) sweep() {
	select {
	case <-p.quit:
		return
	default:
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now().UnixNano()
	expireNano := int64(idleTimeoutLimit)

	alive := p.all[:0]
	for _, c := range p.all {
		if c.inUse.Load() {
			alive = append(alive, c)
			continue
		}
		if c.failed.Load() || now-c.lastUsed.Load() > expireNano {
			_ = c.Conn.Close()
			continue
		}
		alive = append(alive, c)
	}
	p.all = alive

	// Rebuild free list from surviving, non-in-use connections so there are
	// no dangling pointers to closed connections.
	p.free = p.free[:0]
	for _, c := range p.all {
		if !c.inUse.Load() && !c.failed.Load() {
			p.free = append(p.free, c)
		}
	}
}

// get acquires a healthy connection from the idle stack or dials a new one.
func (p *connPool) get(ctx context.Context) (*pooledConn, error) {
	now := time.Now().UnixNano()
	expireNano := int64(idleTimeoutLimit)

	// Pop idle connections until we find a healthy one or exhaust the free list.
	for {
		pc := p.popFree()
		if pc == nil {
			break
		}

		// Mark in-use before any liveness check so concurrent sweep skips it.
		pc.inUse.Store(true)

		if !pc.failed.Load() && now-pc.lastUsed.Load() <= expireNano && p.isAlive(pc.Conn) {
			pc.lastUsed.Store(now)
			return pc, nil
		}

		pc.failed.Store(true)
		pc.inUse.Store(false)
	}

	// No idle connection available — dial new
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{Conn: conn}
	pc.inUse.Store(true)
	pc.lastUsed.Store(now)

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.all) < p.maxSize {
		p.all = append(p.all, pc)
		return pc, nil
	}

	// At capacity: evict a dead or expired entry
	for i, c := range p.all {
		if c.failed.Load() || (!c.inUse.Load() && now-c.lastUsed.Load() > expireNano) {
			_ = c.Conn.Close()
			p.all[i] = pc
			return pc, nil
		}
	}

	_ = pc.Conn.Close()
	return nil, errPoolFull
}

// dial negotiates a new network connection, caching the resolved address
// in an atomic pointer to avoid repeated DNS lookups on the hot path.
func (p *connPool) dial(ctx context.Context) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.timeout}

	if ptr := p.resolved.Load(); ptr != nil && ptr.IsValid() {
		conn, err := dialer.DialContext(ctx, def.TCP, ptr.String())
		if err == nil {
			return conn, nil
		}
		p.resolved.Store(nil)
	}

	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		return dialer.DialContext(ctx, def.TCP, p.addr)
	}

	portNum, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return dialer.DialContext(ctx, def.TCP, p.addr)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(resCtx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(resCtx, network, address)
		},
	}
	addrs, err := resolver.LookupNetIP(ctx, networkTypeIPv4, host)
	if err != nil || len(addrs) == 0 {
		return dialer.DialContext(ctx, def.TCP, p.addr)
	}

	var lastErr error
	for _, addr := range addrs {
		ap := netip.AddrPortFrom(addr, uint16(portNum))
		conn, err := dialer.DialContext(ctx, def.TCP, ap.String())
		if err == nil {
			copy := ap
			p.resolved.Store(&copy)
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// put returns an active connection to the reusable pool.
// Failed connections are dropped on the floor and reclaimed by sweep.
func (p *connPool) put(pc *pooledConn) {
	if pc == nil {
		return
	}
	if pc.failed.Load() {
		pc.inUse.Store(false)
		return
	}
	pc.lastUsed.Store(time.Now().UnixNano())
	pc.inUse.Store(false)
	p.pushFree(pc)
}

// close terminates all sockets and background tasks.
func (p *connPool) close() {
	p.once.Do(func() {
		close(p.quit)
		if p.scheduler != nil {
			_ = p.scheduler.Stop()
		}
	})

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.all {
		_ = c.Conn.Close()
	}
	p.all = p.all[:0]
	p.free = p.free[:0]
}

// isAlive checks the platform-specific socket status.
func (p *connPool) isAlive(conn net.Conn) bool {
	return afs.ConnAlive(conn)
}
