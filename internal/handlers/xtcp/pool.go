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

// pooledConn wraps a net.Conn with lock-free lifecycle tracking.
// next is used only when the connection sits on the idle Treiber stack.
type pooledConn struct {
	net.Conn
	next     atomic.Pointer[pooledConn]
	lastUsed atomic.Int64 // unix nanoseconds
	inUse    atomic.Bool
	failed   atomic.Bool
}

type connPool struct {
	// hot path: lock-free Treiber stack of idle connections
	head atomic.Pointer[pooledConn]

	// cold path: protects all[] (ownership), maxSize accounting, and dial fallbacks
	mu      sync.Mutex
	all     []*pooledConn
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

// pushFree adds a connection to the lock-free idle stack.
func (p *connPool) pushFree(pc *pooledConn) {
	for {
		old := p.head.Load()
		pc.next.Store(old)
		if p.head.CompareAndSwap(old, pc) {
			return
		}
	}
}

// popFree removes and returns the top idle connection, or nil if empty.
func (p *connPool) popFree() *pooledConn {
	for {
		old := p.head.Load()
		if old == nil {
			return nil
		}
		next := old.next.Load()
		if p.head.CompareAndSwap(old, next) {
			old.next.Store(nil)
			return old
		}
	}
}

// sweep reaps idle and failed connections under one exclusive lock.
// The single-pass filter eliminates the prior RLock→Lock TOCTOU window.
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
}

// get acquires a healthy connection from the idle stack or dials a new one.
// The fast path (reuse) is fully lock-free.
func (p *connPool) get(ctx context.Context) (*pooledConn, error) {
	now := time.Now().UnixNano()
	expireNano := int64(idleTimeoutLimit)

	// Lock-free pop from idle stack
	for {
		pc := p.popFree()
		if pc == nil {
			break
		}

		// Mark in-use immediately so concurrent sweep does not reap it.
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

	// Drain the lock-free stack so nothing lingers.
	for p.popFree() != nil {
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, c := range p.all {
		_ = c.Conn.Close()
	}
	p.all = p.all[:0]
}

// isAlive checks the platform-specific socket status.
func (p *connPool) isAlive(conn net.Conn) bool {
	return afs.ConnAlive(conn)
}
