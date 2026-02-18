package xtcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	metrics2 "git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
)

var rngPool = sync.Pool{
	New: func() any {
		var seed int64
		_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
		return mrand.New(mrand.NewSource(seed))
	},
}

// pooledConn wraps a net.Conn with metadata for the pool
type pooledConn struct {
	net.Conn
	lastUsed time.Time
	inUse    atomic.Bool
	failed   atomic.Bool
}

// connPool manages reusable connections for health checks
type connPool struct {
	mu       sync.RWMutex
	conns    []*pooledConn
	maxSize  int
	timeout  time.Duration
	addr     string
	resolved netip.AddrPort // cached resolved address
}

func newConnPool(addr string, maxSize int, timeout time.Duration) *connPool {
	return &connPool{
		addr:    addr,
		maxSize: maxSize,
		timeout: timeout,
	}
}

// get returns a usable connection from the pool or creates new one
func (p *connPool) get() (*pooledConn, error) {
	p.mu.RLock()
	for _, c := range p.conns {
		if c.inUse.CompareAndSwap(false, true) && !c.failed.Load() {
			// Verify connection is still alive with a quick peek
			if p.isAlive(c.Conn) {
				c.lastUsed = time.Now()
				p.mu.RUnlock()
				return c, nil
			}
			c.failed.Store(true)
			c.inUse.Store(false)
		}
	}
	p.mu.RUnlock()

	// Create new connection
	conn, err := p.dial()
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{
		Conn:     conn,
		lastUsed: time.Now(),
	}
	pc.inUse.Store(true)

	// Try to add to pool if space available
	p.mu.Lock()
	if len(p.conns) < p.maxSize {
		p.conns = append(p.conns, pc)
	} else {
		// Replace oldest failed/idle connection
		replaced := false
		for i, c := range p.conns {
			if c.failed.Load() || (!c.inUse.Load() && time.Since(c.lastUsed) > 5*time.Minute) {
				_ = c.Conn.Close()
				p.conns[i] = pc
				replaced = true
				break
			}
		}
		// If no slot available, close the new connection and return error
		if !replaced {
			_ = pc.Conn.Close()
			p.mu.Unlock()
			return nil, fmt.Errorf("connection pool full")
		}
	}
	p.mu.Unlock()

	return pc, nil
}

func (p *connPool) dial() (net.Conn, error) {
	// Use cached resolved address if available
	if p.resolved.IsValid() {
		conn, err := net.DialTimeout(woos.TCP, p.resolved.String(), p.timeout)
		if err == nil {
			return conn, nil
		}
		// Resolution might be stale, clear and retry with DNS
		p.resolved = netip.AddrPort{}
	}

	// Resolve and cache
	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	// Use resolver with caching
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: p.timeout}
			return d.DialContext(ctx, network, address)
		},
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		// Fallback to standard dial
		return net.DialTimeout(woos.TCP, p.addr, p.timeout)
	}

	// Try each resolved address
	var lastErr error
	for _, addr := range addrs {
		addrPort := netip.AddrPortFrom(addr, parsePort(port))
		conn, err := net.DialTimeout(woos.TCP, addrPort.String(), p.timeout)
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

func (p *connPool) isAlive(conn net.Conn) bool {
	// Set very short read deadline to test liveness without blocking
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})

	// EOF or timeout means dead, nil or data means alive
	return err == nil || (!errors.Is(err, io.EOF) && !isTimeout(err))
}

func (p *connPool) put(pc *pooledConn) {
	if pc == nil {
		return
	}
	pc.inUse.Store(false)
	pc.lastUsed = time.Now()
}

func (p *connPool) close() {
	p.mu.Lock()
	for _, c := range p.conns {
		_ = c.Conn.Close()
	}
	p.conns = p.conns[:0]
	p.mu.Unlock()
}

func parsePort(s string) uint16 {
	var p uint16
	fmt.Sscanf(s, "%d", &p)
	return p
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

type Snapshot struct {
	Address     string
	Alive       bool
	ActiveConns int64
	Failures    int64
	MaxConns    int64
	TotalReqs   uint64
	Latency     metrics2.LatencySnapshot
}

type Backend struct {
	Address string
	Weight  int

	Activity *metrics2.Activity
	Health   *metrics2.Health
	Alive    *atomic.Bool

	MaxConns int64

	hcInterval time.Duration
	hcTimeout  time.Duration
	hcSend     []byte
	hcExpect   []byte
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
	pool     *connPool
	poolOnce sync.Once // ensures pool is initialized only once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		// Use poolOnce to safely check/close pool even if healthCheckLoop hasn't run yet
		b.poolOnce.Do(func() {
			// Pool might not be initialized, check nil
			if b.pool != nil {
				b.pool.close()
			}
		})
	})
}

func (b *Backend) OnDialFailure(_ error) {
	b.Activity.Failures.Add(1)

	if b.failThresh > 0 {
		current := b.Activity.Failures.Load()
		if int64(current) >= b.failThresh {
			b.Alive.Store(false)
		}
	}
}

func (b *Backend) healthCheckLoop() {
	// Initialize connection pool exactly once
	b.poolOnce.Do(func() {
		b.pool = newConnPool(b.Address, 3, b.hcTimeout)
	})

	r := rngPool.Get().(*mrand.Rand)
	jitter := time.Duration(r.Intn(1000)) * time.Millisecond
	rngPool.Put(r)
	time.Sleep(jitter)

	ticker := time.NewTicker(b.hcInterval)
	defer ticker.Stop()

	consecutiveFailures := int64(0)
	currentInterval := b.hcInterval
	// Cap backoff at 30s using existing hcInterval as base
	maxBackoff := 30 * time.Second
	if b.hcInterval > maxBackoff {
		maxBackoff = b.hcInterval * 10
	}

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			if b.check() {
				consecutiveFailures = 0
				b.Health.RecordSuccess()
				b.Activity.Failures.Store(0)

				// Reset interval on success
				if currentInterval != b.hcInterval {
					currentInterval = b.hcInterval
					ticker.Reset(currentInterval)
				}

				if !b.Alive.Load() {
					b.Alive.Store(true)
				}
			} else {
				consecutiveFailures++
				b.Health.RecordFailure()

				if consecutiveFailures >= b.failThresh {
					b.Alive.Store(false)
					// Exponential backoff: double the interval, cap at maxBackoff
					currentInterval *= 2
					if currentInterval > maxBackoff {
						currentInterval = maxBackoff
					}
					ticker.Reset(currentInterval)
				}
			}
		}
	}
}

func (b *Backend) check() bool {
	// Fast path: simple TCP connect with pooled connection
	if len(b.hcSend) == 0 && len(b.hcExpect) == 0 {
		pc, err := b.pool.get()
		if err != nil {
			return false
		}
		// Just having a usable connection means it's alive
		b.pool.put(pc)
		return true
	}

	// Full check with send/expect - need dedicated connection
	pc, err := b.pool.get()
	if err != nil {
		return false
	}
	defer b.pool.put(pc)

	conn := pc.Conn
	_ = conn.SetDeadline(time.Now().Add(b.hcTimeout))

	if len(b.hcSend) > 0 {
		if _, err := conn.Write(b.hcSend); err != nil {
			pc.failed.Store(true)
			return false
		}
	}

	if len(b.hcExpect) > 0 {
		// Reuse buffer from pool to avoid alloc
		buf := getCheckBuf()
		defer putCheckBuf(buf)

		n, err := conn.Read(buf)
		if err != nil {
			pc.failed.Store(true)
			return false
		}
		if !bytes.Contains(buf[:n], b.hcExpect) {
			return false
		}
	}

	return true
}

// Buffer pool for health check reads
var checkBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1024)
		return &b
	},
}

func getCheckBuf() []byte {
	return *(checkBufPool.Get().(*[]byte))
}

func putCheckBuf(b []byte) {
	checkBufPool.Put(&b)
}

func (b *Backend) Snapshot() *Snapshot {
	return &Snapshot{
		Address:     b.Address,
		Alive:       b.Alive.Load(),
		ActiveConns: b.Activity.InFlight.Load(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxConns:    b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}
