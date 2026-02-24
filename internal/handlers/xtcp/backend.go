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
	"runtime/debug"
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

func newConnPool(addr string, maxSize int, timeout time.Duration) *connPool {
	return &connPool{
		addr:    addr,
		maxSize: maxSize,
		timeout: timeout,
	}
}

func (p *connPool) get() (*pooledConn, error) {
	p.mu.RLock()
	for _, c := range p.conns {
		if c.inUse.CompareAndSwap(false, true) && !c.failed.Load() {
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

	conn, err := p.dial()
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
			if c.failed.Load() || (!c.inUse.Load() && time.Since(c.lastUsed) > 5*time.Minute) {
				_ = c.Conn.Close()
				p.conns[i] = pc
				replaced = true
				break
			}
		}
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
	if p.resolved.IsValid() {
		conn, err := net.DialTimeout(woos.TCP, p.resolved.String(), p.timeout)
		if err == nil {
			return conn, nil
		}
		p.resolved = netip.AddrPort{}
	}

	host, port, err := net.SplitHostPort(p.addr)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.timeout)
	defer cancel()

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: p.timeout}
			return d.DialContext(ctx, network, address)
		},
	}

	addrs, err := resolver.LookupNetIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return net.DialTimeout(woos.TCP, p.addr, p.timeout)
	}

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
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
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
	poolOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		b.poolOnce.Do(func() {
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
	// Added Panic Recovery
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[CRITICAL] TCP health check panic for %s: %v\nStack: %s\n", b.Address, r, debug.Stack())
		}
	}()

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
	if len(b.hcSend) == 0 && len(b.hcExpect) == 0 {
		pc, err := b.pool.get()
		if err != nil {
			return false
		}
		b.pool.put(pc)
		return true
	}

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
