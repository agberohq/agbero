package xtcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
)

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
			p.mu.RUnlock()
			if p.isAlive(c.Conn) {
				c.lastUsed = time.Now()
				return c, nil
			}
			c.failed.Store(true)
			c.inUse.Store(false)
			p.mu.RLock()
			continue
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
	sys, ok := conn.(syscall.Conn)
	if !ok {
		return true
	}
	raw, err := sys.SyscallConn()
	if err != nil {
		return false
	}

	var sysErr error
	var n int

	// Read raw file descriptor
	err = raw.Read(func(fd uintptr) bool {
		buf := make([]byte, 1)
		// MSG_PEEK: Read without removing from queue
		// MSG_DONTWAIT: Return immediately if no data
		n, _, sysErr = syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		return true
	})

	if err != nil {
		return false
	}

	if sysErr != nil {
		// EWOULDBLOCK/EAGAIN means connection is open but no data is waiting
		if errors.Is(sysErr, syscall.EAGAIN) || errors.Is(sysErr, syscall.EWOULDBLOCK) {
			return true
		}
		return false
	}

	// n == 0 indicates EOF (peer closed connection)
	return n > 0
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
