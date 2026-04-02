package xtcp

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/lb"
	"github.com/olekukonko/mappo"
	"github.com/pires/go-proxyproto"
)

type tcpRoute struct {
	selector      *lb.Selector
	strategyName  string
	proxyProtocol bool
}

// Stops all active backends associated with this TCP route
// Iterates through the selector pool and triggers backend shutdown
func (r *tcpRoute) Stop() {
	for _, b := range r.selector.Backends() {
		if be, ok := b.(*Backend); ok {
			be.Stop()
		}
	}
}

type connEntry struct {
	conn   net.Conn
	closed atomic.Bool
}

type Proxy struct {
	Listen      string
	IdleTimeout time.Duration
	MaxConns    int64

	mu     sync.RWMutex
	routes map[string]*tcpRoute
	def    *tcpRoute

	conns   sync.Map
	closing atomic.Bool
	connCnt atomic.Int64

	res  *resource.Resource
	quit chan struct{}
	wg   sync.WaitGroup
}

// Initializes a new TCP proxy instance for the specified listen address
// Configures the underlying connection maps and resource dependencies
func NewProxy(res *resource.Resource, listen string) *Proxy {
	return &Proxy{
		Listen: listen,
		routes: make(map[string]*tcpRoute),
		res:    res,
		quit:   make(chan struct{}),
	}
}

// Returns the total number of currently tracked active connections
// Uses atomic operations to ensure thread-safe connection counting
func (p *Proxy) BackendCount() int {
	return int(p.connCnt.Load())
}

// Configures the maximum idle duration before a connection is dropped
// Applies to both client and backend TCP streams within the proxy
func (p *Proxy) SetIdleTimeout(timeout time.Duration) {
	p.IdleTimeout = timeout
}

// Constructs a TCP route structure from the provided proxy configuration
// Initializes the load balancing selector and parses protocol settings
func (p *Proxy) buildRoute(cfg alaye.Proxy) *tcpRoute {
	var backends []lb.Backend
	for _, srv := range cfg.Backends {
		be, err := NewBackend(BackendConfig{
			Server:   srv,
			Proxy:    cfg,
			Resource: p.res,
			Logger:   p.res.Logger,
		})
		if err == nil {
			backends = append(backends, be)
		}
	}
	strategy := lb.ParseStrategy(cfg.Strategy)
	stratName := cfg.Strategy
	if stratName == "" {
		stratName = alaye.StrategyRoundRobin
	}
	selector := lb.NewSelector(backends, strategy)
	return &tcpRoute{
		selector:      selector,
		strategyName:  stratName,
		proxyProtocol: cfg.ProxyProtocol,
	}
}

// Registers a new TCP route for the specified SNI hostname
// Assigns it as the default route if the hostname is empty or a wildcard
func (p *Proxy) AddRoute(hostname string, cfg alaye.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	route := p.buildRoute(cfg)
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" || hostname == "*" {
		p.def = route
	} else {
		p.routes[hostname] = route
	}
}

// Swaps the active routing table safely using mutex locks
// Stops any previously configured routes that are no longer active
func (p *Proxy) UpdateRoutes(newRoutes map[string]*tcpRoute, newDefault *tcpRoute) {
	p.mu.Lock()
	oldDef := p.def
	oldRoutes := p.routes
	p.routes = newRoutes
	p.def = newDefault
	p.mu.Unlock()

	if oldDef != nil {
		oldDef.Stop()
	}
	for _, r := range oldRoutes {
		r.Stop()
	}
	p.res.Logger.Fields("listen", p.Listen).Info("tcp proxy routes updated")
}

// Opens the TCP listener and spawns a goroutine to accept connections
// Enforces maximum connection limits and handles transient accept errors
func (p *Proxy) Start() error {
	l, err := net.Listen(woos.TCP, p.Listen)
	if err != nil {
		return err
	}

	p.res.TCPCache.Store(p.Listen, &mappo.Item{Value: p})

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer l.Close()
		defer func() {
			if it, ok := p.res.TCPCache.Load(p.Listen); ok && it.Value == p {
				p.res.TCPCache.Delete(p.Listen)
			}
		}()

		bo := zulu.NewInfinite()

		for {
			select {
			case <-p.quit:
				return
			default:
			}

			if t, ok := l.(*net.TCPListener); ok {
				_ = t.SetDeadline(time.Now().Add(woos.AcceptLoopDeadline))
			}

			conn, err := l.Accept()
			if err != nil {
				var opErr *net.OpError
				if errors.As(err, &opErr) && opErr.Timeout() {
					continue
				}
				if p.MaxConns > 0 && p.connCnt.Load() >= p.MaxConns {
					p.res.Logger.Fields("remote", conn.RemoteAddr().String(), "limit", p.MaxConns).Warn("tcp max connections reached, dropping")
					conn.Close()
					continue
				}
				if p.closing.Load() {
					return
				}
				sleepDuration := bo.NextBackOff()
				p.res.Logger.Fields("err", err, "retry_in", sleepDuration).Warn("tcp accept error, backing off")
				select {
				case <-time.After(sleepDuration):
					continue
				case <-p.quit:
					return
				}
			}
			bo.Reset()
			p.wg.Add(1)
			go p.handle(conn)
		}
	}()

	p.res.Logger.Fields("bind", p.Listen).Info("tcp proxy started")
	return nil
}

// Initiates a graceful shutdown of the proxy and its tracked connections
// Closes the listener, active sockets, and wait-groups for completion
func (p *Proxy) Stop() {
	if !p.closing.CompareAndSwap(false, true) {
		return
	}
	close(p.quit)

	var wg sync.WaitGroup
	p.conns.Range(func(key, value any) bool {
		wg.Add(1)
		go func(c net.Conn, e *connEntry) {
			defer wg.Done()
			if e.closed.CompareAndSwap(false, true) {
				_ = c.Close()
			}
		}(key.(net.Conn), value.(*connEntry))
		return true
	})
	wg.Wait()
	p.conns.Clear()
	p.connCnt.Store(0)

	p.mu.RLock()
	def := p.def
	routes := p.routes
	p.mu.RUnlock()

	if def != nil {
		def.Stop()
	}
	for _, r := range routes {
		r.Stop()
	}
	p.wg.Wait()
}

// Safely tracks or untracks active connections in the concurrent map
// Immediately closes incoming connections if the proxy is shutting down
func (p *Proxy) trackConn(c net.Conn, add bool) {
	if add {
		entry := &connEntry{conn: c}
		p.conns.Store(c, entry)
		p.connCnt.Add(1)

		if p.closing.Load() {
			if val, ok := p.conns.LoadAndDelete(c); ok {
				if e, ok := val.(*connEntry); ok {
					if e.closed.CompareAndSwap(false, true) {
						_ = c.Close()
					}
				}
				p.connCnt.Add(-1)
			}
			return
		}
	} else {
		if val, ok := p.conns.LoadAndDelete(c); ok {
			if e, ok := val.(*connEntry); ok {
				if e.closed.CompareAndSwap(false, true) {
					_ = c.Close()
				}
			}
			p.connCnt.Add(-1)
		}
	}
}

// Manages a single accepted connection through SNI extraction and dialing
// Proxies traffic to the selected backend and manages proxy protocol headers
func (p *Proxy) handle(src net.Conn) {
	p.trackConn(src, true)
	defer p.trackConn(src, false)
	defer p.wg.Done()

	remoteAddr := src.RemoteAddr().String()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	p.mu.RLock()
	needSNI := len(p.routes) > 0
	p.mu.RUnlock()

	var (
		peekBuf   []byte
		n         int
		sni       string
		readBytes bool
	)

	if needSNI {
		peekBuf = make([]byte, woos.PeekBufferSize)
		_ = src.SetReadDeadline(time.Now().Add(woos.InitialReadTimeout))
		n0, err := io.ReadAtLeast(src, peekBuf, 1)
		_ = src.SetReadDeadline(time.Time{})

		if err != nil {
			if p.isTimeout(err) && n0 == 0 {
				p.mu.RLock()
				hasDefault := p.def != nil
				p.mu.RUnlock()
				if !hasDefault {
					p.res.Logger.Fields("remote", remoteAddr).Debug("tcp peek timeout, no default route")
					_ = src.Close()
					return
				}
			} else {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					p.res.Logger.Fields("remote", remoteAddr, "err", err).Debug("tcp peek error")
				}
				_ = src.Close()
				return
			}
		}

		if n0 > 0 {
			n = n0
			readBytes = true
			sni, _ = p.readClientHello(peekBuf[:n0])
		}
	}

	route := p.pickRoute(sni)
	if route == nil || len(route.selector.Backends()) == 0 {
		p.res.Logger.Fields("remote", remoteAddr, "sni", sni).Debug("no tcp route found")
		_ = src.Close()
		return
	}

	var client net.Conn = src
	if readBytes && n > 0 {
		client = newPeekedConn(src, peekBuf[:n])
	}

	tried := make(map[lb.Backend]bool)
	var (
		dst     net.Conn
		backend *Backend
		err     error
	)

	maxAttempts := woos.BackendRetry
	if c := len(route.selector.Backends()); c > 0 && c < maxAttempts {
		maxAttempts = c
	}

	keyFunc := func() uint64 {
		return uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
	}

	for i := 0; i < maxAttempts; i++ {
		var picked lb.Backend
		for range 5 {
			picked = route.selector.Pick(nil, keyFunc)
			if picked != nil && !tried[picked] {
				break
			}
		}
		if picked == nil || tried[picked] {
			picked = route.selector.Pick(nil, keyFunc)
		}
		if picked == nil {
			break
		}
		tried[picked] = true
		backend = picked.(*Backend)
		dst, err = net.DialTimeout(woos.TCP, backend.Address, woos.BackendDialTimeout)
		if err == nil {
			break
		}
		backend.OnDialFailure(err)
		p.res.Logger.Fields("backend", backend.Address, "err", err).Warn("tcp dial failed")
	}

	if dst == nil {
		p.res.Logger.Fields("remote", remoteAddr, "sni", sni).Warn("tcp proxy: upstream unavailable")
		_ = client.Close()
		return
	}

	backend.Activity.StartRequest()
	start := time.Now()
	requestFailed := false
	defer func() {
		duration := time.Since(start).Microseconds()
		backend.Activity.EndRequest(duration, requestFailed)
	}()

	if route.proxyProtocol {
		header := proxyproto.HeaderProxyFromAddrs(
			byte(1),
			client.RemoteAddr(),
			client.LocalAddr(),
		)
		if _, err := header.WriteTo(dst); err != nil {
			p.res.Logger.Fields("err", err).Error("failed to write proxy protocol header")
			_ = client.Close()
			_ = dst.Close()
			requestFailed = true
			return
		}
	}

	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	p.pipe(client, dst)
}

// Matches an extracted SNI hostname against configured routing rules
// Falls back to the wildcard or default route if no exact match exists
func (p *Proxy) pickRoute(sni string) *tcpRoute {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if sni != "" {
		sni = strings.ToLower(strings.TrimSpace(sni))
		if sni != "" {
			if b, ok := p.routes[sni]; ok {
				return b
			}
			for routeSNI, b := range p.routes {
				if strings.HasPrefix(routeSNI, "*.") {
					root := routeSNI[2:]
					if sni == root || strings.HasSuffix(sni, "."+root) {
						return b
					}
				}
			}
		}
	}
	return p.def
}

// Establishes a bidirectional data stream between the client and backend
// Enforces idle timeouts and ensures both connections close upon completion
func (p *Proxy) pipe(client, backend net.Conn) {
	timeout := p.IdleTimeout
	if timeout == 0 {
		timeout = woos.IdleTimeoutDeadline
	}

	cWrapped := &deadlineConn{Conn: client, timeout: timeout}
	bWrapped := &deadlineConn{Conn: backend, timeout: timeout}

	errc := make(chan error, 1)
	copyAndClose := func(dst, src net.Conn) {
		buf := proxyBufPool.Get()
		defer proxyBufPool.Put(buf)
		_, err := io.CopyBuffer(dst, src, buf)
		if err != nil {
			select {
			case errc <- err:
			default:
			}
			_ = dst.Close()
			_ = src.Close()
		} else {
			closeWrite(dst)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); copyAndClose(bWrapped, cWrapped) }()
	go func() { defer wg.Done(); copyAndClose(cWrapped, bWrapped) }()
	wg.Wait()

	_ = client.Close()
	_ = backend.Close()
}

// Parses a raw TLS byte buffer to extract the Server Name Indication
// Returns an error if the payload is too short or not a valid ClientHello
func (p *Proxy) readClientHello(data []byte) (string, error) {
	if len(data) < woos.MinClientHelloLen {
		return "", woos.ErrShortData
	}
	if data[0] != woos.RecordTypeHandshake {
		return "", woos.ErrNotTLS
	}
	pos := 5
	if pos >= len(data) {
		return "", woos.ErrShort
	}
	if data[pos] != woos.HandshakeTypeClientHello {
		return "", woos.ErrNotClientHello
	}
	pos += 38
	if pos >= len(data) {
		return "", woos.ErrShort
	}
	sessionIdLen := int(data[pos])
	pos += 1 + sessionIdLen
	if pos+2 > len(data) {
		return "", woos.ErrShort
	}
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen
	if pos+1 > len(data) {
		return "", woos.ErrShort
	}
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return "", woos.ErrShort
	}
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+extLen > len(data) {
		return "", woos.ErrShortExt
	}
	end := pos + extLen
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos:])
		extSize := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+extSize > end {
			return "", woos.ErrShortExt
		}
		if extType == woos.ExtTypeServerName {
			if extSize < 2 {
				return "", woos.ErrShortSNI
			}
			listLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2
			listEnd := pos + listLen
			if listEnd > pos+extSize-2 {
				return "", woos.ErrShortSNIList
			}
			for pos+3 <= listEnd {
				nameType := data[pos]
				nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
				pos += 3
				if pos+nameLen > listEnd {
					return "", woos.ErrShortName
				}
				if nameType == woos.NameTypeHostName {
					return string(data[pos : pos+nameLen]), nil
				}
				pos += nameLen
			}
		} else {
			pos += extSize
		}
	}
	return "", nil
}

// Determines whether a given network error represents a timeout condition
// Casts the error to the net.Error interface to evaluate its timeout flag
func (p *Proxy) isTimeout(err error) bool {
	if netErr, ok := errors.AsType[net.Error](err); ok {
		return netErr.Timeout()
	}
	return false
}

// Retrieves a snapshot of all active backends across configured routes
// Iterates deeply through the load balancer hierarchy to extract endpoints
func (p *Proxy) SnapBackends() []*Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var all []*Backend
	extract := func(sel *lb.Selector) {
		for _, b := range sel.Backends() {
			if be, ok := b.(*Backend); ok {
				all = append(all, be)
			}
		}
	}

	unwrap := func(bal lb.Balancer) {
		for bal != nil {
			if sel, ok := bal.(*lb.Selector); ok {
				extract(sel)
				return
			}
			if u, ok := bal.(interface{ Unwrap() lb.Balancer }); ok {
				bal = u.Unwrap()
			} else {
				return
			}
		}
	}

	for _, route := range p.routes {
		unwrap(route.selector)
	}
	if p.def != nil {
		unwrap(p.def.selector)
	}
	return all
}
