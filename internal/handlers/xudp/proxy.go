package xudp

import (
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/lb"
	"github.com/olekukonko/mappo"
)

// udpRoute is the per-listen-address route holding a backend selector
// and the resolved Matcher for protocol-aware session keying.
type udpRoute struct {
	selector  *lb.Selector
	matcher   Matcher // nil = use src:port as session key
	proxyName string
}

func (r *udpRoute) stop() {
	for _, b := range r.selector.Backends() {
		if be, ok := b.(*Backend); ok {
			be.Stop()
		}
	}
}

// Proxy is the UDP load balancer for a single listen address.
// It manages the listen UDPConn, the session table, and all backend routing.
//
// The concurrency model:
//   - One goroutine reads datagrams from the listen socket.
//   - For each datagram, the session key is extracted via the Matcher (or falls
//     back to src:port). If a session exists, the datagram is forwarded to the
//     backend conn. If no session exists, a new backend is picked and a reply
//     goroutine is started for that session.
//   - Each session has one goroutine reading replies from the backend conn and
//     writing them back to the client via the shared listen conn.
type Proxy struct {
	Listen     string
	MaxSess    int64
	sessionTTL time.Duration

	mu     sync.RWMutex
	routes map[string]*udpRoute // keyed by SNI pattern (unused for UDP but kept for API parity)
	def    *udpRoute

	sessions *sessionTable
	closing  atomic.Bool

	res  *resource.Resource
	quit chan struct{}
	wg   sync.WaitGroup
}

// NewProxy creates a UDP proxy for the given listen address.
func NewProxy(res *resource.Resource, listen string) *Proxy {
	return &Proxy{
		Listen: listen,
		routes: make(map[string]*udpRoute),
		res:    res,
		quit:   make(chan struct{}),
	}
}

// SetSessionTTL configures the idle timeout for UDP sessions.
// Must be called before Start().
func (p *Proxy) SetSessionTTL(d time.Duration) {
	p.sessionTTL = d
}

// AddRoute registers a UDP route. For UDP, routing is not SNI-based —
// the route name is used as a label only. The first route added becomes
// the default unless a subsequent call overrides it.
func (p *Proxy) AddRoute(name string, cfg alaye.Proxy) {
	p.mu.Lock()
	defer p.mu.Unlock()

	route := p.buildRoute(cfg)
	if name == "" || name == "*" {
		p.def = route
	} else {
		p.routes[name] = route
		// Also set as default if we don't have one yet
		if p.def == nil {
			p.def = route
		}
	}
}

// buildRoute constructs a udpRoute from an alaye.Proxy config.
func (p *Proxy) buildRoute(cfg alaye.Proxy) *udpRoute {
	var backends []lb.Backend
	for _, srv := range cfg.Backends {
		be, err := NewBackend(BackendConfig{
			Server:   srv,
			Proxy:    cfg,
			Resource: p.res,
			Logger:   p.res.Logger,
		})
		if err != nil {
			p.res.Logger.Fields("backend", srv.Address.String(), "err", err).
				Error("xudp: failed to create backend")
			continue
		}
		backends = append(backends, be)
	}

	strategy := lb.ParseStrategy(cfg.Strategy)
	selector := lb.NewSelector(backends, strategy)
	selector.Update(backends)

	return &udpRoute{
		selector:  selector,
		matcher:   lookupMatcher(cfg.Matcher),
		proxyName: cfg.Name,
	}
}

// Start begins listening on the UDP address. Non-blocking — runs the
// receive loop in a goroutine.
func (p *Proxy) Start() error {
	addr, err := net.ResolveUDPAddr("udp", p.Listen)
	if err != nil {
		return fmt.Errorf("xudp: resolve %q: %w", p.Listen, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("xudp: listen %q: %w", p.Listen, err)
	}

	// Update Listen to the real bound address — important when port 0
	// is used (OS assigns a free port) so callers can read p.Listen.
	p.Listen = conn.LocalAddr().String()

	maxSess := p.MaxSess
	if maxSess <= 0 {
		maxSess = def.UDPMaxSessions
	}

	p.mu.Lock()
	ttl := p.sessionTTL
	if ttl <= 0 {
		ttl = def.UDPDefaultSessionTTL
	}
	p.sessions = newSessionTable(ttl, maxSess)

	// Store in TCPCache for uptime/management — reuse the same cache
	// keyed by listen address.
	p.res.TCPCache.Store(p.Listen, &mappo.Item{Value: p})
	p.mu.Unlock()

	p.wg.Add(1)
	go p.receiveLoop(conn)

	p.res.Logger.Fields("bind", p.Listen, "max_sessions", maxSess).
		Info("xudp: proxy started")
	return nil
}

// receiveLoop reads datagrams from the listen socket and dispatches them.
func (p *Proxy) receiveLoop(conn *net.UDPConn) {
	defer p.wg.Done()
	defer conn.Close()
	defer func() {
		if it, ok := p.res.TCPCache.Load(p.Listen); ok && it.Value == p {
			p.res.TCPCache.Delete(p.Listen)
		}
	}()

	for {
		select {
		case <-p.quit:
			return
		default:
		}

		// Short read deadline so we can check p.quit periodically
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

		buf := getDatagram()
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			putDatagram(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if p.closing.Load() {
				return
			}
			p.res.Logger.Fields("err", err).Warn("xudp: read error")
			continue
		}

		data := buf[:n]
		go p.handleDatagram(conn, clientAddr, data, buf)
	}
}

// handleDatagram processes a single incoming datagram.
func (p *Proxy) handleDatagram(listenConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, buf []byte) {
	defer putDatagram(buf)

	p.mu.RLock()
	route := p.activeRoute()
	p.mu.RUnlock()

	if route == nil || len(route.selector.Backends()) == 0 {
		p.res.Logger.Fields("remote", clientAddr.String()).Debug("xudp: no route, dropping datagram")
		return
	}

	// Determine session key: try protocol matcher first, fall back to src:port
	sessionKey := clientAddr.String() // default: src_ip:src_port
	if route.matcher != nil {
		if key, ok := route.matcher.Match(data); ok && key != "" {
			sessionKey = key
		}
	}

	// Fast path: existing session
	if sess := p.sessions.get(sessionKey); sess != nil {
		if _, err := sess.backendConn.Write(data); err != nil {
			p.res.Logger.Fields("key", sessionKey[:min(20, len(sessionKey))], "err", err).
				Warn("xudp: write to backend failed, evicting session")
			p.sessions.delete(sessionKey)
			sess.backend.OnDialFailure(err)
		} else {
			sess.backend.Activity.Requests.Add(1)
		}
		return
	}

	// Slow path: new session — pick a backend
	backend := p.pickBackend(route)
	if backend == nil {
		p.res.Logger.Fields("remote", clientAddr.String()).Warn("xudp: no available backend")
		return
	}

	if p.sessions.len() >= p.sessions.maxSess {
		p.res.Logger.Fields("remote", clientAddr.String(), "limit", p.sessions.maxSess).
			Warn("xudp: max sessions reached, dropping")
		return
	}

	// Dial a dedicated UDP conn to the backend for this session
	backendConn, err := net.DialTimeout("udp", backend.Address, def.UDPDialTimeout)
	if err != nil {
		p.res.Logger.Fields("backend", backend.Address, "err", err).Error("xudp: dial backend failed")
		backend.OnDialFailure(err)
		return
	}

	sess := newSession(backend, backendConn)
	if !p.sessions.create(sessionKey, sess) {
		// Race: another goroutine just created this session
		_ = backendConn.Close()
		if existing := p.sessions.get(sessionKey); existing != nil {
			_, _ = existing.backendConn.Write(data)
		}
		return
	}

	backend.Activity.StartRequest()

	// Forward the first datagram
	if _, err := backendConn.Write(data); err != nil {
		p.res.Logger.Fields("backend", backend.Address, "err", err).Error("xudp: write to backend failed")
		p.sessions.delete(sessionKey)
		backend.OnDialFailure(err)
		backend.Activity.EndRequest(0, true)
		return
	}
	backend.Activity.Requests.Add(1)

	p.res.Logger.Fields(
		"remote", clientAddr.String(),
		"backend", backend.Address,
		"key", sessionKey[:min(20, len(sessionKey))],
		"matcher", matcherName(route.matcher),
	).Debug("xudp: new session")

	// Start reply forwarding goroutine for this session
	p.wg.Add(1)
	go p.replyLoop(listenConn, clientAddr, sessionKey, sess)
}

// replyLoop reads reply datagrams from the backend conn and writes them
// back to the original client via the shared listen conn.
// Runs for the lifetime of the session.
func (p *Proxy) replyLoop(
	listenConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	sessionKey string,
	sess *session,
) {
	defer p.wg.Done()
	defer func() {
		p.sessions.delete(sessionKey)
		sess.backend.Activity.EndRequest(
			time.Since(time.Unix(0, sess.lastSeen.Load())).Microseconds(),
			false,
		)
	}()

	ttl := p.sessions.ttl

	for {
		// Extend read deadline on each packet — session stays alive as long
		// as traffic flows within TTL.
		_ = sess.backendConn.SetReadDeadline(time.Now().Add(ttl))

		buf := getDatagram()
		n, err := sess.backendConn.Read(buf)
		if err != nil {
			putDatagram(buf)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// No traffic for TTL duration — session expired
				p.res.Logger.Fields(
					"key", sessionKey[:min(20, len(sessionKey))],
					"backend", sess.backend.Address,
				).Debug("xudp: session expired")
			} else if !p.closing.Load() {
				p.res.Logger.Fields(
					"backend", sess.backend.Address,
					"err", err,
				).Warn("xudp: backend read error")
				sess.backend.RecordResult(false)
			}
			return
		}

		sess.touch()

		// Write reply back to the original client
		if _, err := listenConn.WriteToUDP(buf[:n], clientAddr); err != nil {
			putDatagram(buf)
			if !p.closing.Load() {
				p.res.Logger.Fields("remote", clientAddr.String(), "err", err).
					Warn("xudp: write to client failed")
			}
			return
		}
		putDatagram(buf)
	}
}

// pickBackend selects a backend from the route using the lb selector.
func (p *Proxy) pickBackend(route *udpRoute) *Backend {
	keyFunc := func() uint64 {
		return uint64(rand.Uint32())<<32 | uint64(rand.Uint32())
	}

	for i := 0; i < def.BackendRetryCount; i++ {
		picked := route.selector.Pick(nil, keyFunc)
		if picked == nil {
			break
		}
		be, ok := picked.(*Backend)
		if !ok {
			continue
		}
		if be.IsUsable() {
			return be
		}
	}
	return nil
}

// activeRoute returns the current default route.
// Caller must hold at least p.mu.RLock.
func (p *Proxy) activeRoute() *udpRoute {
	return p.def
}

// Stop gracefully shuts down the proxy — closes the listen socket,
// drains all sessions, and waits for all goroutines to exit.
func (p *Proxy) Stop() {
	if !p.closing.CompareAndSwap(false, true) {
		return
	}
	close(p.quit)

	if p.sessions != nil {
		p.sessions.closeAll()
	}

	p.wg.Wait()

	p.mu.RLock()
	def := p.def
	routes := p.routes
	p.mu.RUnlock()

	if def != nil {
		def.stop()
	}
	for _, r := range routes {
		r.stop()
	}

	p.res.Logger.Fields("bind", p.Listen).Info("xudp: proxy stopped")
}

// SnapBackends returns a snapshot of all backends for the uptime handler.
func (p *Proxy) SnapBackends() []*Backend {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var all []*Backend
	add := func(r *udpRoute) {
		if r == nil {
			return
		}
		for _, b := range r.selector.Backends() {
			if be, ok := b.(*Backend); ok {
				all = append(all, be)
			}
		}
	}
	add(p.def)
	for _, r := range p.routes {
		add(r)
	}
	return all
}

// ActiveSessions returns the current number of active UDP sessions.
func (p *Proxy) ActiveSessions() int64 {
	if p.sessions == nil {
		return 0
	}
	return p.sessions.len()
}

func matcherName(m Matcher) string {
	if m == nil {
		return def.DefaultUDPMatcher
	}
	return m.Name()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
