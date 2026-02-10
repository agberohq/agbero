package tcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/pires/go-proxyproto"
)

type Proxy struct {
	Listen string

	// RWMutex protects Routes and Default during hot reloads
	mu      sync.RWMutex
	Routes  map[string]*Balancer
	Default *Balancer

	Logger *ll.Logger

	// Connection tracking for graceful shutdown
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	quit chan struct{}
	wg   sync.WaitGroup
}

func NewProxy(listen string, logger *ll.Logger) *Proxy {
	return &Proxy{
		Listen: listen,
		Routes: make(map[string]*Balancer),
		Logger: logger,
		conns:  make(map[net.Conn]struct{}),
		quit:   make(chan struct{}),
	}
}

func (p *Proxy) AddRoute(hostname string, cfg alaye.TCPRoute) {
	p.mu.Lock()
	defer p.mu.Unlock()

	bal := NewBalancer(cfg) // Ensure NewBalancer is exported in tcp.go
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if hostname == "" || hostname == "*" {
		p.Default = bal
	} else {
		p.Routes[hostname] = bal
	}
}

// UpdateRoutes allows hot-swapping the routing logic without dropping connections
func (p *Proxy) UpdateRoutes(newRoutes map[string]*Balancer, newDefault *Balancer) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 1. Stop health checks on old balancers
	if p.Default != nil {
		p.Default.Stop()
	}
	for _, r := range p.Routes {
		r.Stop()
	}

	// 2. Swap
	p.Routes = newRoutes
	p.Default = newDefault

	p.Logger.Fields("listen", p.Listen).Info("tcp proxy routes updated")
}

func (p *Proxy) Start() error {
	l, err := net.Listen(woos.TCP, p.Listen)
	if err != nil {
		return err
	}

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer l.Close()

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
				if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
					continue
				}
				p.Logger.Fields("err", err).Warn("tcp accept error")
				continue
			}

			p.wg.Add(1)
			go p.handle(conn)
		}
	}()

	p.Logger.Fields("bind", p.Listen).Info("tcp proxy started")
	return nil
}

func (p *Proxy) Stop() {
	select {
	case <-p.quit:
		return
	default:
		close(p.quit)
	}

	p.mu.Lock()
	if p.Default != nil {
		p.Default.Stop()
	}
	for _, r := range p.Routes {
		r.Stop()
	}
	p.mu.Unlock()

	// Force close active connections after grace period
	// This prevents DB/Long-lived connections from hanging the server process forever
	go func() {
		time.Sleep(5 * time.Second)
		p.connsMu.Lock()
		count := len(p.conns)
		for c := range p.conns {
			_ = c.Close()
		}
		p.connsMu.Unlock()
		if count > 0 {
			p.Logger.Fields("count", count).Warn("forced closed active tcp connections")
		}
	}()

	p.wg.Wait()
}

func (p *Proxy) trackConn(c net.Conn, add bool) {
	p.connsMu.Lock()
	defer p.connsMu.Unlock()
	if add {
		p.conns[c] = struct{}{}
	} else {
		delete(p.conns, c)
	}
}

func (p *Proxy) handle(src net.Conn) {
	p.trackConn(src, true)
	defer p.trackConn(src, false)
	defer p.wg.Done()

	// Enable KeepAlive to prevent intermediate firewalls (AWS/Azure) from dropping idle DB conns
	if tcpConn, ok := src.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	// Acquire Read Lock to check if we need SNI sniffing
	p.mu.RLock()
	needSNI := len(p.Routes) > 0
	p.mu.RUnlock()

	var (
		peekBuf   []byte
		n         int
		sni       string
		readBytes bool
	)

	if needSNI {
		peekBuf = make([]byte, woos.PeekBufferSize)

		// 1s timeout to allow slow mobile/IoT clients to send ClientHello
		_ = src.SetReadDeadline(time.Now().Add(woos.InitialReadTimeout))
		n0, err := src.Read(peekBuf)
		_ = src.SetReadDeadline(time.Time{})

		if err != nil {
			// If timeout with 0 bytes, client is silent.
			// If we have a default route, we might route blindly, but usually this is a dead conn.
			if isTimeout(err) && n0 == 0 {
				p.mu.RLock()
				hasDefault := p.Default != nil
				p.mu.RUnlock()

				if !hasDefault {
					_ = src.Close()
					return
				}
				// Proceed blindly to default
			} else if err != io.EOF {
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

	balancer := p.pickBalancer(sni)
	if balancer == nil {
		_ = src.Close()
		return
	}

	var client net.Conn = src
	if readBytes && n > 0 {
		client = &peekedConn{
			Conn:   src,
			reader: io.MultiReader(bytes.NewReader(peekBuf[:n]), src),
		}
	}

	// Dial with Retries
	tried := make(map[*Backend]struct{}, 4)
	var (
		dst     net.Conn
		backend *Backend
		err     error
	)

	maxAttempts := 3
	if c := balancer.BackendCount(); c > 0 && c < maxAttempts {
		maxAttempts = c
	}

	for i := 0; i < maxAttempts; i++ {
		backend = balancer.Pick(tried)
		if backend == nil {
			break
		}
		tried[backend] = struct{}{}

		dst, err = net.DialTimeout(woos.TCP, backend.Address, woos.BackendDialTimeout)
		if err == nil {
			break
		}

		backend.OnDialFailure(err)
		p.Logger.Fields("backend", backend.Address, "err", err).Warn("tcp dial failed, retrying")
	}

	if dst == nil {
		_ = client.Close()
		return
	}

	if balancer.useProtocol() {
		// We must write the header BEFORE sending any client bytes

		// Determine Source/Dest
		// We cast to proper net.Addr types usually, but the library handles it.
		header := proxyproto.HeaderProxyFromAddrs(
			byte(1), // PROXY protocol version 1 (Text) is most compatible with DBs
			client.RemoteAddr(),
			client.LocalAddr(),
		)

		// Write to backend connection
		if _, err := header.WriteTo(dst); err != nil {
			p.Logger.Fields("err", err).Error("failed to write proxy protocol header")
			_ = client.Close()
			_ = dst.Close()
			return
		}
	}

	// KeepAlive on backend connection
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	backend.ActiveConns.Add(1)
	defer backend.ActiveConns.Add(-1)

	p.pipe(client, dst)
}

func (p *Proxy) pickBalancer(sni string) *Balancer {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if sni != "" {
		sni = strings.ToLower(strings.TrimSpace(sni))
		if sni != "" {
			if b, ok := p.Routes[sni]; ok {
				return b
			}
			for routeSNI, b := range p.Routes {
				if strings.HasPrefix(routeSNI, "*.") {
					suffix := routeSNI[1:]
					if strings.HasSuffix(sni, suffix) {
						return b
					}
				}
			}
		}
	}
	return p.Default
}

// pipe ensures robust bidirectional copying with support for TCP Half-Close.
// This is critical for gRPC, PostgreSQL, and other protocols that use
// half-closed states to signal end-of-request.
func (p *Proxy) pipe(client, backend net.Conn) {
	// Set an idle timeout (e.g., 5 minutes) to prevent leaks from silent drops
	idleTimeout := 5 * time.Minute

	cWrapped := &deadlineConn{Conn: client, timeout: idleTimeout}
	bWrapped := &deadlineConn{Conn: backend, timeout: idleTimeout}

	errc := make(chan error, 1)
	copyAndClose := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
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

	go func() {
		defer wg.Done()
		copyAndClose(bWrapped, cWrapped)
	}()

	go func() {
		defer wg.Done()
		copyAndClose(cWrapped, bWrapped)
	}()

	wg.Wait()
	_ = client.Close()
	_ = backend.Close()
}

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

	pos += 38 // Skip fixed headers
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

type peekedConn struct {
	net.Conn
	reader io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func closeWrite(c net.Conn) {
	switch v := c.(type) {
	case *net.TCPConn:
		_ = v.CloseWrite()
	case *peekedConn:
		closeWrite(v.Conn)
	default:
		// Fallback for non-TCP connections (e.g. buffers in tests)
		// Usually no-op or full Close depending on implementation,
		// but we leave full Close to the defer in pipe()
	}
}

func isTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}
