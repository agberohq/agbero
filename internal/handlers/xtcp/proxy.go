package xtcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/cache"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/pires/go-proxyproto"
)

var noopBalancer = &Balancer{}

type Proxy struct {
	Listen      string
	IdleTimeout time.Duration

	Mu      sync.RWMutex
	Routes  map[string]*Balancer
	Default *Balancer

	Logger *ll.Logger

	connsMu sync.Mutex
	conns   map[net.Conn]struct{}

	quit chan struct{}
	wg   sync.WaitGroup
}

func NewProxy(listen string, logger *ll.Logger) *Proxy {
	return &Proxy{
		Listen: listen,
		Routes: make(map[string]*Balancer),
		Logger: logger.Namespace("proxy"),
		conns:  make(map[net.Conn]struct{}),
		quit:   make(chan struct{}),
	}
}

func (p *Proxy) BackendCount() int {
	return len(p.conns)
}

func (p *Proxy) SetIdleTimeout(timeout time.Duration) {
	p.IdleTimeout = timeout
}

func (p *Proxy) AddRoute(hostname string, cfg alaye.TCPRoute) {
	p.Mu.Lock()
	defer p.Mu.Unlock()

	bal := NewBalancer(cfg)
	hostname = strings.ToLower(strings.TrimSpace(hostname))

	if hostname == "" || hostname == "*" {
		p.Default = bal
	} else {
		p.Routes[hostname] = bal
	}
}

func (p *Proxy) UpdateRoutes(newRoutes map[string]*Balancer, newDefault *Balancer) {
	p.Mu.Lock()
	oldDefault := p.Default
	oldRoutes := p.Routes

	p.Routes = newRoutes
	p.Default = newDefault
	p.Mu.Unlock()

	if oldDefault != nil {
		oldDefault.Stop()
	}
	for _, r := range oldRoutes {
		r.Stop()
	}

	p.Logger.Fields("listen", p.Listen).Info("tcp proxy routes updated")
}

func (p *Proxy) Start() error {
	l, err := net.Listen(woos.TCP, p.Listen)
	if err != nil {
		return err
	}

	cache.TCP.Store(p.Listen, &cache.Item{Value: p})

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		defer l.Close()
		defer cache.TCP.Delete(p.Listen)

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

	p.Mu.Lock()
	if p.Default != nil {
		p.Default.Stop()
	}
	for _, r := range p.Routes {
		r.Stop()
	}
	p.Mu.Unlock()

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

	remoteAddr := src.RemoteAddr().String()

	if tcpConn, ok := src.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(30 * time.Second)
	}

	p.Mu.RLock()
	needSNI := len(p.Routes) > 0
	p.Mu.RUnlock()

	var (
		peekBuf   []byte
		n         int
		sni       string
		readBytes bool
	)

	if needSNI {
		peekBuf = make([]byte, woos.PeekBufferSize)
		_ = src.SetReadDeadline(time.Now().Add(woos.InitialReadTimeout))
		n0, err := src.Read(peekBuf)
		_ = src.SetReadDeadline(time.Time{})

		if err != nil {
			if p.isTimeout(err) && n0 == 0 {
				p.Mu.RLock()
				hasDefault := p.Default != nil
				p.Mu.RUnlock()

				if !hasDefault {
					p.Logger.Fields("remote", remoteAddr).Debug("tcp peek timeout, no default route")
					_ = src.Close()
					return
				}
			} else if err != io.EOF {
				p.Logger.Fields("remote", remoteAddr, "err", err).Debug("tcp peek error")
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
		p.Logger.Fields("remote", remoteAddr, "sni", sni).Debug("no tcp route found")
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

	tried := make(map[*Backend]struct{}, 4)
	var (
		dst     net.Conn
		backend *Backend
		err     error
	)

	maxAttempts := woos.BackendRetry
	if c := balancer.BackendCount(); c > 0 && c < maxAttempts {
		maxAttempts = c
	}

	for i := 0; i < maxAttempts; i++ {
		backend = balancer.Pick(tried)
		if backend == nil {
			break
		}

		// Mark as tried so Pick() won't return it again in the next iteration
		tried[backend] = struct{}{}

		dst, err = net.DialTimeout(woos.TCP, backend.Address, woos.BackendDialTimeout)
		if err == nil {
			break
		}

		backend.OnDialFailure(err)
		p.Logger.Fields("backend", backend.Address, "err", err).Warn("tcp dial failed")
	}

	if dst == nil {
		p.Logger.Fields("remote", remoteAddr, "sni", sni).Warnf("tcp proxy: upstream (%s) unavailable", backend.Address)
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

	if balancer.useProtocol() {
		header := proxyproto.HeaderProxyFromAddrs(
			byte(1),
			client.RemoteAddr(),
			client.LocalAddr(),
		)
		if _, err := header.WriteTo(dst); err != nil {
			p.Logger.Fields("err", err).Error("failed to write proxy protocol header")
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

func (p *Proxy) pickBalancer(sni string) *Balancer {
	p.Mu.RLock()
	defer p.Mu.RUnlock()

	if sni != "" {
		sni = strings.ToLower(strings.TrimSpace(sni))
		if sni != "" {
			if b, ok := p.Routes[sni]; ok {
				return b
			}
			for routeSNI, b := range p.Routes {
				if strings.HasPrefix(routeSNI, "*.") {
					root := routeSNI[2:]
					if sni == root || strings.HasSuffix(sni, "."+root) {
						return b
					}
				}
			}
		}
	}

	if p.Default != nil {
		return p.Default
	}

	// Return the singleton no-op balancer
	return noopBalancer
}

func (p *Proxy) pipe(client, backend net.Conn) {
	timeout := p.IdleTimeout
	if timeout == 0 {
		timeout = woos.IdleTimeoutDeadline
	}

	cWrapped := &deadlineConn{Conn: client, timeout: timeout}
	bWrapped := &deadlineConn{Conn: backend, timeout: timeout}

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

func (p *Proxy) isTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout()
	}
	return false
}

func (p *Proxy) SnapBackends() []*Backend {
	p.Mu.RLock()
	defer p.Mu.RUnlock()

	var all []*Backend
	for _, bal := range p.Routes {
		all = append(all, bal.Backends()...)
	}
	if p.Default != nil {
		all = append(all, p.Default.Backends()...)
	}
	return all
}
