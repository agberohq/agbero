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
)

type Proxy struct {
	Listen string

	// Map of SNI Hostname -> Balancer
	Routes map[string]*TCPBalancer
	// Fallback balancer if no SNI matches or non-TLS
	Default *TCPBalancer

	Logger *ll.Logger
	quit   chan struct{}
	wg     sync.WaitGroup
}

// NewProxy creates a proxy for a specific listener address.
// Routes are added subsequently.
func NewProxy(listen string, logger *ll.Logger) *Proxy {
	return &Proxy{
		Listen: listen,
		Routes: make(map[string]*TCPBalancer),
		Logger: logger,
		quit:   make(chan struct{}),
	}
}

// AddRoute registers a balancer for a specific SNI hostname.
// If hostname is empty, it sets the default balancer.
func (p *Proxy) AddRoute(hostname string, cfg alaye.TCPRoute) {
	bal := newTCPBalancer(cfg)

	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "" || hostname == "*" {
		p.Default = bal
	} else {
		p.Routes[hostname] = bal
	}
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
				t.SetDeadline(time.Now().Add(woos.AcceptLoopDeadline))
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

	p.Logger.Fields("bind", p.Listen, "sni_routes", len(p.Routes)).Info("tcp proxy started")
	return nil
}

func (p *Proxy) Stop() {
	close(p.quit)
	p.wg.Wait()
}

func (p *Proxy) handle(src net.Conn) {
	defer p.wg.Done()

	peekBuf := make([]byte, woos.PeekBufferSize)

	// keep this small so plain TCP doesn't stall waiting for client data
	src.SetReadDeadline(time.Now().Add(woos.InitialReadTimeout))
	n, err := src.Read(peekBuf)
	src.SetReadDeadline(time.Time{})

	// If we timed out *and* read nothing, that's fine: assume non-TLS/no SNI yet.
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() && n == 0 {
			err = nil
		}
	}

	if err != nil && err != io.EOF {
		_ = src.Close()
		return
	}

	sni := ""
	if n > 0 {
		sni, _ = p.readClientHello(peekBuf[:n])
	}

	// pick balancer (same as your code)
	var balancer *TCPBalancer
	if sni != "" {
		sni = strings.ToLower(sni)
		if b, ok := p.Routes[sni]; ok {
			balancer = b
		} else {
			for routeSNI, b := range p.Routes {
				if strings.HasPrefix(routeSNI, "*.") {
					suffix := routeSNI[1:]
					if strings.HasSuffix(sni, suffix) {
						balancer = b
						break
					}
				}
			}
		}
	}
	if balancer == nil {
		balancer = p.Default
	}
	if balancer == nil {
		_ = src.Close()
		return
	}

	backend := balancer.Pick()
	if backend == nil {
		_ = src.Close()
		return
	}

	var wrappedSrc net.Conn = src
	if n > 0 {
		wrappedSrc = &peekedConn{
			Conn:   src,
			reader: io.MultiReader(bytes.NewReader(peekBuf[:n]), src),
		}
	}

	backend.ActiveConns.Add(1)
	defer backend.ActiveConns.Add(-1)

	dest, err := net.DialTimeout(woos.TCP, backend.Address, woos.BackendDialTimeout)
	if err != nil {
		_ = src.Close()
		return
	}

	p.pipe(wrappedSrc, dest)
}

func (p *Proxy) pipe(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()

	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(dst, src)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(src, dst)
		errc <- err
	}()
	<-errc
}

func (p *Proxy) readClientHello(data []byte) (string, error) {
	if len(data) < woos.MinClientHelloLen {
		return "", woos.ErrShortData
	}

	// TLS Record Header
	// 0x16 = Handshake
	if data[0] != woos.RecordTypeHandshake {
		return "", woos.ErrNotTLS
	}
	// Version (ignore)
	// Length (2 bytes) at index 3
	// Handshake Header starts at 5
	// Handshake Type 0x01 = ClientHello
	if data[5] != woos.HandshakeTypeClientHello {
		return "", woos.ErrNotClientHello
	}

	// Skip Record Header (5) + Handshake Type (1) + Length (3) + Version (2) + Random (32)
	// Session ID Len (1)
	pos := woos.RecordHeaderLen + woos.HandshakeTypeLen + woos.HandshakeLength + woos.VersionLen + woos.RandomLen
	if pos >= len(data) {
		return "", woos.ErrShort
	}

	sessionIdLen := int(data[pos])
	pos++
	pos += sessionIdLen
	if pos+2 >= len(data) {
		return "", woos.ErrShort
	}

	// Cipher Suites
	cipherLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherLen
	if pos+1 >= len(data) {
		return "", woos.ErrShort
	}

	// Enabled Methods
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 >= len(data) {
		return "", woos.ErrShort
	}

	// Extensions
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

		if extType == woos.ExtTypeServerName { // Server Name Extension
			if pos+2 > end {
				return "", woos.ErrShortSNI
			}
			// SNI List Length
			listLen := int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2

			listEnd := pos + listLen
			if listEnd > end {
				return "", woos.ErrShortSNIList

			}

			for pos+3 <= listEnd {
				nameType := data[pos]
				nameLen := int(binary.BigEndian.Uint16(data[pos+1:]))
				pos += 3

				if nameType == woos.NameTypeHostName { // Host Name
					if pos+nameLen > listEnd {
						return "", woos.ErrShortName
					}
					return string(data[pos : pos+nameLen]), nil
				}
				pos += nameLen
			}
		}
		pos += extSize
	}

	return "", nil
}

type peekedConn struct {
	net.Conn
	reader io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
