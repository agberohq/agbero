package xtcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/resource"
	"github.com/olekukonko/ll"
)

func newTestLogger() *ll.Logger {
	return ll.New("test").Disable()
}
func waitTCPReady(t *testing.T, addr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 150*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener not ready: %s", addr)
}
func startIDServer(t *testing.T, id string) (addr string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start ID server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = conn.Write([]byte(id))
			}(c)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		<-done
	}
}
func startHalfCloseServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start half-close server: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer l.Close()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				for {
					_, rerr := conn.Read(buf)
					if rerr != nil {
						break
					}
				}
				_, _ = conn.Write([]byte("OK"))
			}(c)
		}
	}()
	return l.Addr().String(), func() {
		_ = l.Close()
		<-done
	}
}
func getFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}
func makeSNIClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)
	extDataLen := 2 + 1 + 2 + sniLen
	extData := make([]byte, extDataLen)
	binary.BigEndian.PutUint16(extData[0:], uint16(sniLen+3))
	extData[2] = 0x00
	binary.BigEndian.PutUint16(extData[3:], uint16(sniLen))
	copy(extData[5:], sniBytes)
	extBlockLen := 2 + 2 + extDataLen
	extBlock := make([]byte, extBlockLen)
	binary.BigEndian.PutUint16(extBlock[0:], 0x0000)
	binary.BigEndian.PutUint16(extBlock[2:], uint16(extDataLen))
	copy(extBlock[4:], extData)
	allExtLen := extBlockLen
	handshakeBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + allExtLen
	body := make([]byte, handshakeBodyLen)
	pos := 0
	body[pos], body[pos+1] = 0x03, 0x03
	pos += 2
	pos += 32
	body[pos] = 0x00
	pos++
	body[pos], body[pos+1] = 0x00, 0x02
	pos += 2
	body[pos], body[pos+1] = 0x00, 0x00
	pos += 2
	body[pos] = 0x01
	pos++
	body[pos] = 0x00
	pos++
	binary.BigEndian.PutUint16(body[pos:], uint16(allExtLen))
	pos += 2
	copy(body[pos:], extBlock)
	recordLen := 1 + 3 + handshakeBodyLen
	pkt := make([]byte, 5+recordLen)
	pkt[0] = 0x16
	pkt[1], pkt[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(pkt[3:], uint16(recordLen))
	pkt[5] = 0x01
	l := uint32(handshakeBodyLen)
	pkt[6], pkt[7], pkt[8] = byte(l>>16), byte(l>>8), byte(l)
	copy(pkt[9:], body)
	return pkt
}
func readOne(t *testing.T, c net.Conn) string {
	t.Helper()
	buf := make([]byte, 256)
	_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
	n, err := c.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("read failed: %v", err)
	}
	return string(buf[:n])
}
func TestProxy_SNIRouting_Exact_Wildcard_Default(t *testing.T) {
	sA, stopA := startIDServer(t, "BackendA")
	defer stopA()
	sW, stopW := startIDServer(t, "BackendW")
	defer stopW()
	sD, stopD := startIDServer(t, "BackendD")
	defer stopD()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("a.com", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(sA)},
	})
	p.AddRoute("*.w.com", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(sW)},
	})
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(sD)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	tests := []struct {
		name string
		sni  string
		want string
	}{
		{"Exact Match", "a.com", "BackendA"},
		{"Wildcard Match", "x.w.com", "BackendW"},
		{"Default Route", "other.com", "BackendD"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()
			_, _ = conn.Write(makeSNIClientHello(tt.sni))
			got := readOne(t, conn)
			if !bytes.Contains([]byte(got), []byte(tt.want)) {
				t.Fatalf("got %q, want containing %q", got, tt.want)
			}
		})
	}
}
func TestProxy_DefaultRoute_NoClientData_StillConnects(t *testing.T) {
	sD, stopD := startIDServer(t, "BackendD")
	defer stopD()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(sD)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	got := readOne(t, conn)
	if !bytes.Contains([]byte(got), []byte("BackendD")) {
		t.Fatalf("got %q, want containing %q", got, "BackendD")
	}
}
func TestProxy_DialRetry_SkipsDeadBackend(t *testing.T) {
	live, stopLive := startIDServer(t, "LIVE")
	defer stopLive()
	deadAddr := getFreePort(t)
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{
			alaye.NewServer(deadAddr),
			alaye.NewServer(live),
		},
		Strategy: "round_robin",
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	got := readOne(t, conn)
	if got != "LIVE" {
		t.Fatalf("got %q, want %q", got, "LIVE")
	}
}
func TestProxy_HalfClose_PropagatesEOF(t *testing.T) {
	up, stop := startHalfCloseServer(t)
	defer stop()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.SetIdleTimeout(5 * time.Second)
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(up)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("hello"))
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("expected *net.TCPConn")
	}
	_ = tc.CloseWrite()
	got := readOne(t, conn)
	if got != "OK" {
		t.Fatalf("got %q, want %q", got, "OK")
	}
}
func TestProxy_UpdateRoutes(t *testing.T) {
	s1, stop1 := startIDServer(t, "Backend1")
	defer stop1()
	s2, stop2 := startIDServer(t, "Backend2")
	defer stop2()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(s1)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	newRoutes := make(map[string]*tcpRoute)
	newDefault := p.buildRoute(alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(s2)},
	})
	p.UpdateRoutes(newRoutes, newDefault)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	got := readOne(t, conn)
	if !bytes.Contains([]byte(got), []byte("Backend2")) {
		t.Fatalf("got %q, want containing %q", got, "Backend2")
	}
}
func TestProxy_Stop_ClosesConnections(t *testing.T) {
	s1, stop1 := startIDServer(t, "Backend1")
	defer stop1()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(s1)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	p.Stop()
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed or timeout after proxy stop")
	}
	_ = conn.Close()
}
func TestProxy_BackendCount(t *testing.T) {
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	count := p.BackendCount()
	if count != 0 {
		t.Errorf("expected 0 backends, got %d", count)
	}
}
func TestProxy_NoRoute_NoDefault(t *testing.T) {
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(makeSNIClientHello("test.com"))
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(buf)
	if err == nil {
		t.Error("expected connection to be closed with no route")
	}
}
func TestProxy_WildcardSubdomain(t *testing.T) {
	sW, stopW := startIDServer(t, "WildcardBackend")
	defer stopW()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*.example.com", alaye.Proxy{
		Backends: []alaye.Server{alaye.NewServer(sW)},
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	tests := []struct {
		sni  string
		want string
	}{
		{"sub.example.com", "WildcardBackend"},
		{"deep.sub.example.com", "WildcardBackend"},
		{"notexample.com", ""},
	}
	for _, tt := range tests {
		t.Run(tt.sni, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()
			_, _ = conn.Write(makeSNIClientHello(tt.sni))
			got := readOne(t, conn)
			if tt.want != "" {
				if !bytes.Contains([]byte(got), []byte(tt.want)) {
					t.Fatalf("got %q, want containing %q", got, tt.want)
				}
			}
		})
	}
}
func TestProxy_ProxyProtocol(t *testing.T) {
	s1, stop1 := startIDServer(t, "Backend1")
	defer stop1()
	proxyAddr := getFreePort(t)
	p := NewProxy(resource.New(), newTestLogger(), proxyAddr)
	p.AddRoute("*", alaye.Proxy{
		Backends:      []alaye.Server{alaye.NewServer(s1)},
		ProxyProtocol: true,
	})
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	waitTCPReady(t, proxyAddr, 800*time.Millisecond)
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(makeSNIClientHello("test.com"))
	got := readOne(t, conn)
	if !bytes.Contains([]byte(got), []byte("Backend1")) {
		t.Fatalf("got %q, want containing %q", got, "Backend1")
	}
}
