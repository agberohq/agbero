package xtcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
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
				// Write immediately on accept so tests can validate routing
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

				// Read until EOF (this is what half-close should propagate)
				buf := make([]byte, 64)
				for {
					_, rerr := conn.Read(buf)
					if rerr != nil {
						break
					}
				}

				// After seeing EOF from client side, respond.
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

// Minimal TLS ClientHello with SNI extension (enough for your parser).
func makeSNIClientHello(sni string) []byte {
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	// server_name extension payload:
	// list_len(2) + name_type(1) + name_len(2) + name
	extDataLen := 2 + 1 + 2 + sniLen
	extData := make([]byte, extDataLen)
	binary.BigEndian.PutUint16(extData[0:], uint16(sniLen+3))
	extData[2] = 0x00
	binary.BigEndian.PutUint16(extData[3:], uint16(sniLen))
	copy(extData[5:], sniBytes)

	// extension wrapper: type(2)=0, len(2), payload
	extBlockLen := 2 + 2 + extDataLen
	extBlock := make([]byte, extBlockLen)
	binary.BigEndian.PutUint16(extBlock[0:], 0x0000)
	binary.BigEndian.PutUint16(extBlock[2:], uint16(extDataLen))
	copy(extBlock[4:], extData)

	allExtLen := extBlockLen

	// ClientHello body:
	// ver(2) + random(32) + sessionIDLen(1) + cipherLen(2)+cipher(2) + compLen(1)+comp(1) + extLen(2)+ext
	handshakeBodyLen := 2 + 32 + 1 + 2 + 2 + 1 + 1 + 2 + allExtLen
	body := make([]byte, handshakeBodyLen)

	pos := 0
	body[pos], body[pos+1] = 0x03, 0x03 // TLS 1.2
	pos += 2
	pos += 32 // random zeros
	body[pos] = 0x00
	pos++

	// cipher suites: length=2, suite=0x0000
	body[pos], body[pos+1] = 0x00, 0x02
	pos += 2
	body[pos], body[pos+1] = 0x00, 0x00
	pos += 2

	// compression: length=1, method=0
	body[pos] = 0x01
	pos++
	body[pos] = 0x00
	pos++

	// extensions length + block
	binary.BigEndian.PutUint16(body[pos:], uint16(allExtLen))
	pos += 2
	copy(body[pos:], extBlock)

	// TLS record + handshake header
	recordLen := 1 + 3 + handshakeBodyLen // handshakeType(1)+len(3)+body
	pkt := make([]byte, 5+recordLen)

	// record header
	pkt[0] = 0x16
	pkt[1], pkt[2] = 0x03, 0x01
	binary.BigEndian.PutUint16(pkt[3:], uint16(recordLen))

	// handshake header
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
	p := NewProxy(proxyAddr, newTestLogger())

	// Exact
	p.AddRoute("a.com", alaye.TCPRoute{
		Backends: []*alaye.Server{{Address: sA}},
	})

	// Wildcard
	p.AddRoute("*.w.com", alaye.TCPRoute{
		Backends: []*alaye.Server{{Address: sW}},
	})

	// Default
	p.AddRoute("*", alaye.TCPRoute{
		Backends: []*alaye.Server{{Address: sD}},
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
	// Validates the important behavior for Redis/NATS/plain TCP clients:
	// client can connect and send nothing; proxy should still route to Default.
	sD, stopD := startIDServer(t, "BackendD")
	defer stopD()

	proxyAddr := getFreePort(t)
	p := NewProxy(proxyAddr, newTestLogger())

	p.AddRoute("*", alaye.TCPRoute{
		Backends: []*alaye.Server{{Address: sD}},
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

	// Do NOT write anything.
	// The proxy should time out its peek and then fall back to Default.
	got := readOne(t, conn)
	if !bytes.Contains([]byte(got), []byte("BackendD")) {
		t.Fatalf("got %q, want containing %q", got, "BackendD")
	}
}

func TestProxy_DialRetry_SkipsDeadBackend(t *testing.T) {
	// First backend is dead; second is live. Proxy should retry and succeed.
	live, stopLive := startIDServer(t, "LIVE")
	defer stopLive()

	deadAddr := getFreePort(t) // nobody listening on it

	proxyAddr := getFreePort(t)
	p := NewProxy(proxyAddr, newTestLogger())
	p.AddRoute("*", alaye.TCPRoute{
		Backends: []*alaye.Server{
			{Address: deadAddr},
			{Address: live},
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
	// Backend waits for EOF then replies "OK".
	up, stop := startHalfCloseServer(t)
	defer stop()

	proxyAddr := getFreePort(t)
	p := NewProxy(proxyAddr, newTestLogger())
	p.SetIdleTimeout(5 * time.Second)
	p.AddRoute("*", alaye.TCPRoute{
		Backends: []*alaye.Server{{Address: up}},
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

	// Send some data then half-close write side to signal EOF.
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
