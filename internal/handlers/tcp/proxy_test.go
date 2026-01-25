package tcp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
)

func newTestLogger() *ll.Logger {
	return ll.New("test", ll.WithHandler(lh.NewTextHandler(io.Discard)))
}

func startIDServer(t *testing.T, id string) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start ID server: %v", err)
	}
	go func() {
		defer l.Close()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Write([]byte(id))
			}(conn)
		}
	}()
	return l.Addr().String()
}

func getFreePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// Helper to construct a minimal TLS ClientHello with SNI extension
func makeSNIClientHello(sni string) []byte {
	// 1. Extensions: SNI
	sniBytes := []byte(sni)
	sniLen := len(sniBytes)

	// Server Name List (2 bytes len) + Name Type (1) + Name Len (2) + Name
	extDataLen := 2 + 1 + 2 + sniLen
	extData := make([]byte, extDataLen)
	binary.BigEndian.PutUint16(extData[0:], uint16(sniLen+3))
	extData[2] = 0x00 // host_name type
	binary.BigEndian.PutUint16(extData[3:], uint16(sniLen))
	copy(extData[5:], sniBytes)

	// Extension Wrapper: Type (2) + Len (2) + Data
	extBlockLen := 2 + 2 + extDataLen
	extBlock := make([]byte, extBlockLen)
	binary.BigEndian.PutUint16(extBlock[0:], 0x0000) // server_name extension type
	binary.BigEndian.PutUint16(extBlock[2:], uint16(extDataLen))
	copy(extBlock[4:], extData)

	// All Extensions length (2 bytes)
	allExtLen := extBlockLen

	// 2. Handshake Body (ClientHello)
	// Version (2) + Random (32) + SessionID (1) + Ciphers (2+2) + Compression (1+1) + Extensions (2 + ext)
	handshakeBodyLen := 2 + 32 + 1 + 4 + 2 + 2 + allExtLen
	handshakeBody := make([]byte, handshakeBodyLen)

	pos := 0
	// Version 3.3 (TLS 1.2)
	handshakeBody[pos] = 0x03
	pos++
	handshakeBody[pos] = 0x03
	pos++
	// Random (32 bytes zeros for test)
	pos += 32
	// Session ID Len 0
	handshakeBody[pos] = 0
	pos++
	// Cipher Suites (Length 2, value 0x0000)
	handshakeBody[pos] = 0
	pos++
	handshakeBody[pos] = 2
	pos++
	handshakeBody[pos] = 0
	pos++
	handshakeBody[pos] = 0
	pos++
	// Compression (Length 1, value 0)
	handshakeBody[pos] = 1
	pos++
	handshakeBody[pos] = 0
	pos++
	// Extensions Length
	binary.BigEndian.PutUint16(handshakeBody[pos:], uint16(allExtLen))
	pos += 2
	copy(handshakeBody[pos:], extBlock)

	// 3. Record Layer
	// ContentType (1) + Version (2) + Length (2) + HandshakeHeader(1+3) + Body
	recordLen := 1 + 3 + handshakeBodyLen
	packet := make([]byte, 5+recordLen)

	// Record Header
	packet[0] = 0x16 // Handshake
	packet[1] = 0x03 // Ver 3.1
	packet[2] = 0x01
	binary.BigEndian.PutUint16(packet[3:], uint16(4+handshakeBodyLen)) // Length of following data

	// Handshake Header
	packet[5] = 0x01 // ClientHello
	// Length (3 bytes)
	l := uint32(handshakeBodyLen)
	packet[6] = byte(l >> 16)
	packet[7] = byte(l >> 8)
	packet[8] = byte(l)

	copy(packet[9:], handshakeBody)

	return packet
}

func TestProxy_SNIRouting(t *testing.T) {
	sA := startIDServer(t, "BackendA")
	sB := startIDServer(t, "BackendB")

	proxyAddr := getFreePort(t)
	p := NewProxy(proxyAddr, newTestLogger())

	// Route a.com -> A
	p.AddRoute("a.com", alaye.TCPRoute{
		Backends: []alaye.Server{{Address: sA}},
	})

	// Default -> B
	p.AddRoute("*", alaye.TCPRoute{
		Backends: []alaye.Server{{Address: sB}},
	})

	if err := p.Start(); err != nil {
		t.Fatalf("failed to start: %v", err)
	}
	defer p.Stop()
	time.Sleep(50 * time.Millisecond)

	tests := []struct {
		name string
		sni  string
		want string
	}{
		{"Match Route", "a.com", "BackendA"},
		{"Default Route", "other.com", "BackendB"},
		{"No SNI (Empty)", "", "BackendB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
			if err != nil {
				t.Fatalf("dial failed: %v", err)
			}
			defer conn.Close()

			if tt.sni != "" {
				hello := makeSNIClientHello(tt.sni)
				conn.Write(hello)
			} else {
				conn.Write([]byte("NOT TLS"))
			}

			buf := make([]byte, 100)
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, err := conn.Read(buf)
			if err != nil && err != io.EOF {
				t.Fatalf("read failed: %v", err)
			}

			got := string(buf[:n])
			if !bytes.Contains([]byte(got), []byte(tt.want)) {
				t.Errorf("got %q, want containing %q", got, tt.want)
			}
		})
	}
}

func TestProxy_BasicEcho(t *testing.T) {
	upstream := startIDServer(t, "echo")
	proxyAddr := getFreePort(t)

	cfg := alaye.TCPRoute{
		Listen:   proxyAddr,
		Backends: []alaye.Server{{Address: upstream}},
	}

	p := NewProxy(proxyAddr, newTestLogger())
	p.AddRoute("*", cfg)

	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 10)
	n, _ := conn.Read(buf)
	if string(buf[:n]) != "echo" {
		t.Errorf("got %s", buf[:n])
	}
}
