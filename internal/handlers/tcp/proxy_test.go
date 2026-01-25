package tcp

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
)

// Helper to create a silent logger for tests
func newTestLogger() *ll.Logger {
	return ll.New("test")
}

// Helper to start a dummy upstream TCP server that echos received data
func startEchoServer(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start echo server: %v", err)
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
				io.Copy(c, c)
			}(conn)
		}
	}()

	return l.Addr().String()
}

// Helper to start a server that sends a specific ID on connect then closes
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

// Helper to find a free local port
func getFreePort(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

func TestProxy_BasicEcho(t *testing.T) {
	upstream := startEchoServer(t)
	proxyAddr := getFreePort(t)

	// Configure Proxy
	cfg := alaye.TCPRoute{
		Listen: proxyAddr,
		Backends: []alaye.Server{
			{Address: upstream, Weight: 1},
		},
		Strategy: "round_robin",
	}

	p := NewProxy(cfg, newTestLogger())
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()

	// Connect to Proxy
	conn, err := net.DialTimeout("tcp", proxyAddr, 1*time.Second)
	if err != nil {
		t.Fatalf("failed to dial proxy: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello world")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("failed to write: %v", err)
	}

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("failed to read: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Errorf("expected %s, got %s", msg, buf)
	}
}

func TestProxy_RoundRobin(t *testing.T) {
	s1 := startIDServer(t, "1")
	s2 := startIDServer(t, "2")
	proxyAddr := getFreePort(t)

	cfg := alaye.TCPRoute{
		Listen: proxyAddr,
		Backends: []alaye.Server{
			{Address: s1, Weight: 1},
			{Address: s2, Weight: 1},
		},
		Strategy: "round_robin",
	}

	p := NewProxy(cfg, newTestLogger())
	if err := p.Start(); err != nil {
		t.Fatalf("failed to start proxy: %v", err)
	}
	defer p.Stop()

	// Give time for listener to bind
	time.Sleep(50 * time.Millisecond)

	// Round Robin logic:
	// Counter starts 0.
	// Pick 1: (0+1) % 2 = 1 -> Backend[1] (s2)
	// Pick 2: (1+1) % 2 = 0 -> Backend[0] (s1)
	// Pick 3: (2+1) % 2 = 1 -> Backend[1] (s2)

	responses := []string{}
	for i := 0; i < 4; i++ {
		conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("dial %d failed: %v", i, err)
		}
		buf := make([]byte, 1)
		io.ReadFull(conn, buf)
		responses = append(responses, string(buf))
		conn.Close()
	}

	// Expect alternating responses
	expected := []string{"2", "1", "2", "1"}
	for i, v := range responses {
		if v != expected[i] {
			t.Errorf("req %d: expected %s, got %s", i, expected[i], v)
		}
	}
}

func TestProxy_LeastConn(t *testing.T) {
	// For this test, we need valid upstreams, but we won't actually connect fully
	// because we are manipulating the balancer state directly.
	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	addr1 := l1.Addr().String()
	defer l1.Close()

	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	addr2 := l2.Addr().String()
	defer l2.Close()

	proxyAddr := getFreePort(t)

	cfg := alaye.TCPRoute{
		Listen: proxyAddr,
		Backends: []alaye.Server{
			{Address: addr1, Weight: 1},
			{Address: addr2, Weight: 1},
		},
		Strategy: "least_conn",
	}

	p := NewProxy(cfg, newTestLogger())
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	time.Sleep(50 * time.Millisecond)

	// Artificial Load:
	// Manually increment active conns on backend 0 to force traffic to backend 1
	// Note: We are manipulating internal state for testing stability because timing
	// real connections in unit tests is unreliable.
	p.Balancer.backends[0].ActiveConns.Store(10)
	p.Balancer.backends[1].ActiveConns.Store(0)

	// Validate logic: Pick() should return backend 1
	picked := p.Balancer.Pick()
	if picked.Address != addr2 {
		t.Errorf("expected least conn to pick %s (0 conns), got %s", addr2, picked.Address)
	}

	// Swap load
	p.Balancer.backends[0].ActiveConns.Store(0)
	p.Balancer.backends[1].ActiveConns.Store(10)

	picked = p.Balancer.Pick()
	if picked.Address != addr1 {
		t.Errorf("expected least conn to pick %s (0 conns), got %s", addr1, picked.Address)
	}
}

func TestProxy_Stop(t *testing.T) {
	upstream := startEchoServer(t)
	proxyAddr := getFreePort(t)

	cfg := alaye.TCPRoute{
		Listen: proxyAddr,
		Backends: []alaye.Server{
			{Address: upstream},
		},
	}

	p := NewProxy(cfg, newTestLogger())
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}

	// Verify it accepts connections
	conn, err := net.DialTimeout("tcp", proxyAddr, 100*time.Millisecond)
	if err != nil {
		t.Fatal("proxy should be up")
	}
	conn.Close()

	// Stop the proxy
	p.Stop()

	// Verify it rejects connections
	// We might need a small loop because listener close is async in kernel/runtime
	start := time.Now()
	closed := false
	for time.Since(start) < 200*time.Millisecond {
		_, err = net.DialTimeout("tcp", proxyAddr, 20*time.Millisecond)
		if err != nil {
			closed = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !closed {
		t.Error("proxy should be down after Stop()")
	}
}
