package xudp

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	resource "github.com/agberohq/agbero/internal/hub/resource"
)

// startUDPBackend starts a UDP server that responds with a fixed reply prefix
// so tests can identify which backend handled a datagram.
func startUDPBackend(t *testing.T, id string) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("startUDPBackend %s: %v", id, err)
	}
	go func() {
		buf := make([]byte, udpBufSize)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := []byte(id + ":" + string(buf[:n]))
			_, _ = conn.WriteToUDP(reply, addr)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

func newTestProxy(t *testing.T, backends []string) (*Proxy, func()) {
	t.Helper()
	res := resource.New()

	prx := NewProxy(res, "127.0.0.1:0")

	servers := make([]alaye.Server, len(backends))
	for i, addr := range backends {
		servers[i] = alaye.Server{
			Address: alaye.Address(addr),
			Weight:  1,
			Enabled: expect.Active,
		}
	}

	cfg := alaye.Proxy{
		Name:        "test",
		Listen:      "127.0.0.1:0",
		Protocol:    "udp",
		Strategy:    "round_robin",
		SessionTTL:  expect.Duration(int64(2 * time.Second)),
		MaxSessions: 1000,
		Backends:    servers,
		Enabled:     expect.Active,
	}
	prx.AddRoute("*", cfg)
	prx.SetSessionTTL(2 * time.Second)

	if err := prx.Start(); err != nil {
		t.Fatalf("proxy Start: %v", err)
	}

	return prx, func() { prx.Stop() }
}

func sendAndReceive(t *testing.T, listenAddr, payload string) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("udp", listenAddr, time.Second)
	if err != nil {
		return "", fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	return string(buf[:n]), nil
}

func TestProxy_ForwardAndReply(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	prx, stopProxy := newTestProxy(t, []string{backendAddr})
	defer stopProxy()

	reply, err := sendAndReceive(t, prx.Listen, "hello")
	if err != nil {
		t.Fatalf("sendAndReceive: %v", err)
	}
	if reply != "B1:hello" {
		t.Fatalf("unexpected reply %q", reply)
	}
}

func TestProxy_SessionStickiness(t *testing.T) {
	// Two backends: a session must always return to the same backend
	b1Addr, stopB1 := startUDPBackend(t, "B1")
	b2Addr, stopB2 := startUDPBackend(t, "B2")
	defer stopB1()
	defer stopB2()

	prx, stopProxy := newTestProxy(t, []string{b1Addr, b2Addr})
	defer stopProxy()

	// Send from the same source address (same net.Conn = same src:port)
	conn, err := net.DialTimeout("udp", prx.Listen, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	var firstBackend string
	buf := make([]byte, 512)

	for i := 0; i < 5; i++ {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_, _ = conn.Write([]byte(fmt.Sprintf("msg%d", i)))
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		reply := string(buf[:n])
		// Extract backend ID (first two chars)
		backend := reply[:2]
		if firstBackend == "" {
			firstBackend = backend
		} else if backend != firstBackend {
			t.Fatalf("session not sticky: first %q, then %q", firstBackend, backend)
		}
	}
}

func TestProxy_DifferentClientsGetDifferentSessions(t *testing.T) {
	b1Addr, stopB1 := startUDPBackend(t, "B1")
	b2Addr, stopB2 := startUDPBackend(t, "B2")
	defer stopB1()
	defer stopB2()

	prx, stopProxy := newTestProxy(t, []string{b1Addr, b2Addr})
	defer stopProxy()

	// Multiple concurrent clients — should all get responses
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			reply, err := sendAndReceive(t, prx.Listen, fmt.Sprintf("client%d", i))
			if err != nil {
				errors <- err
				return
			}
			if reply == "" {
				errors <- fmt.Errorf("empty reply for client %d", i)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent client error: %v", err)
	}
}

func TestProxy_MaxSessionsDropsNew(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	res := resource.New()
	p := NewProxy(res, "127.0.0.1:0")
	p.MaxSess = 1 // Only 1 session allowed

	cfg := alaye.Proxy{
		Name:        "test",
		Listen:      "127.0.0.1:0",
		Protocol:    "udp",
		Strategy:    "round_robin",
		MaxSessions: 1,
		Backends: []alaye.Server{
			{Address: alaye.Address(backendAddr), Weight: 1, Enabled: expect.Active},
		},
		Enabled: expect.Active,
	}
	p.AddRoute("*", cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// First client establishes the only allowed session
	conn1, err := net.DialTimeout("udp", p.Listen, time.Second)
	if err != nil {
		t.Fatalf("dial conn1: %v", err)
	}
	defer conn1.Close()
	_ = conn1.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn1.Write([]byte("first"))
	buf := make([]byte, 512)
	conn1.Read(buf)

	// Verify session count
	time.Sleep(20 * time.Millisecond) // let goroutines settle
	if p.ActiveSessions() > 1 {
		t.Fatalf("expected at most 1 active session, got %d", p.ActiveSessions())
	}
}

func TestProxy_SessionTTLExpiry(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	res := resource.New()
	p := NewProxy(res, "127.0.0.1:0")
	p.SetSessionTTL(100 * time.Millisecond)

	cfg := alaye.Proxy{
		Name:     "test",
		Listen:   "127.0.0.1:0",
		Protocol: "udp",
		Backends: []alaye.Server{
			{Address: alaye.Address(backendAddr), Weight: 1, Enabled: expect.Active},
		},
		Enabled: expect.Active,
	}
	p.AddRoute("*", cfg)
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// Send one datagram to create a session
	_, err := sendAndReceive(t, p.Listen, "ping")
	if err != nil {
		t.Fatalf("sendAndReceive: %v", err)
	}

	// Wait for TTL to expire
	time.Sleep(300 * time.Millisecond)
	p.sessions.sweep()

	if p.ActiveSessions() != 0 {
		t.Fatalf("expected 0 sessions after TTL expiry, got %d", p.ActiveSessions())
	}
}

func TestProxy_StopGraceful(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	_, stopProxy := newTestProxy(t, []string{backendAddr})

	// Stop should not hang
	done := make(chan struct{})
	go func() {
		stopProxy()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop timed out")
	}
}

func TestProxy_StopIdempotent(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	p, stopProxy := newTestProxy(t, []string{backendAddr})
	stopProxy()
	p.Stop() // second stop must not panic
}

func TestProxy_ActiveSessions_Initial(t *testing.T) {
	backendAddr, stopBackend := startUDPBackend(t, "B1")
	defer stopBackend()

	p, stopProxy := newTestProxy(t, []string{backendAddr})
	defer stopProxy()

	if p.ActiveSessions() != 0 {
		t.Fatalf("expected 0 sessions before any traffic, got %d", p.ActiveSessions())
	}
}

func TestProxy_NoRoute_DropsPacket(t *testing.T) {
	res := resource.New()
	p := NewProxy(res, "127.0.0.1:0")
	// No route added — proxy has no backends
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	// Send a datagram — should be dropped silently (no panic)
	conn, err := net.DialTimeout("udp", p.Listen, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	_, _ = conn.Write([]byte("hello"))

	buf := make([]byte, 512)
	_, err = conn.Read(buf)
	// Expect timeout — no reply
	if err == nil {
		t.Fatal("expected no reply when no route configured")
	}
}
