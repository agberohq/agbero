package xudp

import (
	"context"
	"net"
	"testing"
	"time"
)

// startEchoServer starts a UDP server that echoes back whatever it receives.
// Returns the listen address and a stop function.
func startEchoServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("startEchoServer: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

// startSilentServer starts a UDP server that accepts but never replies.
func startSilentServer(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("startSilentServer: %v", err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			_, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			// intentionally not replying
		}
	}()
	return conn.LocalAddr().String(), func() { conn.Close() }
}

func TestUDPExecutor_ProbeSuccess(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()

	exec := &UDPExecutor{
		Address: addr,
		Send:    []byte("ping"),
		Expect:  []byte("ping"),
		Timeout: time.Second,
	}

	ctx := context.Background()
	ok, latency, err := exec.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe success")
	}
	if latency <= 0 {
		t.Fatal("latency should be positive")
	}
}

func TestUDPExecutor_ProbeWrongResponse(t *testing.T) {
	addr, stop := startEchoServer(t)
	defer stop()

	exec := &UDPExecutor{
		Address: addr,
		Send:    []byte("ping"),
		Expect:  []byte("pong"), // echo server returns "ping", not "pong"
		Timeout: time.Second,
	}

	ctx := context.Background()
	ok, _, err := exec.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected probe failure for wrong response")
	}
}

func TestUDPExecutor_ProbeNoExpect(t *testing.T) {
	// No Expect set — any non-empty response counts as success
	addr, stop := startEchoServer(t)
	defer stop()

	exec := &UDPExecutor{
		Address: addr,
		Send:    []byte("hello"),
		Timeout: time.Second,
	}

	ctx := context.Background()
	ok, _, err := exec.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe success with no Expect set")
	}
}

func TestUDPExecutor_ProbeTimeout(t *testing.T) {
	addr, stop := startSilentServer(t)
	defer stop()

	exec := &UDPExecutor{
		Address: addr,
		Send:    []byte("ping"),
		Expect:  []byte("ping"),
		Timeout: 50 * time.Millisecond,
	}

	ctx := context.Background()
	start := time.Now()
	ok, _, err := exec.Probe(ctx)
	elapsed := time.Since(start)

	if ok {
		t.Fatal("expected probe failure for silent server")
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// Should have timed out in roughly the configured timeout
	if elapsed > 500*time.Millisecond {
		t.Fatalf("probe took too long: %v", elapsed)
	}
}

func TestUDPExecutor_ContextDeadline(t *testing.T) {
	addr, stop := startSilentServer(t)
	defer stop()

	exec := &UDPExecutor{
		Address: addr,
		Send:    []byte("ping"),
		Timeout: 5 * time.Second, // long timeout — context deadline should win
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, _ = exec.Probe(ctx)
	elapsed := time.Since(start)

	// Should respect the context deadline, not the executor timeout
	if elapsed > 500*time.Millisecond {
		t.Fatalf("probe should respect context deadline, took %v", elapsed)
	}
}

func TestUDPExecutor_UnreachableAddress(t *testing.T) {
	exec := &UDPExecutor{
		Address: "127.0.0.1:1", // port 1 is typically unreachable
		Send:    []byte("ping"),
		Expect:  []byte("ping"),
		Timeout: 50 * time.Millisecond,
	}

	ctx := context.Background()
	ok, _, _ := exec.Probe(ctx)
	// UDP to an unreachable port may or may not error at dial time
	// (ICMP port unreachable may come back) — we just assert no panic
	_ = ok
}

func TestUDPExecutor_STUNProbe(t *testing.T) {
	// Real STUN probe format: send Binding Request, expect response type bytes
	addr, stop := startEchoServer(t)
	defer stop()

	txID := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := STUNBindingRequest(txID)

	exec := &UDPExecutor{
		Address: addr,
		Send:    req,
		Expect:  req[:2], // echo server returns same bytes; real STUN would return 0x01 0x01
		Timeout: time.Second,
	}

	ctx := context.Background()
	ok, _, err := exec.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected probe success")
	}
}
