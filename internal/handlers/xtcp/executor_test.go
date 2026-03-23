package xtcp

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestTCPExecutor_Probe_Success(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) == "PING" {
			conn.Write([]byte("PONG"))
		}
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected successful probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_ExpectMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conn.Write([]byte("WRONG_RESPONSE"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if success {
		t.Error("expected failed probe due to expect mismatch")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_ConnectionRefused(t *testing.T) {
	port := getFreePort(t)
	pool := newConnPool(port, 3, 500*time.Millisecond)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err == nil {
		t.Error("expected connection refused error")
	}
	if success {
		t.Error("expected failed probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_ContextTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		time.Sleep(500 * time.Millisecond)
		conn.Write([]byte("PONG"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err == nil {
		t.Error("expected context timeout error")
	}
	if success {
		t.Error("expected failed probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_EmptySend(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte("HELLO"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte{},
		Expect: []byte("HELLO"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected successful probe with empty send")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_EmptyExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conn.Write([]byte("ANY_RESPONSE"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected successful probe with empty expect")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_EmptySendAndExpect(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		time.Sleep(50 * time.Millisecond)
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte{},
		Expect: []byte{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected successful connection-only probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_ConnectionMarkedFailed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, _ = executor.Probe(ctx)

	pool.mu.RLock()
	markedFailed := false
	for _, c := range pool.conns {
		if c.failed.Load() {
			markedFailed = true
			break
		}
	}
	pool.mu.RUnlock()

	if !markedFailed {
		t.Error("expected connection to be marked as failed")
	}
}

func TestTCPExecutor_Probe_ConnectionReuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Server that handles multiple requests on same connection
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				// Keep connection alive for multiple reads
				for {
					n, rerr := c.Read(buf)
					if rerr != nil {
						break
					}
					if n > 0 {
						_, _ = c.Write([]byte("PONG"))
					}
				}
			}(conn)
		}
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx := context.Background()
	for i := range 3 {
		success, _, err := executor.Probe(ctx)
		if err != nil {
			t.Fatalf("probe %d: unexpected error: %v", i+1, err)
		}
		if !success {
			t.Errorf("probe %d: expected success", i+1)
		}
	}

	// Verify connection was reused by checking pool state
	pool.mu.RLock()
	usedConns := 0
	for _, pc := range pool.conns {
		if !pc.failed.Load() {
			usedConns++
		}
	}
	pool.mu.RUnlock()

	if usedConns > 1 {
		t.Errorf("expected single reused connection, got %d active conns", usedConns)
	}
}

func TestTCPExecutor_Probe_PartialExpectMatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conn.Write([]byte("PREFIX_PONG_SUFFIX"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, _, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !success {
		t.Error("expected success with partial expect match (bytes.Contains)")
	}
}

func TestTCPExecutor_Probe_ReadError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conn.Close()
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err == nil {
		t.Error("expected read error")
	}
	if success {
		t.Error("expected failed probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_WriteError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	success, latency, err := executor.Probe(ctx)
	if err == nil {
		t.Error("expected write error")
	}
	if success {
		t.Error("expected failed probe")
	}
	if latency < 0 {
		t.Error("expected non-negative latency")
	}
}

func TestTCPExecutor_Probe_Concurrent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				c.Write([]byte("PONG"))
			}(conn)
		}
	}()

	pool := newConnPool(ln.Addr().String(), 5, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	var wg sync.WaitGroup
	successes := 0
	var mu sync.Mutex

	for range 10 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			success, _, err := executor.Probe(ctx)
			if err == nil && success {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		})
	}

	wg.Wait()

	if successes < 5 {
		t.Errorf("expected at least 5 successful probes, got %d", successes)
	}
}

func TestTCPExecutor_Probe_LatencyMeasurement(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		time.Sleep(50 * time.Millisecond)
		conn.Write([]byte("PONG"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, latency, err := executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if latency < 50*time.Millisecond {
		t.Errorf("expected latency >= 50ms, got %v", latency)
	}
}

func TestTCPExecutor_Probe_BufferPool(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	// Server that handles multiple requests on same connection
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				// Keep connection alive for multiple reads
				for {
					n, rerr := c.Read(buf)
					if rerr != nil {
						break
					}
					if n > 0 {
						_, _ = c.Write(buf[:n]) // Echo back
					}
				}
			}(conn)
		}
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PING"), // Expect echoed response
	}

	ctx := context.Background()
	for i := range 5 {
		success, _, err := executor.Probe(ctx)
		if err != nil {
			t.Fatalf("probe %d: unexpected error: %v", i+1, err)
		}
		if !success {
			t.Errorf("probe %d: expected success", i+1)
		}
	}
}

func TestTCPExecutor_Probe_DeadlinePropagation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		conn.Write([]byte("PONG"))
	}()

	pool := newConnPool(ln.Addr().String(), 3, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _, err = executor.Probe(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func BenchmarkTCPExecutor_Probe(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				c.Write([]byte("PONG"))
			}(conn)
		}
	}()

	pool := newConnPool(ln.Addr().String(), 10, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := executor.Probe(ctx)
		if err != nil {
			b.Fatalf("probe failed: %v", err)
		}
	}
}

func BenchmarkTCPExecutor_Probe_Parallel(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				c.Write([]byte("PONG"))
			}(conn)
		}
	}()

	pool := newConnPool(ln.Addr().String(), 20, 5*time.Second)
	defer pool.close()

	executor := &TCPExecutor{
		Pool:   pool,
		Send:   []byte("PING"),
		Expect: []byte("PONG"),
	}

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		ctx := context.Background()
		for pb.Next() {
			_, _, err := executor.Probe(ctx)
			if err != nil {
				b.Fatalf("probe failed: %v", err)
			}
		}
	})
}
