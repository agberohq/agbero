package xtcp

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/zulu"
)

// testServer creates a local TCP server for testing
type testServer struct {
	addr  string
	ln    net.Listener
	done  chan struct{}
	conns []net.Conn
	mu    sync.Mutex
}

func newTestServer(t *testing.T) *testServer {
	port := zulu.PortFree()
	addr := fmt.Sprintf("localhost:%d", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to start test server: %v", err)
	}

	ts := &testServer{
		addr: addr,
		ln:   ln,
		done: make(chan struct{}),
	}

	go ts.acceptLoop()

	return ts
}

// newTestServerForBench creates a server for benchmarks (no *testing.T)
func newTestServerForBench() (*testServer, error) {
	port := zulu.PortFree()
	addr := fmt.Sprintf("localhost:%d", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	ts := &testServer{
		addr: addr,
		ln:   ln,
		done: make(chan struct{}),
	}

	go ts.acceptLoop()

	return ts, nil
}

// acceptLoop accepts incoming connections from the test listener
// and stores them to keep alive for the full test duration
func (ts *testServer) acceptLoop() {
	for {
		conn, err := ts.ln.Accept()
		if err != nil {
			select {
			case <-ts.done:
				return
			default:
				continue
			}
		}
		ts.mu.Lock()
		ts.conns = append(ts.conns, conn)
		ts.mu.Unlock()
	}
}

// close terminates the listener and all accepted connections
// to ensure clean shutdown after tests
func (ts *testServer) close() {
	close(ts.done)
	ts.ln.Close()

	ts.mu.Lock()
	for _, c := range ts.conns {
		_ = c.Close()
	}
	ts.conns = nil
	ts.mu.Unlock()
}

func TestConnPoolBasic(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 5, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Get first connection
	pc1, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	if pc1 == nil {
		t.Fatal("Got nil connection")
	}

	// Return it to pool - this updates lastUsed
	pool.put(pc1)

	// Small sleep to ensure timestamp difference
	time.Sleep(time.Millisecond)

	// Get same connection again - should be the same one
	pc2, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	// Compare by value, not reference, since the connection might be wrapped
	if pc1.Conn != pc2.Conn {
		t.Error("Pool returned different connection")
	}
}

func TestConnPoolMaxSize(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Fill pool to max
	conns := make([]*pooledConn, 2)
	for i := 0; i < 2; i++ {
		conn, err := pool.get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}

	// Try to get another connection (should fail)
	_, err := pool.get(ctx)
	if err != errPoolFull {
		t.Errorf("Expected errPoolFull, got: %v", err)
	}

	// Return one connection
	pool.put(conns[0])

	// Now should succeed
	conn, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection after return: %v", err)
	}
	if conn == nil {
		t.Fatal("Got nil connection")
	}
}

func TestConnPoolIdleTimeout(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Get and return connection
	pc, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	pool.put(pc)

	// Manually set lastUsed to simulate idle timeout
	pool.mu.Lock()
	pc.lastUsed = time.Now().Add(-(idleTimeoutLimit + time.Minute))
	pool.mu.Unlock()

	// Run sweeper manually
	pool.sweep()

	// Pool should be empty
	pool.mu.RLock()
	if len(pool.conns) != 0 {
		t.Errorf("Expected 0 connections after sweep, got %d", len(pool.conns))
	}
	pool.mu.RUnlock()

	// Should create new connection
	pc2, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get new connection: %v", err)
	}
	if pc2.Conn == pc.Conn {
		t.Error("Got same connection after sweep")
	}
}

func TestConnPoolFailedConnection(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Get connection
	pc, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	// Mark as failed
	pc.failed.Store(true)
	pool.put(pc)

	// Get should create new connection
	pc2, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get new connection: %v", err)
	}
	if pc2.Conn == pc.Conn {
		t.Error("Got failed connection")
	}
}

func TestConnPoolConcurrent(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 10, time.Second)
	defer pool.close()

	ctx := context.Background()
	done := make(chan struct{})
	workers := 20
	iterations := 100

	for w := 0; w < workers; w++ {
		go func() {
			for i := 0; i < iterations; i++ {
				pc, err := pool.get(ctx)
				if err == nil {
					// Simulate work
					time.Sleep(time.Millisecond)
					pool.put(pc)
				}
			}
			done <- struct{}{}
		}()
	}

	// Wait for all workers
	for w := 0; w < workers; w++ {
		<-done
	}

	// Verify pool state
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	if len(pool.conns) > pool.maxSize {
		t.Errorf("Pool size %d exceeds max %d", len(pool.conns), pool.maxSize)
	}
}

func TestConnPoolReplaceFailedOnFull(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Fill pool
	conns := make([]*pooledConn, 2)
	for i := 0; i < 2; i++ {
		conn, err := pool.get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}

	// Mark one as failed
	conns[0].failed.Store(true)

	// Return both
	pool.put(conns[0])
	pool.put(conns[1])

	// Get should replace failed connection
	pc, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	if pc.Conn == conns[0].Conn {
		t.Error("Got failed connection")
	}
}

func TestConnPoolSweeperShutdown(t *testing.T) {
	server := newTestServer(t)
	pool := newConnPool(server.addr, 5, time.Second)

	// Close pool immediately
	pool.close()
	server.close()

	// Sweeper should exit cleanly
	time.Sleep(100 * time.Millisecond)

	// Should be able to call close again
	pool.close()
}

func TestConnPoolDialWithContext(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()

	// Let context expire
	time.Sleep(time.Millisecond)

	_, err := pool.get(ctx)
	if err == nil {
		t.Error("Expected error from expired context")
	}
}

func TestConnPoolIsAlive(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	// Create real connection first
	realConn, err := net.DialTimeout("tcp", server.addr, time.Second)
	if err != nil {
		t.Fatalf("Failed to create real connection: %v", err)
	}
	defer realConn.Close()

	// Real connection should be alive
	if !pool.isAlive(realConn) {
		t.Error("isAlive should return true for real connection")
	}

	// Create closed connection
	closedConn, err := net.DialTimeout("tcp", server.addr, time.Second)
	if err != nil {
		t.Fatalf("Failed to create closed test connection: %v", err)
	}
	closedConn.Close()

	// Windows needs a moment for TCP state to propagate
	if runtime.GOOS == "windows" {
		time.Sleep(100 * time.Millisecond)
	}

	if pool.isAlive(closedConn) {
		t.Error("isAlive should return false for closed connection")
	}
}

func TestConnPoolSweepEmpty(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	// Sweep empty pool
	pool.sweep()

	pool.mu.RLock()
	if len(pool.conns) != 0 {
		t.Errorf("Expected empty pool, got %d", len(pool.conns))
	}
	pool.mu.RUnlock()
}

func TestConnPoolSweepWithActiveConnections(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, def.BackendRetryCount, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Create connections
	conns := make([]*pooledConn, def.BackendRetryCount)
	for i := 0; i < def.BackendRetryCount; i++ {
		conn, err := pool.get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}

	// Return all first
	for _, c := range conns {
		pool.put(c)
	}

	// Mark one as in use (simulate active)
	conns[0].inUse.Store(true)

	// Mark one as failed (should be removed)
	conns[1].failed.Store(true)

	// Set one as expired
	pool.mu.Lock()
	conns[2].lastUsed = time.Now().Add(-(idleTimeoutLimit + time.Hour))
	pool.mu.Unlock()

	// Sweep
	pool.sweep()

	// Failed and expired connections should be removed, active should remain
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	found := make(map[*pooledConn]bool)
	for _, c := range pool.conns {
		found[c] = true
	}

	if found[conns[0]] != true {
		t.Error("Active connection was removed")
	}
	if found[conns[1]] != false {
		t.Error("Failed connection was not removed")
	}
	if found[conns[2]] != false {
		t.Error("Expired connection was not removed")
	}
}

func TestConnPoolReplaceDuringGet(t *testing.T) {
	server := newTestServer(t)
	defer server.close()

	pool := newConnPool(server.addr, 2, time.Second)
	defer pool.close()

	ctx := context.Background()

	// Fill pool
	conns := make([]*pooledConn, 2)
	for i := 0; i < 2; i++ {
		conn, err := pool.get(ctx)
		if err != nil {
			t.Fatalf("Failed to get connection %d: %v", i, err)
		}
		conns[i] = conn
	}

	// Return both but mark one as expired
	pool.put(conns[0])
	pool.mu.Lock()
	conns[0].lastUsed = time.Now().Add(-(idleTimeoutLimit + time.Hour))
	pool.mu.Unlock()
	pool.put(conns[1])

	// Get should replace expired connection
	pc, err := pool.get(ctx)
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}
	if pc.Conn == conns[0].Conn {
		t.Error("Got expired connection")
	}
}

// BenchmarkConnPoolGet benchmarks connection acquisition
func BenchmarkConnPoolGet(b *testing.B) {
	server, err := newTestServerForBench()
	if err != nil {
		b.Fatalf("Failed to start test server: %v", err)
	}
	defer server.close()

	pool := newConnPool(server.addr, 100, time.Second)
	defer pool.close()
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pc, _ := pool.get(ctx)
		pool.put(pc)
	}
}

// BenchmarkConnPoolConcurrent benchmarks concurrent access
func BenchmarkConnPoolConcurrent(b *testing.B) {
	server, err := newTestServerForBench()
	if err != nil {
		b.Fatalf("Failed to start test server: %v", err)
	}
	defer server.close()

	pool := newConnPool(server.addr, 100, time.Second)
	defer pool.close()
	ctx := context.Background()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pc, _ := pool.get(ctx)
			pool.put(pc)
		}
	})
}
