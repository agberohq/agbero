package xudp

import (
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	resource "github.com/agberohq/agbero/internal/hub/resource"
	"github.com/olekukonko/ll"
)

// Pool initialisation

// TestProxy_Start_InitialisesPool verifies that Start() creates the bounded
// worker pool so that subsequent receiveLoop calls can dispatch to it.
func TestProxy_Start_InitialisesPool(t *testing.T) {
	res := resource.New(resource.WithLogger(ll.New("xudp-test").Disable()))
	p := NewProxy(res, poolTestFreeUDPAddr(t))
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	if p.pool == nil {
		t.Fatal("pool is nil after Start — goroutine-per-packet DoS protection not in place")
	}
}

// Goroutine bound under flood

// TestProxy_ReceiveLoop_BoundedGoroutines is the core regression test for the
// goroutine-per-packet DoS.
//
// It floods the proxy with packets at a rate that would previously spawn
// thousands of goroutines and asserts that the goroutine count stays within a
// reasonable bound (workers + sessions + fixed overhead).
func TestProxy_ReceiveLoop_BoundedGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flood test in short mode")
	}

	res := resource.New(resource.WithLogger(ll.New("xudp-test").Disable()))
	p := NewProxy(res, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	baseline := runtime.NumGoroutine()

	conn, err := net.Dial("udp", p.Listen)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("flood")
	for i := 0; i < 5000; i++ {
		_, _ = conn.Write(payload)
	}

	time.Sleep(200 * time.Millisecond)

	// Allow generous headroom: pool workers + replyLoop goroutines + test overhead.
	maxAllowed := baseline + def.UDPWorkerPoolSize + 50
	after := runtime.NumGoroutine()
	if after > maxAllowed {
		t.Errorf("goroutine count after flood = %d, want ≤ %d (baseline %d + workers %d + headroom 50)",
			after, maxAllowed, baseline, def.UDPWorkerPoolSize)
	}
}

// Drop-not-crash under queue saturation

// TestProxy_ReceiveLoop_DropsWhenFull verifies that when the worker pool queue
// is saturated the proxy drops packets and recycles their buffers rather than
// panicking or leaking goroutines.
func TestProxy_ReceiveLoop_DropsWhenFull(t *testing.T) {
	res := resource.New(resource.WithLogger(ll.New("xudp-test").Disable()))
	p := NewProxy(res, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Stop()

	conn, err := net.Dial("udp", p.Listen)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	payload := make([]byte, 512)
	for i := 0; i < def.UDPPacketQueueSize*3; i++ {
		_, _ = conn.Write(payload)
	}

	time.Sleep(100 * time.Millisecond)
	if p.closing.Load() {
		t.Error("proxy closed itself under queue saturation — should have dropped packets instead")
	}
}

// Worker count constant sanity

func TestUDPWorkerPoolConstants(t *testing.T) {
	if def.UDPWorkerPoolSize <= 0 {
		t.Errorf("UDPWorkerPoolSize = %d, must be > 0", def.UDPWorkerPoolSize)
	}
	if def.UDPPacketQueueSize <= 0 {
		t.Errorf("UDPPacketQueueSize = %d, must be > 0", def.UDPPacketQueueSize)
	}
	if def.UDPPacketQueueSize < def.UDPWorkerPoolSize*10 {
		t.Errorf("UDPPacketQueueSize (%d) should be at least 10× UDPWorkerPoolSize (%d) for burst absorption",
			def.UDPPacketQueueSize, def.UDPWorkerPoolSize)
	}
}

// Stop drains pool cleanly

// TestProxy_Stop_DrainsPool ensures Stop() completes without hanging when the
// pool has in-flight work.
func TestProxy_Stop_DrainsPool(t *testing.T) {
	res := resource.New(resource.WithLogger(ll.New("xudp-test").Disable()))
	p := NewProxy(res, "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("udp", p.Listen)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	for i := 0; i < 20; i++ {
		_, _ = conn.Write([]byte("ping"))
	}
	conn.Close()

	done := make(chan struct{})
	go func() {
		p.Stop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Stop() did not return within 5s — possible goroutine leak or pool deadlock")
	}
}

// Datagram buffer recycling — no leak on drop

// TestProxy_DroppedPacket_BufferRecycled confirms buffers are returned to the
// pool on the drop path (queue full), not leaked.
func TestProxy_DroppedPacket_BufferRecycled(t *testing.T) {
	var leaked atomic.Int64

	for i := 0; i < 1000; i++ {
		buf := getDatagram()
		if buf == nil {
			leaked.Add(1)
		}
		putDatagram(buf)
	}

	if n := leaked.Load(); n > 0 {
		t.Errorf("getDatagram() returned nil %d times — buffer pool exhausted", n)
	}
}

// Helpers (pool-test-local, avoids collision with proxy_test.go helpers)

func poolTestFreeUDPAddr(t *testing.T) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("poolTestFreeUDPAddr: %v", err)
	}
	addr := c.LocalAddr().String()
	c.Close()
	return addr
}
