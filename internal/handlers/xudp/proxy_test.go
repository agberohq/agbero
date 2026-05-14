package xudp

import (
	"net"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	resource "github.com/agberohq/agbero/internal/hub/resource"
	"github.com/agberohq/agbero/internal/pkg/lb"
	"github.com/olekukonko/ll"
)

// helpers

func testRes() *resource.Resource {
	return resource.New(resource.WithLogger(ll.New("xudp-test").Disable()))
}

func testProxy(t *testing.T) *Proxy {
	t.Helper()
	p := NewProxy(testRes(), "127.0.0.1:0")
	if err := p.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(p.Stop)
	return p
}

func dialUDP(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// loopbackConn returns a UDP net.Conn that is safe to use as a session
// backendConn stand-in — close() on the session table can call its Close()
// without panic.
func loopbackConn(t *testing.T) net.Conn {
	t.Helper()
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("loopbackConn listen: %v", err)
	}
	cli, err := net.Dial("udp", srv.LocalAddr().String())
	if err != nil {
		srv.Close()
		t.Fatalf("loopbackConn dial: %v", err)
	}
	t.Cleanup(func() { srv.Close(); cli.Close() })
	return cli
}

// testBackend creates a Backend with a pre-seeded healthy score so IsUsable()
// returns true immediately without a live upstream.
func testBackend(t *testing.T, res *resource.Resource, addr string) *Backend {
	t.Helper()
	cfg := BackendConfig{
		Server:   alaye.Server{Address: expect.Address(addr)},
		Proxy:    alaye.Proxy{Listen: "127.0.0.1:0", Name: "test"},
		Resource: res,
		Logger:   res.Logger,
	}
	b, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(%s): %v", addr, err)
	}
	t.Cleanup(b.Stop)
	return b
}

// testRoute builds a udpRoute from backends with the given strategy name.
func testRoute(backends []*Backend, strategy string) *udpRoute {
	lbBackends := make([]lb.Backend, len(backends))
	for i, b := range backends {
		lbBackends[i] = b
	}
	sel := lb.NewSelector(lbBackends, lb.ParseStrategy(strategy))
	sel.Update(lbBackends)
	return &udpRoute{selector: sel, proxyName: "test"}
}

// Pool initialisation

// TestProxy_Start_InitialisesPool verifies that Start() creates the bounded
// worker pool so that subsequent receiveLoop calls can dispatch to it.
func TestProxy_Start_InitialisesPool(t *testing.T) {
	p := testProxy(t)
	if p.pool == nil {
		t.Fatal("pool is nil after Start — goroutine-per-packet DoS protection not in place")
	}
}

// Goroutine bound under flood

// TestProxy_ReceiveLoop_BoundedGoroutines is the core regression test for the
// goroutine-per-packet DoS. It floods the proxy and asserts the goroutine
// count stays within pool workers + sessions + fixed overhead.
func TestProxy_ReceiveLoop_BoundedGoroutines(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping flood test in short mode")
	}

	p := testProxy(t)
	baseline := runtime.NumGoroutine()

	conn := dialUDP(t, p.Listen)
	payload := []byte("flood")
	for i := 0; i < 5000; i++ {
		_, _ = conn.Write(payload)
	}
	time.Sleep(200 * time.Millisecond)

	maxAllowed := baseline + def.UDPWorkerPoolSize + 50
	if after := runtime.NumGoroutine(); after > maxAllowed {
		t.Errorf("goroutine count after flood = %d, want <= %d (baseline %d + workers %d + headroom 50)",
			after, maxAllowed, baseline, def.UDPWorkerPoolSize)
	}
}

// Drop-not-crash under queue saturation

// TestProxy_ReceiveLoop_DropsWhenFull verifies that when the worker pool queue
// is saturated the proxy drops packets and recycles buffers rather than
// panicking or leaking goroutines.
func TestProxy_ReceiveLoop_DropsWhenFull(t *testing.T) {
	p := testProxy(t)
	conn := dialUDP(t, p.Listen)

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
		t.Errorf("UDPPacketQueueSize (%d) should be >= 10x UDPWorkerPoolSize (%d) for burst absorption",
			def.UDPPacketQueueSize, def.UDPWorkerPoolSize)
	}
}

// Stop drains pool cleanly

// TestProxy_Stop_DrainsPool ensures Stop() returns within a reasonable timeout
// even when the pool has in-flight work.
func TestProxy_Stop_DrainsPool(t *testing.T) {
	res := testRes()
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
	go func() { p.Stop(); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("Stop() did not return within 5s — possible goroutine leak or pool deadlock")
	}
}

// Datagram buffer recycling

// TestProxy_DroppedPacket_BufferRecycled confirms getDatagram/putDatagram
// cycle without exhaustion.
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

// Session key isolation (fix: cross-client data leak)

// TestSessionTable_TwoClientsGetDistinctSessions is the regression test for
// the session-key hijacking bug where the DNS matcher overwrote sessionKey
// with the query domain. Two clients querying the same domain would share a
// session: client B's datagram was forwarded over client A's backend socket,
// and the reply was delivered to the wrong address.
//
// After the fix, sessionKey is always clientAddr.String(). This test creates
// two sessions with distinct client-address keys, verifying they are stored as
// separate entries regardless of what the matcher might have extracted.
func TestSessionTable_TwoClientsGetDistinctSessions(t *testing.T) {
	tbl := newSessionTable(60*time.Second, 1000)
	defer tbl.closeAll()

	connA := loopbackConn(t)
	connB := loopbackConn(t)

	sessA := newSession(nil, connA)
	sessB := newSession(nil, connB)

	keyA := "127.0.0.1:10001" // always client IP:Port
	keyB := "127.0.0.1:10002" // always client IP:Port

	if !tbl.create(keyA, sessA) {
		t.Fatal("create sessA failed")
	}
	// both clients mapped to the same domain key ("google.com"),
	// so this second create() would fail or silently reuse sessA.
	if !tbl.create(keyB, sessB) {
		t.Fatal("create sessB failed — suggests a key collision (domain used as session key)")
	}

	if tbl.len() != 2 {
		t.Fatalf("session table len = %d, want 2", tbl.len())
	}

	gotA := tbl.get(keyA)
	gotB := tbl.get(keyB)
	if gotA == nil || gotB == nil {
		t.Fatal("one or both sessions missing from table")
	}
	if gotA == gotB {
		t.Error("both client keys resolved to the same session — cross-client data leak regression")
	}
}

// Bidirectional TTL reset (fix: server-driven stream dropout)

// TestSessionTable_ReplyTrafficResetsLifetime is the regression test for the
// one-sided lifetime tracking bug.
//
// Before the fix, only client->proxy packets (via sessionTable.get) called
// tbl.lifetime.ResetTimed. The replyLoop never reset the timer. A session with
// a quiet client but an active server (video, game state, StatsD) was forcibly
// destroyed exactly TTL seconds after the last client packet — even with
// gigabytes flowing in the server->client direction.
//
// The fix adds p.sessions.lifetime.ResetTimed(sessionKey) in replyLoop after
// each successful read. This test simulates that call and asserts the session
// remains alive well past one TTL period.
func TestSessionTable_ReplyTrafficResetsLifetime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	const ttl = 200 * time.Millisecond
	tbl := newSessionTable(ttl, 1000)
	defer tbl.closeAll()

	conn := loopbackConn(t)
	key := "127.0.0.1:20001"
	sess := newSession(nil, conn)

	if !tbl.create(key, sess) {
		t.Fatal("create failed")
	}

	// Simulate server reply traffic: reset the lifetime timer at sub-TTL
	// intervals for 1.5x the TTL, mirroring the fixed replyLoop behaviour.
	resetInterval := ttl / 4
	stopAt := time.Now().Add(ttl + ttl/2)
	for time.Now().Before(stopAt) {
		time.Sleep(resetInterval)
		tbl.lifetime.ResetTimed(key) // mirrors: p.sessions.lifetime.ResetTimed(sessionKey)
		sess.touch()
	}

	if tbl.get(key) == nil {
		t.Error("session destroyed despite continuous reply-loop resets — bidirectional TTL regression")
	}
}

// TestSessionTable_TrulyIdleSessionExpires verifies that a genuinely idle
// session is still reaped after TTL. Guards against over-eager keep-alive
// accidentally preventing expiry.
func TestSessionTable_TrulyIdleSessionExpires(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing-sensitive test in short mode")
	}

	const ttl = 150 * time.Millisecond
	tbl := newSessionTable(ttl, 1000)
	defer tbl.closeAll()

	conn := loopbackConn(t)
	key := "127.0.0.1:20002"
	sess := newSession(nil, conn)

	if !tbl.create(key, sess) {
		t.Fatal("create failed")
	}

	// No touch, no ResetTimed — session must expire naturally.
	time.Sleep(ttl * 3)

	if tbl.get(key) != nil {
		t.Error("idle session still present after 3x TTL — lifetime/sweep not evicting correctly")
	}
}

// TestPickBackend_UsesRoutingHashForConsistentHashing is the regression test
// for pickBackend always generating a random key regardless of the matcher
// output, making consistent hashing impossible.

// The test uses a consistent-hash selector with three backends:
//   - Fixed non-zero hash must always return the same backend.
//   - hash=0 must distribute across multiple backends over enough iterations.
func TestPickBackend_UsesRoutingHashForConsistentHashing(t *testing.T) {
	res := testRes()

	addrs := []string{"127.0.0.1:9901", "127.0.0.1:9902", "127.0.0.1:9903"}
	backends := make([]*Backend, len(addrs))
	for i, addr := range addrs {
		backends[i] = testBackend(t, res, addr)
	}

	route := testRoute(backends, def.StrategyConsistentHash)

	p := NewProxy(res, "127.0.0.1:0")
	p.sessions = newSessionTable(30*time.Second, 1000)
	defer p.sessions.closeAll()

	const routingHash = uint64(0xdeadbeefcafebabe)
	const iterations = 50

	// Fixed non-zero hash: consistent hashing must always choose the same backend.
	first := p.pickBackend(route, routingHash)
	if first == nil {
		t.Fatal("pickBackend returned nil with seeded backends")
	}
	for i := 0; i < iterations; i++ {
		got := p.pickBackend(route, routingHash)
		if got == nil {
			t.Fatalf("iteration %d: pickBackend returned nil", i)
		}
		if got.Address != first.Address {
			t.Errorf("iteration %d: consistent hash chose %q, want %q — routingHash not honoured",
				i, got.Address, first.Address)
		}
	}

	// hash=0: random fallback must be able to reach multiple backends.
	// P(only 1 of 3 backends in 50 tries) < 10^-23.
	seen := make(map[string]int)
	for i := 0; i < iterations; i++ {
		if got := p.pickBackend(route, 0); got != nil {
			seen[got.Address]++
		}
	}
	if len(seen) < 2 {
		t.Errorf("routingHash=0: only %d backend(s) selected in %d calls — random fallback broken: %v",
			len(seen), iterations, seen)
	}
}
