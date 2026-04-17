package xudp

import (
	"github.com/agberohq/agbero/internal/core/def"
	"net"
	"sync"
	"testing"
	"time"
)

// mockConn is a minimal net.Conn for testing — all operations are no-ops.
type mockConn struct {
	closed bool
	mu     sync.Mutex
}

func (m *mockConn) Read(b []byte) (int, error)         { return 0, nil }
func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockConn) Close() error                       { m.mu.Lock(); m.closed = true; m.mu.Unlock(); return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestSession() *session {
	return newSession(nil, &mockConn{})
}

func TestSessionTable_CreateAndGet(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 100)
	defer tbl.closeAll()

	sess := newTestSession()
	if !tbl.create("key1", sess) {
		t.Fatal("create should succeed")
	}

	got := tbl.get("key1")
	if got == nil {
		t.Fatal("get should return the session")
	}
	if got != sess {
		t.Fatal("get should return the same session pointer")
	}
}

func TestSessionTable_GetMissing(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 100)
	defer tbl.closeAll()

	if tbl.get("nonexistent") != nil {
		t.Fatal("get should return nil for unknown key")
	}
}

func TestSessionTable_Delete(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 100)
	defer tbl.closeAll()

	mc := &mockConn{}
	sess := newSession(nil, mc)
	tbl.create("key1", sess)
	tbl.delete("key1")

	if tbl.get("key1") != nil {
		t.Fatal("session should be gone after delete")
	}
	mc.mu.Lock()
	closed := mc.closed
	mc.mu.Unlock()
	if !closed {
		t.Fatal("backend conn should be closed on delete")
	}
}

func TestSessionTable_MaxSessions(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 3)
	defer tbl.closeAll()

	for i := 0; i < 3; i++ {
		key := string(rune('a' + i))
		if !tbl.create(key, newTestSession()) {
			t.Fatalf("create %d should succeed", i)
		}
	}

	// Fourth create should fail — at capacity
	if tbl.create("overflow", newTestSession()) {
		t.Fatal("create should fail when at max capacity")
	}
	if tbl.len() != 3 {
		t.Fatalf("expected 3 sessions, got %d", tbl.len())
	}
}

func TestSessionTable_CountAccurate(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 100)
	defer tbl.closeAll()

	tbl.create("a", newTestSession())
	tbl.create("b", newTestSession())
	tbl.create("c", newTestSession())

	if tbl.len() != 3 {
		t.Fatalf("expected 3, got %d", tbl.len())
	}

	tbl.delete("b")
	if tbl.len() != 2 {
		t.Fatalf("expected 2 after delete, got %d", tbl.len())
	}
}

func TestSessionTable_SweepExpiredSessions(t *testing.T) {
	// Very short TTL for testing
	tbl := newSessionTable(10*time.Millisecond, 100)
	defer tbl.closeAll()

	mc := &mockConn{}
	sess := newSession(nil, mc)
	tbl.create("expiring", sess)

	// Wait for TTL to expire then sweep
	time.Sleep(50 * time.Millisecond)
	tbl.sweep()

	if tbl.get("expiring") != nil {
		t.Fatal("expired session should be swept")
	}
	mc.mu.Lock()
	closed := mc.closed
	mc.mu.Unlock()
	if !closed {
		t.Fatal("backend conn should be closed when session is swept")
	}
}

func TestSessionTable_TouchExtendsTTL(t *testing.T) {
	tbl := newSessionTable(50*time.Millisecond, 100)
	defer tbl.closeAll()

	sess := newTestSession()
	tbl.create("key", sess)

	// Touch repeatedly to keep alive
	for i := 0; i < 3; i++ {
		time.Sleep(20 * time.Millisecond)
		got := tbl.get("key") // get calls touch internally
		if got == nil {
			t.Fatal("session should still exist after touch")
		}
	}
}

func TestSessionTable_CloseAllClosesConns(t *testing.T) {
	tbl := newSessionTable(30*time.Second, 100)

	mcs := make([]*mockConn, 5)
	for i := range mcs {
		mcs[i] = &mockConn{}
		tbl.create(string(rune('a'+i)), newSession(nil, mcs[i]))
	}

	tbl.closeAll()

	for i, mc := range mcs {
		mc.mu.Lock()
		closed := mc.closed
		mc.mu.Unlock()
		if !closed {
			t.Fatalf("mockConn[%d] should be closed after closeAll", i)
		}
	}
	if tbl.len() != 0 {
		t.Fatalf("expected 0 sessions after closeAll, got %d", tbl.len())
	}
}

func TestSessionTable_ConcurrentAccess(t *testing.T) {
	tbl := newSessionTable(30*time.Second, def.DefaultCacheMaxItems)
	defer tbl.closeAll()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := string(rune('A' + (i % 26)))
			tbl.create(key, newTestSession())
			_ = tbl.get(key)
			if i%3 == 0 {
				tbl.delete(key)
			}
		}(i)
	}
	wg.Wait()
	// No panic = pass
}

func TestSession_Age(t *testing.T) {
	sess := newTestSession()
	time.Sleep(10 * time.Millisecond)
	if sess.age() < 10*time.Millisecond {
		t.Fatal("age should be at least 10ms")
	}
}

func TestSession_TouchResetsAge(t *testing.T) {
	sess := newTestSession()
	time.Sleep(20 * time.Millisecond)
	sess.touch()
	if sess.age() >= 20*time.Millisecond {
		t.Fatal("age should be reset after touch")
	}
}

func TestSession_CloseIdempotent(t *testing.T) {
	mc := &mockConn{}
	sess := newSession(nil, mc)
	sess.close()
	sess.close() // second close must not panic
	mc.mu.Lock()
	if !mc.closed {
		mc.mu.Unlock()
		t.Fatal("conn should be closed")
	}
	mc.mu.Unlock()
}
