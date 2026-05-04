package xudp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

// session represents one active client→backend UDP flow.
//
// Each session owns a dedicated net.UDPConn dialed to the pinned
// backend. A goroutine reads reply datagrams from backendConn and
// writes them back to the client via the shared listen conn.
type session struct {
	backend     *Backend
	backendConn net.Conn
	lastSeen    atomic.Int64
	closeOnce   sync.Once
	removed     atomic.Bool // Ensures deletion only happens once
}

func newSession(b *Backend, bc net.Conn) *session {
	s := &session{
		backend:     b,
		backendConn: bc,
	}
	s.lastSeen.Store(time.Now().UnixNano())
	return s
}

// touch updates the last-seen timestamp.
func (s *session) touch() {
	s.lastSeen.Store(time.Now().UnixNano())
}

// age returns how long ago this session last saw traffic.
func (s *session) age() time.Duration {
	return time.Duration(time.Now().UnixNano() - s.lastSeen.Load())
}

// close shuts down the backend conn exactly once.
func (s *session) close() {
	s.closeOnce.Do(func() {
		_ = s.backendConn.Close()
	})
}

// sessionTable manages the full set of active UDP sessions.
// mappo.Concurrent is backed by xsync — optimised for read-heavy
// workloads where packet routing (reads) far outnumber new session
// creation (writes).
type sessionTable struct {
	sessions *mappo.Concurrent[string, *session]
	ttl      time.Duration
	maxSess  int64
	count    atomic.Int64

	sweeper  *jack.Scheduler
	stopOnce sync.Once
}

func newSessionTable(ttl time.Duration, maxSessions int64) *sessionTable {
	if ttl <= 0 {
		ttl = def.UDPDefaultSessionTTL
	}
	if maxSessions <= 0 {
		maxSessions = def.UDPMaxSessions
	}

	t := &sessionTable{
		sessions: mappo.NewConcurrent[string, *session](),
		ttl:      ttl,
		maxSess:  maxSessions,
	}

	// Schedule periodic TTL sweep using jack.Scheduler — same pattern as xtcp pool.
	sched, _ := jack.NewScheduler(
		def.UDPSweepRoutineName,
		jack.NewPool(def.UDPSweepPoolSize),
		jack.Routine{Interval: def.UDPSweepIntervalSeconds},
	)
	_ = sched.Do(jack.Do(t.sweep))
	t.sweeper = sched

	return t
}

// get returns the session for key, or nil if not found.
// Hot path — reads from mappo.Concurrent are lock-free.
func (t *sessionTable) get(key string) *session {
	s, ok := t.sessions.Get(key)
	if !ok {
		return nil
	}
	s.touch()
	return s
}

// create stores a new session under key.
//
// Returns false only when the table is at capacity or a live session already
// owns the key. A stale entry whose session has been marked removed but not
// yet deleted from the map is treated as a live conflict — callers must handle
// this via the removed flag check.
func (t *sessionTable) create(key string, s *session) bool {
	if t.count.Load() >= t.maxSess {
		return false
	}
	// SetIfAbsent is atomic: only one concurrent creator wins the key.
	if _, loaded := t.sessions.SetIfAbsent(key, s); loaded {
		return false
	}
	t.count.Add(1)
	return true
}

// createOrReplace stores s under key when the existing entry is a dead
// session (removed == true).
//
// This closes the re-establishment race: after a session's CompareAndSwap
// in delete() marks it removed and closes its conn — but before
// sessions.Delete actually removes the map entry — a reconnecting client's
// datagram arrives and create() sees the stale key as occupied. Rather than
// dropping the packet, handleDatagram calls createOrReplace, which overwrites
// the dead entry and installs the fresh session.
//
// Returns true if the new session was installed, false if a live session still
// owns the key (genuine concurrent creation — caller should not write).
func (t *sessionTable) createOrReplace(key string, s *session) bool {
	if t.count.Load() >= t.maxSess {
		return false
	}
	existing, ok := t.sessions.Get(key)
	if !ok {
		// Entry was concurrently deleted between create() failing and now;
		// attempt a clean insert.
		if _, loaded := t.sessions.SetIfAbsent(key, s); loaded {
			return false
		}
		t.count.Add(1)
		return true
	}
	if !existing.removed.Load() {
		// A genuinely live session owns the key; don't evict it.
		return false
	}
	// The existing session is dead: its conn is already closed and its count
	// was already decremented by delete(). Overwrite the stale map entry.
	// We use unconditional Set: if two goroutines race here both are
	// replacing the same dead entry, so last-writer-wins is safe.
	t.sessions.Set(key, s)
	t.count.Add(1)
	return true
}

func (t *sessionTable) delete(key string) {
	if s, ok := t.sessions.Get(key); ok {
		// Prevent double-decrementing if replyLoop and sweeper
		// trigger a delete at the exact same moment.
		if s.removed.CompareAndSwap(false, true) {
			s.close()
			t.sessions.Delete(key)
			t.count.Add(-1)
		}
	}
}

// sweep evicts sessions that have been idle longer than ttl.
// Called by jack.Scheduler — must not block.
func (t *sessionTable) sweep() {
	var expired []string

	t.sessions.Range(func(key string, s *session) bool {
		if s.age() > t.ttl {
			expired = append(expired, key)
		}
		return true
	})

	for _, key := range expired {
		t.delete(key)
	}
}

// len returns the current number of active sessions.
func (t *sessionTable) len() int64 {
	return t.count.Load()
}

// stopSweeper stops the background sweeper goroutine.
func (t *sessionTable) stopSweeper() {
	t.stopOnce.Do(func() {
		if t.sweeper != nil {
			_ = t.sweeper.Stop()
		}
	})
}

// closeAll closes all sessions and clears the table.
func (t *sessionTable) closeAll() {
	t.stopSweeper()

	var keys []string
	t.sessions.Range(func(key string, _ *session) bool {
		keys = append(keys, key)
		return true
	})
	for _, key := range keys {
		t.delete(key)
	}
}
