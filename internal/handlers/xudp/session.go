package xudp

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

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
	backendConn net.Conn     // dialed UDP conn to backend — owned by this session
	lastSeen    atomic.Int64 // unix nano of last datagram in either direction
	closeOnce   sync.Once
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
		ttl = time.Duration(defaultSessionTTLSeconds) * time.Second
	}
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}

	t := &sessionTable{
		sessions: mappo.NewConcurrent[string, *session](),
		ttl:      ttl,
		maxSess:  maxSessions,
	}

	// Schedule periodic TTL sweep using jack.Scheduler — same pattern as xtcp pool.
	sched, _ := jack.NewScheduler(
		sweepRoutineName,
		jack.NewPool(sweepPoolSize),
		jack.Routine{Interval: time.Duration(sweepIntervalSeconds) * time.Second},
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

// create stores a new session. Returns false if the table is at capacity.
func (t *sessionTable) create(key string, s *session) bool {
	if t.count.Load() >= t.maxSess {
		return false
	}
	t.sessions.Set(key, s)
	t.count.Add(1)
	return true
}

// delete removes a session by key and closes its backend conn.
func (t *sessionTable) delete(key string) {
	if s, ok := t.sessions.Get(key); ok {
		s.close()
		t.sessions.Delete(key)
		t.count.Add(-1)
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
