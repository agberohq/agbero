package xudp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/mappo"
)

// session represents one active client→backend UDP flow.
type session struct {
	backend     *Backend
	backendConn net.Conn
	lastSeen    atomic.Int64
	closeOnce   sync.Once
	removed     atomic.Bool
}

func newSession(b *Backend, bc net.Conn) *session {
	s := &session{backend: b, backendConn: bc}
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
	s.closeOnce.Do(func() { _ = s.backendConn.Close() })
}

// sessionTable manages the full set of active UDP sessions.
// jack.Lifetime provides per-session precision expiry — sessions expire within
// one Lifetime tick of their deadline rather than up to one sweep interval.
// sweep() is retained as a fallback and for test compatibility.
type sessionTable struct {
	sessions *mappo.Concurrent[string, *session]
	ttl      time.Duration
	maxSess  int64
	count    atomic.Int64

	lifetime *jack.Lifetime
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
		lifetime: jack.NewLifetime(jack.LifetimeWithShards(def.LifetimeShards)),
	}

	// Periodic sweep as a fallback — also lets tests call tbl.sweep() directly.
	sched, _ := jack.NewScheduler(
		def.UDPSweepRoutineName,
		jack.NewPool(def.UDPSweepPoolSize),
		jack.Routine{Interval: def.UDPSweepIntervalSeconds},
	)
	_ = sched.Do(jack.Do(t.sweep))
	t.sweeper = sched

	return t
}

func (t *sessionTable) get(key string) *session {
	s, ok := t.sessions.Get(key)
	if !ok {
		return nil
	}
	s.touch()
	// Reset the Lifetime timer — extends the session deadline on each packet.
	t.lifetime.ResetTimed(key)
	return s
}

// create stores a new session and schedules its TTL via jack.Lifetime.
func (t *sessionTable) create(key string, s *session) bool {
	if t.count.Load() >= t.maxSess {
		return false
	}
	if _, loaded := t.sessions.SetIfAbsent(key, s); loaded {
		return false
	}
	t.count.Add(1)
	t.lifetime.ScheduleTimed(context.Background(), key, func(_ context.Context, id string) {
		t.delete(id)
	}, t.ttl)
	return true
}

// createOrReplace installs a new session when the existing entry is dead.
func (t *sessionTable) createOrReplace(key string, s *session) bool {
	if t.count.Load() >= t.maxSess {
		return false
	}
	existing, ok := t.sessions.Get(key)
	if !ok {
		if _, loaded := t.sessions.SetIfAbsent(key, s); loaded {
			return false
		}
		t.count.Add(1)
		t.lifetime.ScheduleTimed(context.Background(), key, func(_ context.Context, id string) {
			t.delete(id)
		}, t.ttl)
		return true
	}
	if !existing.removed.Load() {
		return false
	}
	t.sessions.Set(key, s)
	t.count.Add(1)
	t.lifetime.ScheduleTimed(context.Background(), key, func(_ context.Context, id string) {
		t.delete(id)
	}, t.ttl)
	return true
}

func (t *sessionTable) delete(key string) {
	s, ok := t.sessions.Get(key)
	if !ok {
		return
	}
	// CAS on the session's removed flag. Only the goroutine that wins
	// the swap owns the teardown sequence for THIS session instance.
	if !s.removed.CompareAndSwap(false, true) {
		return
	}
	t.lifetime.CancelTimed(key)
	s.close()

	// only remove the key if it still holds
	// the same session pointer we just closed. If createOrReplace() raced
	// between our CAS and here, the map already holds a NEW session — we
	// must not delete it (that would orphan the new session and leak the
	// socket). mappo.Concurrent.Get + conditional Delete is safe here
	// because SetIfAbsent and Set in createOrReplace are also atomic:
	// if current != s the new session is already live and we leave it alone.
	if current, still := t.sessions.Get(key); still && current == s {
		t.sessions.Delete(key)
		t.count.Add(-1)
	}
	// If the key was already replaced, count was incremented by createOrReplace
	// so we must not decrement it — the new session is healthy.
}

// sweep evicts sessions idle longer than ttl.
// Called periodically by the scheduler and directly by tests.
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

func (t *sessionTable) len() int64 { return t.count.Load() }

func (t *sessionTable) stopSweeper() {
	t.stopOnce.Do(func() {
		if t.sweeper != nil {
			_ = t.sweeper.Stop()
		}
		t.lifetime.StopAll()
	})
}

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
