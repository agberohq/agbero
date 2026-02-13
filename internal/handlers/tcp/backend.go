package tcp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/metrics"
	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

var rngPool = sync.Pool{
	New: func() any {
		var seed int64
		_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
		return mrand.New(mrand.NewSource(seed))
	},
}

type TCPSnapshot struct {
	Address     string
	Alive       bool
	ActiveConns int64
	Failures    int64
	MaxConns    int64
	TotalReqs   uint64
	Latency     metrics.LatencySnapshot
}

type Backend struct {
	Address string
	Weight  int

	Activity *metrics.Activity
	Health   *metrics.Health
	Alive    atomic.Bool

	MaxConns int64

	hcInterval time.Duration
	hcTimeout  time.Duration
	hcSend     []byte
	hcExpect   []byte
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		if b.Activity != nil && b.Activity.Latency != nil {
			b.Activity.Latency.Close()
		}
	})
}

func (b *Backend) OnDialFailure(_ error) {
	b.Activity.Failures.Add(1)

	// We use the Activity failure count for immediate circuit breaking
	// distinct from the background health check failures
	if b.failThresh > 0 {
		current := b.Activity.Failures.Load()
		if int64(current) >= b.failThresh {
			b.Alive.Store(false)
		}
	}
}

func (b *Backend) healthCheckLoop() {
	r := rngPool.Get().(*mrand.Rand)
	jitter := time.Duration(r.Intn(1000)) * time.Millisecond
	rngPool.Put(r)
	time.Sleep(jitter)

	ticker := time.NewTicker(b.hcInterval)
	defer ticker.Stop()

	// Local tracker for consecutive failures in the health loop
	consecutiveFailures := int64(0)

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			if b.check() {
				consecutiveFailures = 0
				b.Health.RecordSuccess()
				b.Activity.Failures.Store(0)
				if !b.Alive.Load() {
					b.Alive.Store(true)
				}
			} else {
				consecutiveFailures++
				b.Health.RecordFailure()
				if consecutiveFailures >= b.failThresh {
					b.Alive.Store(false)
				}
			}
		}
	}
}

func (b *Backend) check() bool {
	conn, err := net.DialTimeout(woos.TCP, b.Address, b.hcTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	if len(b.hcSend) == 0 && len(b.hcExpect) == 0 {
		return true
	}

	_ = conn.SetDeadline(time.Now().Add(b.hcTimeout))

	if len(b.hcSend) > 0 {
		if _, err := conn.Write(b.hcSend); err != nil {
			return false
		}
	}

	if len(b.hcExpect) > 0 {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			return false
		}
		if !bytes.Contains(buf[:n], b.hcExpect) {
			return false
		}
	}

	return true
}

func (b *Backend) Snapshot() *TCPSnapshot {
	return &TCPSnapshot{
		Address:     b.Address,
		Alive:       b.Alive.Load(),
		ActiveConns: b.Activity.InFlight.Load(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxConns:    b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}
