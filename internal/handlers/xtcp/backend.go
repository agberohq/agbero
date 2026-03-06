package xtcp

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/zulu"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/lb"
	"git.imaxinacion.net/aibox/agbero/internal/pkg/metrics"
)

type Backend struct {
	Address  string
	Activity *metrics.Activity
	Health   *metrics.Health

	MaxConns int64

	hcInterval time.Duration
	hcTimeout  time.Duration
	hcSend     []byte
	hcExpect   []byte
	failThresh int64
	weight     int
	alive      *atomic.Bool

	stop     chan struct{}
	stopOnce sync.Once
	pool     *connPool
	poolOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() {
		close(b.stop)
		b.poolOnce.Do(func() {
			if b.pool != nil {
				b.pool.close()
			}
		})
	})
}

func (b *Backend) OnDialFailure(_ error) {
	b.Activity.Failures.Add(1)

	if b.failThresh > 0 {
		current := b.Activity.Failures.Load()
		if int64(current) >= b.failThresh {
			b.alive.Store(false)
		}
	}
}

func (b *Backend) Snapshot() *Snapshot {
	return &Snapshot{
		Address:     b.Address,
		Alive:       b.alive.Load(),
		ActiveConns: b.Activity.InFlight.Load(),
		Failures:    int64(b.Activity.Failures.Load()),
		MaxConns:    b.MaxConns,
		TotalReqs:   b.Activity.Requests.Load(),
		Latency:     b.Activity.Latency.Snapshot(),
	}
}

func (b *Backend) healthCheckLoop() {
	// Added Panic Recovery
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[CRITICAL] TCP health check panic for %s: %v\nStack: %s\n", b.Address, r, debug.Stack())
		}
	}()

	b.poolOnce.Do(func() {
		b.pool = newConnPool(b.Address, 3, b.hcTimeout)
	})

	r := zulu.Rand()
	jitter := time.Duration(r.IntN(1000)) * time.Millisecond
	zulu.RandPut(r)
	time.Sleep(jitter)

	ticker := time.NewTicker(b.hcInterval)
	defer ticker.Stop()

	consecutiveFailures := int64(0)
	currentInterval := b.hcInterval
	maxBackoff := 30 * time.Second
	if b.hcInterval > maxBackoff {
		maxBackoff = b.hcInterval * 10
	}

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			if b.check() {
				consecutiveFailures = 0
				b.Health.RecordSuccess()
				b.Activity.Failures.Store(0)

				if currentInterval != b.hcInterval {
					currentInterval = b.hcInterval
					ticker.Reset(currentInterval)
				}

				if !b.alive.Load() {
					b.alive.Store(true)
				}
			} else {
				consecutiveFailures++
				b.Health.RecordFailure()

				if consecutiveFailures >= b.failThresh {
					b.alive.Store(false)
					currentInterval *= 2
					if currentInterval > maxBackoff {
						currentInterval = maxBackoff
					}
					ticker.Reset(currentInterval)
				}
			}
		}
	}
}

func (b *Backend) check() bool {
	if len(b.hcSend) == 0 && len(b.hcExpect) == 0 {
		pc, err := b.pool.get()
		if err != nil {
			return false
		}
		b.pool.put(pc)
		return true
	}

	pc, err := b.pool.get()
	if err != nil {
		return false
	}
	defer b.pool.put(pc)

	conn := pc.Conn
	_ = conn.SetDeadline(time.Now().Add(b.hcTimeout))

	if len(b.hcSend) > 0 {
		if _, err := conn.Write(b.hcSend); err != nil {
			pc.failed.Store(true)
			return false
		}
	}

	if len(b.hcExpect) > 0 {
		buf := getCheckBuf()
		defer putCheckBuf(buf)

		n, err := conn.Read(buf)
		if err != nil {
			pc.failed.Store(true)
			return false
		}
		if !bytes.Contains(buf[:n], b.hcExpect) {
			return false
		}
	}

	return true
}

func (b *Backend) Status(v bool)   { b.alive.Store(v) }
func (b *Backend) Alive() bool     { return b.alive.Load() }
func (b *Backend) Weight() int     { return b.weight }
func (b *Backend) InFlight() int64 { return b.Activity.InFlight.Load() }
func (b *Backend) ResponseTime() int64 {
	snap := b.Activity.Latency.Snapshot()
	if snap.Count == 0 {
		return 0
	}
	return snap.Avg
}

// Check
var _ lb.Backend = (*Backend)(nil)
