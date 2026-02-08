package tcp

import (
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

var rngPool = sync.Pool{
	New: func() any {
		return rand.New(rand.NewSource(time.Now().UnixNano()))
	},
}

type Backend struct {
	Address string
	Weight  int

	ActiveConns atomic.Int64
	Alive       atomic.Bool
	Failures    atomic.Int64

	hcInterval time.Duration
	hcTimeout  time.Duration
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() { close(b.stop) })
}

// OnDialFailure increments failure counter and marks backend dead if threshold reached.
func (b *Backend) OnDialFailure(_ error) {
	n := b.Failures.Add(1)
	if b.failThresh <= 0 {
		b.failThresh = 2
	}
	if n >= b.failThresh {
		b.Alive.Store(false)
	}
}

func (b *Backend) healthCheckLoop() {
	// Add jitter to prevent thundering herd on health checks
	time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)

	ticker := time.NewTicker(b.hcInterval)
	defer ticker.Stop()

	for {
		select {
		case <-b.stop:
			return
		case <-ticker.C:
			b.check()
		}
	}
}

func (b *Backend) check() {
	conn, err := net.DialTimeout(woos.TCP, b.Address, b.hcTimeout)
	if err == nil {
		_ = conn.Close()
		// Success: Reset failures and mark alive
		b.Failures.Store(0)
		if !b.Alive.Load() {
			b.Alive.Store(true)
		}
		return
	}

	// Failure: Increment count
	n := b.Failures.Add(1)
	if b.failThresh <= 0 {
		b.failThresh = 2
	}
	if n >= b.failThresh {
		b.Alive.Store(false)
	}
}
