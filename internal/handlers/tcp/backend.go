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

	"git.imaxinacion.net/aibox/agbero/internal/woos"
)

// --- Fast RNG Pool ---
var rngPool = sync.Pool{
	New: func() any {
		var seed int64
		_ = binary.Read(rand.Reader, binary.LittleEndian, &seed)
		return mrand.New(mrand.NewSource(seed))
	},
}

// Backend represents a single upstream node (e.g. one Redis server)
type Backend struct {
	Address string
	Weight  int

	// State
	ActiveConns atomic.Int64
	Alive       atomic.Bool
	Failures    atomic.Int64

	// Config
	MaxConns int64 // Node-level limit

	// Health Check
	hcInterval time.Duration
	hcTimeout  time.Duration
	hcSend     []byte
	hcExpect   []byte
	failThresh int64

	stop     chan struct{}
	stopOnce sync.Once
}

func (b *Backend) Stop() {
	b.stopOnce.Do(func() { close(b.stop) })
}

func (b *Backend) OnDialFailure(_ error) {
	n := b.Failures.Add(1)
	if n >= b.failThresh {
		b.Alive.Store(false)
	}
}

func (b *Backend) healthCheckLoop() {
	// Jitter startup to avoid thundering herd on config reload
	r := rngPool.Get().(*mrand.Rand)
	jitter := time.Duration(r.Intn(1000)) * time.Millisecond
	rngPool.Put(r)
	time.Sleep(jitter)

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
	if err != nil {
		b.markDead()
		return
	}
	defer conn.Close()

	// 1. Simple TCP Connect Check
	if len(b.hcSend) == 0 && len(b.hcExpect) == 0 {
		b.markAlive()
		return
	}

	// 2. L7 Protocol Check (Send/Expect)
	_ = conn.SetDeadline(time.Now().Add(b.hcTimeout))

	if len(b.hcSend) > 0 {
		if _, err := conn.Write(b.hcSend); err != nil {
			b.markDead()
			return
		}
	}

	if len(b.hcExpect) > 0 {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			b.markDead()
			return
		}
		if !bytes.Contains(buf[:n], b.hcExpect) {
			b.markDead()
			return
		}
	}

	b.markAlive()
}

func (b *Backend) markAlive() {
	b.Failures.Store(0)
	if !b.Alive.Load() {
		b.Alive.Store(true)
	}
}

func (b *Backend) markDead() {
	n := b.Failures.Add(1)
	if n >= b.failThresh {
		b.Alive.Store(false)
	}
}
