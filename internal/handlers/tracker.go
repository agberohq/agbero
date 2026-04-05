package handlers

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ConnTracker uses Go's native sync.Map for safe, concurrent connection tracking.
type ConnTracker struct {
	conns sync.Map
	count atomic.Int64
}

func NewConnTracker() *ConnTracker {
	return &ConnTracker{}
}

func (ct *ConnTracker) Track(c net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		ct.conns.Store(c, struct{}{})
		ct.count.Add(1)
	case http.StateClosed, http.StateHijacked:
		if _, loaded := ct.conns.LoadAndDelete(c); loaded {
			ct.count.Add(-1)
		}
	}
}

func (ct *ConnTracker) Count() int64 {
	return ct.count.Load()
}

func (ct *ConnTracker) Wait(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ct.Count() == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
