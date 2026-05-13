package xhttp

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/zulu"
)

var proxyBufPool = zulu.NewBufferPool()

type backendCtxKey struct{}

// backendState holds per-request failure state. Pooled to eliminate the
// new(bool) heap allocation per proxied request. Stored in context under
// the comparable backendCtxKey so the fixed ErrorHandler closure can
// signal failure back to ServeHTTP's defer.
type backendState struct {
	failed bool
}

var backendStatePool = sync.Pool{New: func() any { return &backendState{} }}

type basicStatusWriter struct {
	http.ResponseWriter
	code int
}

var basicStatusWriterPool = sync.Pool{New: func() any { return &basicStatusWriter{} }}

func (b *basicStatusWriter) WriteHeader(code int) {
	b.code = code
	b.ResponseWriter.WriteHeader(code)
}

func (b *basicStatusWriter) Flush() {
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (b *basicStatusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := b.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijacking not supported")
}

// hedgeWriter ensures only the fastest responding backend gets to write
// to the client. The slower (losing) backend discards its data safely.
type hedgeWriter struct {
	http.ResponseWriter
	winner *atomic.Int32
	id     int32
}

func (h *hedgeWriter) WriteHeader(code int) {
	if h.winner.CompareAndSwap(0, h.id) || h.winner.Load() == h.id {
		h.ResponseWriter.WriteHeader(code)
	}
}

func (h *hedgeWriter) Write(b []byte) (int, error) {
	if h.winner.CompareAndSwap(0, h.id) || h.winner.Load() == h.id {
		return h.ResponseWriter.Write(b)
	}
	// Silently discard the loser's data so io.Copy doesn't error out
	return len(b), nil
}

func (h *hedgeWriter) Flush() {
	if h.winner.Load() == h.id {
		if f, ok := h.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	}
}

func (h *hedgeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h.winner.CompareAndSwap(0, h.id) || h.winner.Load() == h.id {
		if hijacker, ok := h.ResponseWriter.(http.Hijacker); ok {
			return hijacker.Hijack()
		}
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	return nil, nil, fmt.Errorf("backend lost hedge race")
}
