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
	code atomic.Int32
}

var basicStatusWriterPool = sync.Pool{New: func() any { return &basicStatusWriter{} }}

func (b *basicStatusWriter) WriteHeader(code int) {
	b.code.Store(int32(code))
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

// hedgeState closes a hedge race before the winning request returns. Without
// this, a slow losing goroutine can write after the shared response writer has
// been returned to its pool, producing a nil-pointer panic.
type hedgeState struct {
	mu     sync.Mutex
	winner int32
	closed bool
}

func (s *hedgeState) run(id int32, fn func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	if s.winner == 0 {
		s.winner = id
	}
	if s.winner != id {
		return false
	}
	fn()
	return true
}

func (s *hedgeState) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}

// hedgeWriter ensures only the fastest responding backend gets to write
// to the client. The slower (losing) backend discards its data safely.
type hedgeWriter struct {
	http.ResponseWriter
	state  *hedgeState
	id     int32
	header http.Header
}

// Header returns a private header map. Both hedge attempts run
// httputil.ReverseProxy concurrently; returning the shared underlying
// http.Header would make them race while copying response headers.
func (h *hedgeWriter) Header() http.Header {
	if h.header == nil {
		h.header = make(http.Header)
	}
	return h.header
}

func (h *hedgeWriter) WriteHeader(code int) {
	h.state.run(h.id, func() {
		dst := h.ResponseWriter.Header()
		for k, vv := range h.header {
			for _, v := range vv {
				dst.Add(k, v)
			}
		}
		h.ResponseWriter.WriteHeader(code)
	})
}

func (h *hedgeWriter) Write(b []byte) (int, error) {
	var n int
	var err error
	if !h.state.run(h.id, func() { n, err = h.ResponseWriter.Write(b) }) {
		// Silently discard the loser's data so io.Copy doesn't error out
		return len(b), nil
	}
	return n, err
}

func (h *hedgeWriter) Flush() {
	h.state.run(h.id, func() {
		if f, ok := h.ResponseWriter.(http.Flusher); ok {
			f.Flush()
		}
	})
}

func (h *hedgeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	var conn net.Conn
	var rw *bufio.ReadWriter
	var err error
	ok := h.state.run(h.id, func() {
		if hijacker, ok := h.ResponseWriter.(http.Hijacker); ok {
			conn, rw, err = hijacker.Hijack()
			return
		}
		err = fmt.Errorf("hijacking not supported")
	})
	if !ok {
		return nil, nil, fmt.Errorf("backend lost hedge race")
	}
	return conn, rw, err
}
