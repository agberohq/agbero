package xhttp

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"sync"

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
