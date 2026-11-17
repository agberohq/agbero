package mcp

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// Stats are daemon-lifetime MCP HTTP counters: requests, bytes in/out, and
// error responses.
type Stats struct {
	start time.Time
	req   atomic.Uint64
	err   atomic.Uint64
	in    atomic.Uint64
	out   atomic.Uint64
}

type StatsSnapshot struct {
	Requests  uint64 `json:"requests"`
	Errors    uint64 `json:"errors"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
	StartedAt string `json:"started_at"`
}

func NewStats() *Stats {
	return &Stats{start: time.Now()}
}

func (s *Stats) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{}
	}
	return StatsSnapshot{
		Requests: s.req.Load(), Errors: s.err.Load(),
		BytesIn: s.in.Load(), BytesOut: s.out.Load(),
		StartedAt: s.start.UTC().Format(time.RFC3339),
	}
}

func (s *Stats) Middleware(next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.req.Add(1)
		if r.Body != nil {
			r.Body = &countingBody{ReadCloser: r.Body, n: &s.in}
		}
		cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(cw, r)
		s.out.Add(cw.bytes)
		if cw.status >= 400 {
			s.err.Add(1)
		}
	})
}

type countingBody struct {
	io.ReadCloser
	n *atomic.Uint64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.n.Add(uint64(n))
	}
	return n, err
}

type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  uint64
}

func (w *countingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += uint64(n)
	return n, err
}

func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
