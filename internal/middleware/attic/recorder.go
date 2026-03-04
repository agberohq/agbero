package attic

import (
	"bytes"
	"net/http"
	"sync"
)

// recorder captures HTTP response for caching
type recorder struct {
	http.ResponseWriter
	headers     http.Header
	buf         *bytes.Buffer
	status      int
	wroteHeader bool
	mu          sync.RWMutex
}

func newRecorder(w http.ResponseWriter) *recorder {
	return &recorder{
		ResponseWriter: w,
		headers:        make(http.Header),
		buf:            bytes.NewBuffer(make([]byte, 0, 4096)),
		status:         http.StatusOK,
	}
}

func (r *recorder) Header() http.Header {
	return r.headers
}

func (r *recorder) WriteHeader(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.wroteHeader {
		return
	}

	r.status = code
	r.wroteHeader = true

	for k, vv := range r.headers {
		for _, v := range vv {
			r.ResponseWriter.Header().Add(k, v)
		}
	}

	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	r.mu.RLock()
	wh := r.wroteHeader
	r.mu.RUnlock()

	if !wh {
		r.WriteHeader(http.StatusOK)
	}

	r.mu.Lock()
	r.buf.Write(b)
	r.mu.Unlock()

	return r.ResponseWriter.Write(b)
}

func (r *recorder) Body() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.buf.Bytes()
}

func (r *recorder) StatusCode() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
