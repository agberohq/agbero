package attic

import (
	"bytes"
	"net/http"
	"sync"

	"github.com/agberohq/agbero/internal/core/def"
)

// recorder captures HTTP response for caching
type recorder struct {
	http.ResponseWriter
	headers     http.Header
	buf         *bytes.Buffer
	status      int
	wroteHeader bool
	cacheable   bool
	mu          sync.RWMutex
}

func newRecorder(w http.ResponseWriter) *recorder {
	return &recorder{
		ResponseWriter: w,
		headers:        make(http.Header),
		buf:            bytes.NewBuffer(make([]byte, 0, def.CacheBufferSize)),
		status:         http.StatusOK,
		cacheable:      true,
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
	cacheable := r.cacheable
	r.mu.RUnlock()

	if !wh {
		r.WriteHeader(http.StatusOK)
	}

	if cacheable {
		r.mu.Lock()
		if r.cacheable {
			if r.buf.Len()+len(b) > def.CacheMaxBodySize {
				// Response too large: stop buffering and free memory
				r.cacheable = false
				r.buf = nil
			} else {
				r.buf.Write(b)
			}
		}
		r.mu.Unlock()
	}

	return r.ResponseWriter.Write(b)
}

func (r *recorder) Body() []byte {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.cacheable || r.buf == nil {
		return nil
	}
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

func (r *recorder) Cacheable() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cacheable
}
