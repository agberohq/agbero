package compress

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/klauspost/compress/gzip"
)

// Use a sync.Pool to reuse writers and reduce allocation overhead.
// klauspost/compress writers are heavy to allocate.
var gzipWriterPool = sync.Pool{
	New: func() any {
		// Level 5 offers a great balance between compression ratio and speed.
		// Standard lib default is usually equivalent to level 6.
		w, _ := gzip.NewWriterLevel(io.Discard, 5)
		return w
	},
}

func Compress() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if client supports gzip
			if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
				next.ServeHTTP(w, r)
				return
			}

			// Check if WebSocket (cannot compress upgrade requests)
			if r.Header.Get("Connection") == "Upgrade" {
				next.ServeHTTP(w, r)
				return
			}

			// Set headers
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Add("Vary", "Accept-Encoding")

			// Grab a writer from the pool
			gz := gzipWriterPool.Get().(*gzip.Writer)
			gz.Reset(w)

			defer func() {
				gz.Close()
				gzipWriterPool.Put(gz)
			}()

			cw := &compressWriter{
				ResponseWriter: w,
				w:              gz,
			}

			next.ServeHTTP(cw, r)
		})
	}
}

type compressWriter struct {
	http.ResponseWriter
	w *gzip.Writer
}

func (cw *compressWriter) Write(b []byte) (int, error) {
	return cw.w.Write(b)
}

// Flush is required for streaming responses (e.g. server-sent events)
func (cw *compressWriter) Flush() {
	cw.w.Flush()
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack is required for websockets (though we skip compression for them above,
// the interface check might still happen in some chains)
/*
func (cw *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := cw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}
*/
