package compress

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/andybalholm/brotli"
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

var brotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotli.DefaultCompression)
	},
}

func Compress(route *alaye.Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if WebSocket (cannot compress upgrade requests)
			if r.Header.Get(woos.HeaderKeyConnection) == woos.HeaderKeyUpgrade {
				next.ServeHTTP(w, r)
				return
			}

			cc := route.CompressionConfig
			if !cc.Status.Yes() {
				next.ServeHTTP(w, r)
				return
			}

			ae := r.Header.Get(woos.HeaderAcceptEncoding)
			compType := strings.ToLower(cc.Type)
			if compType == "" {
				compType = woos.CompressionGzip // Default
			}

			var useComp bool
			var encoding string
			switch compType {
			case woos.CompressionBrotli:
				useComp = strings.Contains(ae, "br")
				encoding = woos.BrotliEncodingType
			case woos.CompressionGzip:
				useComp = strings.Contains(ae, "gzip")
				encoding = woos.GzipEncodingType
			default:
				next.ServeHTTP(w, r)
				return
			}

			if !useComp {
				next.ServeHTTP(w, r)
				return
			}

			// Set headers
			level := cc.Level
			if level < 1 || level > 11 {
				level = 5 // Default balanced
			}

			var writer io.WriteCloser
			if compType == woos.CompressionBrotli {
				w.Header().Set(woos.HeaderContentEnc, encoding)
				brw := brotliWriterPool.Get().(*brotli.Writer) // Update type cast
				brw.Reset(w)
				writer = brw
				defer func() {
					brw.Close()
					brotliWriterPool.Put(brw)
				}()
			} else {
				w.Header().Set(woos.HeaderContentEnc, encoding)
				gzw := gzipWriterPool.Get().(*gzip.Writer)
				gzw.Reset(w)
				writer = gzw
				defer func() {
					gzw.Close()
					gzipWriterPool.Put(gzw)
				}()
			}
			w.Header().Add(woos.HeaderKeyVary, woos.HeaderAcceptEncoding)

			cw := &compressWriter{
				ResponseWriter: w,
				w:              writer,
			}

			next.ServeHTTP(cw, r)
		})
	}
}

type compressWriter struct {
	http.ResponseWriter
	w io.WriteCloser
}

func (cw *compressWriter) Write(b []byte) (int, error) {
	return cw.w.Write(b)
}

// Flush is required for streaming responses (e.g. server-sent events)
func (cw *compressWriter) Flush() {
	if f, ok := cw.w.(interface{ Flush() }); ok {
		f.Flush()
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
