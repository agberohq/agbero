package compress

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
)

// Pool for default level (5) - most common case
var gzipWriterPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, 5)
		return w
	},
}

// For custom levels, we can't use the pool effectively without level-specific pools
// For now, create new writers for non-default levels
func getGzipWriter(w io.Writer, level int) *gzip.Writer {
	if level == 5 {
		gzw := gzipWriterPool.Get().(*gzip.Writer)
		gzw.Reset(w)
		return gzw
	}
	// Create new writer for custom level
	gzw, _ := gzip.NewWriterLevel(w, level)
	return gzw
}

func putGzipWriter(gzw *gzip.Writer, level int) {
	if level == 5 {
		gzw.Close()
		gzipWriterPool.Put(gzw)
	}
	// Otherwise, let it be GC'd
}

var brotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotli.DefaultCompression)
	},
}

func Compress(route *alaye.Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get(woos.HeaderKeyConnection), woos.HeaderKeyUpgrade) &&
				strings.EqualFold(r.Header.Get(woos.HeaderKeyUpgrade), "websocket") {
				next.ServeHTTP(w, r)
				return
			}

			cc := route.Compression
			if !cc.Enabled.Active() {
				next.ServeHTTP(w, r)
				return
			}

			ae := r.Header.Get(woos.HeaderAcceptEncoding)
			compType := strings.ToLower(cc.Type)
			if compType == "" {
				compType = woos.CompressionGzip
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

			level := cc.Level
			if level < 1 || level > 11 {
				level = 5
			}

			w.Header().Add(woos.HeaderKeyVary, woos.HeaderAcceptEncoding)

			cw := &compressWriter{
				ResponseWriter: w,
			}

			// Defer closure logic
			defer func() {
				if cw.bypass {
					// If bypassed, ensure the writer doesn't flush trailers to the real response
					if c, ok := cw.w.(*gzip.Writer); ok {
						c.Reset(io.Discard)
						putGzipWriter(c, level)
					} else if c, ok := cw.w.(*brotli.Writer); ok {
						c.Reset(io.Discard)
						brotliWriterPool.Put(c)
					}
					return
				}

				// Normal closure
				if c, ok := cw.w.(io.Closer); ok {
					c.Close()
				}

				// Return to pool
				if c, ok := cw.w.(*gzip.Writer); ok {
					putGzipWriter(c, level)
				} else if c, ok := cw.w.(*brotli.Writer); ok {
					brotliWriterPool.Put(c)
				}
			}()

			// Initialize writer
			if compType == woos.CompressionBrotli {
				brw := brotliWriterPool.Get().(*brotli.Writer)
				brw.Reset(w)
				cw.w = brw
				cw.encoding = encoding // Store to set header later if not bypassed
			} else {
				gzw := getGzipWriter(w, level)
				cw.w = gzw
				cw.encoding = encoding
			}

			next.ServeHTTP(cw, r)
		})
	}
}

type compressWriter struct {
	http.ResponseWriter
	w        io.Writer
	encoding string
	header   bool
	bypass   bool
}

func (cw *compressWriter) WriteHeader(code int) {
	if cw.header {
		return
	}
	// Check if downstream already set Content-Encoding (e.g. pre-compressed file)
	if cw.ResponseWriter.Header().Get("Content-Encoding") != "" {
		cw.bypass = true
	} else {
		// Only set encoding if we are actually compressing
		cw.ResponseWriter.Header().Set("Content-Encoding", cw.encoding)
		// Delete Content-Length because compression changes it
		cw.ResponseWriter.Header().Del("Content-Length")
	}
	cw.header = true
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *compressWriter) Write(b []byte) (int, error) {
	if !cw.header {
		cw.WriteHeader(http.StatusOK)
	}
	if cw.bypass {
		return cw.ResponseWriter.Write(b)
	}
	return cw.w.Write(b)
}

func (cw *compressWriter) Flush() {
	if !cw.bypass {
		if f, ok := cw.w.(interface{ Flush() }); ok {
			f.Flush()
		}
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
