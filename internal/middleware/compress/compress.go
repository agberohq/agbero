package compress

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
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

			cc := route.CompressionConfig
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

			var writer io.WriteCloser
			if compType == woos.CompressionBrotli {
				w.Header().Set(woos.HeaderContentEnc, encoding)
				brw := brotliWriterPool.Get().(*brotli.Writer)
				brw.Reset(w)
				writer = brw
				defer func() {
					brw.Close()
					brotliWriterPool.Put(brw)
				}()
			} else {
				w.Header().Set(woos.HeaderContentEnc, encoding)
				gzw := getGzipWriter(w, level)
				writer = gzw
				defer func() {
					putGzipWriter(gzw, level)
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
	w      io.WriteCloser
	header bool
}

func (cw *compressWriter) Write(b []byte) (int, error) {
	if !cw.header {
		cw.ResponseWriter.WriteHeader(http.StatusOK)
		cw.header = true
	}
	return cw.w.Write(b)
}

func (cw *compressWriter) Flush() {
	if f, ok := cw.w.(interface{ Flush() }); ok {
		f.Flush()
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
