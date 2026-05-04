package compress

import (
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
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

	gzw, _ := gzip.NewWriterLevel(w, level)
	return gzw
}

func putGzipWriter(gzw *gzip.Writer, level int) {
	if level == 5 {
		gzw.Close()
		gzipWriterPool.Put(gzw)
	}
}

var brotliWriterPool = sync.Pool{
	New: func() any {
		return brotli.NewWriterLevel(io.Discard, brotli.DefaultCompression)
	},
}

func Compress(route *alaye.Route) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.EqualFold(r.Header.Get(def.HeaderKeyConnection), def.HeaderKeyUpgrade) &&
				strings.EqualFold(r.Header.Get(def.HeaderKeyUpgrade), "websocket") {
				next.ServeHTTP(w, r)
				return
			}

			cc := route.Compression
			if !cc.Enabled.Active() {
				next.ServeHTTP(w, r)
				return
			}

			ae := r.Header.Get(def.HeaderAcceptEncoding)
			compType := strings.ToLower(cc.Type)
			if compType == "" {
				compType = def.CompressionGzip
			}

			var useComp bool
			var encoding string
			switch compType {
			case def.CompressionBrotli:
				useComp = strings.Contains(ae, "br")
				encoding = def.BrotliEncodingType
			case def.CompressionGzip:
				useComp = strings.Contains(ae, "gzip")
				encoding = def.GzipEncodingType
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

			w.Header().Add(def.HeaderKeyVary, def.HeaderAcceptEncoding)

			cw := &compressWriter{
				ResponseWriter: w,
			}

			defer func() {
				if cw.bypass {
					if c, ok := cw.w.(*gzip.Writer); ok {
						c.Reset(io.Discard)
						putGzipWriter(c, level)
					} else if c, ok := cw.w.(*brotli.Writer); ok {
						c.Reset(io.Discard)
						brotliWriterPool.Put(c)
					}
					return
				}

				if c, ok := cw.w.(io.Closer); ok {
					c.Close()
				}

				if c, ok := cw.w.(*gzip.Writer); ok {
					putGzipWriter(c, level)
				} else if c, ok := cw.w.(*brotli.Writer); ok {
					brotliWriterPool.Put(c)
				}
			}()

			if compType == def.CompressionBrotli {
				brw := brotliWriterPool.Get().(*brotli.Writer)
				brw.Reset(w)
				cw.w = brw
				cw.encoding = encoding
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

	// Bypass compression for responses that must not have a body
	if cw.ResponseWriter.Header().Get("Content-Encoding") != "" ||
		code == http.StatusNoContent ||
		code == http.StatusNotModified ||
		code < 200 {
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
		// Both *gzip.Writer and *brotli.Writer implement Flush() error,
		// not Flush(). Asserting the zero-return interface always fails,
		// leaving the compression buffer unflushed and breaking SSE/streaming.
		if f, ok := cw.w.(interface{ Flush() error }); ok {
			_ = f.Flush()
		}
	}
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
