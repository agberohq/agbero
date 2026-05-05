package zulu

import (
	"bufio"
	"io"
	"net"
	"net/http"
)

// ResponseWriter wraps http.ResponseWriter to track status code and bytes written,
// with safe header handling and support for flushing and efficient reading.
type ResponseWriter struct {
	http.ResponseWriter
	StatusCode   int
	BytesWritten int64
	WroteHeader  bool
}

// writerOnly hides the ReadFrom method from io.Copy to prevent infinite recursion
type writerOnly struct {
	io.Writer
}

func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.WroteHeader {
		rw.StatusCode = code
		rw.WroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *ResponseWriter) Write(b []byte) (int, error) {
	if !rw.WroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	n, err := rw.ResponseWriter.Write(b)
	rw.BytesWritten += int64(n)
	return n, err
}

func (rw *ResponseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker so that WebSocket upgrades (and any other
// connection-hijacking protocol) can pass through wrappers that embed
// ResponseWriter. Without this, the type assertion in the HTTP upgrade path
// fails silently, and all WebSocket connections are refused.
func (rw *ResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return h.Hijack()
}

func (rw *ResponseWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if !rw.WroteHeader {
		rw.WriteHeader(http.StatusOK)
	}

	// Try efficient zero-copy if underlying writer supports it
	if rf, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
		// We trust the underlying ReadFrom to write the bytes,
		// so we just update our counter.
		if n > 0 {
			rw.BytesWritten += n
		}
		return n, err
	}

	// Fallback to standard Read/Write loop.
	// We MUST wrap 'rw' to hide this ReadFrom method, otherwise
	// io.Copy detects it and calls us back, causing infinite recursion.
	return io.Copy(writerOnly{rw}, r)
}
