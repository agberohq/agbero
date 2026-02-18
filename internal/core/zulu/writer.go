package zulu

import (
	"io"
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

func (rw *ResponseWriter) WriteHeader(code int) {
	if !rw.WroteHeader {
		rw.StatusCode = code
		rw.WroteHeader = true
		rw.ResponseWriter.WriteHeader(code)
	}
	// Ignore subsequent calls to prevent multiple header writes.
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

func (rw *ResponseWriter) ReadFrom(r io.Reader) (n int64, err error) {
	if !rw.WroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	if rf, ok := rw.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
		if err == nil {
			rw.BytesWritten += n
		}
		return n, err
	}
	// Fall back to io.Copy, which will use our Write method to count bytes.
	return io.Copy(rw, r)
}
