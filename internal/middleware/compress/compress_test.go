package compress

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	brotlidec "github.com/andybalholm/brotli"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func routeWith(compType string, level int) *alaye.Route {
	return &alaye.Route{
		Compression: alaye.Compression{
			Enabled: expect.Active,
			Type:    compType,
			Level:   level,
		},
	}
}

func routeDisabled() *alaye.Route {
	return &alaye.Route{
		Compression: alaye.Compression{
			Enabled: expect.Inactive,
		},
	}
}

func echoHandler(body string, status int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	})
}

func decodeGzip(t *testing.T, b []byte) string {
	t.Helper()
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("gzip read: %v", err)
	}
	return string(out)
}

func decodeBrotli(t *testing.T, b []byte) string {
	t.Helper()
	out, err := io.ReadAll(brotlidec.NewReader(bytes.NewReader(b)))
	if err != nil {
		t.Fatalf("brotli read: %v", err)
	}
	return string(out)
}

// ---------------------------------------------------------------------------
// Disabled / passthrough
// ---------------------------------------------------------------------------

func TestCompress_Disabled_Passthrough(t *testing.T) {
	h := Compress(routeDisabled())(echoHandler("hello", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty (compression disabled)", enc)
	}
	if w.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", w.Body.String(), "hello")
	}
}

func TestCompress_NoAcceptEncoding_Passthrough(t *testing.T) {
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler("hello", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty when client doesn't accept gzip", enc)
	}
	if w.Body.String() != "hello" {
		t.Errorf("body = %q, want plain text when not compressed", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// WebSocket passthrough
// ---------------------------------------------------------------------------

func TestCompress_WebSocket_Passthrough(t *testing.T) {
	reached := false
	h := Compress(routeWith(def.CompressionGzip, 5))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusSwitchingProtocols)
	}))

	req := httptest.NewRequest(http.MethodGet, "/ws", nil)
	req.Header.Set(def.HeaderKeyConnection, def.HeaderKeyUpgrade)
	req.Header.Set(def.HeaderKeyUpgrade, "websocket")
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !reached {
		t.Fatal("next handler not called for WebSocket upgrade request")
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("WebSocket response must not set Content-Encoding, got %q", enc)
	}
}

// ---------------------------------------------------------------------------
// Gzip
// ---------------------------------------------------------------------------

func TestCompress_Gzip_Basic(t *testing.T) {
	const body = "Hello gzip world!"
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler(body, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != def.GzipEncodingType {
		t.Fatalf("Content-Encoding = %q, want %q", enc, def.GzipEncodingType)
	}
	if cl := w.Header().Get("Content-Length"); cl != "" {
		t.Errorf("Content-Length must be absent when compressing, got %q", cl)
	}
	if got := decodeGzip(t, w.Body.Bytes()); got != body {
		t.Errorf("decoded body = %q, want %q", got, body)
	}
}

func TestCompress_Gzip_VaryHeader(t *testing.T) {
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler("x", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !strings.Contains(w.Header().Get(def.HeaderKeyVary), def.HeaderAcceptEncoding) {
		t.Errorf("Vary must include Accept-Encoding, got %q", w.Header().Get(def.HeaderKeyVary))
	}
}

func TestCompress_Gzip_CustomLevel(t *testing.T) {
	const body = "custom level content"
	h := Compress(routeWith(def.CompressionGzip, 9))(echoHandler(body, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if enc := w.Header().Get("Content-Encoding"); enc != def.GzipEncodingType {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if decodeGzip(t, w.Body.Bytes()) != body {
		t.Error("decoded body does not match original")
	}
}

func TestCompress_Gzip_InvalidLevel_FallsBackToDefault(t *testing.T) {
	h := Compress(routeWith(def.CompressionGzip, 0))(echoHandler("data", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if enc := w.Header().Get("Content-Encoding"); enc != def.GzipEncodingType {
		t.Fatalf("Content-Encoding = %q, want gzip", enc)
	}
	if decodeGzip(t, w.Body.Bytes()) != "data" {
		t.Error("decoded body mismatch after level clamp")
	}
}

// ---------------------------------------------------------------------------
// Brotli
// ---------------------------------------------------------------------------

func TestCompress_Brotli_Basic(t *testing.T) {
	const body = "Hello brotli world!"
	h := Compress(routeWith(def.CompressionBrotli, 5))(echoHandler(body, http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "br")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != def.BrotliEncodingType {
		t.Fatalf("Content-Encoding = %q, want %q", enc, def.BrotliEncodingType)
	}
	if got := decodeBrotli(t, w.Body.Bytes()); got != body {
		t.Errorf("decoded body = %q, want %q", got, body)
	}
}

func TestCompress_Brotli_NoAcceptEncoding_Passthrough(t *testing.T) {
	h := Compress(routeWith(def.CompressionBrotli, 5))(echoHandler("plain", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip") // only gzip, not br
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty when client does not accept br", enc)
	}
	if w.Body.String() != "plain" {
		t.Errorf("body = %q, want plain", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Bypass conditions
// ---------------------------------------------------------------------------

func TestCompress_Bypass_AlreadyEncoded(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "already-compressed")
	})
	h := Compress(routeWith(def.CompressionGzip, 5))(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Body.String() != "already-compressed" {
		t.Errorf("body = %q, want verbatim passthrough", w.Body.String())
	}
}

func TestCompress_Bypass_204NoContent(t *testing.T) {
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler("", http.StatusNoContent))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty for 204", enc)
	}
}

func TestCompress_Bypass_304NotModified(t *testing.T) {
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler("", http.StatusNotModified))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", w.Code)
	}
	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty for 304", enc)
	}
}

// ---------------------------------------------------------------------------
// Flush / SSE — counter-based (fast, deterministic)
// ---------------------------------------------------------------------------

// flushCapture counts Flush() calls reaching the underlying ResponseWriter.
type flushCapture struct {
	httptest.ResponseRecorder
	flushCount int
}

func (f *flushCapture) Flush() {
	f.flushCount++
	f.ResponseRecorder.Flush()
}

// TestCompress_Flush_ReachesThroughGzip is the primary regression test.
//
// *gzip.Writer implements Flush() error, not Flush(). The original code used
// interface{ Flush() } which never matched, so ok was always false, the gzip
// buffer was never drained, and SSE/streaming broke silently. The fix changes
// the assertion to interface{ Flush() error }.
func TestCompress_Flush_ReachesThroughGzip(t *testing.T) {
	fc := &flushCapture{ResponseRecorder: *httptest.NewRecorder()}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "chunk1")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = io.WriteString(w, "chunk2")
	})

	h := Compress(routeWith(def.CompressionGzip, 5))(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	h.ServeHTTP(fc, req)

	if fc.flushCount == 0 {
		t.Error("Flush() was not propagated — gzip buffer never drained (interface{ Flush() } assertion always fails)")
	}
	if full := decodeGzip(t, fc.Body.Bytes()); full != "chunk1chunk2" {
		t.Errorf("decoded body = %q, want %q", full, "chunk1chunk2")
	}
}

func TestCompress_Flush_ReachesThroughBrotli(t *testing.T) {
	fc := &flushCapture{ResponseRecorder: *httptest.NewRecorder()}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "sse-event")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	h := Compress(routeWith(def.CompressionBrotli, 5))(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "br")
	h.ServeHTTP(fc, req)

	if fc.flushCount == 0 {
		t.Error("Flush() not propagated through brotli writer")
	}
}

func TestCompress_Flush_Bypass_StillFlushesUnderlying(t *testing.T) {
	fc := &flushCapture{ResponseRecorder: *httptest.NewRecorder()}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent) // triggers bypass
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	h := Compress(routeWith(def.CompressionGzip, 5))(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	h.ServeHTTP(fc, req)

	if fc.flushCount == 0 {
		t.Error("Flush() not propagated to underlying writer on bypass path")
	}
}

func TestCompress_Flush_NonFlusher_NoPanic(t *testing.T) {
	type plainWriter struct{ httptest.ResponseRecorder }

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Flush() panicked with non-Flusher underlying writer: %v", r)
		}
	}()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	})

	h := Compress(routeWith(def.CompressionGzip, 5))(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")
	h.ServeHTTP(&plainWriter{}, req)
}

// ---------------------------------------------------------------------------
// SSE incremental delivery — proves bytes leave the gzip buffer mid-stream
// ---------------------------------------------------------------------------

// pipeResponseWriter adapts an io.PipeWriter to http.ResponseWriter so writes
// go straight to the pipe rather than an in-memory buffer. The read end can
// therefore observe bytes incrementally instead of waiting for ServeHTTP to return.
type pipeResponseWriter struct {
	pw     *io.PipeWriter
	header http.Header
}

func newPipeResponseWriter(pw *io.PipeWriter) *pipeResponseWriter {
	return &pipeResponseWriter{pw: pw, header: make(http.Header)}
}

func (p *pipeResponseWriter) Header() http.Header         { return p.header }
func (p *pipeResponseWriter) WriteHeader(int)             {}
func (p *pipeResponseWriter) Write(b []byte) (int, error) { return p.pw.Write(b) }

// TestCompress_Gzip_SSE_IncrementalDelivery is the end-to-end streaming proof.
//
// The middleware is wired through an io.Pipe. The handler writes one SSE chunk,
// calls Flush(), then blocks waiting for the test to confirm the chunk arrived
// before writing a second one. This proves data left the gzip buffer mid-stream.
//
// Before the fix, the first pipe Read would block forever — the gzip sync-flush
// block was never emitted because Flush() error never matched interface{ Flush() }.
// The test would time out after 2 seconds, failing with a clear message.
func TestCompress_Gzip_SSE_IncrementalDelivery(t *testing.T) {
	pr, pw := io.Pipe()
	firstChunkReceived := make(chan struct{})

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "event: ping\n\n")

		// The flush under test. Without the fix cw.w is a *gzip.Writer whose
		// Flush() returns error; interface{ Flush() } never matches; ok is false;
		// the bytes stay buffered; the pipe reader below never unblocks.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		<-firstChunkReceived // wait for test confirmation before writing more
		_, _ = io.WriteString(w, "event: pong\n\n")
	})

	h := Compress(routeWith(def.CompressionGzip, 5))(inner)
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "gzip")

	go func() {
		h.ServeHTTP(newPipeResponseWriter(pw), req)
		pw.Close()
	}()

	// Read compressed bytes from the pipe. Any non-zero read proves Flush()
	// emitted a gzip sync-flush block (0x00 0x00 0xff 0xff) draining the buffer.
	bytesArrived := make(chan int, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := pr.Read(buf)
		bytesArrived <- n
	}()

	select {
	case n := <-bytesArrived:
		close(firstChunkReceived)
		_, _ = io.Copy(io.Discard, pr)
		if n == 0 {
			t.Error("Flush() did not push any bytes through the gzip buffer — SSE is broken")
		}
	case <-time.After(2 * time.Second):
		close(firstChunkReceived)
		_, _ = io.Copy(io.Discard, pr)
		t.Fatal("timed out: no bytes arrived after Flush() — gzip buffer was never flushed")
	}
}

// ---------------------------------------------------------------------------
// Unknown compression type
// ---------------------------------------------------------------------------

func TestCompress_UnknownType_Passthrough(t *testing.T) {
	h := Compress(&alaye.Route{
		Compression: alaye.Compression{
			Enabled: expect.Active,
			Type:    "zstd",
			Level:   5,
		},
	})(echoHandler("plain", http.StatusOK))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(def.HeaderAcceptEncoding, "zstd")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if enc := w.Header().Get("Content-Encoding"); enc != "" {
		t.Errorf("Content-Encoding = %q, want empty for unsupported type", enc)
	}
	if w.Body.String() != "plain" {
		t.Errorf("body = %q, want plain passthrough", w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Concurrent safety
// ---------------------------------------------------------------------------

func TestCompress_Gzip_Concurrent(t *testing.T) {
	const body = "concurrent body"
	h := Compress(routeWith(def.CompressionGzip, 5))(echoHandler(body, http.StatusOK))

	done := make(chan struct{}, 20)
	for range 20 {
		go func() {
			defer func() { done <- struct{}{} }()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set(def.HeaderAcceptEncoding, "gzip")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if got := decodeGzip(t, w.Body.Bytes()); got != body {
				t.Errorf("concurrent: decoded body = %q, want %q", got, body)
			}
		}()
	}
	for range 20 {
		<-done
	}
}
