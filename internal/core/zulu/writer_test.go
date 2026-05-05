package zulu

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// Test doubles

// dumbWriter implements http.ResponseWriter but NOT io.ReaderFrom.
type dumbWriter struct {
	header http.Header
	buf    *bytes.Buffer
	code   int
}

func (d *dumbWriter) Header() http.Header {
	if d.header == nil {
		d.header = make(http.Header)
	}
	return d.header
}

func (d *dumbWriter) Write(p []byte) (int, error) {
	if d.buf == nil {
		d.buf = &bytes.Buffer{}
	}
	return d.buf.Write(p)
}

func (d *dumbWriter) WriteHeader(statusCode int) {
	d.code = statusCode
}

// onlyReader hides WriteTo from strings.NewReader to force io.Copy to check the destination.
type onlyReader struct {
	io.Reader
}

// mockReaderFrom implements http.ResponseWriter AND io.ReaderFrom.
type mockReaderFrom struct {
	dumbWriter
	readFromCalled bool
}

func (m *mockReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	m.readFromCalled = true
	if m.dumbWriter.buf == nil {
		m.dumbWriter.buf = &bytes.Buffer{}
	}
	return io.Copy(m.dumbWriter.buf, r)
}

// mockFlusher implements http.ResponseWriter + http.Flusher.
type mockFlusher struct {
	dumbWriter
	flushed bool
}

func (m *mockFlusher) Flush() { m.flushed = true }

// mockHijacker implements http.ResponseWriter + http.Hijacker.
type mockHijacker struct {
	dumbWriter
	hijackCalled bool
	hijackErr    error
}

func (m *mockHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijackCalled = true
	if m.hijackErr != nil {
		return nil, nil, m.hijackErr
	}
	// Return a pair of connected net.Pipe connections so callers get a usable conn.
	client, server := net.Pipe()
	_ = server // server end handed to "upstream"
	rw := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	return client, rw, nil
}

func TestResponseWriter_ReadFrom_NoInfiniteRecursion(t *testing.T) {
	underlying := &dumbWriter{}

	wrapper := &ResponseWriter{
		ResponseWriter: underlying,
		StatusCode:     200,
	}

	srcData := "Hello, World! This simulates a static file or proxy body."
	reader := onlyReader{strings.NewReader(srcData)}

	n, err := wrapper.ReadFrom(reader)

	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if n != int64(len(srcData)) {
		t.Errorf("Expected %d bytes written, got %d", len(srcData), n)
	}
	if wrapper.BytesWritten != int64(len(srcData)) {
		t.Errorf("Wrapper metric BytesWritten mismatch. Expected %d, got %d", len(srcData), wrapper.BytesWritten)
	}
	if underlying.buf.String() != srcData {
		t.Errorf("Underlying writer did not receive correct data")
	}
}

func TestResponseWriter_ReadFrom_FastPath(t *testing.T) {
	underlying := &mockReaderFrom{
		dumbWriter: dumbWriter{buf: &bytes.Buffer{}},
	}

	wrapper := &ResponseWriter{
		ResponseWriter: underlying,
		StatusCode:     200,
	}

	srcData := "Fast Path Data"
	reader := strings.NewReader(srcData)

	n, err := wrapper.ReadFrom(reader)

	if err != nil {
		t.Fatalf("ReadFrom error: %v", err)
	}
	if !underlying.readFromCalled {
		t.Error("Expected underlying ReadFrom to be called (Fast Path optimization failed)")
	}
	if n != int64(len(srcData)) {
		t.Errorf("Bytes mismatch: %d", n)
	}
}

func TestResponseWriter_WriteHeader_WritesOnce(t *testing.T) {
	u := &dumbWriter{}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	rw.WriteHeader(http.StatusCreated)
	rw.WriteHeader(http.StatusInternalServerError) // must be ignored

	if rw.StatusCode != http.StatusCreated {
		t.Errorf("StatusCode = %d, want %d", rw.StatusCode, http.StatusCreated)
	}
	if u.code != http.StatusCreated {
		t.Errorf("underlying code = %d, want %d", u.code, http.StatusCreated)
	}
	if !rw.WroteHeader {
		t.Error("WroteHeader should be true after first WriteHeader")
	}
}

func TestResponseWriter_Write_SetsDefaultStatus(t *testing.T) {
	u := &dumbWriter{}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	_, _ = rw.Write([]byte("hello"))

	if u.code != http.StatusOK {
		t.Errorf("implicit WriteHeader = %d, want 200", u.code)
	}
	if rw.BytesWritten != 5 {
		t.Errorf("BytesWritten = %d, want 5", rw.BytesWritten)
	}
}

func TestResponseWriter_Write_AccumulatesBytes(t *testing.T) {
	u := &dumbWriter{}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	for _, chunk := range []string{"foo", "bar", "baz"} {
		_, _ = rw.Write([]byte(chunk))
	}

	if rw.BytesWritten != 9 {
		t.Errorf("BytesWritten = %d, want 9", rw.BytesWritten)
	}
	if u.buf.String() != "foobarbaz" {
		t.Errorf("body = %q, want %q", u.buf.String(), "foobarbaz")
	}
}

func TestResponseWriter_Flush_DelegatesWhenSupported(t *testing.T) {
	u := &mockFlusher{}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	rw.Flush()

	if !u.flushed {
		t.Error("expected Flush to be called on underlying writer")
	}
}

func TestResponseWriter_Flush_NoopWhenNotSupported(t *testing.T) {
	// dumbWriter does not implement http.Flusher — must not panic.
	rw := &ResponseWriter{ResponseWriter: &dumbWriter{}, StatusCode: http.StatusOK}
	rw.Flush() // must not panic
}

// TestResponseWriter_Hijack_Delegates verifies that Hijack() passes through to
// the underlying ResponseWriter when it implements http.Hijacker. This is the
// critical path for WebSocket upgrades: if the assertion fails, the upgrade
// is silently refused.
func TestResponseWriter_Hijack_Delegates(t *testing.T) {
	u := &mockHijacker{}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	conn, brw, err := rw.Hijack()

	if err != nil {
		t.Fatalf("Hijack() returned unexpected error: %v", err)
	}
	if !u.hijackCalled {
		t.Error("expected Hijack to be delegated to underlying writer")
	}
	if conn == nil {
		t.Error("expected non-nil net.Conn from Hijack")
	}
	if brw == nil {
		t.Error("expected non-nil bufio.ReadWriter from Hijack")
	}
	conn.Close()
}

// TestResponseWriter_Hijack_PropagatesError verifies that errors returned by
// the underlying Hijacker are surfaced rather than swallowed.
func TestResponseWriter_Hijack_PropagatesError(t *testing.T) {
	want := errors.New("hijack failed: connection already closed")
	u := &mockHijacker{hijackErr: want}
	rw := &ResponseWriter{ResponseWriter: u, StatusCode: http.StatusOK}

	_, _, err := rw.Hijack()

	if !errors.Is(err, want) {
		t.Errorf("Hijack() error = %v, want %v", err, want)
	}
}

// TestResponseWriter_Hijack_NotSupported verifies that when the underlying
// ResponseWriter does not implement http.Hijacker, Hijack() returns
// http.ErrNotSupported rather than panicking. This ensures the wrapper never
// silently drops the error — callers get a clear, inspectable sentinel.
func TestResponseWriter_Hijack_NotSupported(t *testing.T) {
	// dumbWriter intentionally does NOT implement http.Hijacker.
	rw := &ResponseWriter{ResponseWriter: &dumbWriter{}, StatusCode: http.StatusOK}

	conn, brw, err := rw.Hijack()

	if conn != nil || brw != nil {
		t.Error("expected nil conn and brw when Hijack is unsupported")
	}
	if !errors.Is(err, http.ErrNotSupported) {
		t.Errorf("Hijack() error = %v, want http.ErrNotSupported", err)
	}
}

// TestResponseWriter_Hijack_ImplementsInterface is a compile-time assertion
// that *ResponseWriter satisfies http.Hijacker. If this assignment compiles,
// the interface is fully implemented.
func TestResponseWriter_Hijack_ImplementsInterface(t *testing.T) {
	var _ http.Hijacker = &ResponseWriter{}
}
