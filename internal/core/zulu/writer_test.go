package zulu

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

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

// onlyReader hides WriteTo from strings.NewReader to force io.Copy to check the destination
type onlyReader struct {
	io.Reader
}

func TestResponseWriter_ReadFrom_NoInfiniteRecursion(t *testing.T) {
	// 1. Setup a writer that DOES NOT support ReaderFrom (simulates HTTP/3 response writer)
	underlying := &dumbWriter{}

	wrapper := &ResponseWriter{
		ResponseWriter: underlying,
		StatusCode:     200,
	}

	// 2. Create data and wrap it to hide 'WriteTo'
	// This forces io.Copy to check if 'wrapper' is a ReaderFrom.
	srcData := "Hello, World! This simulates a static file or proxy body."
	reader := onlyReader{strings.NewReader(srcData)}

	// 3. Perform ReadFrom
	n, err := wrapper.ReadFrom(reader)

	// 4. Assertions
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

// mockReaderFrom implements http.ResponseWriter AND io.ReaderFrom
type mockReaderFrom struct {
	dumbWriter
	readFromCalled bool
}

func (m *mockReaderFrom) ReadFrom(r io.Reader) (int64, error) {
	m.readFromCalled = true
	return io.Copy(m.dumbWriter.buf, r)
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
