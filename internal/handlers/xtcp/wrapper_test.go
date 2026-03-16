package xtcp

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockConn implements net.Conn for testing without real network
type mockConn struct {
	readData  []byte
	writeData bytes.Buffer
	closed    bool
	readPos   int
	mu        sync.Mutex
}

func (m *mockConn) Read(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.EOF
	}
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n := copy(p, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeData.Write(p)
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}
func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678}
}
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockConn) GetWritten() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writeData.Bytes()
}

// TestNewPeekedConn_EmptyPeek tests creation with empty peek buffer
func TestNewPeekedConn_EmptyPeek(t *testing.T) {
	mock := &mockConn{readData: []byte("rest of data")}
	pc := newPeekedConn(mock, []byte{})

	if !pc.done {
		t.Error("expected done=true for empty peek")
	}

	buf := make([]byte, 4)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 || string(buf) != "rest" {
		t.Errorf("expected 'rest', got %q", string(buf[:n]))
	}
}

// TestNewPeekedConn_WithPeek tests creation with peek buffer
func TestNewPeekedConn_WithPeek(t *testing.T) {
	mock := &mockConn{readData: []byte("rest")}
	peek := []byte("peek")
	pc := newPeekedConn(mock, peek)

	if pc.done {
		t.Error("expected done=false with peek data")
	}
	if pc.pos != 0 {
		t.Errorf("expected pos=0, got %d", pc.pos)
	}
	if !bytes.Equal(pc.peek, peek) {
		t.Error("peek buffer mismatch")
	}
}

// TestPeekedConn_Read_FromPeekOnly tests reading only from peek buffer
func TestPeekedConn_Read_FromPeekOnly(t *testing.T) {
	mock := &mockConn{readData: []byte("never read")}
	pc := newPeekedConn(mock, []byte("hello"))

	buf := make([]byte, 3)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 3 || string(buf) != "hel" {
		t.Errorf("expected 'hel', got %q", string(buf[:n]))
	}

	buf = make([]byte, 3)
	n, err = pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2 || string(buf[:n]) != "lo" {
		t.Errorf("expected 'lo', got %q", string(buf[:n]))
	}

	if !pc.done {
		t.Error("expected done=true after draining peek")
	}
	if pc.peek != nil {
		t.Error("expected peek to be nil after drain")
	}
}

// TestPeekedConn_Read_PartialPeekThenConn tests partial peek then conn
func TestPeekedConn_Read_PartialPeekThenConn(t *testing.T) {
	mock := &mockConn{readData: []byte("world")}
	pc := newPeekedConn(mock, []byte("hello "))

	buf := make([]byte, 6)
	n, err := pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 6 || string(buf) != "hello " {
		t.Errorf("expected 'hello ', got %q", string(buf[:n]))
	}

	buf = make([]byte, 5)
	n, err = pc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 5 || string(buf) != "world" {
		t.Errorf("expected 'world', got %q", string(buf[:n]))
	}
}

// TestPeekedConn_ImplementsReaderFrom verifies io.ReaderFrom implementation
func TestPeekedConn_ImplementsReaderFrom(t *testing.T) {
	mock := &mockConn{}
	pc := newPeekedConn(mock, []byte("test"))

	rf, ok := any(pc).(io.ReaderFrom)
	if !ok {
		t.Fatal("peekedConn does not implement io.ReaderFrom - splice disabled!")
	}

	src := strings.NewReader("source data")
	n, err := rf.ReadFrom(src)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != 15 {
		t.Errorf("expected 13 bytes, got %d", n)
	}

	written := mock.GetWritten()
	if string(written) != "testsource data" {
		t.Errorf("expected 'testsource data', got %q", string(written))
	}
}

func TestPeekedConn_WriteTo_DrainsPeekThenDelegates(t *testing.T) {
	mock := &mockConn{readData: []byte("data")}
	pc := newPeekedConn(mock, []byte("peek"))

	var dst bytes.Buffer
	n, err := pc.WriteTo(&dst)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	// "peek" (4) + "data" (4) = 8 bytes
	if n != 8 {
		t.Errorf("expected 8 bytes, got %d", n)
	}

	if dst.String() != "peekdata" {
		t.Errorf("expected 'peekdata', got %q", dst.String())
	}
}

// TestPeekedConn_ReadFrom_DrainsPeekThenDelegates tests peek drain then delegation
func TestPeekedConn_ReadFrom_DrainsPeekThenDelegates(t *testing.T) {
	mock := &mockConn{readData: []byte("more")}
	pc := newPeekedConn(mock, []byte("peek"))

	src := strings.NewReader("source")
	n, err := pc.ReadFrom(src)
	if err != nil {
		t.Fatalf("ReadFrom failed: %v", err)
	}
	if n != 10 {
		t.Errorf("expected 10 bytes, got %d", n)
	}

	written := mock.GetWritten()
	if string(written) != "peeksource" {
		t.Errorf("expected 'peeksource', got %q", string(written))
	}

	if !pc.done {
		t.Error("expected done=true after ReadFrom")
	}
}

// TestPeekedConn_ImplementsWriterTo verifies io.WriterTo implementation
func TestPeekedConn_ImplementsWriterTo(t *testing.T) {
	mock := &mockConn{readData: []byte("connection data")}
	pc := newPeekedConn(mock, []byte("peek "))

	wt, ok := any(pc).(io.WriterTo)
	if !ok {
		t.Fatal("peekedConn does not implement io.WriterTo")
	}

	var dst bytes.Buffer
	n, err := wt.WriteTo(&dst)
	if err != nil {
		t.Fatalf("WriteTo failed: %v", err)
	}
	if n != 20 {
		t.Errorf("expected 20 bytes, got %d", n)
	}

	if dst.String() != "peek connection data" {
		t.Errorf("expected 'peek connection data', got %q", dst.String())
	}
}

// TestCloseWrite_PeekedConn tests closeWrite unwraps peekedConn
func TestCloseWrite_PeekedConn(t *testing.T) {
	mock := &mockConn{}
	pc := &peekedConn{Conn: mock}
	closeWrite(pc) // Should not panic
}

// TestCloseWrite_DeadlineConn tests closeWrite unwraps deadlineConn
func TestCloseWrite_DeadlineConn(t *testing.T) {
	mock := &mockConn{}
	dc := &deadlineConn{Conn: mock}
	closeWrite(dc) // Should not panic
}

// TestDeadlineConn_Read tests deadlineConn applies read deadline
func TestDeadlineConn_Read(t *testing.T) {
	mock := &mockConn{readData: []byte("data")}
	dc := &deadlineConn{Conn: mock, timeout: time.Hour}

	buf := make([]byte, 4)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 || string(buf) != "data" {
		t.Errorf("expected 'data', got %q", string(buf[:n]))
	}
}

// TestDeadlineConn_Write tests deadlineConn applies write deadline
func TestDeadlineConn_Write(t *testing.T) {
	mock := &mockConn{}
	dc := &deadlineConn{Conn: mock, timeout: time.Hour}

	n, err := dc.Write([]byte("test"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 4 {
		t.Errorf("expected 4 bytes written, got %d", n)
	}

	written := mock.GetWritten()
	if string(written) != "test" {
		t.Errorf("expected 'test', got %q", string(written))
	}
}

// BenchmarkPeekedConn_Read benchmarks Read operations
func BenchmarkPeekedConn_Read(b *testing.B) {
	mock := &mockConn{readData: make([]byte, 1024)}
	pc := newPeekedConn(mock, []byte("peek buffer data here"))
	buf := make([]byte, 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mock.readPos = 0
		pc.done = false
		pc.pos = 0
		pc.peek = []byte("peek buffer data here")

		for {
			_, err := pc.Read(buf)
			if err == io.EOF {
				break
			}
		}
	}
}

// BenchmarkPeekedConn_ReadFrom benchmarks ReadFrom (zero-copy path)
func BenchmarkPeekedConn_ReadFrom(b *testing.B) {
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mock := &mockConn{}
		pc := newPeekedConn(mock, []byte("small peek"))
		src := bytes.NewReader(data)
		pc.ReadFrom(src)
	}
}

// Integration test simulating actual proxy usage
func TestPeekedConn_Integration_ProxyScenario(t *testing.T) {
	clientData := []byte("CLIENT_HELLO_EXTRA_TLS_DATA")
	mock := &mockConn{readData: clientData[10:]}

	peek := clientData[:10]
	pc := newPeekedConn(mock, peek)

	var backend bytes.Buffer
	n, err := io.Copy(&backend, pc)
	if err != nil {
		t.Fatalf("copy failed: %v", err)
	}

	expected := "CLIENT_HELLO_EXTRA_TLS_DATA"
	if backend.String() != expected {
		t.Errorf("expected %q, got %q", expected, backend.String())
	}
	if n != int64(len(expected)) {
		t.Errorf("expected %d bytes, got %d", len(expected), n)
	}
}
