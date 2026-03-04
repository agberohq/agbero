package xtcp

import (
	"bytes"
	"io"
	"net"
	"time"
)

// peekedConn wraps a net.Conn to prepend a peek buffer for SNI inspection.
// It implements io.ReaderFrom to re-enable Linux splice/sendfile zero-copy
// once the peek buffer is drained, avoiding Kernel -> User -> Kernel copies.
type peekedConn struct {
	net.Conn
	peek []byte // remaining peek data (nil once drained)
	pos  int    // current position in peek
	done bool   // true when peek is exhausted, allows zero-copy path
}

// newPeekedConn creates a peekedConn that serves 'peek' first, then c.
// The peek slice is referenced, not copied (caller must not modify after call).
func newPeekedConn(c net.Conn, peek []byte) *peekedConn {
	return &peekedConn{
		Conn: c,
		peek: peek,
		pos:  0,
		done: len(peek) == 0,
	}
}

// Read serves from the peek buffer first, then underlying conn.
func (c *peekedConn) Read(p []byte) (int, error) {
	if c.done {
		return c.Conn.Read(p)
	}

	n := copy(p, c.peek[c.pos:])
	c.pos += n

	if c.pos >= len(c.peek) {
		c.done = true
		c.peek = nil // allow GC
	}

	if n > 0 {
		return n, nil
	}

	return c.Conn.Read(p)
}

// ReadFrom implements io.ReaderFrom to enable splice/sendfile zero-copy.
// Once the peek buffer is drained, delegates to underlying conn's ReadFrom
// (e.g., *net.TCPConn uses splice(2) on Linux).
func (c *peekedConn) ReadFrom(r io.Reader) (int64, error) {
	// If peek buffer still has data, drain it first to maintain order.
	if !c.done {
		peekReader := bytes.NewReader(c.peek[c.pos:])
		n, err := io.Copy(c.Conn, peekReader)
		if err != nil {
			return n, err
		}
		c.done = true
		c.peek = nil

		// Continue with remaining data from r using zero-copy if available.
		var m int64
		if rf, ok := c.Conn.(io.ReaderFrom); ok {
			m, err = rf.ReadFrom(r)
		} else {
			m, err = io.Copy(c.Conn, r)
		}
		return n + m, err
	}

	// Peek exhausted: delegate to underlying conn for zero-copy.
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}

	return io.Copy(c.Conn, r)
}

// WriteTo implements io.WriterTo for zero-copy in the reverse direction.
func (c *peekedConn) WriteTo(w io.Writer) (int64, error) {
	var total int64

	if !c.done {
		n, err := w.Write(c.peek[c.pos:])
		total += int64(n)
		if err != nil {
			return total, err
		}
		c.done = true
		c.peek = nil
	}

	if wt, ok := c.Conn.(io.WriterTo); ok {
		n, err := wt.WriteTo(w)
		return total + n, err
	}

	n, err := io.Copy(w, c.Conn)
	return total + n, err
}

func closeWrite(c net.Conn) {
	switch v := c.(type) {
	case *net.TCPConn:
		_ = v.CloseWrite()
	case *peekedConn:
		closeWrite(v.Conn)
	case *deadlineConn:
		closeWrite(v.Conn)
	default:
		type closer interface {
			CloseWrite() error
		}
		if cw, ok := c.(closer); ok {
			_ = cw.CloseWrite()
		}
	}
}

type deadlineConn struct {
	net.Conn
	timeout time.Duration
}

func (c *deadlineConn) Read(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(b)
}

func (c *deadlineConn) Write(b []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.SetWriteDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Write(b)
}
