package xtcp

import (
	"io"
	"net"
	"time"
)

type peekedConn struct {
	net.Conn
	reader io.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func closeWrite(c net.Conn) {
	switch v := c.(type) {
	case *net.TCPConn:
		_ = v.CloseWrite()
	case *peekedConn:
		closeWrite(v.Conn)
	case *deadlineConn:
		closeWrite(v.Conn)
	default:
		// Attempt to upgrade to interface if the struct is private or other wrappers exist
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
