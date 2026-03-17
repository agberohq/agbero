//go:build !windows

package afs

import (
	"net"
	"syscall"

	"github.com/olekukonko/errors"
)

// inodeOf returns the inode number for path using the POSIX stat syscall.
// Returns 0 if the stat call fails for any reason.
func inodeOf(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}

// connAlive performs a non-blocking peek on the connection's file descriptor.
// EAGAIN and EWOULDBLOCK indicate no data is waiting but the connection is
// open. Any other error or a zero-byte read indicates the remote end closed.
func connAlive(conn net.Conn) bool {
	sys, ok := conn.(syscall.Conn)
	if !ok {
		return true
	}
	raw, err := sys.SyscallConn()
	if err != nil {
		return false
	}

	var sysErr error
	var n int

	err = raw.Read(func(fd uintptr) bool {
		var buf [1]byte
		n, _, sysErr = syscall.Recvfrom(int(fd), buf[:], syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		return true
	})

	if err != nil {
		return false
	}
	if sysErr != nil {
		if errors.Is(sysErr, syscall.EAGAIN) || errors.Is(sysErr, syscall.EWOULDBLOCK) {
			return true
		}
		return false
	}
	return n > 0
}
