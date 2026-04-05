// Package dependency provides platform-specific primitive implementations
// behind a single stable API. Each function in this package has a
// platform-neutral signature defined here and is implemented in one or
// more build-tagged files alongside it:
//
// Contributors adding new platform-specific behaviour should follow the
// same pattern: define the function signature and documentation here,
// implement it in a build-tagged file, and add a stub for every other
// platform that returns a safe zero value.
//
// This mirrors the approach used for the cluster.Cluster interface: the
// abstraction costs nothing today and avoids a painful refactor when
// platform-specific optimisations (e.g. io_uring, kqueue, IOCP) are added.
package afs

import "net"

// InodeOf returns the inode number of the file at path.
// On platforms that do not expose inode numbers the function returns 0.
// Callers must treat 0 as "inode unavailable" and fall back gracefully.
func InodeOf(path string) uint64 {
	return inodeOf(path)
}

// ConnAlive reports whether conn appears to still be open from the remote end.
// It uses a non-blocking peek on the underlying file descriptor on platforms
// that support it. On platforms where this is not possible it returns true
// conservatively and lets the next read or write detect the closed state.
//
// Callers must not treat a true return as a guarantee — the connection may
// close between this check and the next use. The function is intended as a
// fast pre-filter to avoid handing out connections that are definitely dead.
func ConnAlive(conn net.Conn) bool {
	return connAlive(conn)
}
