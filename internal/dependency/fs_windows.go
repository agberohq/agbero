//go:build windows

package dependency

import "net"

// inodeOf returns 0 on Windows. The Windows syscall.Stat_t does not expose
// inode numbers. ETag generation in web serving falls back to size+modtime only.
// A future contributor may implement this using the FileIdInfo structure via
// GetFileInformationByHandleEx if a stable inode equivalent is needed on Windows.
func inodeOf(_ string) uint64 {
	return 0
}

// ConnAlive reports whether conn appears to still be open from the remote end.
// It uses a non-blocking peek on the underlying file descriptor on platforms
// that support it. On platforms where this is not possible it returns true
// conservatively and lets the next read or write detect the closed state.
//
// Callers must not treat a true return as a guarantee — the connection may
// close between this check and the next use. The function is intended as a
// fast pre-filter to avoid handing out connections that are definitely dead.
func connAlive(_ net.Conn) bool {
	return true
}
