// Package dependency provides platform-specific primitive implementations
// behind a single stable API. Each function in this package has a
// platform-neutral signature defined here and is implemented in one or
// more build-tagged files alongside it:
//
//	fs_unix.go    — non-Windows (Linux, macOS, BSD)
//	fs_windows.go — Windows
//
// Contributors adding new platform-specific behaviour should follow the
// same pattern: define the function signature and documentation here,
// implement it in a build-tagged file, and add a stub for every other
// platform that returns a safe zero value.
//
// This mirrors the approach used for the cluster.Cluster interface: the
// abstraction costs nothing today and avoids a painful refactor when
// platform-specific optimisations (e.g. io_uring, kqueue, IOCP) are added.
package dependency

// InodeOf returns the inode number of the file at path.
// On platforms that do not expose inode numbers the function returns 0.
// Callers must treat 0 as "inode unavailable" and fall back gracefully.
func InodeOf(path string) uint64 {
	return inodeOf(path)
}
