//go:build !windows

package dependency

import "syscall"

// inodeOf returns the inode number for path using the POSIX stat syscall.
// Returns 0 if the stat call fails for any reason.
func inodeOf(path string) uint64 {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return 0
	}
	return st.Ino
}
