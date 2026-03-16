//go:build windows

package dependency

// inodeOf returns 0 on Windows. The Windows syscall.Stat_t does not expose
// inode numbers. ETag generation in web serving falls back to size+modtime only.
// A future contributor may implement this using the FileIdInfo structure via
// GetFileInformationByHandleEx if a stable inode equivalent is needed on Windows.
func inodeOf(_ string) uint64 {
	return 0
}
