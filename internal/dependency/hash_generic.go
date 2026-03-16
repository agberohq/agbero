//go:build (!amd64 && !arm64) || noasm

package dependency

// crc32Hash delegates to the pure Go implementation safely.
// Invoked on architectures without explicit assembly routines.
func crc32Hash(s string) uint64 {
	return crc32HashFallback(s)
}

// crc32HashBytes delegates to the pure Go implementation safely.
// Invoked on architectures without explicit assembly routines.
func crc32HashBytes(b []byte) uint64 {
	return crc32HashBytesFallback(b)
}
