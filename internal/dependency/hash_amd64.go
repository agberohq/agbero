//go:build amd64 && !noasm

package dependency

import "unsafe"

// crc32HashAsm is implemented in high-performance assembly.
// Executes hardware CRCQ instructions for optimal throughput.
func crc32HashAsm(p unsafe.Pointer, length int) uint64

// crc32Hash routes the string hashing to the optimal implementation.
// Leverages SSE4.2 if detected, otherwise falls back to pure Go.
func crc32Hash(s string) uint64 {
	if hasCRC32 && len(s) > 0 {
		return crc32HashAsm(unsafe.Pointer(unsafe.StringData(s)), len(s))
	} else if hasCRC32 {
		return 0
	}
	return crc32HashFallback(s)
}

// crc32HashBytes routes the byte hashing to the optimal implementation.
// Leverages SSE4.2 if detected, otherwise falls back to pure Go.
func crc32HashBytes(b []byte) uint64 {
	if hasCRC32 && len(b) > 0 {
		return crc32HashAsm(unsafe.Pointer(unsafe.SliceData(b)), len(b))
	} else if hasCRC32 {
		return 0
	}
	return crc32HashBytesFallback(b)
}
