//go:build arm64 && !noasm

package ahash

import "unsafe"

// crc32HashAsm is implemented in high-performance assembly.
// Executes hardware CRC32X instructions natively available on ARMv8.
func crc32HashAsm(p unsafe.Pointer, length int) uint64

// crc32Hash routes the string hashing to the optimal implementation.
// Leverages ARM64 CRC32X instructions universally.
func crc32Hash(s string) uint64 {
	if len(s) > 0 {
		return crc32HashAsm(unsafe.Pointer(unsafe.StringData(s)), len(s))
	}
	return crc32HashFallback(s)
}

// crc32HashBytes routes the byte hashing to the optimal implementation.
// Leverages ARM64 CRC32X instructions universally.
func crc32HashBytes(b []byte) uint64 {
	if len(b) > 0 {
		return crc32HashAsm(unsafe.Pointer(unsafe.SliceData(b)), len(b))
	}
	return crc32HashBytesFallback(b)
}
