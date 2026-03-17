package ahash

import "hash/crc32"

const crcShift = 32

var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// crc32HashFallback computes the CRC32C hash using pure Go packages.
// Provides a portable baseline for environments lacking hardware acceleration.
func crc32HashFallback(s string) uint64 {
	h := crc32.Checksum([]byte(s), castagnoliTable)
	return uint64(h) | (uint64(h) << crcShift)
}

// crc32HashBytesFallback computes the CRC32C hash using pure Go packages.
// Provides a portable baseline for environments lacking hardware acceleration.
func crc32HashBytesFallback(b []byte) uint64 {
	h := crc32.Checksum(b, castagnoliTable)
	return uint64(h) | (uint64(h) << crcShift)
}
