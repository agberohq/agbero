package ahash

// CRC32Hash computes a 64-bit CRC32C hash of a string natively.
// Utilizes hardware acceleration on amd64/arm64 when available.
func CRC32Hash(s string) uint64 {
	return crc32Hash(s)
}

// CRC32HashBytes computes a 64-bit CRC32C hash of a byte slice natively.
// Utilizes hardware acceleration on amd64/arm64 when available.
func CRC32HashBytes(b []byte) uint64 {
	return crc32HashBytes(b)
}
