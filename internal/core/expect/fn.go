package expect

import "encoding/base64"

// decodeValueBase64 accepts both padded and unpadded standard base64.
// Named separately from decodeBase64 in encoded.go to avoid collision
// within the same package — both live in package expect.
func decodeBase64Bytes(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// isPrintableASCII reports whether all bytes are printable ASCII (0x20–0x7E)
// or common control characters (\t \n \r).
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 || c > 0x7E {
			return false
		}
	}
	return true
}
