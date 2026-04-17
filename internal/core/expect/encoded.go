package expect

import (
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Encoded is a byte slice that can be expressed in HCL/JSON config using
// human-friendly prefixed strings. It solves the problem that HCL does not
// support \xNN hex byte escapes, which are commonly needed for binary protocol
// health checks (e.g. STUN, custom TCP probes).
//
// Supported input formats:
//
//	hex:000100002112a442   — lowercase hex pairs, no separator
//	base64:AAEAAAAhEqRC   — standard base64 (with or without padding)
//	b64:AAEAAAAhEqRC      — shorthand alias for base64:
//	PING\r\n              — plain ASCII / UTF-8, stored as raw bytes
//
// MarshalText always emits hex: so round-trips through the encoder are stable.
// Both b64: and base64: are accepted on input for consistency with expect.Value.
type Encoded []byte

var (
	_ encoding.TextMarshaler   = Encoded(nil)
	_ encoding.TextUnmarshaler = (*Encoded)(nil)
	_ json.Marshaler           = Encoded(nil)
	_ json.Unmarshaler         = (*Encoded)(nil)
	_ fmt.Stringer             = Encoded(nil)
	_ fmt.GoStringer           = Encoded(nil)
)

const (
	encodedPrefixHex    = "hex:"
	encodedPrefixBase64 = "base64:"
	encodedPrefixB64    = "b64:"
)

// UnmarshalText decodes a config string into raw bytes.
// Called automatically by the HCL and JSON decoders.
func (e *Encoded) UnmarshalText(text []byte) error {
	s := string(text)

	switch {
	case strings.HasPrefix(s, encodedPrefixHex):
		b, err := hex.DecodeString(strings.TrimPrefix(s, encodedPrefixHex))
		if err != nil {
			return fmt.Errorf("encoded: invalid hex %q: %w", s, err)
		}
		*e = b

	case strings.HasPrefix(s, encodedPrefixBase64):
		b, err := decodeBase64Bytes(strings.TrimPrefix(s, encodedPrefixBase64))
		if err != nil {
			return fmt.Errorf("encoded: invalid base64 %q: %w", s, err)
		}
		*e = b

	case strings.HasPrefix(s, encodedPrefixB64):
		b, err := decodeBase64Bytes(strings.TrimPrefix(s, encodedPrefixB64))
		if err != nil {
			return fmt.Errorf("encoded: invalid b64 %q: %w", s, err)
		}
		*e = b

	default:
		// Plain string — store the UTF-8 bytes directly.
		// Covers ASCII health check payloads like "PING\r\n".
		*e = []byte(s)
	}

	return nil
}

// MarshalText encodes the bytes as a hex: prefixed string.
// This keeps round-trips through the HCL encoder stable and human-readable.
func (e Encoded) MarshalText() ([]byte, error) {
	if len(e) == 0 {
		return []byte{}, nil
	}
	return []byte(encodedPrefixHex + hex.EncodeToString(e)), nil
}

// MarshalJSON emits a hex: prefixed JSON string, consistent with MarshalText.
func (e Encoded) MarshalJSON() ([]byte, error) {
	text, err := e.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

// UnmarshalJSON accepts the same prefixed formats as UnmarshalText.
func (e *Encoded) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("encoded: expected JSON string: %w", err)
	}
	return e.UnmarshalText([]byte(s))
}

// Bytes returns the raw byte slice.
func (e Encoded) Bytes() []byte { return []byte(e) }

// Empty reports whether the encoded value holds no bytes.
func (e Encoded) Empty() bool { return len(e) == 0 }

func (e Encoded) NotEmpty() bool { return !e.Empty() }

// Hex returns the bytes as a lowercase hex string (without prefix).
func (e Encoded) Hex() string { return hex.EncodeToString(e) }

// String returns a human-readable representation.
// If the bytes are printable ASCII it returns the string as-is,
// otherwise it returns the hex: prefixed form.
func (e Encoded) String() string {
	if len(e) == 0 {
		return ""
	}
	if isPrintableASCII(e) {
		return string(e)
	}
	return encodedPrefixHex + hex.EncodeToString(e)
}

func (e Encoded) Get() string {
	return string(e)
}

// GoString returns the Go syntax representation.
func (e Encoded) GoString() string {
	return fmt.Sprintf("expect.Encoded(%#v)", []byte(e))
}

// EncodedHex constructs an Encoded value from a hex string.
// Panics on invalid input — intended for use in tests and compile-time literals.
func EncodedHex(s string) Encoded {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("expect.EncodedHex: invalid hex %q: %v", s, err))
	}
	return Encoded(b)
}

// EncodedBase64 constructs an Encoded value from a base64 string.
// Panics on invalid input — intended for use in tests and compile-time literals.
func EncodedBase64(s string) Encoded {
	b, err := decodeBase64Bytes(s)
	if err != nil {
		panic(fmt.Sprintf("expect.EncodedBase64: invalid base64 %q: %v", s, err))
	}
	return Encoded(b)
}

// EncodedString constructs an Encoded value from a plain string.
func EncodedString(s string) Encoded { return Encoded(s) }

// EncodedBytes constructs an Encoded value from a raw byte slice.
func EncodedBytes(b []byte) Encoded { return Encoded(b) }
