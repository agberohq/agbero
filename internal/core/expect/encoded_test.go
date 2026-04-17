package expect_test

import (
	"encoding/json"
	"testing"

	"github.com/agberohq/agbero/internal/core/expect"
)

// Encoded — UnmarshalText

func TestEncoded_UnmarshalText_hex(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("hex:000100002112a442")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42}
	if string(e) != string(want) {
		t.Errorf("got %v, want %v", []byte(e), want)
	}
}

func TestEncoded_UnmarshalText_hex_stun(t *testing.T) {
	// Full STUN binding request header — the motivating use case.
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("hex:000100002112a44200000000000000000000000000000000")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(e) != 24 {
		t.Errorf("got %d bytes, want 24", len(e))
	}
	if e[4] != 0x21 || e[5] != 0x12 || e[6] != 0xa4 || e[7] != 0x42 {
		t.Errorf("STUN magic cookie mismatch: %x", []byte(e)[4:8])
	}
}

func TestEncoded_UnmarshalText_base64_padded(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("base64:AAE=")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x01}
	if string(e) != string(want) {
		t.Errorf("got %v, want %v", []byte(e), want)
	}
}

func TestEncoded_UnmarshalText_base64_unpadded(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("base64:AAE")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x01}
	if string(e) != string(want) {
		t.Errorf("got %v, want %v", []byte(e), want)
	}
}

func TestEncoded_UnmarshalText_b64_prefix(t *testing.T) {
	// b64: is the shorthand alias — must decode identically to base64:
	var e1, e2 expect.Encoded
	if err := e1.UnmarshalText([]byte("base64:AAE=")); err != nil {
		t.Fatalf("base64: error: %v", err)
	}
	if err := e2.UnmarshalText([]byte("b64:AAE=")); err != nil {
		t.Fatalf("b64: error: %v", err)
	}
	if e1.Hex() != e2.Hex() {
		t.Errorf("b64: and base64: decoded differently: %q vs %q", e1.Hex(), e2.Hex())
	}
}

func TestEncoded_UnmarshalText_b64_unpadded(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("b64:AAE")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0x00, 0x01}
	if string(e) != string(want) {
		t.Errorf("got %v, want %v", []byte(e), want)
	}
}

func TestEncoded_UnmarshalText_plain_ascii(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("PING")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(e) != "PING" {
		t.Errorf("got %q, want PING", string(e))
	}
}

func TestEncoded_UnmarshalText_plain_crlf(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("PING\r\n")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(e) != "PING\r\n" {
		t.Errorf("got %q, want PING\\r\\n", string(e))
	}
}

func TestEncoded_UnmarshalText_empty(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !e.Empty() {
		t.Error("expected empty")
	}
}

func TestEncoded_UnmarshalText_high_bytes(t *testing.T) {
	// Bytes above 0x7F must survive as exact byte values, not unicode codepoints.
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("hex:ff00fe01")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{0xff, 0x00, 0xfe, 0x01}
	for i, b := range want {
		if []byte(e)[i] != b {
			t.Errorf("byte[%d]: got 0x%02x, want 0x%02x", i, []byte(e)[i], b)
		}
	}
}

func TestEncoded_UnmarshalText_hex_invalid(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("hex:ZZZZ")); err == nil {
		t.Fatal("expected error for invalid hex, got nil")
	}
}

func TestEncoded_UnmarshalText_base64_invalid(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("base64:!!!")); err == nil {
		t.Fatal("expected error for invalid base64:, got nil")
	}
}

func TestEncoded_UnmarshalText_b64_invalid(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("b64:!!!")); err == nil {
		t.Fatal("expected error for invalid b64:, got nil")
	}
}

// Encoded — MarshalText

func TestEncoded_MarshalText_roundtrip(t *testing.T) {
	original := []byte{0x00, 0x01, 0x21, 0x12, 0xa4, 0x42}
	e := expect.Encoded(original)

	text, err := e.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}

	var e2 expect.Encoded
	if err := e2.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if string(e) != string(e2) {
		t.Errorf("round-trip mismatch: got %v, want %v", []byte(e2), []byte(e))
	}
}

func TestEncoded_MarshalText_emits_hex_prefix(t *testing.T) {
	e := expect.Encoded([]byte{0xde, 0xad, 0xbe, 0xef})
	text, err := e.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(text) != "hex:deadbeef" {
		t.Errorf("got %q, want hex:deadbeef", string(text))
	}
}

func TestEncoded_MarshalText_b64_input_roundtrips_as_hex(t *testing.T) {
	// Whatever the input format, MarshalText always emits hex:
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("b64:AAE=")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	text, err := e.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(text) != "hex:0001" {
		t.Errorf("got %q, want hex:0001", string(text))
	}
}

func TestEncoded_MarshalText_base64_input_roundtrips_as_hex(t *testing.T) {
	var e expect.Encoded
	if err := e.UnmarshalText([]byte("base64:AAE=")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	text, err := e.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if string(text) != "hex:0001" {
		t.Errorf("got %q, want hex:0001", string(text))
	}
}

func TestEncoded_MarshalText_empty(t *testing.T) {
	e := expect.Encoded(nil)
	text, err := e.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	if len(text) != 0 {
		t.Errorf("expected empty, got %q", string(text))
	}
}

// Encoded — JSON

func TestEncoded_JSON_roundtrip(t *testing.T) {
	original := expect.EncodedHex("0001000021")
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded expect.Encoded
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if original.Hex() != decoded.Hex() {
		t.Errorf("got %q, want %q", decoded.Hex(), original.Hex())
	}
}

func TestEncoded_JSON_accepts_base64(t *testing.T) {
	var e expect.Encoded
	if err := json.Unmarshal([]byte(`"base64:AAE="`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Hex() != "0001" {
		t.Errorf("got %q, want 0001", e.Hex())
	}
}

func TestEncoded_JSON_accepts_b64(t *testing.T) {
	var e expect.Encoded
	if err := json.Unmarshal([]byte(`"b64:AAE="`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if e.Hex() != "0001" {
		t.Errorf("got %q, want 0001", e.Hex())
	}
}

func TestEncoded_JSON_accepts_plain(t *testing.T) {
	var e expect.Encoded
	if err := json.Unmarshal([]byte(`"PING"`), &e); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if string(e) != "PING" {
		t.Errorf("got %q, want PING", string(e))
	}
}

func TestEncoded_JSON_rejects_non_string(t *testing.T) {
	var e expect.Encoded
	if err := json.Unmarshal([]byte(`123`), &e); err == nil {
		t.Fatal("expected error for non-string JSON, got nil")
	}
}

// Encoded — Constructors

func TestEncodedHex_valid(t *testing.T) {
	e := expect.EncodedHex("deadbeef")
	if e.Hex() != "deadbeef" {
		t.Errorf("got %q, want deadbeef", e.Hex())
	}
}

func TestEncodedHex_panics_on_invalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic, got none")
		}
	}()
	_ = expect.EncodedHex("ZZZZ")
}

func TestEncodedBase64_valid(t *testing.T) {
	e := expect.EncodedBase64("AAE=")
	if e.Hex() != "0001" {
		t.Errorf("got %q, want 0001", e.Hex())
	}
}

func TestEncodedBase64_unpadded(t *testing.T) {
	e := expect.EncodedBase64("AAE")
	if e.Hex() != "0001" {
		t.Errorf("got %q, want 0001", e.Hex())
	}
}

func TestEncodedBase64_panics_on_invalid(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic, got none")
		}
	}()
	_ = expect.EncodedBase64("!!!")
}

func TestEncodedString(t *testing.T) {
	e := expect.EncodedString("PING\r\n")
	if string(e) != "PING\r\n" {
		t.Errorf("got %q, want PING\\r\\n", string(e))
	}
}

func TestEncodedBytes(t *testing.T) {
	b := []byte{0x01, 0x02, 0x03}
	e := expect.EncodedBytes(b)
	if string(e.Bytes()) != string(b) {
		t.Errorf("got %v, want %v", e.Bytes(), b)
	}
}

// Encoded — String / GoString

func TestEncoded_String_printable(t *testing.T) {
	e := expect.EncodedString("PING")
	if e.String() != "PING" {
		t.Errorf("got %q, want PING", e.String())
	}
}

func TestEncoded_String_binary(t *testing.T) {
	e := expect.EncodedHex("0001")
	if e.String() != "hex:0001" {
		t.Errorf("got %q, want hex:0001", e.String())
	}
}

func TestEncoded_String_empty(t *testing.T) {
	var e expect.Encoded
	if e.String() != "" {
		t.Errorf("got %q, want empty", e.String())
	}
}

func TestEncoded_GoString(t *testing.T) {
	e := expect.EncodedHex("0102")
	if e.GoString() == "" {
		t.Error("GoString returned empty string")
	}
}

// Encoded — helpers

func TestEncoded_Empty_nil(t *testing.T) {
	var e expect.Encoded
	if !e.Empty() {
		t.Error("nil Encoded should be empty")
	}
}

func TestEncoded_Empty_nonzero(t *testing.T) {
	e := expect.EncodedHex("00")
	if e.Empty() {
		t.Error("non-nil Encoded should not be empty")
	}
}

func TestEncoded_Hex(t *testing.T) {
	e := expect.Encoded([]byte{0xca, 0xfe})
	if e.Hex() != "cafe" {
		t.Errorf("got %q, want cafe", e.Hex())
	}
}

// Value — base64: alias

func TestValue_base64_prefix_resolves(t *testing.T) {
	// base64: should decode identically to b64.
	v1 := expect.ValueB64("AAE=")     // b64.AAE=
	v2 := expect.Value("base64:AAE=") // new alias

	s1 := v1.String()
	s2 := v2.String()

	if s1 != s2 {
		t.Errorf("b64. and base64: resolved differently: %q vs %q", s1, s2)
	}
}

func TestValue_base64_unpadded(t *testing.T) {
	v := expect.Value("base64:AAE")
	if v.String() != "\x00\x01" {
		t.Errorf("got %q, want \\x00\\x01", v.String())
	}
}

func TestValue_b64_dot_still_works(t *testing.T) {
	// Existing b64. prefix must not break.
	v := expect.Value("b64.AAE=")
	if v.String() != "\x00\x01" {
		t.Errorf("b64. broken: got %q", v.String())
	}
}

func TestValue_IsBase64_b64_dot(t *testing.T) {
	v := expect.Value("b64.AAE=")
	if !v.IsBase64() {
		t.Error("expected IsBase64() true for b64. prefix")
	}
}

func TestValue_IsBase64_base64_colon(t *testing.T) {
	v := expect.Value("base64:AAE=")
	if !v.IsBase64() {
		t.Error("expected IsBase64() true for base64: prefix")
	}
}

func TestValue_IsBase64_false_for_plain(t *testing.T) {
	v := expect.Value("plaintext")
	if v.IsBase64() {
		t.Error("expected IsBase64() false for plain value")
	}
}

// Interface compliance

func TestEncoded_implements_interfaces(t *testing.T) {
	var e expect.Encoded
	var _ interface{ MarshalText() ([]byte, error) } = e
	var _ interface{ UnmarshalText([]byte) error } = &e
	var _ interface{ MarshalJSON() ([]byte, error) } = e
	var _ interface{ UnmarshalJSON([]byte) error } = &e
	var _ interface{ String() string } = e
	var _ interface{ GoString() string } = e
}
