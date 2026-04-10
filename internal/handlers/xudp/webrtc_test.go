package xudp

import (
	"encoding/hex"
	"testing"
)

func TestSTUNMatcher_ValidBindingRequest(t *testing.T) {
	// Well-formed STUN Binding Request with known transaction ID
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	pkt := STUNBindingRequest(txID)

	m := &stunMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected STUN match, got false")
	}
	want := hex.EncodeToString(txID[:])
	if key != want {
		t.Fatalf("expected key %q, got %q", want, key)
	}
}

func TestSTUNMatcher_TooShort(t *testing.T) {
	m := &stunMatcher{}
	_, ok := m.Match([]byte{0x00, 0x01, 0x00})
	if ok {
		t.Fatal("expected no match for short packet")
	}
}

func TestSTUNMatcher_WrongMagicCookie(t *testing.T) {
	pkt := make([]byte, 20)
	pkt[0] = 0x00
	pkt[1] = 0x01
	// Wrong magic cookie
	pkt[4] = 0xFF
	pkt[5] = 0xFF
	pkt[6] = 0xFF
	pkt[7] = 0xFF

	m := &stunMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match for wrong magic cookie")
	}
}

func TestSTUNMatcher_TopBitsNotZero(t *testing.T) {
	// First byte high bits set — not STUN
	pkt := STUNBindingRequest([12]byte{})
	pkt[0] |= 0x80 // set top bit

	m := &stunMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match when top bits are set")
	}
}

func TestSTUNMatcher_NonSTUNUDPPayload(t *testing.T) {
	// Random non-STUN data
	m := &stunMatcher{}
	_, ok := m.Match([]byte("this is not a stun packet at all, just random bytes 123456"))
	if ok {
		t.Fatal("expected no match for non-STUN payload")
	}
}

func TestSTUNMatcher_DifferentTxIDsDifferentKeys(t *testing.T) {
	m := &stunMatcher{}

	txA := [12]byte{0xAA}
	txB := [12]byte{0xBB}

	keyA, okA := m.Match(STUNBindingRequest(txA))
	keyB, okB := m.Match(STUNBindingRequest(txB))

	if !okA || !okB {
		t.Fatal("both should match")
	}
	if keyA == keyB {
		t.Fatal("different transaction IDs should produce different keys")
	}
}

func TestSTUNMatcher_BindingResponse(t *testing.T) {
	// STUN Binding Success Response (0x0101) — should still match
	pkt := make([]byte, 20)
	pkt[0] = 0x01
	pkt[1] = 0x01
	pkt[4] = stunMagicB0
	pkt[5] = stunMagicB1
	pkt[6] = stunMagicB2
	pkt[7] = stunMagicB3

	m := &stunMatcher{}
	_, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected match for STUN response")
	}
}

func TestIsSTUN(t *testing.T) {
	valid := STUNBindingRequest([12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	if !IsSTUN(valid) {
		t.Fatal("IsSTUN should return true for valid STUN packet")
	}
	if IsSTUN([]byte("not stun")) {
		t.Fatal("IsSTUN should return false for non-STUN data")
	}
}

func TestSTUNMessageType(t *testing.T) {
	cases := []struct {
		data []byte
		want string
	}{
		{[]byte{0x00, 0x01}, "BindingRequest"},
		{[]byte{0x01, 0x01}, "BindingSuccessResponse"},
		{[]byte{0x01, 0x11}, "BindingErrorResponse"},
		{[]byte{0xFF, 0xFF}, "0xffff"},
		{[]byte{}, "unknown"},
	}
	for _, tc := range cases {
		got := STUNMessageType(tc.data)
		if got != tc.want {
			t.Errorf("STUNMessageType(%x) = %q, want %q", tc.data, got, tc.want)
		}
	}
}

func TestSTUNMatcher_Name(t *testing.T) {
	m := &stunMatcher{}
	if m.Name() != "stun" {
		t.Fatalf("expected name %q got %q", "stun", m.Name())
	}
}

func TestSTUNMatcher_RegisteredInRegistry(t *testing.T) {
	m := lookupMatcher("stun")
	if m == nil {
		t.Fatal("stun matcher not found in registry")
	}
	if m.Name() != "stun" {
		t.Fatalf("expected stun, got %q", m.Name())
	}
}
