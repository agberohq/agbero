package xudp

import (
	"testing"
)

func TestSIPMatcher_InviteWithCallID(t *testing.T) {
	pkt := []byte(
		"INVITE sip:bob@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n" +
			"Max-Forwards: 70\r\n" +
			"To: Bob <sip:bob@biloxi.com>\r\n" +
			"From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n" +
			"Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n" +
			"CSeq: 314159 INVITE\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)
	m := &sipMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected SIP match")
	}
	if key != "a84b4c76e66710@pc33.atlanta.com" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestSIPMatcher_CompactCallIDForm(t *testing.T) {
	// "i:" is the compact form of "Call-ID:"
	pkt := []byte(
		"INVITE sip:bob@example.com SIP/2.0\r\n" +
			"i: compact-call-id-12345\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)
	m := &sipMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected SIP match with compact Call-ID")
	}
	if key != "compact-call-id-12345" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestSIPMatcher_Response200(t *testing.T) {
	pkt := []byte(
		"SIP/2.0 200 OK\r\n" +
			"Call-ID: response-call-id@server.example.com\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)
	m := &sipMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected SIP match for response")
	}
	if key != "response-call-id@server.example.com" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestSIPMatcher_NoCallID(t *testing.T) {
	pkt := []byte(
		"INVITE sip:bob@example.com SIP/2.0\r\n" +
			"Via: SIP/2.0/UDP pc33.atlanta.com\r\n" +
			"Content-Length: 0\r\n" +
			"\r\n",
	)
	m := &sipMatcher{}
	_, ok := m.Match(pkt)
	if ok {
		t.Fatal("expected no match when Call-ID is absent")
	}
}

func TestSIPMatcher_NonSIPPayload(t *testing.T) {
	m := &sipMatcher{}
	_, ok := m.Match([]byte("this is not sip at all"))
	if ok {
		t.Fatal("expected no match for non-SIP payload")
	}
}

func TestSIPMatcher_STUNNotSIP(t *testing.T) {
	stun := STUNBindingRequest([12]byte{1, 2, 3})
	m := &sipMatcher{}
	_, ok := m.Match(stun)
	if ok {
		t.Fatal("STUN packet should not match SIP matcher")
	}
}

func TestSIPMatcher_LFOnlyLineEnding(t *testing.T) {
	// Some SIP implementations use \n without \r
	pkt := []byte(
		"INVITE sip:bob@example.com SIP/2.0\n" +
			"Call-ID: lf-only-call-id-9876\n" +
			"Content-Length: 0\n" +
			"\n",
	)
	m := &sipMatcher{}
	key, ok := m.Match(pkt)
	if !ok {
		t.Fatal("expected SIP match with LF-only line endings")
	}
	if key != "lf-only-call-id-9876" {
		t.Fatalf("unexpected key %q", key)
	}
}

func TestSIPMatcher_TooShort(t *testing.T) {
	m := &sipMatcher{}
	_, ok := m.Match([]byte("SIP"))
	if ok {
		t.Fatal("expected no match for too-short packet")
	}
}

func TestSIPMatcher_Name(t *testing.T) {
	m := &sipMatcher{}
	if m.Name() != "sip" {
		t.Fatalf("expected %q, got %q", "sip", m.Name())
	}
}

func TestSIPMatcher_RegisteredInRegistry(t *testing.T) {
	m := lookupMatcher("sip")
	if m == nil {
		t.Fatal("sip matcher not found in registry")
	}
}

func TestIsSIP(t *testing.T) {
	valid := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: test@host\r\n\r\n")
	if !IsSIP(valid) {
		t.Fatal("IsSIP should return true for valid SIP packet")
	}
	if IsSIP([]byte("not sip")) {
		t.Fatal("IsSIP should return false for non-SIP data")
	}
}
