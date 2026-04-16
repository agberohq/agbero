package xudp

import "testing"

func TestLookupMatcher_Empty(t *testing.T) {
	if lookupMatcher("") != nil {
		t.Fatal("empty name should return nil")
	}
}

func TestLookupMatcher_Unknown(t *testing.T) {
	if lookupMatcher("nonexistent-protocol-xyz") != nil {
		t.Fatal("unknown matcher should return nil")
	}
}

func TestLookupMatcher_CaseInsensitive(t *testing.T) {
	cases := []string{"stun", "STUN", "Stun", "sTuN"}
	for _, name := range cases {
		m := lookupMatcher(name)
		if m == nil {
			t.Fatalf("lookupMatcher(%q) should not be nil", name)
		}
		if m.Name() != "stun" {
			t.Fatalf("lookupMatcher(%q).Name() = %q, want %q", name, m.Name(), "stun")
		}
	}
}

func TestLookupMatcher_AllRegistered(t *testing.T) {
	expected := []string{"stun", "dns", "sip"}
	for _, name := range expected {
		if lookupMatcher(name) == nil {
			t.Errorf("matcher %q should be registered", name)
		}
	}
}

func TestMatcherName_Nil(t *testing.T) {
	if matcherName(nil) != "src_port" {
		t.Fatal("nil matcher should return src_port")
	}
}

func TestMatcherName_NonNil(t *testing.T) {
	m := lookupMatcher("stun")
	if matcherName(m) != "stun" {
		t.Fatalf("expected stun, got %q", matcherName(m))
	}
}
