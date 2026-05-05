package tlss

import (
	"testing"
)

// isValidSNI unit tests

func TestIsValidSNI(t *testing.T) {
	tests := []struct {
		input string
		want  bool
		desc  string
	}{
		// valid hostnames
		{"localhost", true, "bare localhost"},
		{"example.com", true, "simple FQDN"},
		{"admin.localhost", true, "subdomain of localhost"},
		{"foo.bar.local", true, "multi-label .local"},
		{"*.example.com", true, "wildcard cert"},
		{"xn--nxasmq6b.com", true, "punycode label"},
		{"a-b.example.com", true, "hyphenated label"},

		// traversal payloads
		{"../../etc/passwd.local", false, "classic unix traversal with .local suffix"},
		{"../foo.local", false, "single dotdot traversal"},
		{"foo/bar.local", false, "forward slash"},
		{"foo\\bar.local", false, "backslash"},
		{"../../../../../../etc/ld.so.preload.local", false, "deep traversal (the PoC SNI)"},
		{"etc/ld.local", false, "path separator without traversal"},

		// other illegal inputs
		{"", false, "empty string"},
		{"foo..bar", false, "consecutive dots (empty label)"},
		{".foo.com", false, "leading dot"},
		{"foo.com.", false, "trailing dot"},
		{"foo bar.com", false, "space in name"},
		{"foo\x00bar.com", false, "null byte"},
		{"foo@bar.com", false, "@ character"},
		{"[::1]", false, "IPv6 bracket literal"},
		{"192.168.1.1", true, "IPv4 dotted-decimal (digits+dots = valid labels)"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := isValidSNI(tt.input)
			if got != tt.want {
				t.Errorf("isValidSNI(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestIsValidSNI_TraversalVariants ensures a broad set of traversal encodings
// are all rejected, not just the exact PoC value.
func TestIsValidSNI_TraversalVariants(t *testing.T) {
	traversalInputs := []string{
		"../secret.local",
		"..%2Fsecret.local", // URL-encoded slash (literal %, not decoded here)
		"foo/../../etc/cron.d.local",
		"\\\\server\\share.local",
		"foo\\..\\.local",
		"/etc/passwd.local",
		"C:\\Windows\\System32.local",
	}
	for _, s := range traversalInputs {
		if isValidSNI(s) {
			t.Errorf("isValidSNI(%q) returned true — traversal variant must be rejected", s)
		}
	}
}
