package wellknown

import (
	"fmt"
	"testing"
)

func TestNewPathInfo(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		wantNil  bool
		wantType Type
		wantSub  string
		wantSegs []string
	}{
		{
			name:     "valid acme challenge path",
			path:     "/.well-known/acme-challenge/token123",
			wantNil:  false,
			wantType: ACMEChallenge,
			wantSub:  "token123",
			wantSegs: []string{".well-known", "acme-challenge", "token123"},
		},
		{
			name:     "valid acme challenge without leading slash",
			path:     ".well-known/acme-challenge/token123",
			wantNil:  false,
			wantType: ACMEChallenge,
			wantSub:  "token123",
			wantSegs: []string{".well-known", "acme-challenge", "token123"},
		},
		{
			name:     "security.txt path",
			path:     "/.well-known/security.txt",
			wantNil:  false,
			wantType: SecurityTXT,
			wantSub:  "",
			wantSegs: []string{".well-known", "security.txt"},
		},
		{
			name:     "openid configuration",
			path:     "/.well-known/openid-configuration",
			wantNil:  false,
			wantType: OpenIDConfiguration,
			wantSub:  "",
			wantSegs: []string{".well-known", "openid-configuration"},
		},
		{
			name:     "deep nested path",
			path:     "/.well-known/acme-challenge/token123/extra/info",
			wantNil:  false,
			wantType: ACMEChallenge,
			wantSub:  "token123/extra/info",
			wantSegs: []string{".well-known", "acme-challenge", "token123", "extra", "info"},
		},
		{
			name:     "not a well-known path",
			path:     "/something/else",
			wantNil:  true,
			wantType: "",
			wantSub:  "",
			wantSegs: nil,
		},
		{
			name:     "empty path",
			path:     "",
			wantNil:  true,
			wantType: "",
			wantSub:  "",
			wantSegs: nil,
		},
		{
			name:     "just .well-known",
			path:     "/.well-known/",
			wantNil:  false,
			wantType: "",
			wantSub:  "",
			wantSegs: []string{".well-known", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := NewPathInfo(tt.path)
			if tt.wantNil {
				if info != nil {
					t.Errorf("NewPathInfo(%q) = %v, want nil", tt.path, info)
				}
				return
			}
			if info == nil {
				t.Fatalf("NewPathInfo(%q) = nil, want non-nil", tt.path)
			}
			if info.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", info.Type, tt.wantType)
			}
			if info.SubPath != tt.wantSub {
				t.Errorf("SubPath = %q, want %q", info.SubPath, tt.wantSub)
			}
			if len(info.Segments) != len(tt.wantSegs) {
				t.Errorf("Segments length = %d, want %d", len(info.Segments), len(tt.wantSegs))
			} else {
				for i, seg := range info.Segments {
					if seg != tt.wantSegs[i] {
						t.Errorf("Segment[%d] = %q, want %q", i, seg, tt.wantSegs[i])
					}
				}
			}
		})
	}
}

func TestPathInfo_IsACMEChallenge(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/.well-known/acme-challenge/token123", true},
		{"/.well-known/acme-challenge/", true},
		{"/.well-known/security.txt", false},
		{"/.well-known/openid-configuration", false},
		{"/something/else", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			info := NewPathInfo(tt.path)
			if info == nil {
				if tt.want {
					t.Errorf("IsACMEChallenge() for %q = false, want true", tt.path)
				}
				return
			}
			if got := info.IsACMEChallenge(); got != tt.want {
				t.Errorf("IsACMEChallenge() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathInfo_GetACMEToken(t *testing.T) {
	tests := []struct {
		path      string
		wantToken string
		wantOK    bool
	}{
		{"/.well-known/acme-challenge/token123", "token123", true},
		{"/.well-known/acme-challenge/token123/extra", "token123/extra", true},
		{"/.well-known/acme-challenge/", "", false},
		{"/.well-known/security.txt", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			info := NewPathInfo(tt.path)
			if info == nil {
				if tt.wantOK {
					t.Errorf("GetACMEToken() for %q = (_, false), want (_, true)", tt.path)
				}
				return
			}
			token, ok := info.GetACMEToken()
			if ok != tt.wantOK {
				t.Errorf("GetACMEToken() ok = %v, want %v", ok, tt.wantOK)
			}
			if token != tt.wantToken {
				t.Errorf("GetACMEToken() token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

func TestPathInfo_HasPrefix(t *testing.T) {
	info := NewPathInfo("/.well-known/acme-challenge/token123")
	if info == nil {
		t.Fatal("Failed to parse path")
	}

	tests := []struct {
		prefix string
		want   bool
	}{
		{"acme", true},
		{"acme-challenge", true},
		{"security", false},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			if got := info.HasPrefix(tt.prefix); got != tt.want {
				t.Errorf("HasPrefix(%q) = %v, want %v", tt.prefix, got, tt.want)
			}
		})
	}
}

func TestPathInfo_IsType(t *testing.T) {
	info := NewPathInfo("/.well-known/acme-challenge/token123")
	if info == nil {
		t.Fatal("Failed to parse path")
	}

	tests := []struct {
		typ  Type
		want bool
	}{
		{ACMEChallenge, true},
		{SecurityTXT, false},
		{OpenIDConfiguration, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.typ), func(t *testing.T) {
			if got := info.IsType(tt.typ); got != tt.want {
				t.Errorf("IsType(%q) = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}

func TestBuildPath(t *testing.T) {
	tests := []struct {
		name    string
		typ     Type
		subPath []string
		want    string
	}{
		{
			name:    "acme challenge with token",
			typ:     ACMEChallenge,
			subPath: []string{"token123"},
			want:    "/.well-known/acme-challenge/token123",
		},
		{
			name:    "acme challenge without token",
			typ:     ACMEChallenge,
			subPath: []string{},
			want:    "/.well-known/acme-challenge",
		},
		{
			name:    "security.txt",
			typ:     SecurityTXT,
			subPath: []string{},
			want:    "/.well-known/security.txt",
		},
		{
			name:    "nested path",
			typ:     ACMEChallenge,
			subPath: []string{"token123", "extra", "info"},
			want:    "/.well-known/acme-challenge/token123/extra/info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildPath(tt.typ, tt.subPath...); got != tt.want {
				t.Errorf("BuildPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuilder(t *testing.T) {
	tests := []struct {
		name  string
		build func() string
		want  string
	}{
		{
			name: "basic acme challenge",
			build: func() string {
				return NewBuilder().
					WithType(ACMEChallenge).
					WithSegment("token123").
					Build()
			},
			want: "/.well-known/acme-challenge/token123",
		},
		{
			name: "security.txt",
			build: func() string {
				return NewBuilder().
					WithType(SecurityTXT).
					Build()
			},
			want: "/.well-known/security.txt",
		},
		{
			name: "multiple segments",
			build: func() string {
				return NewBuilder().
					WithType(ACMEChallenge).
					WithSegments("token123", "extra", "info").
					Build()
			},
			want: "/.well-known/acme-challenge/token123/extra/info",
		},
		{
			name: "chained with empty segments",
			build: func() string {
				return NewBuilder().
					WithType(ACMEChallenge).
					WithSegment("").
					WithSegment("token123").
					WithSegment("").
					Build()
			},
			want: "/.well-known/acme-challenge/token123",
		},
		{
			name: "stringer interface",
			build: func() string {
				return NewBuilder().
					WithType(ACMEChallenge).
					WithSegment("token123").
					String()
			},
			want: "/.well-known/acme-challenge/token123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.build(); got != tt.want {
				t.Errorf("Builder = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/.well-known/acme-challenge/token123", true},
		{".well-known/acme-challenge/token123", true},
		{"/.well-known/", true},
		{"/something/else", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsPath(tt.path); got != tt.want {
				t.Errorf("IsPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestGetType(t *testing.T) {
	tests := []struct {
		path     string
		wantType Type
		wantOK   bool
	}{
		{"/.well-known/acme-challenge/token123", ACMEChallenge, true},
		{"/.well-known/security.txt", SecurityTXT, true},
		{"/.well-known/openid-configuration", OpenIDConfiguration, true},
		{"/.well-known/", "", true},
		{"/something/else", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			typ, ok := GetType(tt.path)
			if ok != tt.wantOK {
				t.Errorf("GetType() ok = %v, want %v", ok, tt.wantOK)
			}
			if typ != tt.wantType {
				t.Errorf("GetType() type = %q, want %q", typ, tt.wantType)
			}
		})
	}
}

func TestACMEChallengePath(t *testing.T) {
	tests := []struct {
		token string
		want  string
	}{
		{"token123", "/.well-known/acme-challenge/token123"},
		{"", "/.well-known/acme-challenge"},
		{"token/with/slashes", "/.well-known/acme-challenge/token/with/slashes"},
	}

	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			if got := ACMEChallengePath(tt.token); got != tt.want {
				t.Errorf("ACMEChallengePath(%q) = %q, want %q", tt.token, got, tt.want)
			}
		})
	}
}

func TestParseACMEChallengePath(t *testing.T) {
	tests := []struct {
		path      string
		wantToken string
		wantOK    bool
	}{
		{"/.well-known/acme-challenge/token123", "token123", true},
		{"/.well-known/acme-challenge/token123/extra", "token123/extra", true},
		{"/.well-known/acme-challenge/", "", false},
		{"/.well-known/security.txt", "", false},
		{"/something/else", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			token, ok := ParseACMEChallengePath(tt.path)
			if ok != tt.wantOK {
				t.Errorf("ParseACMEChallengePath() ok = %v, want %v", ok, tt.wantOK)
			}
			if token != tt.wantToken {
				t.Errorf("ParseACMEChallengePath() token = %q, want %q", token, tt.wantToken)
			}
		})
	}
}

// Benchmarks

func BenchmarkNewPathInfo(b *testing.B) {
	paths := []string{
		"/.well-known/acme-challenge/token123",
		"/.well-known/security.txt",
		"/.well-known/openid-configuration",
		"/.well-known/acme-challenge/deep/nested/path/here",
		"/something/else",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewPathInfo(paths[i%len(paths)])
	}
}

func BenchmarkNewPathInfo_Parallel(b *testing.B) {
	paths := []string{
		"/.well-known/acme-challenge/token123",
		"/.well-known/security.txt",
		"/.well-known/openid-configuration",
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_ = NewPathInfo(paths[i%len(paths)])
			i++
		}
	})
}

func BenchmarkIsACMEChallenge(b *testing.B) {
	path := "/.well-known/acme-challenge/token123"
	info := NewPathInfo(path)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = info.IsACMEChallenge()
	}
}

func BenchmarkGetACMEToken(b *testing.B) {
	path := "/.well-known/acme-challenge/token123"
	info := NewPathInfo(path)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = info.GetACMEToken()
	}
}

func BenchmarkBuildPath(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = BuildPath(ACMEChallenge, "token123")
	}
}

func BenchmarkBuilder(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = NewBuilder().WithType(ACMEChallenge).WithSegment("token123").Build()
	}
}

func BenchmarkIsPath(b *testing.B) {
	paths := []string{
		"/.well-known/acme-challenge/token123",
		"/something/else",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = IsPath(paths[i%len(paths)])
	}
}

func BenchmarkParseACMEChallengePath(b *testing.B) {
	paths := []string{
		"/.well-known/acme-challenge/token123",
		"/.well-known/acme-challenge/another-token",
		"/.well-known/security.txt",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseACMEChallengePath(paths[i%len(paths)])
	}
}

// Example usage
func ExampleNewPathInfo() {
	info := NewPathInfo("/.well-known/acme-challenge/token123")
	if info == nil {
		fmt.Println("Not a well-known path")
		return
	}

	if info.IsACMEChallenge() {
		if token, ok := info.GetACMEToken(); ok {
			fmt.Printf("ACME token: %s\n", token)
		}
	}
	// Output: ACME token: token123
}
