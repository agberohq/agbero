package expect

import (
	"net"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantType KeyType
	}{
		{
			name:     "valid IP",
			input:    "192.168.0.1",
			wantErr:  false,
			wantType: TypeIP,
		},
		{
			name:     "valid domain",
			input:    "dance.localhost",
			wantErr:  false,
			wantType: TypeDomain,
		},
		{
			name:     "valid path",
			input:    "/api/v1",
			wantErr:  false,
			wantType: TypePath,
		},
		{
			name:     "valid username",
			input:    "admin",
			wantErr:  false,
			wantType: TypeUsername,
		},
		{
			name:     "valid SSH",
			input:    "user@host",
			wantErr:  false,
			wantType: TypeSSH,
		},
		{
			name:     "valid secret URI",
			input:    "ss://admin/jwt_secret",
			wantErr:  false,
			wantType: TypeSecret,
		},
		{
			name:     "valid JWT",
			input:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr:  false,
			wantType: TypeJWT,
		},
		{
			name:    "empty key",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:     "URL encoded",
			input:    "admin%40example.com",
			wantErr:  false,
			wantType: TypeSSH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}
			hasErr := e.Error() != nil
			if hasErr != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", e.Error(), tt.wantErr)
				return
			}
			if !tt.wantErr && e.Type() != tt.wantType {
				t.Errorf("New() type = %v, want %v", e.Type(), tt.wantType)
			}
		})
	}
}

func TestExpect_IP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    net.IP
		wantErr bool
	}{
		{
			name:    "valid IPv4",
			input:   "192.168.0.1",
			want:    net.ParseIP("192.168.0.1"),
			wantErr: false,
		},
		{
			name:    "valid IPv6",
			input:   "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
			want:    net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
			wantErr: false,
		},
		{
			name:    "invalid IP",
			input:   "999.999.999.999",
			wantErr: true,
		},
		{
			name:    "not an IP",
			input:   "example.com",
			wantErr: true,
		},
		{
			name:    "loopback IP not allowed",
			input:   "127.0.0.1",
			wantErr: true,
		},
		{
			name:    "unspecified IP not allowed",
			input:   "0.0.0.0",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			got, err := e.IP()
			if (err != nil) != tt.wantErr {
				t.Errorf("IP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !got.Equal(tt.want) {
				t.Errorf("IP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpect_Domain(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid domain",
			input:   "example.com",
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "valid subdomain",
			input:   "api.dance.localhost",
			want:    "api.dance.localhost",
			wantErr: false,
		},
		{
			name:    "domain with hyphen",
			input:   "my-site.com",
			want:    "my-site.com",
			wantErr: false,
		},
		{
			name:    "invalid domain - no TLD",
			input:   "example",
			wantErr: true,
		},
		{
			name:    "invalid domain - starts with hyphen",
			input:   "-example.com",
			wantErr: true,
		},
		{
			name:    "domain too long",
			input:   string(make([]byte, 254)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			got, err := e.Domain()
			if (err != nil) != tt.wantErr {
				t.Errorf("Domain() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Domain() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpect_SSH(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantUsername string
		wantHost     string
		wantErr      bool
	}{
		{
			name:         "valid SSH user@host",
			input:        "admin@example.com",
			wantUsername: "admin",
			wantHost:     "example.com",
			wantErr:      false,
		},
		{
			name:         "valid SSH with IP",
			input:        "user@192.168.0.1",
			wantUsername: "user",
			wantHost:     "192.168.0.1",
			wantErr:      false,
		},
		{
			name:         "SSH with path",
			input:        "admin@example.com/api/v1",
			wantUsername: "admin",
			wantHost:     "example.com",
			wantErr:      false,
		},
		{
			name:    "invalid SSH - missing @",
			input:   "admin",
			wantErr: true,
		},
		{
			name:    "invalid SSH - empty username",
			input:   "@example.com",
			wantErr: true,
		},
		{
			name:    "invalid SSH - empty host",
			input:   "admin@",
			wantErr: true,
		},
		{
			name:    "invalid username format",
			input:   "admin!@example.com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			username, host, err := e.SSH()
			if (err != nil) != tt.wantErr {
				t.Errorf("SSH() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if username != tt.wantUsername {
					t.Errorf("SSH() username = %v, want %v", username, tt.wantUsername)
				}
				if host != tt.wantHost {
					t.Errorf("SSH() host = %v, want %v", host, tt.wantHost)
				}
			}
		})
	}
}

func TestExpect_Path(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid path",
			input:   "/api/v1",
			want:    "/api/v1",
			wantErr: false,
		},
		{
			name:    "valid nested path",
			input:   "/api/v1/users/123",
			want:    "/api/v1/users/123",
			wantErr: false,
		},
		{
			name:    "invalid path - no leading slash",
			input:   "api/v1",
			wantErr: true,
		},
		{
			name:    "invalid path - path traversal",
			input:   "/api/../secret",
			wantErr: true,
		},
		{
			name:    "path too long",
			input:   "/" + string(make([]byte, 2048)),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			got, err := e.Path()
			if (err != nil) != tt.wantErr {
				t.Errorf("Path() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Path() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpect_Username(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "valid username",
			input:   "john_doe",
			want:    "john_doe",
			wantErr: false,
		},
		{
			name:    "username with hyphen",
			input:   "john-doe",
			want:    "john-doe",
			wantErr: false,
		},
		{
			name:    "username with dot",
			input:   "john.doe",
			want:    "john.doe",
			wantErr: false,
		},
		{
			name:    "username too short",
			input:   "ab",
			wantErr: true,
		},
		{
			name:    "username too long",
			input:   string(make([]byte, 65)),
			wantErr: true,
		},
		{
			name:    "invalid characters",
			input:   "john@doe",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			got, err := e.Username()
			if (err != nil) != tt.wantErr {
				t.Errorf("Username() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Username() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExpect_JWT(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "valid JWT",
			input:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr: false,
		},
		{
			name:    "JWT secret too short",
			input:   "short",
			wantErr: true,
		},
		{
			name:    "invalid JWT format",
			input:   "invalid.jwt.token",
			wantErr: true,
		},
		{
			name:    "not a JWT",
			input:   "just-a-regular-string-that-is-long-enough-but-not-jwt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			_, err := e.JWT()
			if (err != nil) != tt.wantErr {
				t.Errorf("JWT() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestExpect_Secret(t *testing.T) {
	tests := []struct {
		name          string
		input         string
		wantScheme    SecretScheme
		wantNamespace string
		wantKey       string
		wantSubKeys   []string
		wantErr       bool
	}{
		{
			name:          "valid ss:// secret",
			input:         "ss://admin/jwt_secret",
			wantScheme:    SchemeSS,
			wantNamespace: "admin",
			wantKey:       "jwt_secret",
			wantSubKeys:   []string{},
			wantErr:       false,
		},
		{
			name:          "valid secret:// with subkeys",
			input:         "secret://production/database/password/primary",
			wantScheme:    SchemeSecret,
			wantNamespace: "production",
			wantKey:       "database",
			wantSubKeys:   []string{"password", "primary"},
			wantErr:       false,
		},
		{
			name:          "valid vault:// secret",
			input:         "vault://stripe/api_key",
			wantScheme:    SchemeVault,
			wantNamespace: "stripe",
			wantKey:       "api_key",
			wantSubKeys:   []string{},
			wantErr:       false,
		},
		{
			name:          "valid env:// secret",
			input:         "env://production/DATABASE_URL",
			wantScheme:    SchemeEnv,
			wantNamespace: "production",
			wantKey:       "DATABASE_URL",
			wantSubKeys:   []string{},
			wantErr:       false,
		},
		{
			name:          "valid file:// secret",
			input:         "file://secrets/tls/cert",
			wantScheme:    SchemeFile,
			wantNamespace: "secrets",
			wantKey:       "tls",
			wantSubKeys:   []string{"cert"},
			wantErr:       false,
		},
		{
			name:    "invalid scheme",
			input:   "invalid://admin/key",
			wantErr: true,
		},
		{
			name:    "missing namespace",
			input:   "ss:///key",
			wantErr: true,
		},
		{
			name:    "missing key",
			input:   "ss://admin/",
			wantErr: true,
		},
		{
			name:    "namespace too short",
			input:   "ss://ab/key",
			wantErr: true,
		},
		{
			name:    "invalid key characters",
			input:   "ss://admin/key!@#",
			wantErr: true,
		},
		{
			name:    "invalid subkey",
			input:   "ss://admin/key/sub!@#",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			secret, err := e.Secret()
			if (err != nil) != tt.wantErr {
				t.Errorf("Secret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if secret.Scheme != tt.wantScheme {
					t.Errorf("Secret() scheme = %v, want %v", secret.Scheme, tt.wantScheme)
				}
				if secret.Namespace != tt.wantNamespace {
					t.Errorf("Secret() namespace = %v, want %v", secret.Namespace, tt.wantNamespace)
				}
				if secret.Key != tt.wantKey {
					t.Errorf("Secret() key = %v, want %v", secret.Key, tt.wantKey)
				}
				if len(secret.SubKeys) != len(tt.wantSubKeys) {
					t.Errorf("Secret() subkeys length = %v, want %v", len(secret.SubKeys), len(tt.wantSubKeys))
				}
			}
		})
	}
}

func TestExpect_SecretHelpers(t *testing.T) {
	e := NewRaw("ss://admin/jwt_secret/v1/primary")
	if e == nil {
		t.Fatalf("New() returned nil")
	}

	// Test Namespace
	namespace, err := e.Namespace()
	if err != nil {
		t.Errorf("Namespace() error = %v", err)
	}
	if namespace != "admin" {
		t.Errorf("Namespace() = %v, want admin", namespace)
	}

	// Test SecretKey
	secretKey, err := e.SecretKey()
	if err != nil {
		t.Errorf("SecretKey() error = %v", err)
	}
	if secretKey != "jwt_secret" {
		t.Errorf("SecretKey() = %v, want jwt_secret", secretKey)
	}

	// Test SubKeys
	subKeys, err := e.SubKeys()
	if err != nil {
		t.Errorf("SubKeys() error = %v", err)
	}
	if len(subKeys) != 2 || subKeys[0] != "v1" || subKeys[1] != "primary" {
		t.Errorf("SubKeys() = %v, want [v1 primary]", subKeys)
	}

	// Test SecretScheme
	scheme, err := e.SecretScheme()
	if err != nil {
		t.Errorf("SecretScheme() error = %v", err)
	}
	if scheme != SchemeSS {
		t.Errorf("SecretScheme() = %v, want ss", scheme)
	}
}

func TestExpect_Raw(t *testing.T) {
	input := "test-key"
	e := NewRaw(input)
	if e == nil {
		t.Fatalf("New() returned nil")
	}

	if e.Raw() != input {
		t.Errorf("Raw() = %v, want %v", e.Raw(), input)
	}
}

func TestExpect_Type(t *testing.T) {
	tests := []struct {
		input string
		want  KeyType
	}{
		{"192.168.0.1", TypeIP},
		{"example.com", TypeDomain},
		{"/api/v1", TypePath},
		{"username", TypeUsername},
		{"user@host", TypeSSH},
		{"ss://admin/key", TypeSecret},
		{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", TypeJWT},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			if e.Type() != tt.want {
				t.Errorf("Type() = %v, want %v", e.Type(), tt.want)
			}
		})
	}
}

func TestExpect_URLEncoded(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "URL encoded space",
			input:    "admin%40example.com",
			expected: "admin@example.com",
		},
		{
			name:     "URL encoded slash",
			input:    "api%2Fv1",
			expected: "api/v1",
		},
		{
			name:     "URL encoded colon",
			input:    "ss%3A%2F%2Fadmin%2Fkey",
			expected: "ss://admin/key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			if e == nil {
				t.Fatalf("New() returned nil")
			}

			if e.Raw() != tt.expected {
				t.Errorf("Raw() = %v, want %v", e.Raw(), tt.expected)
			}
		})
	}
}

func TestExpect_Error(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty", "", true},
		{"whitespace", "   ", true},
		{"invalid format", "!@#$%^", true},
		{"valid", "admin", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewRaw(tt.input)
			hasErr := e.Error() != nil
			if hasErr != tt.wantErr {
				t.Errorf("Error() = %v, wantErr %v", e.Error(), tt.wantErr)
			}
		})
	}
}

func BenchmarkExpect_New(b *testing.B) {
	for i := 0; i < b.N; i++ {
		NewRaw("ss://admin/jwt_secret/v1/primary")
	}
}

func BenchmarkExpect_IP(b *testing.B) {
	e := NewRaw("192.168.0.1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.IP()
	}
}

func BenchmarkExpect_Domain(b *testing.B) {
	e := NewRaw("example.com")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Domain()
	}
}

func BenchmarkExpect_Secret(b *testing.B) {
	e := NewRaw("ss://admin/jwt_secret/v1/primary")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.Secret()
	}
}
