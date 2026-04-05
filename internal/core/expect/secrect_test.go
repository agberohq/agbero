package expect

import (
	"testing"
)

func TestParseSecret(t *testing.T) {
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
			name:          "valid without scheme",
			input:         "admin/jwt_secret",
			wantScheme:    SchemeSS,
			wantNamespace: "admin",
			wantKey:       "jwt_secret",
			wantSubKeys:   []string{},
			wantErr:       false,
		},
		{
			name:          "valid without scheme with subkeys",
			input:         "production/database/password/primary",
			wantScheme:    SchemeSS,
			wantNamespace: "production",
			wantKey:       "database",
			wantSubKeys:   []string{"password", "primary"},
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
			name:    "empty input",
			input:   "",
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
			secret, err := ParseSecret(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if secret.Scheme != tt.wantScheme {
					t.Errorf("Scheme = %v, want %v", secret.Scheme, tt.wantScheme)
				}
				if secret.Namespace != tt.wantNamespace {
					t.Errorf("Namespace = %v, want %v", secret.Namespace, tt.wantNamespace)
				}
				if secret.Key != tt.wantKey {
					t.Errorf("Key = %v, want %v", secret.Key, tt.wantKey)
				}
				if len(secret.SubKeys) != len(tt.wantSubKeys) {
					t.Errorf("SubKeys length = %v, want %v", len(secret.SubKeys), len(tt.wantSubKeys))
				}
			}
		})
	}
}

func TestSecret_WithScheme(t *testing.T) {
	secret := &Secret{
		Scheme:    SchemeSS,
		Namespace: "admin",
		Key:       "jwt_secret",
		SubKeys:   []string{"v1", "primary"},
		Raw:       "ss://admin/jwt_secret/v1/primary",
	}

	expected := "ss://admin/jwt_secret/v1/primary"
	if secret.WithScheme() != expected {
		t.Errorf("WithScheme() = %v, want %v", secret.WithScheme(), expected)
	}
}

func TestSecret_WithoutScheme(t *testing.T) {
	secret := &Secret{
		Scheme:    SchemeSS,
		Namespace: "admin",
		Key:       "jwt_secret",
		SubKeys:   []string{"v1", "primary"},
		Raw:       "ss://admin/jwt_secret/v1/primary",
	}

	expected := "admin/jwt_secret/v1/primary"
	if secret.WithoutScheme() != expected {
		t.Errorf("WithoutScheme() = %v, want %v", secret.WithoutScheme(), expected)
	}
}

func TestSecret_Path(t *testing.T) {
	secret := &Secret{
		Namespace: "admin",
		Key:       "jwt_secret",
		SubKeys:   []string{"v1", "primary"},
	}

	expected := "admin/jwt_secret/v1/primary"
	if secret.Path() != expected {
		t.Errorf("Path() = %v, want %v", secret.Path(), expected)
	}
}

func TestSecret_FullKey(t *testing.T) {
	tests := []struct {
		name     string
		secret   *Secret
		expected string
	}{
		{
			name: "with subkeys",
			secret: &Secret{
				Key:     "jwt_secret",
				SubKeys: []string{"v1", "primary"},
			},
			expected: "jwt_secret/v1/primary",
		},
		{
			name: "without subkeys",
			secret: &Secret{
				Key:     "api_key",
				SubKeys: []string{},
			},
			expected: "api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.secret.FullKey() != tt.expected {
				t.Errorf("FullKey() = %v, want %v", tt.secret.FullKey(), tt.expected)
			}
		})
	}
}

func TestSecret_Value(t *testing.T) {
	tests := []struct {
		name     string
		secret   *Secret
		expected string
	}{
		{
			name: "with subkeys",
			secret: &Secret{
				Key:     "jwt_secret",
				SubKeys: []string{"v1", "primary"},
			},
			expected: "primary",
		},
		{
			name: "without subkeys",
			secret: &Secret{
				Key:     "api_key",
				SubKeys: []string{},
			},
			expected: "api_key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.secret.Value() != tt.expected {
				t.Errorf("Value() = %v, want %v", tt.secret.Value(), tt.expected)
			}
		})
	}
}

func TestSecret_HasScheme(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"with scheme", "ss://admin/key", true},
		{"without scheme", "admin/key", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := ParseSecret(tt.input)
			if err != nil {
				t.Fatalf("ParseSecret failed: %v", err)
			}
			if secret.HasScheme() != tt.expected {
				t.Errorf("HasScheme() = %v, want %v", secret.HasScheme(), tt.expected)
			}
		})
	}
}

func TestSecret_IsInternal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"internal namespace", "ss://internal/key", true},
		{"internal/ prefix", "ss://internal/secret/key", true},
		{"not internal", "ss://admin/key", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := ParseSecret(tt.input)
			if err != nil {
				t.Fatalf("ParseSecret failed: %v", err)
			}
			if secret.IsInternal() != tt.expected {
				t.Errorf("IsInternal() = %v, want %v", secret.IsInternal(), tt.expected)
			}
		})
	}
}

func TestSecret_String(t *testing.T) {
	input := "ss://admin/key"
	secret, err := ParseSecret(input)
	if err != nil {
		t.Fatalf("ParseSecret failed: %v", err)
	}
	if secret.String() != input {
		t.Errorf("String() = %v, want %v", secret.String(), input)
	}
}

func TestSecret_ToSecretPath(t *testing.T) {
	original := &Secret{
		Scheme:    SchemeSS,
		Namespace: "admin",
		Key:       "jwt_secret",
		SubKeys:   []string{"v1", "primary"},
		Raw:       "ss://admin/jwt_secret/v1/primary",
		hasScheme: true,
	}

	copied := original.ToSecretPath()

	if copied.Scheme != original.Scheme {
		t.Errorf("Scheme = %v, want %v", copied.Scheme, original.Scheme)
	}
	if copied.Namespace != original.Namespace {
		t.Errorf("Namespace = %v, want %v", copied.Namespace, original.Namespace)
	}
	if copied.Key != original.Key {
		t.Errorf("Key = %v, want %v", copied.Key, original.Key)
	}
	if len(copied.SubKeys) != len(original.SubKeys) {
		t.Errorf("SubKeys length = %v, want %v", len(copied.SubKeys), len(original.SubKeys))
	}
	if copied.Raw != original.Raw {
		t.Errorf("Raw = %v, want %v", copied.Raw, original.Raw)
	}
}

func BenchmarkParseSecret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseSecret("ss://admin/jwt_secret/v1/primary")
	}
}
