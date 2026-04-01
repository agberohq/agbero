package expect

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestValueString(t *testing.T) {
	tests := []struct {
		name     string
		raw      Value
		expected string
	}{
		{"empty", Value(""), ""},
		{"plaintext", Value("hello"), "hello"},
		{"whitespace", Value("  hello  "), "hello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.raw.String()
			if got != tt.expected {
				t.Errorf("String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestValueEmpty(t *testing.T) {
	tests := []struct {
		name     string
		raw      Value
		expected bool
	}{
		{"empty", Value(""), true},
		{"whitespace", Value("  "), true},
		{"non-empty", Value("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.raw.Empty() != tt.expected {
				t.Errorf("Empty() = %v, want %v", tt.raw.Empty(), tt.expected)
			}
		})
	}
}

func TestValueResolveEnv(t *testing.T) {
	os.Setenv("TEST_VAR", "test_value")
	defer os.Unsetenv("TEST_VAR")

	v := Value("env.TEST_VAR")
	if v.String() != "test_value" {
		t.Errorf("Expected %q, got %q", "test_value", v.String())
	}

	// Non-existent env var returns empty string
	v2 := Value("env.NONEXISTENT")
	if v2.String() != "" {
		t.Errorf("Expected empty string, got %q", v2.String())
	}
}

func TestValueResolveBase64(t *testing.T) {
	// Valid base64
	v := Value("b64.aGVsbG8=") // "hello"
	if v.String() != "hello" {
		t.Errorf("Expected %q, got %q", "hello", v.String())
	}

	// Invalid base64 falls back to raw
	v2 := Value("b64.invalid!!!")
	if v2.String() != "b64.invalid!!!" {
		t.Errorf("Expected fallback to raw, got %q", v2.String())
	}
}

func TestValueResolveShellExpansion(t *testing.T) {
	os.Setenv("EXPAND_VAR", "expanded")
	defer os.Unsetenv("EXPAND_VAR")

	// Test ${VAR} syntax
	v := Value("${EXPAND_VAR}")
	if v.String() != "expanded" {
		t.Errorf("Expected %q, got %q", "expanded", v.String())
	}

	// Test $VAR syntax
	v2 := Value("$EXPAND_VAR")
	if v2.String() != "expanded" {
		t.Errorf("Expected %q, got %q", "expanded", v2.String())
	}

	// Test with text around
	v3 := Value("user:$USER@$HOST")
	os.Setenv("USER", "admin")
	os.Setenv("HOST", "localhost")
	defer os.Unsetenv("USER")
	defer os.Unsetenv("HOST")

	expected := "user:admin@localhost"
	if v3.String() != expected {
		t.Errorf("Expected %q, got %q", expected, v3.String())
	}
}

func TestValueResolveNestedExpansion(t *testing.T) {
	os.Setenv("NESTED", "env.NESTED_VAR")
	defer os.Unsetenv("NESTED")

	// The expansion happens only once; the result is "env.NESTED_VAR",
	// which is not further resolved.
	v := Value("${NESTED}")
	expected := "env.NESTED_VAR"
	if v.String() != expected {
		t.Errorf("Expected %q, got %q", expected, v.String())
	}
}

func TestValueResolveWithCustomLookup(t *testing.T) {
	customLookup := func(key string) string {
		switch key {
		case "CUSTOM_KEY":
			return "custom_value"
		default:
			return ""
		}
	}

	v := Value("env.CUSTOM_KEY")
	if v.Resolve(customLookup) != "custom_value" {
		t.Errorf("Expected %q, got %q", "custom_value", v.Resolve(customLookup))
	}

	// Test with $VAR expansion
	v2 := Value("${CUSTOM_KEY}")
	if v2.Resolve(customLookup) != "custom_value" {
		t.Errorf("Expected %q, got %q", "custom_value", v2.Resolve(customLookup))
	}
}

func TestValueResolveErr(t *testing.T) {
	customLookup := func(key string) string {
		switch key {
		case "SUCCESS_KEY":
			return "success_value"
		default:
			return ""
		}
	}

	// Setup secret store lookup for error testing
	originalStoreLookupFn := storeLookupFn
	defer func() { storeLookupFn = originalStoreLookupFn }()

	SetStoreLookup(func(key string) (string, error) {
		switch key {
		case "SUCCESS_KEY":
			return "success_value", nil
		case "ERROR_KEY":
			return "", fmt.Errorf("lookup error")
		default:
			return "", nil
		}
	})

	tests := []struct {
		name      string
		raw       Value
		expected  string
		expectErr bool
	}{
		{"empty", Value(""), "", false},
		{"plaintext", Value("hello"), "hello", false},
		{"success env", Value("env.SUCCESS_KEY"), "success_value", false},
		{"base64 valid", Value("b64.aGVsbG8="), "hello", false},
		{"base64 invalid", Value("b64.invalid!!!"), "b64.invalid!!!", true}, // decode error
		{"success secret", Value("ss://SUCCESS_KEY"), "success_value", false},
		{"error secret", Value("ss://ERROR_KEY"), "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.raw.ResolveErr(customLookup)
			if tt.expectErr && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectErr && err != nil {
				t.Errorf("Expected no error, got %v", err)
			}
			if got != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestValueIsSecretStoreRef(t *testing.T) {
	tests := []struct {
		raw      Value
		expected bool
	}{
		{Value("ss://key"), true},
		{Value("ss.key"), true},
		{Value("keeper.key"), true},
		{Value("hello"), false},
		{Value("env.VAR"), false},
		{Value("b64.data"), false},
		{Value(""), false},
	}

	for _, tt := range tests {
		if tt.raw.IsSecretStoreRef() != tt.expected {
			t.Errorf("IsSecretStoreRef(%q) = %v, want %v", tt.raw, tt.raw.IsSecretStoreRef(), tt.expected)
		}
	}
}

func TestValueIsEnvRef(t *testing.T) {
	tests := []struct {
		raw      Value
		expected bool
	}{
		{Value("env.VAR"), true},
		{Value("$VAR"), true},
		{Value("${VAR}"), true},
		{Value("hello"), false},
		{Value("ss://key"), false},
	}

	for _, tt := range tests {
		if tt.raw.IsEnvRef() != tt.expected {
			t.Errorf("IsEnvRef(%q) = %v, want %v", tt.raw, tt.raw.IsEnvRef(), tt.expected)
		}
	}
}

func TestValueIsBase64(t *testing.T) {
	tests := []struct {
		raw      Value
		expected bool
	}{
		{Value("b64.data"), true},
		{Value("hello"), false},
		{Value(""), false},
	}

	for _, tt := range tests {
		if tt.raw.IsBase64() != tt.expected {
			t.Errorf("IsBase64(%q) = %v, want %v", tt.raw, tt.raw.IsBase64(), tt.expected)
		}
	}
}

func TestValueMarshalText(t *testing.T) {
	// Secret store ref should keep format
	v := Value("ss://key")
	data, err := v.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ss://key" {
		t.Errorf("Expected %q, got %q", "ss://key", string(data))
	}

	// Plain text should be redacted
	v2 := Value("secret")
	data2, err := v2.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if string(data2) != "[REDACTED]" {
		t.Errorf("Expected %q, got %q", "[REDACTED]", string(data2))
	}
}

func TestValueUnmarshalText(t *testing.T) {
	var v Value
	if err := v.UnmarshalText([]byte("ss://test-key")); err != nil {
		t.Fatal(err)
	}
	if string(v) != "ss://test-key" {
		t.Errorf("Expected %q, got %q", "ss://test-key", string(v))
	}
}

func TestValueMarshalJSON(t *testing.T) {
	v := Value("secret")
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	expected := `"[REDACTED]"`
	if string(data) != expected {
		t.Errorf("Expected %s, got %s", expected, string(data))
	}

	// Secret store ref should not be redacted
	v2 := Value("ss://key")
	data2, err := json.Marshal(v2)
	if err != nil {
		t.Fatal(err)
	}
	expected2 := `"ss://key"`
	if string(data2) != expected2 {
		t.Errorf("Expected %s, got %s", expected2, string(data2))
	}
}

func TestValueUnmarshalJSON(t *testing.T) {
	var v Value
	if err := json.Unmarshal([]byte(`"ss://test-key"`), &v); err != nil {
		t.Fatal(err)
	}
	if string(v) != "ss://test-key" {
		t.Errorf("Expected %q, got %q", "ss://test-key", string(v))
	}

	var v2 Value
	if err := json.Unmarshal([]byte(`"plain-text"`), &v2); err != nil {
		t.Fatal(err)
	}
	if string(v2) != "plain-text" {
		t.Errorf("Expected %q, got %q", "plain-text", string(v2))
	}
}

func TestValueGob(t *testing.T) {
	// Secret store refs are encoded as their raw string
	v := Value("ss://key")
	data, err := v.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ss://key" {
		t.Errorf("Expected ss://key, got %q", string(data))
	}

	var v2 Value
	if err := v2.GobDecode([]byte("ss://key")); err != nil {
		t.Fatal(err)
	}
	if string(v2) != "ss://key" {
		t.Errorf("Expected %q, got %q", "ss://key", string(v2))
	}

	// Plain values are redacted
	v3 := Value("secret")
	data3, err := v3.GobEncode()
	if err != nil {
		t.Fatal(err)
	}
	if string(data3) != "[REDACTED]" {
		t.Errorf("Expected [REDACTED], got %q", string(data3))
	}
}

func TestValueFormatter(t *testing.T) {
	// Use a plain value that resolves to itself (no secret store, no env)
	plain := Value("plain")

	// %s
	if fmt.Sprintf("%s", plain) != "plain" {
		t.Errorf("%%s failed: got %q", fmt.Sprintf("%s", plain))
	}

	// %q
	if fmt.Sprintf("%q", plain) != `"plain"` {
		t.Errorf("%%q failed: got %q", fmt.Sprintf("%q", plain))
	}

	// %v
	if fmt.Sprintf("%v", plain) != "plain" {
		t.Errorf("%%v failed: got %q", fmt.Sprintf("%v", plain))
	}

	// %#v with a secret store ref to check raw representation
	secret := Value("ss://key")
	expected := `expect.Value("ss://key")`
	if fmt.Sprintf("%#v", secret) != expected {
		t.Errorf("%%#v failed: got %q", fmt.Sprintf("%#v", secret))
	}

	// Unknown verb
	output := fmt.Sprintf("%x", plain)
	if !strings.Contains(output, "expect.Value") {
		t.Errorf("Unknown verb handling failed: got %q", output)
	}
}

func TestValueGoString(t *testing.T) {
	v := Value("ss://key")
	expected := `expect.Value("ss://key")`
	if v.GoString() != expected {
		t.Errorf("Expected %q, got %q", expected, v.GoString())
	}
}

func TestHelperConstructors(t *testing.T) {
	// ValueSecret
	v1 := ValueSecret("my-key")
	if string(v1) != "ss://my-key" {
		t.Errorf("Expected ss://my-key, got %q", v1)
	}
	if !v1.IsSecretStoreRef() {
		t.Error("ValueSecret should return secret store ref")
	}

	// ValueEnv
	v2 := ValueEnv("MY_VAR")
	if string(v2) != "env.MY_VAR" {
		t.Errorf("Expected env.MY_VAR, got %q", v2)
	}
	if !v2.IsEnvRef() {
		t.Error("ValueEnv should return env ref")
	}

	// ValueB64
	v3 := ValueB64("aGVsbG8=")
	if string(v3) != "b64.aGVsbG8=" {
		t.Errorf("Expected b64.aGVsbG8=, got %q", v3)
	}
	if !v3.IsBase64() {
		t.Error("ValueB64 should return base64 ref")
	}

	// ValuePlain
	v4 := ValuePlain("plaintext")
	if string(v4) != "plaintext" {
		t.Errorf("Expected plaintext, got %q", v4)
	}
}

func TestValueSecretStoreIntegration(t *testing.T) {
	// Save original and restore after test
	originalStoreLookupFn := storeLookupFn
	defer func() { storeLookupFn = originalStoreLookupFn }()

	// Create a test lookup function that simulates a secret store
	secretStore := map[string]string{
		"db_password": "super_secret_password",
		"api_key":     "abc123xyz",
	}

	SetStoreLookup(func(key string) (string, error) {
		if val, ok := secretStore[key]; ok {
			return val, nil
		}
		return "", fmt.Errorf("key not found: %s", key)
	})

	lookup := func(key string) string {
		return os.Getenv(key)
	}

	// Test ss:// prefix
	v1 := Value("ss://db_password")
	if v1.Resolve(lookup) != "super_secret_password" {
		t.Errorf("Expected super_secret_password, got %q", v1.Resolve(lookup))
	}

	// Test ss. prefix
	v2 := Value("ss.api_key")
	if v2.Resolve(lookup) != "abc123xyz" {
		t.Errorf("Expected abc123xyz, got %q", v2.Resolve(lookup))
	}

	// Test keeper. prefix
	v3 := Value("keeper.db_password")
	if v3.Resolve(lookup) != "super_secret_password" {
		t.Errorf("Expected super_secret_password, got %q", v3.Resolve(lookup))
	}

	// Test with error lookup
	v4 := Value("ss.nonexistent")
	result, err := v4.ResolveErr(lookup)
	if err == nil {
		t.Error("Expected error for nonexistent key")
	}
	if result != "" {
		t.Errorf("Expected empty string, got %q", result)
	}
}

func TestValueChainedResolutions(t *testing.T) {
	os.Setenv("BASE_VAR", "hello")
	os.Setenv("NESTED_VAR", "world")
	defer os.Unsetenv("BASE_VAR")
	defer os.Unsetenv("NESTED_VAR")

	// Test chained expansions
	v := Value("${BASE_VAR}_${NESTED_VAR}")
	expected := "hello_world"
	if v.String() != expected {
		t.Errorf("Expected %q, got %q", expected, v.String())
	}
}

func BenchmarkValueString(b *testing.B) {
	os.Setenv("BENCH_VAR", "benchmark-value")
	defer os.Unsetenv("BENCH_VAR")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := Value("env.BENCH_VAR")
		_ = v.String()
	}
}

func BenchmarkValueResolve(b *testing.B) {
	lookup := func(key string) string {
		if key == "TEST" {
			return "value"
		}
		return ""
	}
	v := Value("env.TEST")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = v.Resolve(lookup)
	}
}

func BenchmarkValueResolveErr(b *testing.B) {
	lookup := func(key string) string {
		if key == "TEST" {
			return "value"
		}
		return ""
	}
	v := Value("env.TEST")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = v.ResolveErr(lookup)
	}
}
