package alaye

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Value is a custom string type that supports dynamic resolution
// from Environment variables ("env."), Base64 ("b64."), or raw strings.
type Value string

// String returns the resolved underlying string.
func (v Value) String() string {
	return string(v)
}

// UnmarshalText implements encoding.TextUnmarshaler.
// This is automatically called by hcl, json, and xml decoders.
func (v *Value) UnmarshalText(text []byte) error {
	raw := strings.TrimSpace(string(text))
	if raw == "" {
		*v = ""
		return nil
	}

	// 1. Base64 Handling
	if strings.HasPrefix(raw, "b64.") {
		b64Str := strings.TrimPrefix(raw, "b64.")
		decoded, err := base64.StdEncoding.DecodeString(b64Str)
		if err != nil {
			return fmt.Errorf("failed to decode base64 config value: %w", err)
		}
		*v = Value(decoded)
		return nil
	}

	// 2. Explicit Env Var (Legacy/Simple style: "env.MY_VAR")
	// This handles the failing test case where no ${} wrappers are used.
	if strings.HasPrefix(raw, "env.") {
		key := strings.TrimPrefix(raw, "env.")
		*v = Value(os.Getenv(key))
		return nil
	}

	// 3. Shell Expansion style: "${env.MY_VAR}" or "foo-${env.BAR}"
	// We use os.Expand but add logic to strip the "env." prefix inside the key.
	resolved := os.Expand(raw, func(key string) string {
		key = strings.TrimPrefix(key, "env.")
		return os.Getenv(key)
	})

	*v = Value(resolved)
	return nil
}
