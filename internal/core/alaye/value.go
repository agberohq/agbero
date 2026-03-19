package alaye

import (
	"encoding/base64"
	"os"
	"strings"
)

// Value is a custom string type that supports dynamic resolution.
// It can resolve data from Environment variables, Base64, or raw strings.
type Value string

// String returns the resolved value by checking the system environment.
// It acts as a convenience wrapper for Resolve using os.Getenv as the provider.
func (v Value) String() string {
	return v.Resolve(os.Getenv)
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
// It stores the raw string value from the configuration without immediate resolution.
func (v *Value) UnmarshalText(text []byte) error {
	*v = Value(string(text))
	return nil
}

// Resolve resolves the underlying value using a provided lookup function.
// It handles "b64." and "env." prefixes, and performs shell-style variable expansion.
func (v Value) Resolve(lookup func(string) string) string {
	raw := strings.TrimSpace(string(v))
	if raw == "" {
		return ""
	}

	if after, ok := strings.CutPrefix(raw, "b64."); ok {
		decoded, err := base64.StdEncoding.DecodeString(after)
		if err != nil {
			return raw
		}
		return string(decoded)
	}

	if after, ok := strings.CutPrefix(raw, "env."); ok {
		return lookup(after)
	}

	return os.Expand(raw, func(key string) string {
		if after, ok := strings.CutPrefix(key, "env."); ok {
			return lookup(after)
		}
		return lookup(key)
	})
}
