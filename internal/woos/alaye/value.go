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

	// Normalize wrapper styles:
	// {env.X}, ${env.X}, with optional whitespace.
	unwrapped := raw

	// ${ ... }
	if strings.HasPrefix(unwrapped, "${") && strings.HasSuffix(unwrapped, "}") {
		unwrapped = strings.TrimSpace(unwrapped[2 : len(unwrapped)-1])
	}
	// { ... }
	if strings.HasPrefix(unwrapped, "{") && strings.HasSuffix(unwrapped, "}") {
		unwrapped = strings.TrimSpace(unwrapped[1 : len(unwrapped)-1])
	}

	// Normalize $env. prefix
	if strings.HasPrefix(unwrapped, "$env.") {
		unwrapped = "env." + strings.TrimPrefix(unwrapped, "$env.")
	}

	// 1) Environment Variable: env.MY_SECRET
	if strings.HasPrefix(unwrapped, "env.") {
		envVar := strings.TrimPrefix(unwrapped, "env.")
		val := os.Getenv(envVar)

		// Decide policy: error vs empty.
		// If you want strict:
		// if val == "" { return fmt.Errorf("missing env var %q", envVar) }

		*v = Value(val)
		return nil
	}

	// 2) Base64: b64.SGVsbG8=
	// (You can also mirror the same wrappers/prefixes for b64 if you want later.)
	if strings.HasPrefix(unwrapped, "b64.") {
		b64Str := strings.TrimPrefix(unwrapped, "b64.")
		decoded, err := base64.StdEncoding.DecodeString(b64Str)
		if err != nil {
			return fmt.Errorf("failed to decode base64 config value: %w", err)
		}
		*v = Value(decoded)
		return nil
	}

	// 3) Literal
	*v = Value(raw) // keep original raw (not unwrapped) so "{hello}" stays literal unless it matches env forms
	return nil
}
