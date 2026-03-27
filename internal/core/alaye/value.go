package alaye

import (
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Value is a lazy-resolving string used throughout alaye config structs.
//
// Supported prefixes (resolved in order):
//
//	ss://key   — secret store lookup (keeper)
//	ss.key     — alias for ss://key
//	keeper.key — alias for ss://key
//	b64.data   — base64-decode the remainder (StdEncoding)
//	env.VAR    — os.Getenv(VAR)
//	$VAR       — shell-style expansion via os.Expand
//	(plain)    — returned as-is
//
// Store resolution is wired in at runtime by calling SetStoreLookup once
// the keeper is unlocked.  This keeps alaye free of any direct import of
// pkg/security.
type Value string

// storeLookupFn is set once by server.go after Store.Unlock() succeeds.
var storeLookupFn func(key string) (string, error)

// SetStoreLookup wires the keeper into all Value resolutions.
// Call from server.go immediately after Store.Unlock().
func SetStoreLookup(fn func(key string) (string, error)) {
	storeLookupFn = fn
}

// ErrStoreLocked is returned when a keeper ref is resolved before unlock.
var ErrStoreLocked = errors.New("secret store is locked")

// Resolve resolves the value using lookup for env vars.
// Keeper refs silently return "" when the store is not yet unlocked,
// matching expected behaviour during initial config load.
func (v Value) Resolve(lookup func(string) string) string {
	result, _ := v.resolve(lookup)
	return result
}

// ResolveErr is like Resolve but surfaces store errors to the caller.
func (v Value) ResolveErr(lookup func(string) string) (string, error) {
	return v.resolve(lookup)
}

func (v Value) resolve(lookup func(string) string) (string, error) {
	raw := strings.TrimSpace(string(v))
	if raw == "" {
		return "", nil
	}

	// Secret store refs: ss://key  ss.key  keeper.key
	for _, pfx := range []string{"ss://", "ss.", "keeper."} {
		if after, ok := strings.CutPrefix(raw, pfx); ok {
			if storeLookupFn == nil {
				return "", ErrStoreLocked
			}
			val, err := storeLookupFn(after)
			if err != nil {
				return "", err
			}
			return val, nil
		}
	}

	// base64: b64.xxxx
	if after, ok := strings.CutPrefix(raw, "b64."); ok {
		decoded, err := base64.StdEncoding.DecodeString(after)
		if err != nil {
			return raw, fmt.Errorf("b64 decode: %w", err)
		}
		return string(decoded), nil
	}

	// explicit env prefix: env.VAR
	if after, ok := strings.CutPrefix(raw, "env."); ok {
		return lookup(after), nil
	}

	// shell expansion: $VAR or ${VAR}
	if strings.ContainsRune(raw, '$') {
		return os.Expand(raw, func(key string) string {
			if after, ok := strings.CutPrefix(key, "env."); ok {
				return lookup(after)
			}
			return lookup(key)
		}), nil
	}

	return raw, nil
}

// String implements fmt.Stringer using os.Getenv for env lookups.
func (v Value) String() string { return v.Resolve(os.Getenv) }

// Empty returns true if the raw string is empty or whitespace-only.
func (v Value) Empty() bool { return strings.TrimSpace(string(v)) == "" }

// IsSecretStoreRef reports whether this value will be resolved from the keeper.
func (v Value) IsSecretStoreRef() bool {
	raw := strings.TrimSpace(string(v))
	for _, pfx := range []string{"ss://", "ss.", "keeper."} {
		if strings.HasPrefix(raw, pfx) {
			return true
		}
	}
	return false
}

// IsEnvRef reports whether this value references an environment variable.
func (v Value) IsEnvRef() bool {
	raw := strings.TrimSpace(string(v))
	return strings.HasPrefix(raw, "env.") || strings.ContainsRune(raw, '$')
}

// IsBase64 reports whether this value is a b64-encoded literal.
func (v Value) IsBase64() bool {
	return strings.HasPrefix(strings.TrimSpace(string(v)), "b64.")
}

// UnmarshalText implements encoding.TextUnmarshaler (HCL / TOML / YAML).
func (v *Value) UnmarshalText(text []byte) error {
	*v = Value(string(text))
	return nil
}

// MarshalText implements encoding.TextMarshaler.
// Keeper refs are emitted as-is; everything else is redacted.
func (v Value) MarshalText() ([]byte, error) {
	if v.IsSecretStoreRef() {
		return []byte(v), nil
	}
	return []byte("[REDACTED]"), nil
}

// MarshalJSON redacts non-keeper values in JSON output.
func (v Value) MarshalJSON() ([]byte, error) {
	if v.IsSecretStoreRef() {
		return []byte(`"` + string(v) + `"`), nil
	}
	return []byte(`"[REDACTED]"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (v *Value) UnmarshalJSON(data []byte) error {
	s := string(data)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	*v = Value(s)
	return nil
}

func (v Value) GobEncode() ([]byte, error) {
	if v.IsSecretStoreRef() {
		return []byte(v), nil
	}
	return []byte("[REDACTED]"), nil
}

func (v *Value) GobDecode(data []byte) error {
	*v = Value(string(data))
	return nil
}

// Format implements fmt.Formatter so %s/%q/%v/%#v all do the right thing.
func (v Value) Format(f fmt.State, verb rune) {
	switch verb {
	case 's':
		fmt.Fprint(f, v.String())
	case 'q':
		fmt.Fprintf(f, "%q", v.String())
	case 'v':
		if f.Flag('#') {
			fmt.Fprintf(f, "alaye.Value(%q)", string(v))
		} else {
			fmt.Fprint(f, v.String())
		}
	default:
		fmt.Fprintf(f, "%%!%c(alaye.Value)", verb)
	}
}

// GoString implements fmt.GoStringer.
func (v Value) GoString() string { return fmt.Sprintf("alaye.Value(%q)", string(v)) }

// Constructor helpers.
func ValueSecret(key string) Value  { return Value("ss://" + key) }
func ValueEnv(name string) Value    { return Value("env." + name) }
func ValueB64(encoded string) Value { return Value("b64." + encoded) }
func ValuePlain(text string) Value  { return Value(text) }

// Compile-time interface checks.
var (
	_ encoding.TextMarshaler   = Value("")
	_ encoding.TextUnmarshaler = (*Value)(nil)
	_ fmt.Stringer             = Value("")
	_ fmt.GoStringer           = Value("")
	_ fmt.Formatter            = Value("")
)
