package expect

import (
	"encoding"
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/errors"
)

type Value string

var storeLookupFn func(key string) (string, error)

func SetStoreLookup(fn func(key string) (string, error)) {
	storeLookupFn = fn
}

var ErrStoreLocked = errors.New("secret store is locked")

func (v Value) Resolve(lookup func(string) string) string {
	result, _ := v.resolve(lookup)
	return result
}

func (v Value) ResolveErr(lookup func(string) string) (string, error) {
	return v.resolve(lookup)
}

func (v Value) resolve(lookup func(string) string) (string, error) {
	raw := strings.TrimSpace(string(v))
	if raw == "" {
		return "", nil
	}

	aliasPrefixes := []string{
		"ss://",
		"ss.",
		"keeper.",
	}
	for _, pfx := range aliasPrefixes {
		if after, ok := strings.CutPrefix(raw, pfx); ok {
			if storeLookupFn == nil {
				return "", ErrStoreLocked
			}

			return storeLookupFn(after)
		}
	}

	schemePrefixes := []string{
		"vault://",
		"keeper://",
		"certs://",
		"spaces://",
	}
	for _, pfx := range schemePrefixes {
		if strings.HasPrefix(raw, pfx) {
			if storeLookupFn == nil {
				return "", ErrStoreLocked
			}

			return storeLookupFn(raw)
		}
	}

	// b64. (original) and base64: (alias) — both decode identically.
	if after, ok := strings.CutPrefix(raw, "b64."); ok {
		decoded, err := decodeBase64Bytes(after)
		if err != nil {
			return raw, fmt.Errorf("b64 decode: %w", err)
		}
		return string(decoded), nil
	}

	if after, ok := strings.CutPrefix(raw, "base64:"); ok {
		decoded, err := decodeBase64Bytes(after)
		if err != nil {
			return raw, fmt.Errorf("base64 decode: %w", err)
		}
		return string(decoded), nil
	}

	if after, ok := strings.CutPrefix(raw, "env."); ok {
		return lookup(after), nil
	}

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

func (v Value) String() string { return v.Resolve(os.Getenv) }

func (v Value) Empty() bool { return strings.TrimSpace(v.String()) == "" }

func (v Value) IsSecretStoreRef() bool {
	raw := strings.TrimSpace(string(v))
	for _, pfx := range []string{"ss://", "ss.", "keeper.", "vault://", "keeper://", "certs://", "spaces://"} {
		if strings.HasPrefix(raw, pfx) {
			return true
		}
	}
	return false
}

func (v Value) IsEnvRef() bool {
	raw := strings.TrimSpace(string(v))
	return strings.HasPrefix(raw, "env.") || strings.ContainsRune(raw, '$')
}

// IsBase64 reports whether the value uses either the b64. or base64: prefix.
func (v Value) IsBase64() bool {
	raw := strings.TrimSpace(string(v))
	return strings.HasPrefix(raw, "b64.") || strings.HasPrefix(raw, "base64:")
}

func (v *Value) UnmarshalText(text []byte) error {
	*v = Value(string(text))
	return nil
}

func (v Value) MarshalText() ([]byte, error) {
	if v.IsSecretStoreRef() {
		return []byte(v), nil
	}
	return []byte("[REDACTED]"), nil
}

func (v Value) MarshalJSON() ([]byte, error) {
	if v.IsSecretStoreRef() {
		return []byte(`"` + string(v) + `"`), nil
	}
	return []byte(`"[REDACTED]"`), nil
}

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

func (v Value) Format(f fmt.State, verb rune) {
	switch verb {
	case 's':
		fmt.Fprint(f, v.String())
	case 'q':
		fmt.Fprintf(f, "%q", v.String())
	case 'v':
		if f.Flag('#') {
			fmt.Fprintf(f, "expect.Value(%q)", string(v))
		} else {
			fmt.Fprint(f, v.String())
		}
	default:
		fmt.Fprintf(f, "%%!%c(expect.Value)", verb)
	}
}

func (v Value) GoString() string { return fmt.Sprintf("expect.Value(%q)", string(v)) }

func ValueSecret(key string) Value  { return Value("ss://" + key) }
func ValueEnv(name string) Value    { return Value("env." + name) }
func ValueB64(encoded string) Value { return Value("b64." + encoded) }
func ValuePlain(text string) Value  { return Value(text) }

var (
	_ encoding.TextMarshaler   = Value("")
	_ encoding.TextUnmarshaler = (*Value)(nil)
	_ fmt.Stringer             = Value("")
	_ fmt.GoStringer           = Value("")
	_ fmt.Formatter            = Value("")
)
