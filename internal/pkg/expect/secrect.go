package expect

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Secret represents a parsed secret reference supporting both
// prefixed (ss://) and non-prefixed (namespace/key) formats.
type Secret struct {
	Scheme    SecretScheme
	Namespace string
	Key       string
	SubKeys   []string
	Raw       string
	hasScheme bool
}

// ParseSecret parses a secret path in either format:
//   - ss://namespace/key/subkey1/subkey2 (with scheme)
//   - namespace/key/subkey1/subkey2 (without scheme, defaults to ss://)
func ParseSecret(input string) (*Secret, error) {
	if input == "" {
		return nil, errors.New("secret input cannot be empty")
	}

	if strings.Contains(input, "://") {
		return parseWithScheme(input)
	}
	return parseWithoutScheme(input)
}

func parseWithScheme(input string) (*Secret, error) {
	parsedURL, err := url.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	scheme := SecretScheme(parsedURL.Scheme)
	if !isValidScheme(scheme) {
		return nil, fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	var parts []string
	if parsedURL.Host != "" {
		parts = append(parts, parsedURL.Host)
	}

	path := strings.Trim(parsedURL.Path, "/")
	if path != "" {
		parts = append(parts, strings.Split(path, "/")...)
	}

	if len(parts) < 2 {
		return nil, errors.New("secret requires namespace and key")
	}

	s := &Secret{
		Scheme:    scheme,
		Namespace: parts[0],
		Key:       parts[1],
		SubKeys:   []string{},
		Raw:       input,
		hasScheme: true,
	}
	if len(parts) > 2 {
		s.SubKeys = parts[2:]
	}

	return s, s.validate()
}

func parseWithoutScheme(input string) (*Secret, error) {
	input = strings.Trim(input, "/")
	parts := strings.Split(input, "/")

	if len(parts) < 2 {
		return nil, errors.New("secret requires namespace/key format")
	}

	s := &Secret{
		Scheme:    SchemeSS,
		Namespace: parts[0],
		Key:       parts[1],
		SubKeys:   []string{},
		Raw:       input,
		hasScheme: false,
	}
	if len(parts) > 2 {
		s.SubKeys = parts[2:]
	}

	return s, s.validate()
}

func (s *Secret) validate() error {
	if len(s.Namespace) < 3 || len(s.Namespace) > 64 {
		return fmt.Errorf("namespace length %d invalid (3-64)", len(s.Namespace))
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(s.Namespace) {
		return fmt.Errorf("invalid namespace: %s", s.Namespace)
	}

	if len(s.Key) < 1 || len(s.Key) > 128 || !_SecretKeyRegex.MatchString(s.Key) {
		return fmt.Errorf("invalid key: %s", s.Key)
	}

	for _, sk := range s.SubKeys {
		if len(sk) < 1 || len(sk) > 64 {
			return fmt.Errorf("subkey too long: %s", sk)
		}
		if matched := regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(sk); !matched {
			return fmt.Errorf("invalid subkey: %s", sk)
		}
	}
	return nil
}

// WithScheme returns "ss://namespace/key/sub1/sub2"
func (s *Secret) WithScheme() string {
	var b strings.Builder
	b.WriteString(string(s.Scheme))
	b.WriteString("://")
	b.WriteString(s.Namespace)
	b.WriteString("/")
	b.WriteString(s.Key)
	for _, sk := range s.SubKeys {
		b.WriteString("/")
		b.WriteString(sk)
	}
	return b.String()
}

// WithoutScheme returns "namespace/key/sub1/sub2"
func (s *Secret) WithoutScheme() string {
	var b strings.Builder
	b.WriteString(s.Namespace)
	b.WriteString("/")
	b.WriteString(s.Key)
	for _, sk := range s.SubKeys {
		b.WriteString("/")
		b.WriteString(sk)
	}
	return b.String()
}

// Path alias for WithoutScheme
func (s *Secret) Path() string { return s.WithoutScheme() }

// FullKey returns "key/sub1/sub2"
func (s *Secret) FullKey() string {
	var b strings.Builder
	b.WriteString(s.Key)
	for _, sk := range s.SubKeys {
		b.WriteString("/")
		b.WriteString(sk)
	}
	return b.String()
}

// Value returns the last component (the value name)
func (s *Secret) Value() string {
	if len(s.SubKeys) > 0 {
		return s.SubKeys[len(s.SubKeys)-1]
	}
	return s.Key
}

// HasScheme returns true if input had scheme prefix
func (s *Secret) HasScheme() bool { return s.hasScheme }

// String returns original input
func (s *Secret) String() string { return s.Raw }

// ToSecretPath converts to backward-compatible SecretPath
func (s *Secret) ToSecretPath() *SecretPath {
	return &SecretPath{
		Scheme:    s.Scheme,
		Namespace: s.Namespace,
		Key:       s.Key,
		SubKeys:   append([]string(nil), s.SubKeys...),
		Raw:       s.Raw,
	}
}

func isValidScheme(s SecretScheme) bool {
	switch s {
	case SchemeSecret, SchemeSS, SchemeVault, SchemeEnv, SchemeFile:
		return true
	}
	return false
}
