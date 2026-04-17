package expect

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/olekukonko/errors"

	"github.com/go-playground/validator/v10"
)

// KeyType represents different types of keys
type KeyType string

const (
	TypeSSH      KeyType = "ssh"
	TypeDomain   KeyType = "domain"
	TypeIP       KeyType = "ip"
	TypePath     KeyType = "path"
	TypeUsername KeyType = "username"
	TypeJWT      KeyType = "jwt"
	TypeSecret   KeyType = "secret"
)

// Raw provides typed validation for different key formats
type Raw struct {
	raw      string
	keyType  KeyType
	secret   *Secret
	parseErr error
	validate *validator.Validate
}

var (
	_Validate   *validator.Validate
	_CommonTLDs = map[string]bool{
		"com": true, "org": true, "net": true, "edu": true, "gov": true, "mil": true,
		"io": true, "co": true, "uk": true, "de": true, "fr": true, "jp": true,
		"cn": true, "au": true, "ru": true, "br": true, "in": true, "localhost": true,
	}
	_Base64URLRegex = regexp.MustCompile(`^[A-Za-z0-9\-_]*={0,2}$`)
	_SecretKeyRegex = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)
	_DomainRegex    = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	_UsernameRegex  = regexp.MustCompile(`^[a-zA-Z0-9_.\-]+$`)
	_HostnameRegex  = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-_.]*[a-zA-Z0-9])?$`)
)

func init() {
	_Validate = validator.New()
	_ = _Validate.RegisterValidation("namespace", validateNamespace)
	_ = _Validate.RegisterValidation("secretkey", validateSecretKey)
	_ = _Validate.RegisterValidation("subkey", validateSubKey)
	_ = _Validate.RegisterValidation("username", validateUsername)
}

// NewRaw creates a new Raw (never returns error - check via typed methods or Error())
func NewRaw(rawKey string) *Raw {
	decoded, err := url.QueryUnescape(rawKey)
	if err != nil {
		return &Raw{raw: rawKey, parseErr: fmt.Errorf("failed to decode key: %w", err), validate: _Validate}
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return &Raw{raw: rawKey, parseErr: errors.New("key cannot be empty"), validate: _Validate}
	}
	e := &Raw{raw: decoded, validate: _Validate}
	e.detectType()
	return e
}

func (e *Raw) detectType() {
	if e.parseErr != nil {
		return
	}

	// Secret URI with scheme (most specific)
	if strings.Contains(e.raw, "://") {
		if err := e.parseSecretURI(); err == nil {
			e.keyType = TypeSecret
			return
		}
	}

	// JWT pattern
	if strings.Count(e.raw, ".") == 2 && len(e.raw) > 50 && e.isValidJWTFormat() {
		e.keyType = TypeJWT
		return
	}

	// Absolute path ONLY (must start with /)
	if strings.HasPrefix(e.raw, "/") {
		e.keyType = TypePath
		return
	}

	// IP address
	if ip := net.ParseIP(e.raw); ip != nil {
		e.keyType = TypeIP
		return
	}

	// SSH: user@host or user@host/path
	if strings.Contains(e.raw, "@") {
		parts := strings.SplitN(e.raw, "@", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			user := parts[0]
			host := strings.SplitN(parts[1], "/", 2)[0]
			if e.validate.Var(user, "username") == nil && e.isValidHostForSSH(host) {
				e.keyType = TypeSSH
				return
			}
		}
	}

	// Domain: valid domain regex + (3+ parts OR 2 parts with known TLD)
	if _DomainRegex.MatchString(e.raw) {
		parts := strings.Split(e.raw, ".")
		if len(parts) >= 3 {
			e.keyType = TypeDomain
			return
		}
		if len(parts) == 2 {
			tld := strings.ToLower(parts[1])
			if _CommonTLDs[tld] {
				e.keyType = TypeDomain
				return
			}
		}
	}

	// Secret without scheme (namespace/key format)
	// Contains / but no @ (avoid SSH), no leading / (avoid Path collision)
	if !strings.Contains(e.raw, "@") && strings.Contains(e.raw, "/") {
		if secret, err := ParseSecret(e.raw); err == nil {
			e.secret = secret.ToSecretPath()
			e.keyType = TypeSecret
			return
		}
	}

	// Username: valid username format (fallback)
	if e.validate.Var(e.raw, "username") == nil {
		e.keyType = TypeUsername
		return
	}

	e.parseErr = fmt.Errorf("unable to determine key type for: %s", e.raw)
}

// isValidHostForSSH validates host part of SSH pattern (IP, simple hostname, or FQDN)
func (e *Raw) isValidHostForSSH(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return _HostnameRegex.MatchString(s)
}

func (e *Raw) parseSecretURI() error {
	// ParseSecret centralizes all URL parsing, splitting, and validation
	// using the highly optimized pre-compiled regexes in constants.go.
	secret, err := ParseSecret(e.raw)
	if err != nil {
		return err
	}

	// Ensure the scheme is one of the strictly supported ones
	if !isValidScheme(secret.Scheme) {
		return fmt.Errorf("unsupported secret scheme: %s", secret.Scheme)
	}

	// Store the unified Secret type (replaces the deprecated SecretPath)
	e.secret = secret
	return nil
}

func (e *Raw) checkError() error { return e.parseErr }

func (e *Raw) IP() (net.IP, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeIP {
		return nil, fmt.Errorf("expected IP key, got %s: %s", e.keyType, e.raw)
	}
	ip := net.ParseIP(e.raw)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address format: %s", e.raw)
	}
	if ip.IsUnspecified() {
		return nil, errors.New("IP address cannot be 0.0.0.0 or ::")
	}
	if ip.IsLoopback() && !e.isAllowedLoopback() {
		return nil, errors.New("loopback IP not allowed")
	}
	return ip, nil
}

func (e *Raw) Domain() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeDomain {
		return "", fmt.Errorf("expected domain key, got %s: %s", e.keyType, e.raw)
	}
	if !_DomainRegex.MatchString(e.raw) && e.raw != "localhost" {
		return "", fmt.Errorf("invalid domain format: %s", e.raw)
	}
	if len(e.raw) > 253 {
		return "", errors.New("domain too long")
	}
	return e.raw, nil
}

func (e *Raw) SSH() (username, host string, err error) {
	if err := e.checkError(); err != nil {
		return "", "", err
	}
	if e.keyType != TypeSSH {
		return "", "", fmt.Errorf("expected SSH key, got %s: %s", e.keyType, e.raw)
	}
	parts := strings.SplitN(e.raw, "@", 2)
	if len(parts) != 2 {
		return "", "", errors.New("invalid SSH format: missing @ separator")
	}
	username = parts[0]
	if username == "" {
		return "", "", errors.New("username cannot be empty")
	}
	if err := e.validate.Var(username, "username"); err != nil {
		return "", "", fmt.Errorf("invalid username format: %s", username)
	}
	hostPart := parts[1]
	hostParts := strings.SplitN(hostPart, "/", 2)
	host = hostParts[0]
	if host == "" {
		return "", "", errors.New("host cannot be empty")
	}
	if !e.isValidHostForSSH(host) {
		return "", "", fmt.Errorf("invalid host format: %s", host)
	}
	return username, host, nil
}

func (e *Raw) Path() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypePath {
		return "", fmt.Errorf("expected path key, got %s: %s", e.keyType, e.raw)
	}
	if strings.Contains(e.raw, "..") {
		return "", errors.New("path traversal not allowed")
	}
	if len(e.raw) > 2048 {
		return "", errors.New("path too long")
	}
	return e.raw, nil
}

func (e *Raw) Username() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeUsername {
		return "", fmt.Errorf("expected username key, got %s: %s", e.keyType, e.raw)
	}
	if err := e.validate.Var(e.raw, "username"); err != nil {
		return "", fmt.Errorf("invalid username format: %s", e.raw)
	}
	return e.raw, nil
}

func (e *Raw) JWT() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeJWT {
		return "", fmt.Errorf("expected JWT key, got %s: %s", e.keyType, e.raw)
	}
	if len(e.raw) < 32 {
		return "", errors.New("JWT secret too short (minimum 32 characters)")
	}
	if !e.isValidJWTFormat() {
		return "", errors.New("invalid JWT format")
	}
	return e.raw, nil
}

// Secret returns backward-compatible SecretPath
func (e *Raw) Secret() (*Secret, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret {
		return nil, fmt.Errorf("expected secret URI, got %s: %s", e.keyType, e.raw)
	}
	if e.secret == nil {
		return nil, errors.New("secret path not parsed")
	}
	return e.secret, nil
}

// SecretRef returns the new Secret type with extended methods
func (e *Raw) SecretRef() (*Secret, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret {
		return nil, fmt.Errorf("expected secret, got %s: %s", e.keyType, e.raw)
	}
	return ParseSecret(e.raw)
}

func (e *Raw) Namespace() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secret == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secret.Namespace, nil
}

func (e *Raw) SecretKey() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secret == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secret.Key, nil
}

func (e *Raw) SubKeys() ([]string, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret || e.secret == nil {
		return nil, errors.New("secret path not parsed")
	}
	return e.secret.SubKeys, nil
}

func (e *Raw) SecretScheme() (SecretScheme, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secret == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secret.Scheme, nil
}

func (e *Raw) Raw() string   { return e.raw }
func (e *Raw) Type() KeyType { return e.keyType }
func (e *Raw) Error() error  { return e.parseErr }

func (e *Raw) isValidJWTFormat() bool {
	if strings.Count(e.raw, ".") != 2 {
		return false
	}
	parts := strings.Split(e.raw, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !_Base64URLRegex.MatchString(part) {
			return false
		}
	}
	return true
}

func (e *Raw) isAllowedLoopback() bool { return false }

// Custom validator functions for go-playground/validator
func validateNamespace(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if len(val) < 3 || len(val) > 64 {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(val)
}

func validateSecretKey(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if len(val) < 1 || len(val) > 128 {
		return false
	}
	return _SecretKeyRegex.MatchString(val)
}

func validateSubKey(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if len(val) < 1 || len(val) > 64 {
		return false
	}
	return regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString(val)
}

func validateUsername(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if len(val) < 3 || len(val) > 64 {
		return false
	}
	return _UsernameRegex.MatchString(val)
}
