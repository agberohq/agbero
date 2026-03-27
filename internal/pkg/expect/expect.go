package expect

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

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

// SecretScheme represents the storage scheme for secret URIs
type SecretScheme string

const (
	SchemeSecret SecretScheme = "secret"
	SchemeSS     SecretScheme = "ss"
	SchemeVault  SecretScheme = "vault"
	SchemeEnv    SecretScheme = "env"
	SchemeFile   SecretScheme = "file"
)

// SecretPath represents a parsed secret path with namespace, key, and subkeys
type SecretPath struct {
	Scheme    SecretScheme
	Namespace string
	Key       string
	SubKeys   []string
	Raw       string
}

// Expect provides typed validation for different key formats
type Expect struct {
	raw        string
	keyType    KeyType
	secretPath *SecretPath
	parseErr   error
	validate   *validator.Validate
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
	_DomainRegex    = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
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

// New creates a new Expect (never returns error - check via typed methods or Error())
func New(rawKey string) *Expect {
	decoded, err := url.QueryUnescape(rawKey)
	if err != nil {
		return &Expect{raw: rawKey, parseErr: fmt.Errorf("failed to decode key: %w", err), validate: _Validate}
	}
	decoded = strings.TrimSpace(decoded)
	if decoded == "" {
		return &Expect{raw: rawKey, parseErr: errors.New("key cannot be empty"), validate: _Validate}
	}
	e := &Expect{raw: decoded, validate: _Validate}
	e.detectType()
	return e
}

func (e *Expect) detectType() {
	if e.parseErr != nil {
		return
	}

	// 1. Secret URI with scheme (most specific)
	if strings.Contains(e.raw, "://") {
		if err := e.parseSecretURI(); err == nil {
			e.keyType = TypeSecret
			return
		}
	}

	// 2. JWT pattern
	if strings.Count(e.raw, ".") == 2 && len(e.raw) > 50 && e.isValidJWTFormat() {
		e.keyType = TypeJWT
		return
	}

	// 3. Absolute path ONLY (must start with /)
	if strings.HasPrefix(e.raw, "/") {
		e.keyType = TypePath
		return
	}

	// 4. IP address
	if ip := net.ParseIP(e.raw); ip != nil {
		e.keyType = TypeIP
		return
	}

	// 5. SSH: user@host or user@host/path
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

	// 6. Domain: valid domain regex + (3+ parts OR 2 parts with known TLD)
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

	// 7. Secret without scheme (namespace/key format)
	// Contains / but no @ (avoid SSH), no leading / (avoid Path collision)
	if !strings.Contains(e.raw, "@") && strings.Contains(e.raw, "/") {
		if secret, err := ParseSecret(e.raw); err == nil {
			e.secretPath = secret.ToSecretPath()
			e.keyType = TypeSecret
			return
		}
	}

	// 8. Username: valid username format (fallback)
	if e.validate.Var(e.raw, "username") == nil {
		e.keyType = TypeUsername
		return
	}

	e.parseErr = fmt.Errorf("unable to determine key type for: %s", e.raw)
}

// isValidHostForSSH validates host part of SSH pattern (IP, simple hostname, or FQDN)
func (e *Expect) isValidHostForSSH(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	return _HostnameRegex.MatchString(s)
}

func (e *Expect) parseSecretURI() error {
	parsedURL, err := url.Parse(e.raw)
	if err != nil {
		return err
	}
	scheme := SecretScheme(parsedURL.Scheme)
	if !isValidScheme(scheme) {
		return fmt.Errorf("unsupported secret scheme: %s", parsedURL.Scheme)
	}

	var pathParts []string
	if parsedURL.Host != "" {
		pathParts = append(pathParts, parsedURL.Host)
	}
	path := strings.Trim(parsedURL.Path, "/")
	if path != "" {
		pathParts = append(pathParts, strings.Split(path, "/")...)
	}
	if len(pathParts) < 2 {
		return errors.New("secret path must contain at least namespace and key")
	}

	secretPath := &SecretPath{
		Scheme:    scheme,
		Namespace: pathParts[0],
		Key:       pathParts[1],
		SubKeys:   []string{},
		Raw:       e.raw,
	}
	if err := e.validate.Var(secretPath.Namespace, "namespace"); err != nil {
		return fmt.Errorf("invalid namespace: %s", secretPath.Namespace)
	}
	if err := e.validate.Var(secretPath.Key, "secretkey"); err != nil {
		return fmt.Errorf("invalid key: %s", secretPath.Key)
	}
	if len(pathParts) > 2 {
		secretPath.SubKeys = pathParts[2:]
		for _, subkey := range secretPath.SubKeys {
			if err := e.validate.Var(subkey, "subkey"); err != nil {
				return fmt.Errorf("invalid subkey: %s", subkey)
			}
		}
	}
	e.secretPath = secretPath
	return nil
}

func (e *Expect) checkError() error { return e.parseErr }

func (e *Expect) IP() (net.IP, error) {
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

func (e *Expect) Domain() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeDomain {
		return "", fmt.Errorf("expected domain key, got %s: %s", e.keyType, e.raw)
	}
	if !_DomainRegex.MatchString(e.raw) {
		return "", fmt.Errorf("invalid domain format: %s", e.raw)
	}
	if len(e.raw) > 253 {
		return "", errors.New("domain too long")
	}
	return e.raw, nil
}

func (e *Expect) SSH() (username, host string, err error) {
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

func (e *Expect) Path() (string, error) {
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

func (e *Expect) Username() (string, error) {
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

func (e *Expect) JWT() (string, error) {
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
func (e *Expect) Secret() (*SecretPath, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret {
		return nil, fmt.Errorf("expected secret URI, got %s: %s", e.keyType, e.raw)
	}
	if e.secretPath == nil {
		return nil, errors.New("secret path not parsed")
	}
	return e.secretPath, nil
}

// SecretRef returns the new Secret type with extended methods
func (e *Expect) SecretRef() (*Secret, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret {
		return nil, fmt.Errorf("expected secret, got %s: %s", e.keyType, e.raw)
	}
	return ParseSecret(e.raw)
}

func (e *Expect) Namespace() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secretPath == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secretPath.Namespace, nil
}

func (e *Expect) SecretKey() (string, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secretPath == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secretPath.Key, nil
}

func (e *Expect) SubKeys() ([]string, error) {
	if err := e.checkError(); err != nil {
		return nil, err
	}
	if e.keyType != TypeSecret || e.secretPath == nil {
		return nil, errors.New("secret path not parsed")
	}
	return e.secretPath.SubKeys, nil
}

func (e *Expect) SecretScheme() (SecretScheme, error) {
	if err := e.checkError(); err != nil {
		return "", err
	}
	if e.keyType != TypeSecret || e.secretPath == nil {
		return "", errors.New("secret path not parsed")
	}
	return e.secretPath.Scheme, nil
}

func (e *Expect) Raw() string   { return e.raw }
func (e *Expect) Type() KeyType { return e.keyType }
func (e *Expect) Error() error  { return e.parseErr }

func (e *Expect) isValidJWTFormat() bool {
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

func (e *Expect) isAllowedLoopback() bool { return false }

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
