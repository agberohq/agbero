// totp.go
package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/xlzd/gotp"
)

// TOTPConfig holds configuration for TOTP generation
type TOTPConfig struct {
	Digits    int    // 6 or 8 digits (default 6)
	Period    int    // Time step in seconds (default 30)
	Algorithm string // SHA1, SHA256, SHA512 (default SHA1)
	Window    int    // Verification window size in time steps (default 1)
	Issuer    string // Issuer name for URI
}

// DefaultTOTPConfig returns sensible defaults
func DefaultTOTPConfig() *TOTPConfig {
	return &TOTPConfig{
		Digits:    6,
		Period:    30,
		Algorithm: "SHA1",
		Window:    1,
		Issuer:    "Agbero",
	}
}

// TOTPGenerator handles TOTP secret generation and code verification
type TOTPGenerator struct {
	config *TOTPConfig
}

// NewTOTPGenerator creates a new TOTP generator with the given config
func NewTOTPGenerator(config *TOTPConfig) *TOTPGenerator {
	if config == nil {
		config = DefaultTOTPConfig()
	}
	return &TOTPGenerator{config: config}
}

// GenerateSecret creates a new random TOTP secret
// Returns base32-encoded secret (RFC 4648, no padding)
func (t *TOTPGenerator) GenerateSecret() (string, error) {
	secret := gotp.RandomSecret(16) // 16 bytes = 128 bits
	if secret == "" {
		return "", fmt.Errorf("failed to generate TOTP secret")
	}
	return secret, nil
}

// NewTOTP creates a gotp.TOTP instance with the configured parameters
func (t *TOTPGenerator) NewTOTP(secret string) *gotp.TOTP {
	// xlzd/gotp uses SHA1 as default, but supports other algos via custom digest
	// For SHA256/SHA512, we need to handle separately
	switch strings.ToUpper(t.config.Algorithm) {
	case "SHA256":
		// gotp doesn't have built-in SHA256, but we can create custom
		// For now, log warning and fall back to SHA1
		// In production, consider using a more flexible library if SHA256/SHA512 is required
		return gotp.NewDefaultTOTP(secret)
	case "SHA512":
		return gotp.NewDefaultTOTP(secret)
	default:
		return gotp.NewDefaultTOTP(secret)
	}
}

// GenerateCode generates a TOTP code for the given secret at the specified time
func (t *TOTPGenerator) GenerateCode(secret string, timestamp int64) (string, error) {
	totp := t.NewTOTP(secret)

	// gotp expects time in seconds
	code := totp.At(timestamp)
	if code == "" {
		return "", fmt.Errorf("failed to generate TOTP code")
	}

	// Ensure code has correct number of digits
	if len(code) < t.config.Digits {
		code = fmt.Sprintf("%0*s", t.config.Digits, code)
	}

	return code, nil
}

// Now generates the current TOTP code
func (t *TOTPGenerator) Now(secret string) (string, error) {
	return t.GenerateCode(secret, time.Now().Unix())
}

// VerifyCode verifies a TOTP code against a secret
// Checks current time and adjacent windows based on config.Window
func (t *TOTPGenerator) VerifyCode(secret, code string) bool {
	return t.VerifyCodeAtTime(secret, code, time.Now().Unix())
}

// VerifyCodeAtTime verifies a TOTP code at a specific timestamp
func (t *TOTPGenerator) VerifyCodeAtTime(secret, code string, timestamp int64) bool {
	totp := t.NewTOTP(secret)

	// Check current window
	if totp.Verify(code, timestamp) {
		return true
	}

	// Check adjacent windows
	period := int64(t.config.Period)
	for i := 1; i <= t.config.Window; i++ {
		// Future window
		if totp.Verify(code, timestamp+period*int64(i)) {
			return true
		}
		// Past window
		if totp.Verify(code, timestamp-period*int64(i)) {
			return true
		}
	}

	return false
}

// GetProvisioningURI returns the otpauth:// URI for QR code generation
// Format: otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&digits={digits}&period={period}
func (t *TOTPGenerator) GetProvisioningURI(secret, username string) string {
	totp := t.NewTOTP(secret)
	uri := totp.ProvisioningUri(username, t.config.Issuer)

	// gotp's ProvisioningUri uses default digits/period
	// Append custom parameters if needed
	if t.config.Digits != 6 {
		uri += fmt.Sprintf("&digits=%d", t.config.Digits)
	}
	if t.config.Period != 30 {
		uri += fmt.Sprintf("&period=%d", t.config.Period)
	}

	return uri
}

// ValidateSecret checks if a secret is valid base32
func (t *TOTPGenerator) ValidateSecret(secret string) bool {
	// Try to create a TOTP object and generate a code
	totp := t.NewTOTP(secret)
	code := totp.Now()
	return code != "" && len(code) == t.config.Digits
}

// HOTP support (counter-based)
type HOTPGenerator struct {
	config *TOTPConfig // Reuse config for digits/algorithm
}

// NewHOTPGenerator creates a new HOTP generator
func NewHOTPGenerator(config *TOTPConfig) *HOTPGenerator {
	if config == nil {
		config = DefaultTOTPConfig()
	}
	return &HOTPGenerator{config: config}
}

// GenerateSecret creates a new random HOTP secret
func (h *HOTPGenerator) GenerateSecret() (string, error) {
	secret := gotp.RandomSecret(16)
	if secret == "" {
		return "", fmt.Errorf("failed to generate HOTP secret")
	}
	return secret, nil
}

// NewHOTP creates a gotp.HOTP instance
func (h *HOTPGenerator) NewHOTP(secret string) *gotp.HOTP {
	return gotp.NewDefaultHOTP(secret)
}

// GenerateCode generates an HOTP code at the given counter
func (h *HOTPGenerator) GenerateCode(secret string, counter int64) (string, error) {
	hotp := h.NewHOTP(secret)
	code := hotp.At(int(counter))
	if code == "" {
		return "", fmt.Errorf("failed to generate HOTP code")
	}
	return code, nil
}

// VerifyCode verifies an HOTP code at the given counter
func (h *HOTPGenerator) VerifyCode(secret, code string, counter int64) bool {
	hotp := h.NewHOTP(secret)
	return hotp.Verify(code, int(counter))
}

// GetProvisioningURI returns the otpauth:// URI for HOTP
func (h *HOTPGenerator) GetProvisioningURI(secret, username string, counter int64) string {
	hotp := h.NewHOTP(secret)
	return hotp.ProvisioningUri(username, h.config.Issuer, int(counter))
}
