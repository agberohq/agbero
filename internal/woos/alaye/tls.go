package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type TLS struct {
	Mode        TlsMode     `hcl:"mode,optional"`
	Local       LocalCert   `hcl:"local,block"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block"`
	CustomCA    CustomCA    `hcl:"custom_ca,block"`
}

type LocalCert struct {
	CertFile string `hcl:"cert_file"`
	KeyFile  string `hcl:"key_file"`
}

type LetsEncrypt struct {
	Email      string `hcl:"email,optional"`
	Staging    bool   `hcl:"staging,optional"`
	ShortLived bool   `hcl:"short_lived,optional"` // Enable 6-day certs
}

type CustomCA struct {
	Root string `hcl:"root"` // CA cert file path
}

func (t *TLS) Validate() error {
	// Mode validation (if provided)
	if t.Mode != "" {
		switch t.Mode {
		case ModeLocalAuto:
			return nil // No validation needed, will auto-generate
		case ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA:
			// Valid modes
		default:
			return errors.Newf("%w: %q must be one of: %s, %s, %s, %s",
				ErrInvalidTLSMode, t.Mode, ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA)
		}
	} else {
		t.Mode = ModeLetsEncrypt // Default
	}

	// Validate based on mode
	switch t.Mode {
	case ModeLocalCert:
		return t.Local.Validate()
	case ModeLetsEncrypt:
		return t.LetsEncrypt.Validate()
	case ModeCustomCA:
		return t.CustomCA.Validate()
	case ModeLocalNone:
		// No TLS, nothing to validate
		return nil
	default:
		return errors.Newf("%w: %s", ErrUnsupportedTLSMode, t.Mode)
	}
}

func (l *LocalCert) Validate() error {
	// Cert file validation
	if l.CertFile == "" {
		return ErrCertFileRequired
	}
	if !strings.HasPrefix(l.CertFile, "/") {
		return ErrCertFileAbsolute
	}

	// Key file validation
	if l.KeyFile == "" {
		return ErrKeyFileRequired
	}
	if !strings.HasPrefix(l.KeyFile, "/") {
		return ErrKeyFileAbsolute
	}

	return nil
}

func (l *LetsEncrypt) Validate() error {
	// Email validation (if provided)
	if l.Email != "" && !strings.Contains(l.Email, "@") {
		return ErrInvalidEmail
	}

	// Staging and ShortLived are booleans, no validation needed
	return nil
}

func (c *CustomCA) Validate() error {
	// Root CA file validation
	if c.Root == "" {
		return ErrRootRequiredCustomCA
	}
	if !strings.HasPrefix(c.Root, "/") {
		return ErrRootAbsolute
	}

	return nil
}
