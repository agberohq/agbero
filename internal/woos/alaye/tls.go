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
		case ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA:
			// Valid modes
		default:
			return errors.Newf("tls mode %q must be one of: %s, %s, %s, %s",
				t.Mode, ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA)
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
		return errors.Newf("unsupported tls mode: %s", t.Mode)
	}
}

func (l *LocalCert) Validate() error {
	// Cert file validation
	if l.CertFile == "" {
		return errors.New("cert_file is required for local tls")
	}
	if !strings.HasPrefix(l.CertFile, "/") {
		return errors.New("cert_file must be an absolute path")
	}

	// Key file validation
	if l.KeyFile == "" {
		return errors.New("key_file is required for local tls")
	}
	if !strings.HasPrefix(l.KeyFile, "/") {
		return errors.New("key_file must be an absolute path")
	}

	return nil
}

func (l *LetsEncrypt) Validate() error {
	// Email validation (if provided)
	if l.Email != "" && !strings.Contains(l.Email, "@") {
		return errors.New("email must be a valid email address")
	}

	// Staging and ShortLived are booleans, no validation needed
	return nil
}

func (c *CustomCA) Validate() error {
	// Root CA file validation
	if c.Root == "" {
		return errors.New("root is required for custom_ca")
	}
	if !strings.HasPrefix(c.Root, "/") {
		return errors.New("root must be an absolute path")
	}

	return nil
}
