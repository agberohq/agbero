package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type TLS struct {
	Mode        TlsMode     `hcl:"mode,optional" json:"mode"`
	Local       LocalCert   `hcl:"local,block" json:"local"`
	LetsEncrypt LetsEncrypt `hcl:"letsencrypt,block" json:"lets_encrypt"`
	CustomCA    CustomCA    `hcl:"custom_ca,block" json:"custom_ca"`

	ClientAuth string   `hcl:"client_auth,optional" json:"client_auth"`
	ClientCAs  []string `hcl:"client_cas,optional" json:"client_cas"`
}

func (t *TLS) Validate() error {
	if t.Mode != "" {
		switch t.Mode {
		case ModeLocalAuto:
			return nil
		case ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA:
		default:
			return errors.Newf("%w: %q must be one of: %s, %s, %s, %s",
				ErrInvalidTLSMode, t.Mode, ModeLocalNone, ModeLocalCert, ModeLetsEncrypt, ModeCustomCA)
		}
	} else {
		t.Mode = ModeLetsEncrypt
	}

	if t.ClientAuth != "" {
		switch strings.ToLower(t.ClientAuth) {
		case TlsNone, TlsRequest, TlsRequire, TlsRequireAndVerify, TlsVerifyIfGiven:
		default:
			return errors.Newf("invalid client_auth mode: %s", t.ClientAuth)
		}
	}

	if len(t.ClientCAs) > 0 {
		for _, ca := range t.ClientCAs {
			if !strings.HasPrefix(ca, Slash) {
				return errors.Newf("client_ca path must be absolute: %s", ca)
			}
		}
	}

	switch t.Mode {
	case ModeLocalCert:
		return t.Local.Validate()
	case ModeLetsEncrypt:
		return t.LetsEncrypt.Validate()
	case ModeCustomCA:
		return t.CustomCA.Validate()
	case ModeLocalNone:
		return nil
	default:
		return errors.Newf("%w: %s", ErrUnsupportedTLSMode, t.Mode)
	}
}

type LocalCert struct {
	Enabled  Enabled `hcl:"enabled,optional" json:"enabled"`
	CertFile string  `hcl:"cert_file" json:"cert_file"`
	KeyFile  string  `hcl:"key_file" json:"key_file"`
}

func (l *LocalCert) Validate() error {
	if l.Enabled.NotActive() {
		return nil
	}
	// Cert file validation
	if l.CertFile == "" {
		return ErrCertFileRequired
	}
	if !strings.HasPrefix(l.CertFile, Slash) {
		return ErrCertFileAbsolute
	}

	// Key file validation
	if l.KeyFile == "" {
		return ErrKeyFileRequired
	}
	if !strings.HasPrefix(l.KeyFile, Slash) {
		return ErrKeyFileAbsolute
	}

	return nil
}

type LetsEncrypt struct {
	Enabled    Enabled `hcl:"enabled,optional" json:"enabled"`
	Email      string  `hcl:"email,optional" json:"email"`
	Staging    bool    `hcl:"staging,optional" json:"staging"`
	ShortLived bool    `hcl:"short_lived,optional" json:"short_lived"` // Enable 6-day certs
}

func (l *LetsEncrypt) Validate() error {
	if l.Enabled.NotActive() {
		return nil
	}
	// Email validation (if provided)
	if l.Email != "" && !strings.Contains(l.Email, "@") {
		return ErrInvalidEmail
	}

	// Staging and ShortLived are booleans, no validation needed
	return nil
}

type CustomCA struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Root    string  `hcl:"root" json:"root"` // CA cert file path
}

func (c *CustomCA) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	// Root CA file validation
	if c.Root == "" {
		return ErrRootRequiredCustomCA
	}
	if !strings.HasPrefix(c.Root, Slash) {
		return ErrRootAbsolute
	}

	return nil
}
