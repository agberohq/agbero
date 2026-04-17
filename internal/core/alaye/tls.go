package alaye

import (
	"net/mail"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type TLS struct {
	Enabled     expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Mode        def.TlsMode   `hcl:"mode,attr" json:"mode"`
	ClientAuth  string        `hcl:"client_auth,attr" json:"client_auth"`
	ClientCAs   []string      `hcl:"client_cas,attr" json:"client_cas"`
	Local       LocalCert     `hcl:"local,block" json:"local"`
	LetsEncrypt LetsEncrypt   `hcl:"letsencrypt,block" json:"lets_encrypt"`
	CustomCA    CustomCA      `hcl:"custom_ca,block" json:"custom_ca"`
}

// Validate checks the TLS mode, client auth setting, and delegates to the relevant sub-block.
func (t *TLS) Validate() error {
	if t.Mode != "" {
		switch t.Mode {
		case def.ModeLocalAuto:
			return nil
		case def.ModeLocalNone, def.ModeLocalCert, def.ModeLetsEncrypt, def.ModeCustomCA:
		default:
			return errors.Newf("%w: %q must be one of: %s, %s, %s, %s",
				def.ErrInvalidTLSMode, t.Mode, def.ModeLocalNone, def.ModeLocalCert, def.ModeLetsEncrypt, def.ModeCustomCA)
		}
	} else {
		t.Mode = def.ModeLetsEncrypt
	}

	if t.ClientAuth != "" {
		switch strings.ToLower(t.ClientAuth) {
		case def.TlsNone, def.TlsRequest, def.TlsRequire, def.TlsRequireAndVerify, def.TlsVerifyIfGiven:
		default:
			return errors.Newf("invalid client_auth mode: %s", t.ClientAuth)
		}
	}

	for _, ca := range t.ClientCAs {
		if !strings.HasPrefix(ca, def.Slash) {
			return errors.Newf("client_ca path must be absolute: %s", ca)
		}
	}

	switch t.Mode {
	case def.ModeLocalCert:
		return t.Local.Validate()
	case def.ModeLetsEncrypt:
		return t.LetsEncrypt.Validate()
	case def.ModeCustomCA:
		return t.CustomCA.Validate()
	case def.ModeLocalNone:
		return nil
	default:
		return errors.Newf("%w: %s", def.ErrUnsupportedTLSMode, t.Mode)
	}
}

func (t TLS) IsZero() bool {
	return t.Enabled.IsZero() &&
		t.Mode == "" &&
		t.ClientAuth == "" &&
		len(t.ClientCAs) == 0 &&
		t.Local.IsZero() &&
		t.LetsEncrypt.IsZero() &&
		t.CustomCA.IsZero()
}

type LocalCert struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	CertFile string        `hcl:"cert_file,attr" json:"cert_file"`
	KeyFile  string        `hcl:"key_file,attr" json:"key_file"`
}

// Validate checks that cert and key file paths are absolute when local TLS is enabled.
func (l *LocalCert) Validate() error {
	if l.Enabled.NotActive() {
		return nil
	}
	if l.CertFile == "" {
		return def.ErrCertFileRequired
	}
	if !strings.HasPrefix(l.CertFile, def.Slash) {
		return def.ErrCertFileAbsolute
	}
	if l.KeyFile == "" {
		return def.ErrKeyFileRequired
	}
	if !strings.HasPrefix(l.KeyFile, def.Slash) {
		return def.ErrKeyFileAbsolute
	}
	return nil
}

func (l LocalCert) IsZero() bool {
	return l.Enabled.IsZero() && l.CertFile == "" && l.KeyFile == ""
}

type Pebble struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	URL        string        `hcl:"url,attr" json:"url"`
	Insecure   expect.Toggle `hcl:"insecure,attr" json:"insecure"`
	ChallSrv   string        `hcl:"chall_srv,attr" json:"chall_srv"`
	MgmtServer string        `hcl:"mgmt_server,attr" json:"mgmt_server"`
}

// Validate checks Pebble configuration and applies sensible URL defaults when enabled.
func (p *Pebble) Validate() error {
	if !p.Enabled.Active() {
		return nil
	}
	if p.URL == "" {
		p.URL = "https://localhost:14000/dir"
	}
	if p.ChallSrv == "" {
		p.ChallSrv = "http://localhost:8055"
	}
	if p.MgmtServer == "" {
		p.MgmtServer = "http://localhost:8055"
	}
	return nil
}

func (p Pebble) IsZero() bool {
	return p.Enabled.IsZero() &&
		p.URL == "" &&
		p.Insecure.IsZero() &&
		p.ChallSrv == "" &&
		p.MgmtServer == ""
}

type LetsEncrypt struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Staging    expect.Toggle `hcl:"staging,attr" json:"staging"`
	Email      string        `hcl:"email,attr" json:"email"`
	ShortLived bool          `hcl:"short_lived,attr" json:"short_lived"`
	Pebble     Pebble        `hcl:"pebble,block" json:"pebble"`
}

// Validate checks that the email address is valid when Let's Encrypt is enabled.
func (l *LetsEncrypt) Validate() error {
	if l.Enabled.NotActive() {
		return nil
	}

	l.Email = strings.TrimSpace(l.Email)
	if l.Email == "" {
		return def.ErrInvalidEmail
	}

	// err == nil means the format is valid according to RFC 5322
	// emailAddress.Address == email ensures there wasn't a display name component
	_, err := mail.ParseAddress(l.Email)
	if err != nil {
		return def.ErrInvalidEmail
	}

	if l.Pebble.Enabled.Active() {
		return l.Pebble.Validate()
	}

	return nil
}

func (l LetsEncrypt) IsZero() bool {
	return l.Enabled.IsZero() &&
		l.Staging.IsZero() &&
		l.Email == "" &&
		!l.ShortLived &&
		l.Pebble.IsZero()
}

type CustomCA struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Root    string        `hcl:"root,attr" json:"root"`
}

// Validate checks that the root path is present and absolute when custom CA is enabled.
func (c *CustomCA) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	if c.Root == "" {
		return def.ErrRootRequiredCustomCA
	}
	if !strings.HasPrefix(c.Root, def.Slash) {
		return def.ErrRootAbsolute
	}
	return nil
}

func (c CustomCA) IsZero() bool {
	return c.Enabled.IsZero() && c.Root == ""
}
