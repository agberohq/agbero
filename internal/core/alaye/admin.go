package alaye

import (
	"net"
	"strings"

	"github.com/olekukonko/errors"
)

type Admin struct {
	Enabled    Enabled  `hcl:"enabled,attr" json:"enabled"`
	Address    string   `hcl:"address,attr" json:"address"`
	AllowedIPs []string `hcl:"allowed_ips,attr" json:"allowed_ips"`

	TOTP TOTP `hcl:"totp,block" json:"totp"`

	BasicAuth   BasicAuth   `hcl:"basic_auth,block" json:"basic_auth"`
	ForwardAuth ForwardAuth `hcl:"forward_auth,block" json:"forward_auth"`
	JWTAuth     JWTAuth     `hcl:"jwt_auth,block" json:"jwt_auth"`
	OAuth       OAuth       `hcl:"o_auth,block" json:"o_auth"`

	Pprof     Pprof     `hcl:"pprof,block" json:"pprof"`
	Telemetry Telemetry `hcl:"telemetry,block" json:"telemetry"`
}

func (a *Admin) Validate() error {
	if a.Enabled.NotActive() {
		return nil
	}

	if a.Address == "" {
		return ErrAdminAddressRequired
	}

	if _, _, err := net.SplitHostPort(a.Address); err != nil {
		if strings.HasPrefix(a.Address, ":") {
			if _, err := net.LookupPort(TCP, a.Address[1:]); err != nil {
				return err
			}
		} else {
			return err
		}
	}

	if err := a.BasicAuth.Validate(); err != nil {
		return errors.Newf("basic_auth: %w", err)
	}

	if err := a.ForwardAuth.Validate(); err != nil {
		return errors.Newf("forward_auth: %w", err)
	}

	if err := a.JWTAuth.Validate(); err != nil {
		return errors.Newf("jwt_auth: %w", err)
	}

	if err := a.OAuth.Validate(); err != nil {
		return errors.Newf("o_auth: %w", err)
	}

	if err := a.Pprof.Validate(); err != nil {
		return errors.Newf("pprof: %w", err)
	}
	return nil
}

type TOTP struct {
	Enabled    Enabled    `hcl:"enabled,attr" json:"enabled"`
	Users      []TOTPUser `hcl:"user,block" json:"users"`
	Issuer     string     `hcl:"issuer,attr" json:"issuer"`
	Algorithm  string     `hcl:"algorithm,attr" json:"algorithm"`
	Digits     int        `hcl:"digits,attr" json:"digits"`
	Period     int        `hcl:"period,attr" json:"period"`
	WindowSize int        `hcl:"window_size,attr" json:"window_size"`
}

type TOTPUser struct {
	Username string `hcl:"username,attr" json:"username"`
	Secret   Value  `hcl:"secret,attr" json:"secret"`
}

func (t *TOTP) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}

	if len(t.Users) == 0 {
		return errors.New("totp enabled but no users configured")
	}

	for _, u := range t.Users {
		if u.Secret.Empty() {
			return errors.Newf("user %q: missing secret", u.Username)
		}
	}
	return nil
}

func (t *TOTP) GetUserSecret(username string) (string, bool) {
	for _, user := range t.Users {
		if user.Username == username {
			if user.Secret.Empty() {
				return "", false
			}
			val, err := user.Secret.ResolveErr(nil)
			if err != nil || val == "" {
				return "", false
			}
			return val, true
		}
	}
	return "", false
}
