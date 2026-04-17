package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type OAuth struct {
	Enabled      expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Provider     string        `hcl:"provider,attr" json:"provider"`
	ClientID     string        `hcl:"client_id,attr" json:"client_id"`
	ClientSecret expect.Value  `hcl:"client_secret,attr" json:"client_secret"`
	RedirectURL  string        `hcl:"redirect_url,attr" json:"redirect_url"`
	AuthURL      string        `hcl:"auth_url,attr" json:"auth_url"`
	TokenURL     string        `hcl:"token_url,attr" json:"token_url"`
	UserApiURL   string        `hcl:"user_api_url,attr" json:"user_api_url"`
	Scopes       []string      `hcl:"scopes,attr" json:"scopes"`
	CookieSecret expect.Value  `hcl:"cookie_secret,attr" json:"cookie_secret"`
	EmailDomains []string      `hcl:"email_domains,attr" json:"email_domains"`
}

// Validate checks required OAuth fields when enabled.
// It does not set default scopes — those are applied by woos.defaultOAuth.
func (o *OAuth) Validate() error {
	if !o.Enabled.Active() {
		return nil
	}
	if o.Provider == "" {
		return errors.New("oauth provider is required")
	}
	if o.ClientID == "" {
		return errors.New("client_id is required")
	}
	if o.ClientSecret == "" {
		return errors.New("client_secret is required")
	}
	if o.RedirectURL == "" {
		return errors.New("redirect_url is required")
	}
	if o.CookieSecret == "" || len(o.CookieSecret) < 16 {
		return errors.New("cookie_secret must be at least 16 characters")
	}
	return nil
}

func (o OAuth) IsZero() bool {
	return o.Enabled.IsZero() &&
		o.Provider == "" &&
		o.ClientID == "" &&
		o.ClientSecret == "" &&
		o.RedirectURL == "" &&
		o.AuthURL == "" &&
		o.TokenURL == "" &&
		o.UserApiURL == "" &&
		len(o.Scopes) == 0 &&
		o.CookieSecret == "" &&
		len(o.EmailDomains) == 0
}
