package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type OAuth struct {
	Enabled      Enabled `hcl:"enabled,optional" json:"enabled"`
	Provider     string  `hcl:"provider" json:"provider"` // "google", "github", "oidc"
	ClientID     string  `hcl:"client_id" json:"client_id"`
	ClientSecret Value   `hcl:"client_secret" json:"client_secret"`
	RedirectURL  string  `hcl:"redirect_url" json:"redirect_url"`          // e.g. https://agbero.com/auth/callback
	AuthURL      string  `hcl:"auth_url,optional" json:"auth_url"`         // For generic/custom provider
	TokenURL     string  `hcl:"token_url,optional" json:"token_url"`       // For generic/custom provider
	UserApiURL   string  `hcl:"user_api_url,optional" json:"user_api_url"` // For generic (to fetch email)

	Scopes       []string `hcl:"scopes,optional" json:"scopes"`
	CookieSecret Value    `hcl:"cookie_secret" json:"cookie_secret"`          // To encrypt session cookie
	EmailDomains []string `hcl:"email_domains,optional" json:"email_domains"` // Restrict to @company.com
}

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

	// Default Scopes if empty
	if len(o.Scopes) == 0 {
		if strings.EqualFold(o.Provider, ProviderGoogle) || strings.EqualFold(o.Provider, ProviderOIDC) {
			o.Scopes = []string{ScopeOpenID, ScopeProfile, ScopeEmail}
		} else if strings.EqualFold(o.Provider, ProviderGitHub) {
			o.Scopes = []string{"user:email"}
		}
	}

	return nil
}
