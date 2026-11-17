package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

// Protect configures a route-local login form and session cookie.
//
// Unlike basic_auth, the password is submitted once to Agbero's login endpoint
// and the browser thereafter carries a signed, HttpOnly session cookie. Users
// are still stored as bcrypt hashes (or ss:// references) in the route config.
type Protect struct {
	Enabled    expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	Title      string          `hcl:"title,attr" json:"title,omitempty"`
	Users      []string        `hcl:"users,attr" json:"users"`
	SessionTTL expect.Duration `hcl:"session_ttl,attr" json:"session_ttl,omitempty"`
	CookieName string          `hcl:"cookie_name,attr" json:"cookie_name,omitempty"`
}

// Validate checks that enabled Protect has users and a usable configuration.
func (a *Protect) Validate() error {
	if a.Enabled.NotActive() {
		return nil
	}
	if len(a.Users) == 0 {
		return errors.New("protect: at least one user is required")
	}
	for i, u := range a.Users {
		u = strings.TrimSpace(u)
		if u == "" {
			return errors.Newf("protect: users[%d] cannot be empty", i)
		}
		username, secret, ok := strings.Cut(u, ":")
		if !ok || strings.TrimSpace(username) == "" || strings.TrimSpace(secret) == "" {
			return errors.Newf("protect: users[%d] must be username:bcrypt-hash", i)
		}
		hash := strings.TrimSpace(secret)
		if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") && !strings.HasPrefix(hash, "$2y$") && !expect.Value(hash).IsSecretStoreRef() {
			return errors.Newf("protect: users[%d] must use a bcrypt hash or secret reference", i)
		}
		a.Users[i] = u
	}
	if a.SessionTTL < 0 {
		return errors.New("protect: session_ttl cannot be negative")
	}
	if a.CookieName != "" {
		for _, r := range a.CookieName {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
				return errors.Newf("protect: cookie_name %q contains invalid characters", a.CookieName)
			}
		}
	}
	return nil
}

func (a Protect) IsZero() bool {
	return a.Enabled.IsZero() &&
		a.Title == "" &&
		len(a.Users) == 0 &&
		a.SessionTTL == 0 &&
		a.CookieName == ""
}

// effectiveSessionTTL returns the configured TTL or the shared default.
func (a *Protect) effectiveSessionTTL() expect.Duration {
	if a.SessionTTL <= 0 {
		return expect.Duration(def.ProtectSessionTTL)
	}
	return a.SessionTTL
}
