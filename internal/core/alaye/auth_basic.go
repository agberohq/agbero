package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type BasicAuth struct {
	Enabled Enabled  `hcl:"enabled,attr" json:"enabled"`
	Users   []string `hcl:"users,attr" json:"users"`
	Realm   string   `hcl:"realm,attr" json:"realm"`
}

// Validate checks that users are present and formatted as username:password pairs.
// Each entry is trimmed of whitespace and normalised in place.
func (b *BasicAuth) Validate() error {
	if b.Enabled.NotActive() {
		return nil
	}

	if len(b.Users) == 0 {
		return ErrEmptyUsers
	}
	for i, user := range b.Users {
		user = strings.TrimSpace(user)
		if user == "" {
			return errors.Newf("users[%d]: %w", i, ErrCannotBeEmpty)
		}
		if !strings.Contains(user, ":") {
			return errors.Newf("%w: users[%d]: %q must be in format 'username:password'", ErrInvaliFormat, i, user)
		}
		b.Users[i] = user
	}

	return nil
}
