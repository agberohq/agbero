package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type BasicAuth struct {
	Enabled Enabled  `hcl:"enabled,optional" json:"enabled"`
	Users   []string `hcl:"users" json:"users"`
	Realm   string   `hcl:"realm,optional" json:"realm"`
}

func (b *BasicAuth) Validate() error {
	if b.Enabled.NotActive() {
		return nil
	}

	// Users validation
	if len(b.Users) == 0 {
		return ErrEmptyUsers
	}
	for i, user := range b.Users {
		user = strings.TrimSpace(user)
		if user == "" {
			return errors.Newf("users[%d]: %w", i, ErrCannotBeEmpty)
		}
		// Check for username:password format
		if !strings.Contains(user, ":") {
			return errors.Newf("%w: users[%d]: %q must be in format 'username:password'", ErrInvaliFormat, i, user)
		}
		b.Users[i] = user // Normalize
	}

	// Realm is optional, no validation needed
	return nil
}
