package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type BasicAuth struct {
	// List of "username:password" (Plaintext for now, or bcrypt in future)
	Users []string `hcl:"users"`
	Realm string   `hcl:"realm,optional"`
}

func (b *BasicAuth) Validate() error {
	// Users validation
	if len(b.Users) == 0 {
		return errors.New("users cannot be empty for basic_auth")
	}
	for i, user := range b.Users {
		user = strings.TrimSpace(user)
		if user == "" {
			return errors.Newf("users[%d]: cannot be empty", i)
		}
		// Check for username:password format
		if !strings.Contains(user, ":") {
			return errors.Newf("users[%d]: %q must be in format 'username:password'", i, user)
		}
		b.Users[i] = user // Normalize
	}

	// Realm is optional, no validation needed
	return nil
}
