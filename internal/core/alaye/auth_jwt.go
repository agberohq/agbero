package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type JWTAuth struct {
	Enabled  expect.Toggle     `hcl:"enabled,attr" json:"enabled"`
	Secret   expect.Value      `hcl:"secret,attr" json:"secret"`
	ClaimMap map[string]string `hcl:"claims_to_headers,attr" json:"claim_map"`
	Issuer   string            `hcl:"issuer,attr" json:"issuer"`
	Audience string            `hcl:"audience,attr" json:"audience"`
}

// Validate checks that a secret is present when JWT auth is enabled.
func (j *JWTAuth) Validate() error {
	if j.Enabled.NotActive() {
		return nil
	}

	if j.Secret == "" {
		return errors.Newf("jwt_auth: %w", ErrSecretRequired)
	}
	return nil
}
