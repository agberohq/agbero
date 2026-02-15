package alaye

import (
	"github.com/olekukonko/errors"
)

type JWTAuth struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`

	// Secret for HMAC (HS256) or Path to Public Key (RS256/ES256)
	Secret Value `hcl:"secret" json:"secret"`
	// Map claims to headers: e.g. "sub" = "X-User-ID"
	ClaimMap map[string]string `hcl:"claims_to_headers,optional" json:"claim_map"`
	// Optional: Validate 'iss' or 'aud'
	Issuer   string `hcl:"issuer,optional" json:"issuer"`
	Audience string `hcl:"audience,optional" json:"audience"`
}

func (j *JWTAuth) Validate() error {
	if j.Enabled.No() {
		return nil
	}

	if j.Secret == "" {
		return errors.Newf("jwt_auth: %w", ErrSecretRequired)
	}
	return nil
}
