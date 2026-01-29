package alaye

import (
	"github.com/olekukonko/errors"
)

type JWTAuth struct {
	// Secret for HMAC (HS256) or Path to Public Key (RS256/ES256)
	Secret Value `hcl:"secret"`
	// Map claims to headers: e.g. "sub" = "X-User-ID"
	ClaimMap map[string]string `hcl:"claims_to_headers,optional"`
	// Optional: Validate 'iss' or 'aud'
	Issuer   string `hcl:"issuer,optional"`
	Audience string `hcl:"audience,optional"`
}

func (j *JWTAuth) Validate() error {
	if j.Secret == "" {
		return errors.New("jwt_auth: secret is required")
	}
	return nil
}
