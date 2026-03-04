package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type CORS struct {
	Enabled          Enabled  `hcl:"enabled,optional" json:"enabled"`
	AllowedOrigins   []string `hcl:"allowed_origins,optional" json:"allowed_origins"`
	AllowedMethods   []string `hcl:"allowed_methods,optional" json:"allowed_methods"`
	AllowedHeaders   []string `hcl:"allowed_headers,optional" json:"allowed_headers"`
	ExposedHeaders   []string `hcl:"exposed_headers,optional" json:"exposed_headers"`
	AllowCredentials bool     `hcl:"allow_credentials,optional" json:"allow_credentials"`
	MaxAge           int      `hcl:"max_age,optional" json:"max_age"`
}

func (c *CORS) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}

	// Validate origins
	for _, o := range c.AllowedOrigins {
		if o == "*" && c.AllowCredentials {
			return errors.New("cors: cannot use '*' origin with allow_credentials=true")
		}
	}

	// Normalize methods
	for i, m := range c.AllowedMethods {
		c.AllowedMethods[i] = strings.ToUpper(m)
	}

	return nil
}
