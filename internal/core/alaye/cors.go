package alaye

import (
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type CORS struct {
	Enabled          expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	AllowedOrigins   []string      `hcl:"allowed_origins,attr" json:"allowed_origins"`
	AllowedMethods   []string      `hcl:"allowed_methods,attr" json:"allowed_methods"`
	AllowedHeaders   []string      `hcl:"allowed_headers,attr" json:"allowed_headers"`
	ExposedHeaders   []string      `hcl:"exposed_headers,attr" json:"exposed_headers"`
	AllowCredentials bool          `hcl:"allow_credentials,attr" json:"allow_credentials"`
	MaxAge           int           `hcl:"max_age,attr" json:"max_age"`
}

// Validate checks that wildcard origins are not combined with allow_credentials.
func (c *CORS) Validate() error {
	if c.Enabled.NotActive() {
		return nil
	}
	for _, o := range c.AllowedOrigins {
		if o == "*" && c.AllowCredentials {
			return errors.New("cors: cannot use '*' origin with allow_credentials=true")
		}
	}
	return nil
}

func (c CORS) IsZero() bool {
	return c.Enabled.IsZero() &&
		len(c.AllowedOrigins) == 0 &&
		len(c.AllowedMethods) == 0 &&
		len(c.AllowedHeaders) == 0 &&
		len(c.ExposedHeaders) == 0 &&
		!c.AllowCredentials &&
		c.MaxAge == 0
}
