package alaye

import (
	"fmt"

	"github.com/agberohq/agbero/internal/core/expect"
)

// REST defines an in-memory API proxy handler using Go's native http client.
// It supports secret-aware header and query parameter injection for secure forwarding.
type REST struct {
	Name         string                  `hcl:"name,label" json:"name"`
	Enabled      Enabled                 `hcl:"enabled,attr" json:"enabled"`
	Env          map[string]expect.Value `hcl:"env,attr" json:"env"`
	URL          string                  `hcl:"url,attr" json:"url"`
	Method       string                  `hcl:"method,attr" json:"method"`
	Headers      map[string]string       `hcl:"headers,attr" json:"headers"`
	Query        map[string]expect.Value `hcl:"query,attr" json:"query"`
	ForwardQuery bool                    `hcl:"forward_query,attr" json:"forward_query"`
	Timeout      Duration                `hcl:"timeout,attr" json:"timeout"`
	Cache        Cache                   `hcl:"cache,block" json:"cache"`
}

// Validate checks the REST block for required fields and logical consistency.
// It ensures the target URL is provided and validates caching parameters.
func (r *REST) Validate() error {
	if r.URL == "" {
		return fmt.Errorf("rest %s: url is required", r.Name)
	}
	return r.Cache.Validate()
}
