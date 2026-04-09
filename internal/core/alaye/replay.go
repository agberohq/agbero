package alaye

import (
	"fmt"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
)

// validHTTPMethods is the set of methods the Replay handler accepts in Methods.
var validHTTPMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {},
	"DELETE": {}, "HEAD": {}, "OPTIONS": {},
}

type Replay struct {
	Name    string        `hcl:"name,label"    json:"name"`
	Enabled expect.Toggle `hcl:"enabled,attr"  json:"enabled"`

	Env map[string]expect.Value `hcl:"env,attr" json:"env"`

	URL          string                  `hcl:"url,attr"           json:"url"`
	Methods      []string                `hcl:"methods,attr"       json:"methods"`
	Headers      map[string]string       `hcl:"headers,attr"       json:"headers"`
	Query        map[string]expect.Value `hcl:"query,attr"         json:"query"`
	ForwardQuery expect.Toggle           `hcl:"forward_query,attr" json:"forward_query"`
	Timeout      Duration                `hcl:"timeout,attr"       json:"timeout"`
	Cache        Cache                   `hcl:"cache,block"        json:"cache"`

	// Replay mode (url must be empty).
	AllowedDomains []string      `hcl:"allowed_domains,attr" json:"allowed_domains"`
	StripHeaders   expect.Toggle `hcl:"strip_headers,attr"   json:"strip_headers"`
	Auth           RestAuth      `hcl:"auth,block"           json:"auth"`

	// Referer handling for upstream requests
	RefererMode  string `hcl:"referer_mode,attr"  json:"referer_mode"`  // "auto" | "fixed" | "forward" | "none"
	RefererValue string `hcl:"referer_value,attr" json:"referer_value"` // used when referer_mode = "fixed"
}

// RestAuth configures the authentication guard for replay mode.
type RestAuth struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Method  string        `hcl:"method,attr"  json:"method"`
	Secret  expect.Value  `hcl:"secret,attr"  json:"secret"`
}

// IsReplayMode reports whether this Replay block is configured in replay mode
// (dynamic upstream URL rather than a fixed one).
func (r *Replay) IsReplayMode() bool {
	return r.URL == ""
}

// NormalisedMethods returns Methods uppercased. The slice is nil when Methods
// is empty (meaning all methods are allowed).
func (r *Replay) NormalisedMethods() []string {
	if len(r.Methods) == 0 {
		return nil
	}
	out := make([]string, len(r.Methods))
	for i, m := range r.Methods {
		out[i] = strings.ToUpper(strings.TrimSpace(m))
	}
	return out
}

// UpstreamMethod returns the HTTP method to use for the outgoing upstream
// request given the incoming request method.
func (r *Replay) UpstreamMethod(incoming string) string {
	nm := r.NormalisedMethods()
	if len(nm) == 1 && !r.IsReplayMode() {
		return nm[0]
	}
	if incoming == "" {
		return "GET"
	}
	return strings.ToUpper(incoming)
}

func (r *Replay) Validate() error {
	if r.URL == "" && len(r.AllowedDomains) == 0 {
		return fmt.Errorf("replay %s: replay mode requires at least one allowed_domain", r.Name)
	}

	for _, m := range r.Methods {
		upper := strings.ToUpper(strings.TrimSpace(m))
		if _, ok := validHTTPMethods[upper]; !ok {
			return fmt.Errorf("replay %s: unsupported method %q", r.Name, m)
		}
	}

	if r.Auth.Enabled.Active() {
		switch r.Auth.Method {
		case "meta", "token", "direct":
		case "":
			return fmt.Errorf("replay %s: auth.method is required when auth is enabled", r.Name)
		default:
			return fmt.Errorf("replay %s: unknown auth.method %q — use meta, token, or direct", r.Name, r.Auth.Method)
		}
	}

	// Validate referer_mode if set
	if r.RefererMode != "" && r.RefererMode != "auto" && r.RefererMode != "fixed" && r.RefererMode != "forward" && r.RefererMode != "none" {
		return fmt.Errorf("replay %s: invalid referer_mode %q — use auto, fixed, forward, or none", r.Name, r.RefererMode)
	}

	return r.Cache.Validate()
}
