package alaye

import (
	"encoding/json"
	"net/url"
	"slices"

	"github.com/agberohq/agbero/internal/core/def"
)

// RedactRoute blanks every credential-bearing field on a route in place.
//
// Callers must pass a copy that they own — never a pointer obtained from
// discovery.LoadAll()/HostManager.Get(), which return the live routing config.
// Use RedactHost/RedactHosts for that.
//
// Fields typed expect.Value already redact themselves on MarshalJSON
// (expect/value.go:140); they are reset here as well so that a change to the
// marshaller can never silently start leaking them.
func RedactRoute(r *Route) {
	if r == nil {
		return
	}
	r.BasicAuth.Users = nil
	r.JWTAuth.Secret = def.RedactedValue
	r.OAuth.ClientSecret = def.RedactedValue
	r.OAuth.CookieSecret = def.RedactedValue
	r.ForwardAuth.URL = def.RedactedValue
	r.ForwardAuth.TLS.ClientCert = def.RedactedValue
	r.ForwardAuth.TLS.ClientKey = def.RedactedValue

	if len(r.Wasm.Config) > 0 {
		r.Wasm.Config = map[string]string{def.RedactedValue: def.RedactedValue}
	}

	// Backend tunnels are often written inline as socks5://user:pass@host:port.
	if r.Backends.Tunnel != "" {
		r.Backends.Tunnel = def.RedactedValue
	}

	redactGit(&r.Web.Git)
	redactGit(&r.Serverless.Git)

	// Cache credentials are plain strings, so the JSON marshaller cannot
	// redact them on its own.
	redactCache(&r.Cache, &r.Serverless)
	redactServerless(&r.Serverless)
}

// redactCache blanks Redis passwords on the route cache, every replay cache and
// every worker cache.
func redactCache(c *Cache, s *Serverless) {
	if c != nil && c.Redis != nil {
		c.Redis.Password = def.RedactedValue
	}
	if s == nil {
		return
	}
	for i := range s.Replay {
		if s.Replay[i].Cache.Redis != nil {
			s.Replay[i].Cache.Redis.Password = def.RedactedValue
		}
	}
	for i := range s.Workers {
		if s.Workers[i].Cache.Redis != nil {
			s.Workers[i].Cache.Redis.Password = def.RedactedValue
		}
	}
}

// redactServerless blanks credentials inside replay blocks: the URL may carry
// userinfo, headers often carry bearer tokens, and Auth.Secret is a credential
// even when it is not a secret-store reference.
func redactServerless(s *Serverless) {
	if s == nil {
		return
	}
	for i := range s.Replay {
		rep := &s.Replay[i]
		if len(rep.Headers) > 0 {
			for k := range rep.Headers {
				rep.Headers[k] = def.RedactedValue
			}
		}
		if rep.URL != "" {
			rep.URL = redactURLUserinfo(rep.URL)
		}
		rep.Auth.Secret = def.RedactedValue
	}
}

// redactURLUserinfo keeps the scheme/host/path but strips user:pass. A URL that
// fails to parse is replaced outright, since it may still hold a secret.
func redactURLUserinfo(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return def.RedactedValue
	}
	if u.User == nil {
		return raw
	}
	u.User = url.User(def.RedactedValue)
	return u.String()
}

func redactGit(g *Git) {
	if g == nil {
		return
	}
	g.Secret = def.RedactedValue
	g.Auth.Password = def.RedactedValue
	g.Auth.SSHKey = def.RedactedValue
	g.Auth.SSHKeyPassphrase = def.RedactedValue
}

// RedactHost returns a redacted deep copy of h. The input is never mutated, so
// a read-only API call can no longer corrupt the live route configuration.
func RedactHost(h *Host) *Host {
	if h == nil {
		return nil
	}
	clone := cloneHost(h)
	for i := range clone.Routes {
		RedactRoute(&clone.Routes[i])
	}
	return clone
}

// RedactHosts redacts every host in the map, returning new values.
func RedactHosts(hosts map[string]*Host) map[string]*Host {
	out := make(map[string]*Host, len(hosts))
	for k, v := range hosts {
		if v == nil {
			continue
		}
		out[k] = RedactHost(v)
	}
	return out
}

// RedactGlobal returns a redacted deep copy of the global configuration.
func RedactGlobal(g *Global) *Global {
	if g == nil {
		return nil
	}
	b, err := json.Marshal(g)
	if err != nil {
		return nil
	}
	var clone Global
	if err := json.Unmarshal(b, &clone); err != nil {
		return nil
	}

	clone.Gossip.SecretKey = def.RedactedValue
	if clone.Gossip.SharedState.Redis != nil {
		clone.Gossip.SharedState.Redis.Password = def.RedactedValue
	}
	for i := range clone.Tunnels {
		clone.Tunnels[i].Username = def.RedactedValue
		clone.Tunnels[i].Password = def.RedactedValue
	}
	clone.Security.Keeper.Passphrase = def.RedactedValue
	clone.Security.Keeper.PassphraseFile = def.RedactedValue
	for i := range clone.Security.Allow.Proxies {
		clone.Security.Allow.Proxies[i] = def.RedactedValue
	}
	clone.LetsEncrypt.Email = def.RedactedValue
	clone.Admin.ForwardAuth.URL = def.RedactedValue
	clone.Admin.OAuth.ClientSecret = def.RedactedValue
	clone.Admin.OAuth.CookieSecret = def.RedactedValue

	clone.Storage.HostsDir = "<configured>"
	clone.Storage.CertsDir = "<configured>"
	clone.Storage.DataDir = "<configured>"
	clone.Storage.WorkDir = "<configured>"
	return &clone
}

// cloneHost deep-copies a host config through JSON. The shallow fallback is
// only there so a marshal failure can never hand back the live object.
func cloneHost(h *Host) *Host {
	if b, err := json.Marshal(h); err == nil {
		var out Host
		if err := json.Unmarshal(b, &out); err == nil {
			return &out
		}
	}
	c := *h
	c.Domains = slices.Clone(h.Domains)
	c.Bind = slices.Clone(h.Bind)
	c.Routes = slices.Clone(h.Routes)
	c.Proxies = slices.Clone(h.Proxies)
	return &c
}
