package bugs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

// The fixtures below are the REAL output of buildHostConfig() / buildHostHCL()
// for a draft that exercises every feature added in the "feature coverage" pass:
// tunnels, JWT audience + claim map, forward-auth options, Redis cache with a
// TTL policy, full CORS, Brotli, firewall/WAF rules, error pages and per-server
// connection caps.
//
// Both sides are *name-sensitive*: `claim_map` vs `claims_to_headers` and
// `policy` vs `ttl_policy` both fail silently at runtime (unknown JSON keys are
// dropped), so the payload is decoded with DisallowUnknownFields.

const wizardFeaturePayload = `{
  "domains": ["app.example.com"],
  "tls": {
    "mode": "letsencrypt",
    "lets_encrypt": { "enabled": "on", "email": "ops@example.com" }
  },
  "limits": { "max_body_size": 1048576 },
  "routes": [
    {
      "enabled": "on",
      "path": "/api",
      "backends": {
        "enabled": "on",
        "strategy": "consistent_hash",
        "servers": [
          { "address": "http://10.0.0.5:8080", "weight": 2, "max_connections": 128 },
          { "address": "http://10.0.0.6:8080", "weight": 1 }
        ],
        "via": "tor",
        "idempotent": true,
        "keys": ["ip", "header:X-User-ID"]
      },
      "cache": {
        "enabled": "on",
        "driver": "redis",
        "ttl": "10m",
        "redis": {
          "host": "redis.internal",
          "port": 6380,
          "password": "sekret",
          "db": 2,
          "key_prefix": "app:"
        },
        "policy": { "enabled": "on", "default": "2m", "key_scope": ["path", "query"] }
      },
      "cors": {
        "enabled": "on",
        "allowed_origins": ["https://app.example.com"],
        "allowed_methods": ["GET", "POST"],
        "allowed_headers": ["Content-Type", "Authorization"],
        "exposed_headers": ["X-Request-ID"],
        "max_age": 600,
        "allow_credentials": true
      },
      "rate_limit": {
        "enabled": "on",
        "use_policy": "api-default",
        "rule": { "enabled": "on", "requests": 120, "window": "1m", "burst": 200, "key": "ip" }
      },
      "compression": { "enabled": "on", "type": "brotli", "level": 5 },
      "jwt_auth": {
        "enabled": "on",
        "secret": "jwt-secret",
        "issuer": "https://issuer.example.com",
        "audience": "app-api",
        "claim_map": { "sub": "X-User-ID", "email": "X-User-Email" }
      }
    },
    {
      "enabled": "on",
      "path": "/admin",
      "backends": {
        "enabled": "on",
        "strategy": "round_robin",
        "servers": [{ "address": "http://10.0.0.7:9090", "weight": 1 }],
        "tunnel": "socks5://user:pass@127.0.0.1:9050"
      },
      "firewall": {
        "enabled": "on",
        "ignore_global": true,
        "apply_rules": ["block-scanners", "allow-office"]
      },
      "waf": {
        "enabled": "on",
        "ignore_global": true,
        "mode": "active",
        "directives": ["SecRuleEngine On"]
      },
      "error_pages": {
        "pages": { "404": "@ERRDIR@/404.html", "503": "@ERRDIR@/503.html" },
        "default": "@ERRDIR@/error.html"
      },
      "forward_auth": {
        "enabled": "on",
        "url": "http://auth.internal:4180/verify",
        "on_failure": "deny",
        "timeout": "5s",
        "allow_private": true
      }
    }
  ]
}`

// wizardFeatureHCL is what buildHostHCL() renders for the same draft.
const wizardFeatureHCL = `domains = ["app.example.com"]

limits {
  max_body_size = 1048576
}

tls {
  mode = "letsencrypt"

  letsencrypt {
    enabled = "on"
    email   = "ops@example.com"
  }
}

route "/api" {
  backend {
    strategy = "consistent_hash"
    keys = ["ip", "header:X-User-ID"]
    via        = "tor"
    idempotent = true
    server {
      address = "http://10.0.0.5:8080"
      weight  = 2
      max_connections = 128
    }
    server { address = "http://10.0.0.6:8080" }
  }

  rate_limit {
    enabled = "on"
    use_policy    = "api-default"

    rule {
      enabled  = "on"
      requests = 120
      window   = "1m"
      burst    = 200
      key      = "ip"
    }
  }

  cors {
    enabled = "on"
    allowed_origins = ["https://app.example.com"]
    allowed_methods = ["GET", "POST"]
    allowed_headers = ["Content-Type", "Authorization"]
    exposed_headers = ["X-Request-ID"]
    max_age = 600
    allow_credentials = true
  }

  cache {
    enabled = "on"
    driver  = "redis"
    ttl     = "10m"

    redis {
      host       = "redis.internal"
      port       = 6380
      password   = "sekret"
      db         = 2
      key_prefix = "app:"
    }

    policy {
      enabled = "on"
      default = "2m"
      key_scope = ["path", "query"]
    }
  }

  compression {
    enabled = "on"
    type    = "brotli"
    level   = 5
  }

  jwt_auth {
    enabled = "on"
    secret  = "jwt-secret"
    issuer   = "https://issuer.example.com"
    audience = "app-api"
    claims_to_headers = { "sub" = "X-User-ID", "email" = "X-User-Email" }
  }
}

route "/admin" {
  backend {
    tunnel     = "socks5://user:pass@127.0.0.1:9050"
    server { address = "http://10.0.0.7:9090" }
  }

  firewall {
    enabled = "on"
    ignore_global = true
    apply_rules = ["block-scanners", "allow-office"]
  }

  waf {
    enabled = "on"
    ignore_global = true
    mode = "active"
    directives = ["SecRuleEngine On"]
  }

  error_pages {
    pages = {
      "404" = "@ERRDIR@/404.html"
      "503" = "@ERRDIR@/503.html"
    }
    default = "@ERRDIR@/error.html"
  }

  forward_auth {
    enabled    = "on"
    url        = "http://auth.internal:4180/verify"
    on_failure = "deny"
    timeout       = "5s"
    allow_private = true
  }
}
`

// TestADMIN_WizardFeaturePayloadConformsToSchema holds the wizard's JSON output to
// the alaye schema, including the features that had no UI before this pass.
func TestADMIN_WizardFeaturePayloadConformsToSchema(t *testing.T) {
	dir := errDirWithPages(t)
	payload := strings.ReplaceAll(wizardFeaturePayload, "@ERRDIR@", dir)

	dec := json.NewDecoder(strings.NewReader(payload))
	dec.DisallowUnknownFields()

	var host alaye.Host
	if err := dec.Decode(&host); err != nil {
		t.Fatalf("wizard feature payload does not match alaye.Host: %v\n"+
			"unknown/renamed JSON tags are dropped silently — compare the builder "+
			"against internal/core/alaye/*.go", err)
	}

	if len(host.Routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(host.Routes))
	}
	api := host.Routes[0]

	if api.Backends.Via != "tor" {
		t.Errorf("backends.via lost (got %q) — tunnelled egress would silently go direct", api.Backends.Via)
	}
	if !api.Backends.Idempotent {
		t.Error("backends.idempotent lost")
	}
	if n := len(api.Backends.Servers); n != 2 || api.Backends.Servers[0].MaxConnections != 128 {
		t.Errorf("server max_connections lost: %+v", api.Backends.Servers)
	}

	if api.JWTAuth.Audience != "app-api" {
		t.Errorf("jwt_auth.audience lost (got %q) — tokens for any audience would be accepted", api.JWTAuth.Audience)
	}
	if got := api.JWTAuth.ClaimMap["sub"]; got != "X-User-ID" {
		t.Errorf("jwt_auth.claim_map lost (got %v) — JSON key is `claim_map`, not `claims_to_headers`", api.JWTAuth.ClaimMap)
	}

	if api.Cache.Driver != "redis" || api.Cache.Redis == nil {
		t.Fatalf("cache.redis lost: %+v", api.Cache)
	}
	rds := *api.Cache.Redis
	if rds.Host != "redis.internal" || rds.Port != 6380 || rds.Password != "sekret" ||
		rds.DB != 2 || rds.KeyPrefix != "app:" {
		t.Errorf("cache.redis fields lost: %+v", rds)
	}
	if !api.Cache.TTLPolicy.Enabled.Active() || len(api.Cache.TTLPolicy.KeyScope) != 2 {
		t.Errorf("cache.policy lost (%+v) — the block key is `policy`", api.Cache.TTLPolicy)
	}

	if len(api.CORS.AllowedMethods) != 2 || len(api.CORS.ExposedHeaders) != 1 || api.CORS.MaxAge != 600 {
		t.Errorf("cors extras lost: %+v", api.CORS)
	}
	if api.RateLimit.UsePolicy != "api-default" {
		t.Errorf("rate_limit.use_policy lost (got %q)", api.RateLimit.UsePolicy)
	}
	if api.Compression.Type != "brotli" || api.Compression.Level != 5 {
		t.Errorf("compression lost: %+v", api.Compression)
	}

	adm := host.Routes[1]
	if adm.Backends.Tunnel != "socks5://user:pass@127.0.0.1:9050" {
		t.Errorf("backends.tunnel lost (got %q)", adm.Backends.Tunnel)
	}
	if !adm.Firewall.Status.Active() || len(adm.Firewall.ApplyRules) != 2 || !adm.Firewall.IgnoreGlobal {
		t.Errorf("route firewall lost: %+v", adm.Firewall)
	}
	if !adm.WAF.Status.Active() || adm.WAF.Mode != "active" || len(adm.WAF.Directives) != 1 || !adm.WAF.IgnoreGlobal {
		t.Errorf("route waf lost: %+v", adm.WAF)
	}
	if len(adm.ErrorPages.Pages) != 2 || adm.ErrorPages.Default == "" {
		t.Errorf("error_pages lost: %+v", adm.ErrorPages)
	}
	if !adm.ForwardAuth.AllowPrivate {
		t.Error("forward_auth.allow_private lost — an internal auth service would be rejected as a private target")
	}
	if adm.ForwardAuth.Timeout.Seconds() != 5 {
		t.Errorf("forward_auth.timeout lost (got %v)", adm.ForwardAuth.Timeout)
	}

	woos.DefaultHost(&host)
	if err := host.Validate(); err != nil {
		t.Fatalf("wizard feature payload does not validate: %v", err)
	}
}

// errDirWithPages creates the error-page files the fixtures reference.
// Route.Validate stats every configured page.
func errDirWithPages(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"404.html", "503.html", "error.html"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("<html></html>"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// TestADMIN_WizardFeatureHCLRoundTrips parses the renderer's output, so the HCL
// preview/fallback path stays in sync with the JSON path.
func TestADMIN_WizardFeatureHCLRoundTrips(t *testing.T) {
	dir := errDirWithPages(t)
	body := strings.ReplaceAll(wizardFeatureHCL, "@ERRDIR@", dir)

	path := filepath.Join(t.TempDir(), "app.example.com.hcl")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp hcl: %v", err)
	}
	host, err := parser.ParseHostConfig(path)
	if err != nil {
		t.Fatalf("client-rendered HCL does not parse: %v", err)
	}
	if len(host.Routes) != 2 {
		t.Fatalf("decoded %d routes, want 2", len(host.Routes))
	}

	api := host.Routes[0]
	if api.Backends.Via != "tor" || !api.Backends.Idempotent {
		t.Errorf("backend via/idempotent lost in HCL: %+v", api.Backends)
	}
	if len(api.Backends.Servers) != 2 || api.Backends.Servers[0].MaxConnections != 128 {
		t.Errorf("server max_connections lost in HCL: %+v", api.Backends.Servers)
	}
	if api.JWTAuth.Audience != "app-api" || api.JWTAuth.ClaimMap["email"] != "X-User-Email" {
		t.Errorf("jwt_auth audience/claims lost in HCL: %+v", api.JWTAuth)
	}
	if api.Cache.Redis == nil || api.Cache.Redis.Host != "redis.internal" {
		t.Errorf("cache redis block lost in HCL: %+v", api.Cache)
	}
	if !api.Cache.TTLPolicy.Enabled.Active() || len(api.Cache.TTLPolicy.KeyScope) != 2 {
		t.Errorf("cache policy block lost in HCL: %+v", api.Cache.TTLPolicy)
	}
	if api.CORS.MaxAge != 600 || len(api.CORS.ExposedHeaders) != 1 {
		t.Errorf("cors max_age/exposed_headers lost in HCL: %+v", api.CORS)
	}
	if api.Compression.Type != "brotli" || api.Compression.Level != 5 {
		t.Errorf("compression lost in HCL: %+v", api.Compression)
	}
	if api.RateLimit.UsePolicy != "api-default" {
		t.Errorf("rate_limit.use_policy lost in HCL: %+v", api.RateLimit)
	}

	adm := host.Routes[1]
	if adm.Backends.Tunnel == "" {
		t.Errorf("backend tunnel lost in HCL: %+v", adm.Backends)
	}
	if len(adm.Firewall.ApplyRules) != 2 || !adm.Firewall.IgnoreGlobal {
		t.Errorf("firewall apply_rules/ignore_global lost in HCL: %+v", adm.Firewall)
	}
	if adm.WAF.Mode != "active" || len(adm.WAF.Directives) != 1 {
		t.Errorf("waf block lost in HCL: %+v", adm.WAF)
	}
	if len(adm.ErrorPages.Pages) != 2 || adm.ErrorPages.Pages["404"] == "" {
		t.Errorf("error_pages lost in HCL: %+v", adm.ErrorPages)
	}
	if !adm.ForwardAuth.AllowPrivate || adm.ForwardAuth.Timeout.Seconds() != 5 {
		t.Errorf("forward_auth options lost in HCL: %+v", adm.ForwardAuth)
	}

	woos.DefaultHost(host)
	if err := host.Validate(); err != nil {
		t.Fatalf("HCL-rendered host does not validate: %v", err)
	}
}

// wizardServerlessHCL covers the serverless additions: artifact root, git source
// with auth, and the route-level env map (previously builder-only, no UI).
const wizardServerlessRootHCL = `domains = ["sl.example"]

route "/fn" {
  serverless {
    root = "/var/lib/agbero/apps/fn"
    git {
      enabled  = "on"
      url      = "https://github.com/org/repo.git"
      id       = "fn"
      branch   = "main"
      interval = "5m"

      auth {
        type = "basic"
        username = "git"
        password = "s3cret"
      }
    }

    work "render" {
      enabled  = "on"
      command  = ["node", "index.js"]
      landlock = "on"
    }
  }
  env = { "NODE_ENV" = "production", "API_URL" = "https://api.internal,with,commas" }
}
`

// TestADMIN_WizardHCLServerlessRootGitEnv guards the serverless root/git-auth and
// route env additions, including that an attribute *after* a block still parses.
func TestADMIN_WizardHCLServerlessRootGitEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sl.example.hcl")
	if err := os.WriteFile(path, []byte(wizardServerlessRootHCL), 0o600); err != nil {
		t.Fatalf("write temp hcl: %v", err)
	}
	host, err := parser.ParseHostConfig(path)
	if err != nil {
		t.Fatalf("serverless HCL does not parse: %v", err)
	}
	if len(host.Routes) != 1 {
		t.Fatalf("decoded %d routes, want 1", len(host.Routes))
	}
	r := host.Routes[0]
	if r.Serverless.Root != "/var/lib/agbero/apps/fn" {
		t.Errorf("serverless.root lost (got %q)", r.Serverless.Root)
	}
	g := r.Serverless.Git
	if !g.Enabled.Active() || g.ID != "fn" || g.URL == "" || g.Interval == 0 {
		t.Errorf("serverless git lost: %+v", g)
	}
	if g.Auth.Type != "basic" || g.Auth.Username != "git" || g.Auth.Password.String() != "s3cret" {
		t.Errorf("serverless git auth lost: %+v", g.Auth)
	}
	if len(r.Serverless.Workers) != 1 || r.Serverless.Workers[0].Name != "render" {
		t.Errorf("work block lost: %+v", r.Serverless.Workers)
	}
	if got := r.Env["API_URL"].String(); got != "https://api.internal,with,commas" {
		t.Errorf("env map lost or comma-split (got %q) — builder must split on newlines only", got)
	}
	if len(r.Env) != 2 {
		t.Errorf("expected 2 env entries, got %d", len(r.Env))
	}
}
