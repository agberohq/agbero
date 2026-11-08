package bugs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

// Documentation accuracy tests.
//
// The HCL decoder ignores attributes it does not recognise, so a wrong key in the
// docs produces NO error at runtime — it is silently dropped (this is how
// `security.trusted_proxies` survived in three docs). These tests pin the
// snippets that the docs publish so the same class of drift fails CI instead.

// loadGlobalHCL writes body to a temp agbero.hcl (with the current config
// version) and decodes it through the real parser.
func loadGlobalHCL(t *testing.T, body string) (*alaye.Global, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agbero.hcl")
	content := fmt.Sprintf("version = %d\n\n%s", def.ConfigFormatVersion, body)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return parser.LoadGlobal(path)
}

// TestDOCS_SecurityAllowProxies guards docs/security.md#trusted-proxies and
// docs/global.md §9: trusted proxies are configured as security.allow.proxies.
func TestDOCS_SecurityAllowProxies(t *testing.T) {
	g, err := loadGlobalHCL(t, `
bind { http = [":8080"] }

security {
  enabled = "on"

  allow {
    proxies = ["127.0.0.0/8", "10.0.0.0/8"]
  }

  block_private_backends = true
}
`)
	if err != nil {
		t.Fatalf("documented security.allow snippet does not parse: %v", err)
	}
	if got := len(g.Security.Allow.Proxies); got != 2 {
		t.Fatalf("security.allow.proxies decoded %d entries, want 2 — the documented key is wrong", got)
	}
	if !g.Security.BlockPrivateBackends {
		t.Fatalf("security.block_private_backends did not decode — the documented key is wrong")
	}
}

// TestDOCS_UnknownKeysAreSilentlyIgnored documents the trap the docs now warn
// about: a top-level `trusted_proxies` key is accepted without error and thrown
// away, so IP-based features silently see the proxy address.
func TestDOCS_UnknownKeysAreSilentlyIgnored(t *testing.T) {
	g, err := loadGlobalHCL(t, `
bind { http = [":8080"] }

security {
  enabled = "on"
  trusted_proxies = ["10.0.0.0/8"]
}
`)
	if err != nil {
		t.Fatalf("unexpected parse error for an unknown attribute: %v", err)
	}
	if len(g.Security.Allow.Proxies) != 0 {
		t.Fatalf("expected the stray trusted_proxies key to be dropped, but allow.proxies is %v",
			g.Security.Allow.Proxies)
	}
}

// TestDOCS_TunnelBlock guards the `tunnel` section added to
// docs/global.md and docs/reference.md.
func TestDOCS_TunnelBlock(t *testing.T) {
	g, err := loadGlobalHCL(t, `
bind { http = [":8080"] }

tunnel "tor" {
  enabled  = "on"
  protocol = "socks5"
  servers  = ["127.0.0.1:9050", "127.0.0.1:9051"]
  strategy = "round_robin"
}

tunnel "vpn-exit" {
  enabled  = "on"
  protocol = "socks5"
  servers  = ["vpn.example.com:1080"]
  username = "myuser"
  password = "ss://network/vpn-pass"
}
`)
	if err != nil {
		t.Fatalf("documented tunnel snippet does not parse: %v", err)
	}
	if len(g.Tunnels) != 2 {
		t.Fatalf("decoded %d tunnel blocks, want 2", len(g.Tunnels))
	}
	if g.Tunnels[0].Name != "tor" || len(g.Tunnels[0].Servers) != 2 {
		t.Fatalf("unexpected tunnel decode: %+v", g.Tunnels[0])
	}
	if g.Tunnels[1].Username.String() != "myuser" {
		t.Fatalf("tunnel username did not decode: %q", g.Tunnels[1].Username.String())
	}
}

// TestDOCS_RateLimitsAreBlocks guards docs/api.md and docs/host.md:
// `rate_limits` uses labelled `rule "name" { }` / `policy "name" { }` blocks.
// A `rules = [...]` attribute is not part of the schema, and `name = "..."`
// written *inside* a rule block is silently dropped because `name` is the block
// label.
func TestDOCS_RateLimitsAreBlocks(t *testing.T) {
	g, err := loadGlobalHCL(t, `
bind { http = [":8080"] }

rate_limits {
  enabled = "on"

  rule "auto-api" {
    enabled  = "off"
    prefixes = ["/auto/"]
  }

  policy "api-strict" {
    requests = 10
    window   = "1m"
    burst    = 15
  }
}
`)
	if err != nil {
		t.Fatalf("documented rate_limits snippet does not parse: %v", err)
	}
	if len(g.RateLimits.Rules) != 1 || g.RateLimits.Rules[0].Name != "auto-api" {
		t.Fatalf("rate_limits rule label did not decode: %+v", g.RateLimits.Rules)
	}
	if len(g.RateLimits.Policies) != 1 || g.RateLimits.Policies[0].Name != "api-strict" {
		t.Fatalf("rate_limits policy label did not decode: %+v", g.RateLimits.Policies)
	}
}

// TestDOCS_FirewallRuleUsesLabel guards docs/host.md firewall examples: the rule
// name is the block label, and a missing label fails validation.
func TestDOCS_FirewallRuleUsesLabel(t *testing.T) {
	g, err := loadGlobalHCL(t, `
bind { http = [":8080"] }

security {
  enabled = "on"
  firewall {
    enabled = "on"
    rule "admin-only" {
      type   = "static"
      action = "deny"
      match {
        all {
          location = "ip"
          pattern  = "!^10\\.0\\.0\\."
        }
      }
    }
  }
}
`)
	if err != nil {
		t.Fatalf("documented firewall rule snippet does not parse: %v", err)
	}
	if len(g.Security.Firewall.Rules) != 1 {
		t.Fatalf("decoded %d firewall rules, want 1", len(g.Security.Firewall.Rules))
	}
	if g.Security.Firewall.Rules[0].Name != "admin-only" {
		t.Fatalf("firewall rule label did not decode, got %q — docs must use rule \"name\" { }",
			g.Security.Firewall.Rules[0].Name)
	}
}
