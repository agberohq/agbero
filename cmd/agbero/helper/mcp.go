package helper

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	agmcp "github.com/agberohq/agbero/internal/operation/mcp"
	"github.com/agberohq/agbero/internal/pkg/revoke"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

type MCP struct {
	p *Helper
}

func (m *MCP) TokenCreate(configPath, user, scope string, ttl time.Duration) {
	if m.p.Store == nil {
		m.p.Logger.Fatal("keeper store is not available")
	}
	if strings.TrimSpace(user) == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = "operator"
		}
	}
	if strings.TrimSpace(scope) == "" {
		scope = agmcp.ScopeRead
	}
	if ttl <= 0 {
		ttl = agmcp.DefaultTokenTTL
	}

	store := agmcp.NewTokenStore(m.p.Store)
	if err := store.Ensure(); err != nil {
		m.p.Logger.Fatal("mcp token key: ", err)
	}
	raw, claims, err := store.Mint(user, strings.Fields(scope), ttl)
	if err != nil {
		m.p.Logger.Fatal("mint mcp token: ", err)
	}
	if global, err := LoadGlobal(configPath); err == nil {
		path := global.Storage.DataDir.FilePath("mcp-tokens.json")
		if reg, err := agmcp.OpenTokenRegistry(path); err == nil {
			_ = reg.Add(agmcp.TokenRecord{
				User: claims.Subject, Scope: claims.Scope, JTI: claims.ID,
				CreatedAt: time.Now(), ExpiresAt: claims.ExpiresAt.Time,
			})
		}
		m.audit(global, map[string]any{
			"event": "mcp_token_create", "actor": "cli", "user": claims.Subject,
			"jti": claims.ID, "scope": claims.Scope, "status": 200,
		})
	}

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("MCP token")
		u.Table([]string{"Field", "Value"}, [][]string{
			{"User", claims.Subject},
			{"Scope", claims.Scope},
			{"Expires", claims.ExpiresAt.Format(time.RFC3339)},
			{"JTI", claims.ID},
		})
		fmt.Println("Token (copy now):")
		fmt.Println(raw)
	})
}

func (m *MCP) TokenRotate() {
	if m.p.Store == nil {
		m.p.Logger.Fatal("keeper store is not available")
	}
	if err := agmcp.NewTokenStore(m.p.Store).Rotate(); err != nil {
		m.p.Logger.Fatal("rotate mcp token key: ", err)
	}
	ui.New().SuccessLine("MCP signing key rotated; existing tokens remain valid until the previous key is retired")
}

func (m *MCP) TokenRevoke(configPath, jti string) {
	if strings.TrimSpace(jti) == "" {
		m.p.Logger.Fatal("jti is required")
	}
	global, err := LoadGlobal(configPath)
	if err != nil {
		m.p.Logger.Fatal("load config: ", err)
	}
	store, err := revoke.New(global.Storage.DataDir, m.p.Logger)
	if err != nil {
		m.p.Logger.Fatal("open revoke store: ", err)
	}
	if err := store.Revoke(jti, def.MCPServiceName, time.Now().Add(agmcp.MaxTokenTTL)); err != nil {
		m.p.Logger.Fatal("revoke token: ", err)
	}
	m.audit(global, map[string]any{"event": "mcp_token_revoke", "actor": "cli", "jti": jti, "status": 200})
	ui.New().SuccessLine("MCP token revoked")
}

func (m *MCP) Status(configPath string) {
	global, err := LoadGlobal(configPath)
	if err != nil {
		m.p.Logger.Fatal("load config: ", err)
	}
	g := global.MCP
	u := ui.New()
	u.Render(func() {
		u.SectionHeader("MCP status")
		u.Table([]string{"Setting", "Value"}, [][]string{
			{"Enabled", toggleLabel(g.Enabled)},
			{"Transport", g.Transport},
			{"Read", toggleLabel(g.Read.Enabled)},
			{"Plan", toggleLabel(g.Plan.Enabled)},
			{"Rate limit", g.RateLimit},
			{"Allowed IPs", strings.Join(g.AllowedIPs, ", ")},
			{"Read allow", wrapList(g.Read.Allow, 4)},
			{"Plan allow", wrapList(g.Plan.Allow, 4)},
		})
	})
}

func (m *MCP) Policy() {
	u := ui.New()
	u.Render(func() {
		u.SectionHeader("MCP capability policy")
		rows := make([][]string, 0, len(agmcp.Registry))
		for _, c := range agmcp.Registry {
			rows = append(rows, []string{string(c.Class), c.Name, c.Tool})
		}
		u.Table([]string{"Class", "Capability", "Tool"}, rows)
	})
}

func toggleLabel(t interface{ Active() bool }) string {
	if t.Active() {
		return "on"
	}
	return "off"
}

func wrapList(items []string, perLine int) string {
	if len(items) == 0 {
		return ""
	}
	if perLine < 1 {
		perLine = 1
	}
	var b strings.Builder
	for i, item := range items {
		if i > 0 {
			if i%perLine == 0 {
				b.WriteString(",\n")
			} else {
				b.WriteString(", ")
			}
		}
		b.WriteString(item)
	}
	return b.String()
}

func (m *MCP) audit(global *alaye.Global, entry map[string]any) {
	if global == nil {
		return
	}
	path := strings.TrimSpace(global.MCP.AuditFile)
	if path == "" {
		path = global.Storage.DataDir.FilePath("mcp-audit.jsonl")
	}
	a, err := agmcp.OpenAuditor(path)
	if err != nil {
		return
	}
	defer a.Close()
	a.Log(entry)
}
