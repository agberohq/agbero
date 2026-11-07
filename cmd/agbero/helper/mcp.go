package helper

import (
	"fmt"
	"os"
	"strings"
	"time"

	agmcp "github.com/agberohq/agbero/internal/operation/mcp"
	"github.com/agberohq/agbero/internal/pkg/revoke"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

type MCP struct {
	p *Helper
}

func (m *MCP) TokenCreate(_ string, user, scope string, ttl time.Duration) {
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

	u := ui.New()
	u.Render(func() {
		u.SectionHeader("MCP token")
		u.KeyValue("User", claims.Subject)
		u.KeyValue("Scope", claims.Scope)
		u.KeyValue("Expires", claims.ExpiresAt.Format(time.RFC3339))
		u.KeyValue("JTI", claims.ID)
	})
	fmt.Println(raw)
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
	if err := store.Revoke(jti, "mcp", time.Now().Add(agmcp.MaxTokenTTL)); err != nil {
		m.p.Logger.Fatal("revoke token: ", err)
	}
	ui.New().SuccessLine("MCP token revoked")
}
