package helper

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
)

// Cluster orchestrates the pre-flight checks and HCL patching needed before
// agbero can operate in cluster mode. Neither Start nor Join attempt to boot
// the server — they validate, patch config, and tell the operator what to do next.
type Cluster struct {
	p *Helper
}

// Start validates that this node is ready to be a cluster seed:
//   - agbero.hcl exists and is parseable
//   - keeper is accessible and holds vault://key/cluster
//   - gossip block is present and has secret_key wired to keeper
//
// If the gossip block is missing the secret_key reference, Start patches it
// automatically so the operator does not need to edit HCL manually.
func (c *Cluster) Start(configPath string) {
	u := ui.New()
	u.Render(func() { u.SectionHeader("Cluster seed pre-flight") })

	global, configPath, ok := c.requireConfig(configPath, u)
	if !ok {
		return
	}

	_, ok = c.requireClusterSecret(global, u)
	if !ok {
		return
	}

	if patched, err := c.ensureGossipBlock(configPath, global, u); err != nil {
		c.p.Logger.Fatal("failed to update agbero.hcl with gossip block: ", err)
		return
	} else if patched {
		u.Render(func() {
			u.Step("ok", "gossip block written to agbero.hcl — secret_key = vault://key/cluster")
		})
	} else {
		u.Render(func() { u.Step("ok", "gossip block already configured") })
	}

	port := global.Gossip.Port
	if port == 0 {
		port = alaye.DefaultGossipPort
	}
	hostname, _ := os.Hostname()
	u.Render(func() {
		u.SuccessLine("This node is ready to seed a cluster.")
		u.KeyValue("Gossip port", fmt.Sprintf("%d", port))
		u.InfoLine("Run  agbero run  to start the server.")
		u.InfoLine("Other nodes join with:")
		u.InfoLine(fmt.Sprintf("  agbero cluster join %s:%d", hostname, port))
	})
}

// Join validates that this node can join an existing cluster seed at peerAddr:
//   - agbero.hcl exists and is parseable
//   - keeper is accessible and holds vault://key/cluster
//   - peerAddr is reachable (port defaults to 7946 if omitted)
//   - gossip block is patched with secret_key and the seed address
//
// The operator then runs agbero run — the server handles the actual join.
func (c *Cluster) Join(configPath, peerAddr string) {
	u := ui.New()
	u.Render(func() { u.SectionHeader("Cluster join pre-flight") })

	if strings.TrimSpace(peerAddr) == "" {
		u.Render(func() {
			u.ErrorHint(
				"peer address required",
				"usage:  agbero cluster join <host>:<port>",
			)
		})
		return
	}
	peerAddr = c.normalisePeer(peerAddr)

	global, configPath, ok := c.requireConfig(configPath, u)
	if !ok {
		return
	}

	_, ok = c.requireClusterSecret(global, u)
	if !ok {
		return
	}

	u.Render(func() { u.Step("run", fmt.Sprintf("checking connectivity to %s", peerAddr)) })
	conn, err := net.Dial("tcp", peerAddr)
	if err != nil {
		u.Render(func() {
			u.ErrorHint(
				fmt.Sprintf("cannot reach peer %s", peerAddr),
				"ensure the seed node is running and the gossip port is open",
			)
		})
		c.p.Logger.Fatal("cluster join aborted: peer unreachable: ", err)
		return
	}
	conn.Close()
	u.Render(func() { u.Step("ok", fmt.Sprintf("peer %s is reachable", peerAddr)) })

	if patched, err := c.ensureGossipBlockWithSeed(configPath, global, peerAddr, u); err != nil {
		c.p.Logger.Fatal("failed to update agbero.hcl: ", err)
		return
	} else if patched {
		u.Render(func() {
			u.Step("ok", "agbero.hcl updated — gossip.seeds and secret_key configured")
		})
	} else {
		u.Render(func() { u.Step("ok", "gossip block already configured") })
	}

	u.Render(func() {
		u.SuccessLine("This node is ready to join the cluster.")
		u.KeyValue("Seed peer", peerAddr)
		u.InfoLine("Run  agbero run  — the server joins automatically on boot.")
	})
}

// requireConfig resolves, loads, and validates the agbero.hcl config.
func (c *Cluster) requireConfig(configPath string, u *ui.UI) (*alaye.Global, string, bool) {
	u.Render(func() { u.Step("run", "locating agbero.hcl") })

	resolved, found := ResolveConfigPath(c.p.Logger, configPath)
	if !found {
		u.Render(func() {
			u.ErrorHint(
				"agbero.hcl not found",
				"run  agbero init  first, or pass -c <path>",
			)
		})
		return nil, "", false
	}

	global, err := loadGlobal(resolved)
	if err != nil {
		u.Render(func() {
			u.ErrorHint("agbero.hcl could not be parsed", err.Error())
		})
		return nil, "", false
	}

	u.Render(func() {
		u.Step("ok", "config loaded")
		u.KeyValue("Config", resolved)
	})
	return global, resolved, true
}

// requireClusterSecret opens the keeper and reads vault://key/cluster.
// It prints targeted error messages for each distinct failure mode so the
// operator knows exactly what is wrong and how to fix it.
func (c *Cluster) requireClusterSecret(global *alaye.Global, u *ui.UI) ([]byte, bool) {
	u.Render(func() { u.Step("run", "reading cluster secret from keeper") })

	dataDir := global.Storage.DataDir
	if !dataDir.IsSet() {
		ctx := setup.NewContext(c.p.Logger)
		dataDir = ctx.Paths.DataDir
	}

	store, err := secrets.MustOpen(secrets.Config{
		DataDir:     dataDir,
		Setting:     &global.Security.Keeper,
		Logger:      c.p.Logger,
		Interactive: false,
	})
	if err != nil {
		u.Render(func() {
			u.ErrorHint(
				"keeper could not be opened",
				"set AGBERO_PASSPHRASE or configure keeper.passphrase in agbero.hcl",
			)
		})
		return nil, false
	}
	defer store.Close()

	val, err := store.Get(expect.Vault().Key("cluster"))
	if err != nil || len(val) == 0 {
		u.Render(func() {
			u.ErrorHint(
				"cluster secret not found (vault://key/cluster)",
				"run  agbero init  to generate it",
			)
		})
		return nil, false
	}

	u.Render(func() { u.Step("ok", "cluster secret found in keeper") })
	return val, true
}

// ensureGossipBlock checks whether the gossip block already references
// vault://key/cluster. If not, it patches the file atomically.
func (c *Cluster) ensureGossipBlock(configPath string, global *alaye.Global, u *ui.UI) (bool, error) {
	u.Render(func() { u.Step("run", "checking gossip configuration") })
	if global.Gossip.Enabled.Active() && global.Gossip.SecretKey.IsSecretStoreRef() {
		return false, nil
	}
	return c.patchHCLGossip(configPath, expect.Vault().Key("cluster"), nil)
}

// ensureGossipBlockWithSeed does the same as ensureGossipBlock but also adds
// peerAddr to the seeds list.
func (c *Cluster) ensureGossipBlockWithSeed(configPath string, global *alaye.Global, peerAddr string, u *ui.UI) (bool, error) {
	u.Render(func() { u.Step("run", "checking gossip configuration") })
	if global.Gossip.Enabled.Active() && global.Gossip.SecretKey.IsSecretStoreRef() {
		for _, seed := range global.Gossip.Seeds {
			if seed == peerAddr {
				return false, nil
			}
		}
	}
	return c.patchHCLGossip(configPath, expect.Vault().Key("cluster"), []string{peerAddr})
}

// patchHCLGossip removes any existing gossip block from the config file and
// appends a canonical one. seeds nil means empty seeds list (seed node).
// The write is atomic: temp file + rename.
func (c *Cluster) patchHCLGossip(configPath, secretKeyRef string, seeds []string) (bool, error) {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", configPath, err)
	}

	var seedsHCL string
	if len(seeds) == 0 {
		seedsHCL = `  seeds      = []`
	} else {
		quoted := make([]string, len(seeds))
		for i, s := range seeds {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		seedsHCL = fmt.Sprintf("  seeds      = [%s]", strings.Join(quoted, ", "))
	}

	gossipBlock := fmt.Sprintf("\ngossip {\n  enabled    = true\n  secret_key = %q\n%s\n}\n", secretKeyRef, seedsHCL)

	content := removeHCLBlock(string(raw), "gossip")
	content = strings.TrimRight(content, "\n") + "\n" + gossipBlock

	tmp := configPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), expect.FilePermSecured); err != nil {
		return false, fmt.Errorf("write temp: %w", err)
	}
	if err := os.Rename(tmp, configPath); err != nil {
		_ = os.Remove(tmp)
		return false, fmt.Errorf("rename: %w", err)
	}
	return true, nil
}

// normalisePeer ensures peerAddr includes a port. Bare IP or hostname gets
// the default gossip port appended.
func (c *Cluster) normalisePeer(addr string) string {
	if _, _, err := net.SplitHostPort(addr); err == nil {
		return addr
	}
	return fmt.Sprintf("%s:%d", addr, alaye.DefaultGossipPort)
}

// removeHCLBlock strips the first top-level block named blockName from content
// using brace-depth counting. Returns content unchanged if none found.
func removeHCLBlock(content, blockName string) string {
	for _, marker := range []string{blockName + " {", blockName + "{"} {
		start := strings.Index(content, marker)
		if start == -1 {
			continue
		}
		depth, end := 0, start
		for i := start; i < len(content); i++ {
			switch content[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i + 1
					if end < len(content) && content[end] == '\n' {
						end++
					}
					return content[:start] + content[end:]
				}
			}
		}
	}
	return content
}
