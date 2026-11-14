package setup

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/keeper"
)

func (h *Home) setupDomain(_ *keeper.Keeper, sess *session) error {
	if !h.ctx.Interactive {
		sess.SiteMode = def.SiteModeLocal
		sess.SiteDomain = "web.localhost"
		return nil
	}
	if sess.SiteMode != "" {
		h.u.Render(func() { h.u.Step("ok", "Initial site already configured") })
		return nil
	}

	mode, err := h.u.Select(
		"Initial site",
		"Choose what the first public host should serve. You can add more hosts later.",
		[]ui.SelectOption{
			{Label: "Basic website — serve a directory", Value: def.SiteModeWeb},
			{Label: "Reverse proxy — point to an existing service", Value: def.SiteModeProxy},
			{Label: "Local development — web.localhost", Value: def.SiteModeLocal},
		},
	)
	if err != nil {
		return err
	}

	switch mode {
	case def.SiteModeLocal:
		sess.SiteMode = def.SiteModeLocal
		sess.SiteDomain = "web.localhost"
		sess.SiteRoot = h.ctx.Paths.WebDir.Path()
		h.u.Render(func() { h.u.Step("ok", "Using http://web.localhost for local development") })
		return nil

	case def.SiteModeWeb:
		domain, err := h.askDomain()
		if err != nil {
			return err
		}
		root, err := h.u.Input(ui.InputConfig{
			Title:       "Document root",
			Description: "Directory to serve. It does not have to exist yet.",
			Placeholder: h.ctx.Paths.WebDir.Path(),
			Width:       70,
		})
		if err != nil {
			return err
		}
		if strings.TrimSpace(root) == "" {
			root = h.ctx.Paths.WebDir.Path()
		}
		if strings.TrimSpace(root) == "." || strings.TrimSpace(root) == "./" {
			return fmt.Errorf("document root cannot be '.'; it would expose the config directory")
		}
		sess.SiteMode = def.SiteModeWeb
		sess.SiteDomain = domain
		sess.SiteRoot = filepath.ToSlash(root)
		h.warnPublicTLS(sess)
		return nil

	case def.SiteModeProxy:
		domain, err := h.askDomain()
		if err != nil {
			return err
		}
		upstream, err := h.u.Input(ui.InputConfig{
			Title:       "Upstream",
			Description: "Existing HTTP service, for example http://127.0.0.1:3000",
			Placeholder: "http://127.0.0.1:3000",
			Width:       70,
		})
		if err != nil {
			return err
		}
		upstream = strings.TrimSpace(upstream)
		u, err := expect.Address(upstream).URL()
		if err != nil || u == nil || (u.Scheme != def.Http && u.Scheme != def.Https) || u.Host == "" {
			return fmt.Errorf("upstream must be an http:// or https:// URL")
		}
		sess.SiteMode = def.SiteModeProxy
		sess.SiteDomain = domain
		sess.SiteUpstream = upstream

		h.warnPublicTLS(sess)
		return nil

	default:
		return fmt.Errorf("unknown site mode %q", mode)
	}
}

func (h *Home) askDomain() (string, error) {
	domain, err := h.u.Input(ui.InputConfig{
		Title:       "Domain",
		Description: "Public hostname, for example app.example.com",
		Placeholder: "app.example.com",
		Width:       70,
	})
	if err != nil {
		return "", err
	}
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	if _, err := expect.NewRaw(domain).Domain(); err != nil {
		return "", fmt.Errorf("invalid domain %q: %w", domain, err)
	}
	return domain, nil
}

func (h *Home) warnPublicTLS(sess *session) {
	if sess.LEEmail != "" {
		return
	}
	h.u.WarnLine("No Let's Encrypt email was set; this host uses a local certificate. Point DNS at this server and set tls.mode = \"letsencrypt\" when ready.")
}

func siteHostFileName(sess *session) string {
	if sess.SiteMode == def.SiteModeLocal || sess.SiteMode == "" {
		return "web.hcl"
	}
	name := strings.TrimSpace(sess.SiteDomain)
	name = strings.ReplaceAll(name, "*", "wildcard")
	name = strings.NewReplacer("/", "_", "\\", "_").Replace(name)
	if name == "" {
		name = "site"
	}
	return name + ".hcl"
}

func siteHostConfig(sess *session, webRoot string) []byte {
	if sess.SiteMode == "" {
		sess.SiteMode = def.SiteModeLocal
	}
	var tlsMode def.TlsMode = def.ModeLocalAuto
	if sess.SiteMode != def.SiteModeLocal && sess.LEEmail != "" {
		tlsMode = def.ModeLetsEncrypt
	}

	switch sess.SiteMode {
	case def.SiteModeWeb:
		root := sess.SiteRoot
		if root == "" {
			root = webRoot
		}
		return []byte(fmt.Sprintf(`domains = [%q]
protected = "off"

tls {
  mode = %q
}

route "/" {
  enabled = "on"

  web {
    enabled = "on"
    root    = %q
    listing = "off"
    spa     = "off"
    index   = ["index.html"]
  }
}
`, sess.SiteDomain, tlsMode, filepath.ToSlash(root)))

	case def.SiteModeProxy:
		return []byte(fmt.Sprintf(`domains = [%q]
protected = "off"

tls {
  mode = %q
}

route "/" {
  enabled = "on"

  backend {
    server {
      address = %q
      streaming {
        enabled = true
      }
    }
  }
}
`, sess.SiteDomain, tlsMode, sess.SiteUpstream))

	default: // local development
		return []byte(fmt.Sprintf(`domains = ["web.localhost", "localhost"]
protected = "off"

tls {
  mode = %q
}

route "/" {
  enabled = "on"

  web {
    enabled = "on"
    root    = %q
    listing = "off"
    spa     = "off"
    index   = ["index.html"]
  }
}
`, tlsMode, filepath.ToSlash(webRoot)))
	}
}
