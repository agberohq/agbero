package helper

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/agberohq/agbero"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/core/zulu"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/agberohq/agbero/internal/pkg/ui"
	"github.com/agberohq/agbero/internal/setup"
)

type Ephemeral struct {
	p *Helper
}

func (e *Ephemeral) Serve() {
	cfg := e.p.Cfg
	path := cfg.ServePath
	if path == "" {
		path = "."
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		e.p.Logger.Errorf("error resolving path: %v\n", err)
		os.Exit(1)
	}
	stat, err := os.Stat(absPath)
	if err != nil || !stat.IsDir() {
		e.p.Logger.Errorf("path must be a valid directory: %s\n", absPath)
		os.Exit(1)
	}

	finalPort, err := zulu.PortScan(cfg.ServeBind, cfg.ServePort, woos.MaxPortRetries)
	if err != nil {
		e.p.Logger.Errorf("error: %v\n", err)
		os.Exit(1)
	}

	ctx := setup.NewContext(e.p.Logger)
	if cfg.ServeHTTPS {
		if err := setup.NewCA(ctx).PromptAndInstall(); err != nil {
			e.p.Logger.Warn("CA installation prompt interrupted: ", err)
		}
	}

	global := e.createGlobal(cfg.ServeBind, finalPort, cfg.ServeHTTPS, ctx)
	hosts := map[string]*alaye.Host{
		"localhost": woos.NewStaticHost(woos.Static{
			Domain:   "localhost",
			Target:   alaye.Address(absPath),
			Markdown: cfg.ServeMarkdown,
			SPA:      cfg.ServeSPA,
			PHP:      cfg.ServePHP,
		}),
	}

	domain := cfg.ServeBind
	if domain == "" || domain == "0.0.0.0" {
		domain = "localhost"
	}
	displayURL := buildURL(cfg.ServeHTTPS, domain, finalPort)

	u := ui.New()
	u.SectionHeader("Serving")

	pairs := []ui.KV{
		{Label: "Directory", Value: absPath},
		{Label: "URL", Value: u.LinkInline(displayURL, displayURL)},
	}
	if cfg.ServeMarkdown {
		pairs = append(pairs, ui.KV{Label: "Markdown", Value: "enabled"})
	}
	if cfg.ServeSPA {
		pairs = append(pairs, ui.KV{Label: "SPA mode", Value: "enabled"})
	}
	if cfg.ServePHP != "" {
		pairs = append(pairs, ui.KV{Label: "PHP", Value: "enabled"})
	}
	u.KeyValueBlock("", pairs)
	u.InfoLine("press Ctrl+C to stop")

	e.run(global, hosts)
}

func (e *Ephemeral) Proxy() {
	cfg := e.p.Cfg
	if cfg.ProxyTarget == "" {
		e.p.Logger.Println("error: target required (e.g., :3000 or http://127.0.0.1:3000)")
		os.Exit(1)
	}

	target := cfg.ProxyTarget
	if strings.HasPrefix(target, ":") {
		target = "127.0.0.1" + target
	}
	if !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	domain := cfg.ProxyDomain
	if domain == "" {
		domain = "localhost"
	}
	port := cfg.ProxyPort

	if strings.Contains(domain, ":") {
		host, portStr, err := net.SplitHostPort(domain)
		if err == nil {
			domain = host
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
	}

	finalPort, err := zulu.PortScan(cfg.ProxyBind, port, woos.MaxPortRetries)
	if err != nil {
		e.p.Logger.Errorf("error: %v\n", err)
		os.Exit(1)
	}

	ctx := setup.NewContext(e.p.Logger)
	if cfg.ProxyHTTPS {
		if err := setup.NewCA(ctx).PromptAndInstall(); err != nil {
			e.p.Logger.Warn("CA installation prompt interrupted: ", err)
		}
	}

	global := e.createGlobal(cfg.ProxyBind, finalPort, cfg.ProxyHTTPS, ctx)
	hosts := map[string]*alaye.Host{
		domain: woos.NewStaticHost(woos.Static{
			Domain:   domain,
			Target:   alaye.Address(target),
			IsProxy:  true,
			Markdown: cfg.ServeMarkdown,
			SPA:      cfg.ServeSPA,
		}),
	}

	displayURL := buildURL(cfg.ProxyHTTPS, domain, finalPort)

	u := ui.New()
	u.SectionHeader("Proxy")
	u.KeyValueBlock("", []ui.KV{
		{Label: "Traffic", Value: domain + "  →  " + u.LinkInline(target, target)},
		{Label: "URL", Value: u.LinkInline(displayURL, displayURL)},
	})
	u.InfoLine("press Ctrl+C to stop")

	e.run(global, hosts)
}

func (e *Ephemeral) createGlobal(bindHost string, port int, useHTTPS bool, ctx *setup.Context) *alaye.Global {
	global := woos.NewEphemeralGlobal(port, useHTTPS)
	if bindHost != "" {
		addr := fmt.Sprintf("%s:%d", bindHost, port)
		if useHTTPS {
			global.Bind.HTTPS = []string{addr}
		} else {
			global.Bind.HTTP = []string{addr}
		}
	}
	if ctx != nil {
		global.Storage.CertsDir = ctx.Paths.CertsDir.Path()
		global.Storage.DataDir = ctx.Paths.DataDir.Path()
		global.Storage.WorkDir = ctx.Paths.WorkDir.Path()
	}
	return global
}

func (e *Ephemeral) run(global *alaye.Global, hosts map[string]*alaye.Host) {
	hm := discovery.NewHost(woos.NewFolder(""), discovery.WithLogger(e.p.Logger))
	hm.LoadStatic(hosts)

	l, _ := zulu.Logging(&global.Logging, e.p.Cfg.DevMode, e.p.Shutdown)

	srv := agbero.NewServer(
		agbero.WithHostManager(hm),
		agbero.WithGlobalConfig(global),
		agbero.WithLogger(l),
		agbero.WithShutdownManager(e.p.Shutdown),
	)

	go func() {
		if err := srv.Start(""); err != nil {
			e.p.Logger.Error(err)
			e.p.Shutdown.TriggerShutdown()
		}
	}()

	stats := e.p.Shutdown.Wait()
	e.p.Logger.Fields(
		"duration", stats.EndTime.Sub(stats.StartTime),
		"tasks_total", stats.TotalEvents,
		"tasks_failed", stats.FailedEvents,
	).Info("agbero stopped gracefully")
}

func buildURL(useHTTPS bool, domain string, port int) string {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s", scheme, domain)
	if port != 80 && port != 443 {
		url = fmt.Sprintf("%s:%d", url, port)
	}
	return url
}
