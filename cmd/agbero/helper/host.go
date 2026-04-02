package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

	"charm.land/huh/v2"
	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	discovery2 "github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

const (
	RouteTypeProxy  = "Reverse Proxy"
	RouteTypeStatic = "Static Site"
	RouteTypeTCP    = "TCP Proxy"
)

type routeData struct {
	Domain string
	Target string
	Port   string
}

type Host struct {
	p         *Helper
	ProxyTpl  string
	StaticTpl string
	TCPTpl    string
}

func (h *Host) List(configPath string) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery2.NewHost(hostsFolder, discovery2.WithLogger(h.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}

	u := ui.New()
	u.SectionHeader("Hosts")

	if len(hosts) == 0 {
		u.WarnLine("no hosts found")
		return nil
	}

	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)

	rows := make([][]string, 0, len(hosts))
	for _, name := range names {
		c := hosts[name]
		domains := strings.Join(c.Domains, ", ")
		routes := fmt.Sprintf("%d", len(c.Routes))
		tls := "—"
		if c.TLS.Mode == alaye.ModeLocalAuto {
			tls = "auto"
		} else if c.TLS.Local.CertFile != "" {
			tls = "local"
		}
		rows = append(rows, []string{name, domains, routes, tls})
	}

	u.Table([]string{"Host", "Domains", "Routes", "TLS"}, rows)
	return nil
}

func (h *Host) Add(configPath string) {
	hostsDir := h.resolveHostsDir(configPath)

	u := ui.New()
	u.SectionHeader("Add host")
	u.KeyValue("Hosts dir", hostsDir)

	var (
		rType  string
		domain string
		target string
		port   string
	)

	if err := huh.NewSelect[string]().
		Title("Route Type").
		Options(
			huh.NewOption(RouteTypeProxy, RouteTypeProxy),
			huh.NewOption(RouteTypeStatic, RouteTypeStatic),
			huh.NewOption(RouteTypeTCP, RouteTypeTCP),
		).
		Value(&rType).
		Run(); err != nil {
		u.InfoLine("cancelled")
		return
	}

	group := []*huh.Input{
		huh.NewInput().
			Title("Domain Name").
			Placeholder("app.localhost").
			Value(&domain).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("required")
				}
				return nil
			}),
	}

	if rType == RouteTypeTCP {
		group = append(group, huh.NewInput().
			Title("Listen Port").
			Placeholder("8080").
			Value(&port).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return fmt.Errorf("required")
				}
				return nil
			}))
	}

	targetTitle, targetPlaceholder := "Target Address", "http://localhost:3000"
	switch rType {
	case RouteTypeStatic:
		targetTitle, targetPlaceholder = "Directory Path", "."
	case RouteTypeTCP:
		targetTitle, targetPlaceholder = "Backend Address", "127.0.0.1:5432"
	}

	group = append(group, huh.NewInput().
		Title(targetTitle).
		Placeholder(targetPlaceholder).
		Value(&target).
		Validate(func(s string) error {
			if strings.TrimSpace(s) == "" {
				return fmt.Errorf("required")
			}
			return nil
		}))

	fields := make([]huh.Field, len(group))
	for i, v := range group {
		fields[i] = v
	}
	if err := huh.NewForm(huh.NewGroup(fields...)).Run(); err != nil {
		u.InfoLine("cancelled")
		return
	}

	domain = strings.TrimSpace(domain)
	target = strings.TrimSpace(target)

	if rType == RouteTypeStatic {
		if abs, err := filepath.Abs(target); err == nil {
			target = abs
		}
	}
	if rType == RouteTypeProxy && !strings.HasPrefix(target, "http") {
		target = "http://" + target
	}

	var tplString string
	switch rType {
	case RouteTypeProxy:
		tplString = h.ProxyTpl
	case RouteTypeStatic:
		tplString = h.StaticTpl
	case RouteTypeTCP:
		tplString = h.TCPTpl
	}

	t, err := template.New("route").Parse(tplString)
	if err != nil {
		h.p.Logger.Fatal("template error: ", err)
	}

	filename := strings.ReplaceAll(fmt.Sprintf("%s.hcl", domain), "*", "wildcard")
	filename = strings.ReplaceAll(filename, ":", "-")
	filePath := filepath.Join(hostsDir, filename)

	f, err := os.Create(filePath)
	if err != nil {
		h.p.Logger.Fatal("failed to create file: ", err)
	}
	defer f.Close()

	if err := t.Execute(f, routeData{Domain: domain, Target: target, Port: port}); err != nil {
		h.p.Logger.Fatal("failed to write config: ", err)
	}

	u.SuccessLine("host created: " + filePath)
	u.InfoLine("daemon will pick up changes automatically")
}

func (h *Host) Remove(configPath string) {
	hostsDir := h.resolveHostsDir(configPath)

	entries, err := os.ReadDir(hostsDir)
	if err != nil {
		h.p.Logger.Fatal("failed to read hosts dir: ", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".hcl") {
			files = append(files, e.Name())
		}
	}

	u := ui.New()
	u.SectionHeader("Remove host")

	if len(files) == 0 {
		u.WarnLine("no host files found in " + hostsDir)
		return
	}

	var selected string
	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Discovery to Remove").
				Options(huh.NewOptions(files...)...).
				Value(&selected),
		),
	).Run(); err != nil {
		u.InfoLine("cancelled")
		return
	}
	if selected == "" {
		return
	}

	if err := os.Remove(filepath.Join(hostsDir, selected)); err != nil {
		h.p.Logger.Fatal("failed to delete file: ", err)
	}

	u.SuccessLine("removed: " + selected)
	u.InfoLine("daemon will pick up changes automatically")
}

func (h *Host) resolveHostsDir(configPath string) string {
	global, err := loadGlobal(configPath)
	if err == nil && global.Storage.HostsDir != "" {
		return global.Storage.HostsDir
	}
	hostsDir := filepath.Join(filepath.Dir(configPath), woos.HostDir.String())
	if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
		h.p.Logger.Fatal("failed to create hosts directory: ", err)
	}
	return hostsDir
}
