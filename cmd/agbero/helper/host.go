package helper

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/discovery"
	"github.com/charmbracelet/huh"
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

type HostHelper struct {
	p         *Helper
	ProxyTpl  string
	StaticTpl string
	TCPTpl    string
}

func (h *HostHelper) List(configPath string) error {
	global, err := loadGlobal(configPath)
	if err != nil {
		return err
	}
	hostsFolder := woos.NewFolder(global.Storage.HostsDir)
	hm := discovery.NewHost(hostsFolder, discovery.WithLogger(h.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		return err
	}
	if len(hosts) == 0 {
		h.p.Logger.Warn("no hosts found")
		return nil
	}
	for name, c := range hosts {
		h.p.Logger.Fields(
			"host_id", name,
			"domains", c.Domains,
			"routes", len(c.Routes),
		).Info("configured host")
	}
	return nil
}

func (h *HostHelper) Add(configPath string) {
	hostsDir := h.resolveHostsDir(configPath)

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
		fmt.Println("Cancelled")
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
		fmt.Println("Cancelled")
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

	h.p.Logger.Infof("host created: %s", filePath)
	fmt.Println("Agbero daemon will pick up changes automatically.")
}

func (h *HostHelper) Remove(configPath string) {
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
	if len(files) == 0 {
		fmt.Println("no host files found in", hostsDir)
		return
	}

	var selected string
	if err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Host to Remove").
				Options(huh.NewOptions(files...)...).
				Value(&selected),
		),
	).Run(); err != nil {
		fmt.Println("Cancelled")
		return
	}
	if selected == "" {
		return
	}

	if err := os.Remove(filepath.Join(hostsDir, selected)); err != nil {
		h.p.Logger.Fatal("failed to delete file: ", err)
	}
	h.p.Logger.Infof("removed host: %s", selected)
}

func (h *HostHelper) resolveHostsDir(configPath string) string {
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
