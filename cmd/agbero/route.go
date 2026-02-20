package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/charmbracelet/huh"
)

const (
	RouteTypeProxy  = "Reverse Proxy"
	RouteTypeStatic = "Static Site"
	RouteTypeTCP    = "TCP Proxy"
)

var proxyTpl = `domains = ["{{ .Domain }}"]

route {
  path = "/"
  backends {
    server { address = "{{ .Target }}" }
  }
}
`

var staticTpl = `domains = ["{{ .Domain }}"]

route {
  path = "/"
  web {
    root = "{{ .Target }}"
    listing = true
  }
}
`

var tcpTpl = `domains = ["{{ .Domain }}"]

proxy {
  name = "tcp-service"
  listen = ":{{ .Port }}"
  backend { address = "{{ .Target }}" }
}
`

type routeData struct {
	Domain string
	Target string
	Port   string
}

func handleRouteCommands(add, remove bool, configPath string) {
	resolvedPath, exists := resolveConfigPath(configPath)
	if !exists {
		logger.Fatal("Config file not found. Run 'agbero install' first.")
	}

	configDir := filepath.Dir(resolvedPath)
	hostsDir := filepath.Join(configDir, woos.HostDir.String())

	if _, err := os.Stat(hostsDir); os.IsNotExist(err) {
		if err := os.MkdirAll(hostsDir, woos.DirPerm); err != nil {
			logger.Fatal("Failed to create hosts directory: ", err)
		}
	}

	if add {
		handleRouteAdd(hostsDir)
	} else if remove {
		handleRouteRemove(hostsDir)
	}
}

func handleRouteAdd(hostsDir string) {
	var (
		rType  string
		domain string
		target string
		port   string
	)

	// Step 1: Select Type
	err := huh.NewSelect[string]().
		Title("Route Type").
		Options(
			huh.NewOption(RouteTypeProxy, RouteTypeProxy),
			huh.NewOption(RouteTypeStatic, RouteTypeStatic),
			huh.NewOption(RouteTypeTCP, RouteTypeTCP),
		).
		Value(&rType).
		Run()

	if err != nil {
		fmt.Println("Cancelled")
		return
	}

	// Step 2: Configure
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

	targetTitle := "Target Address"
	targetPlaceholder := "http://localhost:3000"

	switch rType {
	case RouteTypeStatic:
		targetTitle = "Directory Path"
		targetPlaceholder = "."
	case RouteTypeTCP:
		targetTitle = "Backend Address"
		targetPlaceholder = "127.0.0.1:5432"
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

	// Convert []*Input to []Field explicitly for NewGroup
	fields := make([]huh.Field, len(group))
	for i, v := range group {
		fields[i] = v
	}

	err = huh.NewForm(huh.NewGroup(fields...)).Run()
	if err != nil {
		fmt.Println("Cancelled")
		return
	}

	domain = strings.TrimSpace(domain)
	target = strings.TrimSpace(target)

	if rType == RouteTypeStatic {
		abs, err := filepath.Abs(target)
		if err == nil {
			target = abs
		}
	}

	if rType == RouteTypeProxy {
		if !strings.HasPrefix(target, "http") {
			target = "http://" + target
		}
	}

	data := routeData{
		Domain: domain,
		Target: target,
		Port:   port,
	}

	var tplString string
	switch rType {
	case RouteTypeProxy:
		tplString = proxyTpl
	case RouteTypeStatic:
		tplString = staticTpl
	case RouteTypeTCP:
		tplString = tcpTpl
	}

	t, err := template.New("route").Parse(tplString)
	if err != nil {
		logger.Fatal("Template error: ", err)
	}

	filename := fmt.Sprintf("%s.hcl", domain)
	filename = strings.ReplaceAll(filename, "*", "wildcard")
	filename = strings.ReplaceAll(filename, ":", "-")
	filePath := filepath.Join(hostsDir, filename)

	f, err := os.Create(filePath)
	if err != nil {
		logger.Fatal("Failed to create file: ", err)
	}
	defer f.Close()

	if err := t.Execute(f, data); err != nil {
		logger.Fatal("Failed to write config: ", err)
	}

	logger.Infof("Route created: %s", filePath)
	fmt.Println("Agbero daemon will pick up changes automatically.")
}

func handleRouteRemove(hostsDir string) {
	entries, err := os.ReadDir(hostsDir)
	if err != nil {
		logger.Fatal("Failed to read hosts dir: ", err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".hcl") {
			files = append(files, e.Name())
		}
	}

	if len(files) == 0 {
		fmt.Println("No route files found in", hostsDir)
		return
	}

	var selected string

	err = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Select Route to Remove").
				Options(huh.NewOptions(files...)...).
				Value(&selected),
		),
	).Run()

	if err != nil {
		fmt.Println("Cancelled")
		return
	}

	if selected == "" {
		return
	}

	targetPath := filepath.Join(hostsDir, selected)
	if err := os.Remove(targetPath); err != nil {
		logger.Fatal("Failed to delete file: ", err)
	}

	logger.Infof("Removed route: %s", selected)
}
