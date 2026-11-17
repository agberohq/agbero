package bugs

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

// Fixed guards for the admin UI findings. These are static assertions on the
// shipped JS: cheap, but they still fail on the obvious regression.

func TestHCLEditorTemplateProducesBackend(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "layouts", "shell.js"))
	if err != nil {
		t.Skipf("shell.js not readable: %v", err)
	}
	s := string(src)

	start := strings.Index(s, "_hclTemplate = `")
	if start < 0 {
		t.Fatal("no _hclTemplate found in shell.js")
	}
	body := s[start+len("_hclTemplate = `"):]
	end := strings.Index(body, "`;")
	if end < 0 {
		t.Fatal("unterminated _hclTemplate in shell.js")
	}
	tmpl := body[:end]

	if !strings.Contains(tmpl, "backend {") || !strings.Contains(tmpl, "server {") {
		t.Fatalf("template does not use the real grammar (backend + server block):\n%s", tmpl)
	}
	// The plural `backends` block silently decodes to zero servers.
	if strings.Contains(tmpl, "backends {") {
		t.Fatalf("template still contains the invalid `backends` block:\n%s", tmpl)
	}

	p := filepath.Join(t.TempDir(), "tpl.hcl")
	if err := os.WriteFile(p, []byte(tmpl), 0600); err != nil {
		t.Fatalf("write template: %v", err)
	}
	h, err := parser.ParseHostConfig(p)
	if err != nil {
		t.Fatalf("template does not decode: %v", err)
	}
	woos.DefaultHost(h)

	servers := 0
	for _, r := range h.Routes {
		servers += len(r.Backends.Servers)
	}
	if len(h.Routes) != 1 || servers != 1 {
		t.Fatalf("template decodes to %d route(s), %d server(s); want 1/1", len(h.Routes), servers)
	}
}

// Host and route health must be derived from the worst child, not hardcoded.
func TestGraphDerivesHostAndRouteHealth(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "js", "graph.js"))
	if err != nil {
		t.Skipf("graph.js not readable: %v", err)
	}
	s := string(src)

	for _, want := range []string{
		"function worstStatus(",
		"n.type !== 'route'",
		"n.type !== 'host'",
		"n.status = status;",
		"worstStatus(status, child.status)",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("graph.js does not derive parent health (missing %q)", want)
		}
	}
	if strings.Contains(s, "addNode(hostname, hostname, 'host', 'ok'") ||
		strings.Contains(s, "addNode(routeId, path, 'route', 'ok'") {
		t.Fatal("graph.js still hardcodes host/route health on creation")
	}
}

// The map filter must understand topology cards (`gnode--*`) as well as dots,
// and the legend must map proxy/proxy-udp/replay to emitted node types.
func TestMapFiltersUnderstandTopologyAndLegend(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "pages", "map.js"))
	if err != nil {
		t.Skipf("map.js not readable: %v", err)
	}
	s := string(src)

	for _, want := range []string{
		"gnode--host",
		"gdot--host",
		"gnode--route",
		"gnode--backend",
		"'proxy'",
		"'proxy-udp'",
		"kind === 'replay'",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("map.js filter does not handle %q", want)
		}
	}
}

// The backend drawer must render the sparkline as SVG, not as an inline
// <script> attached through innerHTML (which never executes).
func TestBackendSparklineIsInlineSVG(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "js", "drawer-listeners.js"))
	if err != nil {
		t.Skipf("drawer-listeners.js not readable: %v", err)
	}
	s := string(src)

	start := strings.Index(s, "function buildBackendHTML")
	if start < 0 {
		t.Fatal("buildBackendHTML not found")
	}
	end := strings.Index(s[start:], "\nfunction ")
	if end < 0 {
		end = len(s) - start
	}
	body := s[start : start+end]

	if strings.Contains(body, "<script>") || strings.Contains(body, "innerHTML = buildBackendHTML") {
		t.Fatal("buildBackendHTML still ships an inline script")
	}
	if !strings.Contains(body, "<svg") || !strings.Contains(body, "<polyline") {
		t.Fatal("buildBackendHTML does not render the sparkline as inline SVG")
	}
}

// Renew and Reload must have listeners; a bare emit is a dead button.
func TestRenewAndReloadHaveListeners(t *testing.T) {
	var renewEmits, renewListens, reloadEmits, reloadListens int
	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".js") {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		s := string(data)
		renewEmits += strings.Count(s, "emit('auth:renew:request'")
		renewListens += strings.Count(s, "listen('auth:renew:request'")
		reloadEmits += strings.Count(s, "emit('host:reload'")
		reloadListens += strings.Count(s, "listen('host:reload'")
		return nil
	}
	if werr := filepath.WalkDir(adminRoot, walk); werr != nil {
		t.Skipf("admin JS not walkable: %v", werr)
	}

	if renewEmits == 0 || renewListens == 0 {
		t.Fatalf("auth:renew:request emits=%d listens=%d; want both > 0", renewEmits, renewListens)
	}
	if reloadEmits == 0 || reloadListens == 0 {
		t.Fatalf("host:reload emits=%d listens=%d; want both > 0", reloadEmits, reloadListens)
	}
}

func TestMapInfoPanelEscapesConfigValues(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "pages", "map.js"))
	if err != nil {
		t.Skipf("map.js not readable: %v", err)
	}
	s := string(src)

	if !strings.Contains(s, "function _esc(") {
		t.Fatal("map.js has no _esc helper; config values may be interpolated raw")
	}

	start := strings.Index(s, "function _row(")
	if start < 0 {
		t.Fatal("map.js has no _row helper")
	}
	end := strings.Index(s[start:], "function _statusBadge")
	if end < 0 {
		t.Fatal("could not locate the end of _row in map.js")
	}
	row := s[start : start+end]
	if !strings.Contains(row, "raw ? val : _esc(val)") {
		t.Fatalf("_row interpolates values without escaping:\n%s", row)
	}

	if !strings.Contains(s, "const host = _esc(node.meta?.hostname || '')") {
		t.Fatal("buildNodeActions does not escape the hostname attribute")
	}
	if strings.Contains(s, `data-hostname="${node.meta.hostname}"`) {
		t.Fatal("buildNodeActions still interpolates the raw hostname into an attribute")
	}
}
