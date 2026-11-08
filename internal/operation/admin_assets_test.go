package operation

import (
	"io/fs"
	"strings"
	"testing"
)

// Guards the map info panel: config-derived values end up in HTML, so _row
// must escape them and buildNodeActions must escape its attributes.
func TestMapInfoPanelEscapesConfigValues(t *testing.T) {
	src, err := fs.ReadFile(adminFS, "admin/pages/map.js")
	if err != nil {
		t.Fatalf("read map.js: %v", err)
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

func TestAdminHasMCPPage(t *testing.T) {
	for _, name := range []string{"admin/pages/mcp.html", "admin/pages/mcp.js"} {
		if _, err := fs.ReadFile(adminFS, name); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	shell, err := fs.ReadFile(adminFS, "admin/layouts/shell.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shell), "path: '/mcp'") {
		t.Fatal("MCP page is not in the admin navigation")
	}
}

func TestAdminMCPScopeUsesCheckboxes(t *testing.T) {
	html, err := fs.ReadFile(adminFS, "admin/pages/mcp.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`id="mcpScopeRead"`, `id="mcpScopePlan"`, `value="mcp:read"`, `value="mcp:plan"`} {
		if !strings.Contains(string(html), want) {
			t.Errorf("MCP token scope UI missing %q", want)
		}
	}
	if strings.Contains(string(html), `id="mcpTokenScope"`) {
		t.Error("MCP token scope still uses a free-text input")
	}
}

func TestAdminFocusDashboardAssets(t *testing.T) {
	files, err := fs.ReadFile(adminFS, "admin/pages/focus.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admin/pages/focus.html", "admin/pages/focus.js"} {
		if _, err := fs.ReadFile(adminFS, name); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if strings.Contains(string(files), "history.replaceState(null, '', '/focus?") {
		t.Error("focus page uses path routing instead of the Oja hash convention")
	}
	if !strings.Contains(string(files), "#/focus?") {
		t.Error("focus page does not use #/focus routing")
	}
	html, err := fs.ReadFile(adminFS, "admin/pages/focus.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"focusTopBackends", "focusHostSort", "data-focus-tab=\"logs\""} {
		if !strings.Contains(string(html), want) {
			t.Errorf("focus page missing %q", want)
		}
	}
	if strings.Contains(string(html), "data-focus-tab=\"hosts\"") {
		t.Error("focus page still has a separate Hosts tab")
	}
	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "appGroup.Get('/focus'") {
		t.Error("admin router does not register /focus")
	}
}

func TestAdminLoginPreservesFocusRoute(t *testing.T) {
	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "ctx.path + (qs ? '?' + qs : '')") {
		t.Error("login intended path drops the route query")
	}
	if !strings.Contains(string(main), "hashRoute") {
		t.Error("login redirect does not fall back to the current hash route")
	}
}

func TestAdminSharesAuthWithFocusTabs(t *testing.T) {
	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"agbero:auth-token-request", "agbero:auth-token"} {
		if !strings.Contains(string(main), want) {
			t.Errorf("main.js missing cross-tab auth handoff %q", want)
		}
	}
}
