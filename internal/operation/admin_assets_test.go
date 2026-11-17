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
	// The focus page is a single-host wallboard: live numbers for one host,
	// nothing about other hostnames.
	for _, want := range []string{"data-fw-tab=\"live\"", "data-fw-tab=\"logs\"", "fwRpsChart", "fwKiosk"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("focus page missing %q", want)
		}
	}
	for _, gone := range []string{"focusHostList", "focusHostSort", "All hosts"} {
		if strings.Contains(string(html), gone) {
			t.Errorf("focus page still lists other hosts (%q)", gone)
		}
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

func TestInterceptPageAssets(t *testing.T) {
	for _, name := range []string{"admin/pages/intercept.html", "admin/pages/intercept.js"} {
		if _, err := fs.ReadFile(adminFS, name); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}

	html, err := fs.ReadFile(adminFS, "admin/pages/intercept.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`id="routeAuthHost"`,
		`id="routeAuthRoute"`,
		`id="routeAuthRouteList"`,
		`Route to protect`,
		`data-auth-tab="basic"`,
		`data-auth-tab="protect"`,
		`id="basicAuthForm"`,
		`id="protectForm"`,
		`id="basicAuthAddForm"`,
		`id="protectAddForm"`,
		`id="basicAuthResetForm"`,
		`id="protectResetForm"`,
		`id="basicAuthAddPassword"`,
		`id="protectAddPassword"`,
		`type="password"`,
		`protect`,
		`_agbero/login`,
	} {
		if !strings.Contains(string(html), want) {
			t.Errorf("route auth page missing %q", want)
		}
	}
	if strings.Contains(string(html), `type="text" id="basicAuthAddPassword"`) {
		t.Error("add-user password field is not masked")
	}

	js, err := fs.ReadFile(adminFS, "admin/pages/intercept.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fetchRouteAuth",
		"updateRouteAuthConfig",
		"addRouteAuthUser",
		"resetRouteAuthUser",
		"deleteRouteAuthUser",
		`data-auth-action`,
		`data-route-pick`,
		"data-auth-tab",
		"routeAuthRouteList",
		"pickRoute",
		"#/intercept?",
		"Keeper",
	} {
		if !strings.Contains(string(js), want) {
			t.Errorf("route auth page script missing %q", want)
		}
	}

	shell, err := fs.ReadFile(adminFS, "admin/layouts/shell.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(shell), "path: '/intercept'") {
		t.Error("intercept page is not in the admin navigation")
	}

	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "appGroup.Get('/intercept'") {
		t.Error("admin router does not register /intercept")
	}
	if !strings.Contains(string(main), "fetchRouteAuth,") {
		t.Error("app services do not expose route auth API helpers")
	}

	api, err := fs.ReadFile(adminFS, "admin/js/api.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/api/v1/auth/",
		"/config",
		"/users",
		"deleteRouteAuthUser",
	} {
		if !strings.Contains(string(api), want) {
			t.Errorf("admin API client missing %q", want)
		}
	}
}

func TestInterceptIsSeparateFromFocusAndAdmin(t *testing.T) {
	html, err := fs.ReadFile(adminFS, "admin/pages/intercept.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "Route Intercept") {
		t.Fatal("intercept page does not identify itself")
	}
	if strings.Contains(string(html), "focus") {
		t.Fatal("intercept page still contains focus-dashboard markup")
	}

	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(main), "appGroup.Get('/admin'") {
		t.Fatal("route auth page still uses /admin, which collides with the Agbero admin server")
	}
	shell, err := fs.ReadFile(adminFS, "admin/layouts/shell.js")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(shell), "path: '/admin'") {
		t.Fatal("navigation still exposes the route auth page as /admin")
	}

	hosts, err := fs.ReadFile(adminFS, "admin/pages/hosts/index.js")
	if err != nil {
		t.Fatal(err)
	}
	// Route auth lives in the route manager's Access tab.
	if !strings.Contains(string(hosts), "/routes?host=") || !strings.Contains(string(hosts), "tab=access") {
		t.Error("hosts page has no entry point for route auth")
	}
	if !strings.Contains(string(hosts), "PROTECT") {
		t.Error("hosts page does not badge protect routes")
	}
}

func TestAdminGitModeSelector(t *testing.T) {
	routes, err := fs.ReadFile(adminFS, "admin/pages/add-host/step-routes.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`engineData.git_mode`,
		`value="auto"`,
		`value="pull"`,
		`value="push"`,
		`value="both"`,
	} {
		if !strings.Contains(string(routes), want) {
			t.Errorf("add-host Git form missing %q", want)
		}
	}

	builder, err := fs.ReadFile(adminFS, "admin/js/host-builder.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"web.git.mode", "`mode     = ${_hq(g.mode)}`"} {
		if !strings.Contains(string(builder), want) {
			t.Errorf("host builder missing Git mode wiring %q", want)
		}
	}

	drawer, err := fs.ReadFile(adminFS, "admin/js/drawer-listeners.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(drawer), "configuredMode === 'auto'") {
		t.Error("git drawer does not resolve auto mode")
	}
}

func TestAdminHostBuilderRendersWebMounts(t *testing.T) {
	builder, err := fs.ReadFile(adminFS, "admin/js/host-builder.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Array.isArray(w.mounts)",
		"`mount ${_hq(m.path)} {`",
		"m.git",
	} {
		if !strings.Contains(string(builder), want) {
			t.Errorf("host builder does not render web mounts (%q)", want)
		}
	}
}

func TestAdminWebMountEditor(t *testing.T) {
	routes, err := fs.ReadFile(adminFS, "admin/pages/add-host/step-routes.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Web Mounts",
		"wz-add-mount",
		`data-mount-field="path"`,
		`data-mount-field="root"`,
		`data-mount-field="git_enabled"`,
		`data-mount-field="git_mode"`,
		`data-mount-field="git_auth_type"`,
		`data-mount-field="git_auth_user"`,
		`data-mount-field="git_auth_pass"`,
		`data-mount-field="git_ssh_key"`,
	} {
		if !strings.Contains(string(routes), want) {
			t.Errorf("add-host web mount editor missing %q", want)
		}
	}

	builder, err := fs.ReadFile(adminFS, "admin/js/host-builder.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Array.isArray(data.mounts)", "web.mounts = mounts", "out.git.auth = { type: authType }"} {
		if !strings.Contains(string(builder), want) {
			t.Errorf("host builder does not serialize web mounts (%q)", want)
		}
	}
}

func TestOperationLoginPageTemplate(t *testing.T) {
	if len(LoginPage) == 0 {
		t.Fatal("embedded login page is empty")
	}
	page := string(LoginPage)
	for _, want := range []string{
		"{{.Title}}",
		"{{.Action}}",
		"{{.Next}}",
		"{{.CSRF}}",
		"{{if .Error}}",
		`name="csrf"`,
		`name="username"`,
		`name="password"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("embedded login page missing %q", want)
		}
	}
	if strings.Contains(page, "<script>") {
		t.Error("embedded login page should not contain inline script")
	}
}

func TestAdminHCLFormatterKeepsNewlineAfterClosingBrace(t *testing.T) {
	src, err := fs.ReadFile(adminFS, "admin/js/hcl.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, "// Closing brace")
	if start < 0 {
		t.Fatal("closing-brace formatter block not found")
	}
	end := strings.Index(s[start:], "// Apply indentation")
	if end < 0 {
		t.Fatal("end of closing-brace formatter block not found")
	}
	block := s[start : start+end]
	if !strings.Contains(block, "lastWasNewline = false;") {
		t.Fatal("formatter suppresses the newline after a closing brace; blocks will be glued together")
	}
	if strings.Contains(block, "lastWasNewline = true;") {
		t.Fatal("formatter still marks the closing brace as a newline")
	}
}

func TestAdminRouteManagerAssets(t *testing.T) {
	for _, name := range []string{"admin/pages/routes.html", "admin/pages/routes.js"} {
		if _, err := fs.ReadFile(adminFS, name); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	main, err := fs.ReadFile(adminFS, "admin/js/main.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(main), "appGroup.Get('/routes'") {
		t.Error("admin router does not register /routes")
	}
	html, _ := fs.ReadFile(adminFS, "admin/pages/routes.html")
	for _, tab := range []string{"overview", "backends", "access", "policy", "cache", "hcl"} {
		if !strings.Contains(string(html), `data-rm-tab="`+tab+`"`) {
			t.Errorf("route manager missing the %s tab", tab)
		}
	}
	js, _ := fs.ReadFile(adminFS, "admin/pages/routes.js")
	if !strings.Contains(string(js), "#/routes?") {
		t.Error("route manager does not use #/routes hash routing")
	}
	// Access reuses the auth manager; embedded, it must not rewrite the URL.
	icept, _ := fs.ReadFile(adminFS, "admin/pages/intercept.js")
	if !strings.Contains(string(icept), "if (embedded) return;") {
		t.Error("intercept page rewrites the URL when embedded in the route manager")
	}
}
