package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/agberohq/agbero/internal/hub/discovery"
	"github.com/agberohq/keeper"
	"github.com/go-chi/chi/v5"
	"golang.org/x/crypto/bcrypt"
)

const authTestHash = "$2y$10$abcdefghijklmnopqrstuv"

type authTestEnv struct {
	hosts  *discovery.Host
	dir    expect.Folder
	store  *keeper.Keeper
	shared *Shared
	router chi.Router
}

func setupAuthAPI(t *testing.T, hcl string) *authTestEnv {
	t.Helper()

	tmp := t.TempDir()
	hostsDir := expect.NewFolder(filepath.Join(tmp, "hosts.d"))
	if err := hostsDir.Init(expect.DirPerm); err != nil {
		t.Fatalf("hosts dir: %v", err)
	}
	if err := hostsDir.Put("auth.example.com.hcl", []byte(hcl), expect.FilePerm); err != nil {
		t.Fatalf("write host: %v", err)
	}

	hosts := discovery.NewHost(hostsDir, discovery.WithLogger(testLogger))
	if err := hosts.ReloadFull(); err != nil {
		t.Fatalf("reload hosts: %v", err)
	}

	store, err := keeper.New(keeper.Config{DBPath: filepath.Join(tmp, "auth.db")})
	if err != nil {
		t.Fatalf("keeper.New: %v", err)
	}
	if err := store.Unlock([]byte("test-passphrase")); err != nil {
		store.Close()
		t.Fatalf("keeper unlock: %v", err)
	}

	shared := &Shared{Logger: testLogger, Discovery: hosts, Keeper: store}
	shared.UpdateState(&ActiveState{Global: &alaye.Global{
		Storage: alaye.Storage{HostsDir: hostsDir},
	}})

	r := chi.NewRouter()
	AuthHandler(shared, r)

	t.Cleanup(func() {
		store.Close()
		hosts.Close()
	})
	return &authTestEnv{hosts: hosts, dir: hostsDir, store: store, shared: shared, router: r}
}

func doAuthRequest(t *testing.T, r http.Handler, method, target string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	if body != nil {
		var err error
		payload, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, target, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func (e *authTestEnv) hostHCL(t *testing.T) string {
	t.Helper()
	cfg := e.hosts.Get("auth.example.com")
	if cfg == nil {
		t.Fatal("host missing")
	}
	name := cfg.SourceFile
	if name == "" {
		name = "auth.example.com.hcl"
	}
	raw, err := os.ReadFile(e.dir.FilePath(name))
	if err != nil {
		t.Fatalf("read host HCL: %v", err)
	}
	return string(raw)
}

func decodeAuthResponse(t *testing.T, w *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

func TestAuthAPI_GetReturnsRedactedRouteView(t *testing.T) {
	env := setupAuthAPI(t, `# host comment
domains = ["auth.example.com"]

route "/admin" {
  basic_auth {
    enabled = "on"
    realm   = "Admin"
    users   = ["alice:`+authTestHash+`"]
  }

  protect {
    enabled     = "off"
    title       = "Admin login"
    users       = ["bob:ss://auth/auth.example.com/admin/protect/bob"]
    session_ttl = "2h"
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodGet, "/auth/auth.example.com", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), authTestHash) {
		t.Fatal("response leaked an inline bcrypt hash")
	}

	var view authHostView
	decodeAuthResponse(t, w, &view)
	if view.Host != "auth.example.com" || len(view.Routes) != 1 {
		t.Fatalf("unexpected view: %+v", view)
	}
	route := view.Routes[0]
	if route.Path != "/admin" {
		t.Fatalf("route path = %q", route.Path)
	}
	if !route.BasicAuth.Enabled || route.BasicAuth.Realm != "Admin" {
		t.Fatalf("basic view = %+v", route.BasicAuth)
	}
	if len(route.BasicAuth.Users) != 1 || route.BasicAuth.Users[0].Source != "inline" {
		t.Fatalf("basic users = %+v", route.BasicAuth.Users)
	}
	if len(route.Protect.Users) != 1 {
		t.Fatalf("protect users = %+v", route.Protect.Users)
	}
	u := route.Protect.Users[0]
	if u.Username != "bob" || u.Source != "keeper" || u.KeeperKey != "auth/auth.example.com/admin/protect/bob" {
		t.Fatalf("keeper user view = %+v", u)
	}
}

func TestAuthAPI_UpdateConfigPreservesHCLComments(t *testing.T) {
	env := setupAuthAPI(t, `# host comment
domains = ["auth.example.com"]

route "/admin" {
  # route comment

  basic_auth {
    # basic comment
    enabled = "on"
    realm   = "Admin"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    # backend comment
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodPut, "/auth/auth.example.com/config", map[string]any{
		"route": "/admin",
		"mode":  "basic",
		"realm": "Operations",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT config: want 200, got %d — %s", w.Code, w.Body.String())
	}

	hcl := env.hostHCL(t)
	for _, want := range []string{"# host comment", "# route comment", "# basic comment", "# backend comment", `realm   = "Operations"`, authTestHash} {
		if !strings.Contains(hcl, want) {
			t.Errorf("HCL missing %q after config update:\n%s", want, hcl)
		}
	}
	if strings.Contains(hcl, `realm   = "Admin"`) {
		t.Errorf("realm was not updated:\n%s", hcl)
	}
}

func TestAuthAPI_AddResetDeleteProtectUserBackedByKeeper(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled     = "on"
    title       = "Admin"
    users       = ["alice:`+authTestHash+`"]
    session_ttl = "1h"
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	// Add — bcrypt happens server-side and the hash lands in Keeper, not HCL.
	w := doAuthRequest(t, env.router, http.MethodPost, "/auth/auth.example.com/users", map[string]any{
		"route":    "/admin",
		"mode":     "protect",
		"username": "bob",
		"password": "hunter2!",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("add user: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var added map[string]any
	decodeAuthResponse(t, w, &added)
	key, _ := added["keeper_key"].(string)
	if key == "" {
		t.Fatalf("add response missing keeper_key: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "$2") {
		t.Fatal("add response leaked a bcrypt hash")
	}

	hash, err := env.store.Get(key)
	if err != nil {
		t.Fatalf("keeper Get(%q): %v", key, err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("hunter2!")); err != nil {
		t.Fatalf("keeper value is not the bcrypt hash of the password: %v", err)
	}
	hcl := env.hostHCL(t)
	if !strings.Contains(hcl, `"bob:ss://`+key+`"`) {
		t.Fatalf("HCL does not reference the Keeper key:\n%s", hcl)
	}
	if strings.Contains(hcl, "hunter2!") || strings.Contains(hcl, string(hash)) {
		t.Fatal("password or hash was written into HCL")
	}

	// Duplicate add is rejected without overwriting the stored hash.
	w = doAuthRequest(t, env.router, http.MethodPost, "/auth/auth.example.com/users", map[string]any{
		"route": "/admin", "mode": "protect", "username": "bob", "password": "other-pass",
	})
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate add: want 409, got %d — %s", w.Code, w.Body.String())
	}
	hash, _ = env.store.Get(key)
	if bcrypt.CompareHashAndPassword(hash, []byte("hunter2!")) != nil {
		t.Fatal("duplicate add overwrote the existing hash")
	}

	// Reset — updates the same Keeper key.
	w = doAuthRequest(t, env.router, http.MethodPut, "/auth/auth.example.com/users", map[string]any{
		"route": "/admin", "mode": "protect", "username": "bob", "password": "reset-pass!",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("reset user: want 200, got %d — %s", w.Code, w.Body.String())
	}
	hash, err = env.store.Get(key)
	if err != nil {
		t.Fatalf("keeper Get after reset: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword(hash, []byte("reset-pass!")); err != nil {
		t.Fatalf("hash was not reset: %v", err)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte("hunter2!")) == nil {
		t.Fatal("old password still matches after reset")
	}

	// Delete — removes both the HCL entry and the Keeper secret.
	w = doAuthRequest(t, env.router, http.MethodDelete,
		"/auth/auth.example.com/users?route=%2Fadmin&mode=protect&username=bob", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete user: want 200, got %d — %s", w.Code, w.Body.String())
	}
	if _, err := env.store.Get(key); !errors.Is(err, keeper.ErrKeyNotFound) {
		t.Fatalf("keeper key still exists after delete: %v", err)
	}
	hcl = env.hostHCL(t)
	if strings.Contains(hcl, "\"bob:") {
		t.Fatalf("HCL still lists bob after delete:\n%s", hcl)
	}
	if !strings.Contains(hcl, "\"alice:") {
		t.Fatalf("delete removed the wrong user:\n%s", hcl)
	}
}

func TestAuthAPI_DeleteLastUserRejected(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodDelete,
		"/auth/auth.example.com/users?route=%2Fadmin&mode=protect&username=alice", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("delete last user: want 400, got %d — %s", w.Code, w.Body.String())
	}
	if !strings.Contains(env.hostHCL(t), "\"alice:") {
		t.Fatal("invalid delete still changed the HCL file")
	}
}

func TestAuthAPI_KeeperLockedRejectsUserWrite(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)
	if err := env.store.Lock(); err != nil {
		t.Fatalf("lock keeper: %v", err)
	}

	w := doAuthRequest(t, env.router, http.MethodPost, "/auth/auth.example.com/users", map[string]any{
		"route": "/admin", "mode": "protect", "username": "bob", "password": "hunter2!",
	})
	if w.Code != http.StatusLocked {
		t.Fatalf("locked keeper add: want 423, got %d — %s", w.Code, w.Body.String())
	}
	if strings.Contains(env.hostHCL(t), "bob:") {
		t.Fatal("locked keeper add still mutated HCL")
	}
}

func TestAuthAPI_ResetInlineUserMigratesToKeeper(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodPut, "/auth/auth.example.com/users", map[string]any{
		"route": "/admin", "mode": "protect", "username": "alice", "password": "brand-new-pass",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("reset inline user: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var out map[string]any
	decodeAuthResponse(t, w, &out)
	key, _ := out["keeper_key"].(string)
	if key == "" {
		t.Fatal("reset did not return a Keeper key")
	}
	hcl := env.hostHCL(t)
	if !strings.Contains(hcl, `"alice:ss://`+key+`"`) {
		t.Fatalf("inline entry was not migrated to a Keeper reference:\n%s", hcl)
	}
	hash, err := env.store.Get(key)
	if err != nil {
		t.Fatalf("keeper Get: %v", err)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte("brand-new-pass")) != nil {
		t.Fatal("migrated hash does not match the new password")
	}
}

func TestAuthAPI_Errors(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	cases := []struct {
		name   string
		method string
		target string
		body   any
		want   int
	}{
		{"unknown host", http.MethodGet, "/auth/missing.example.com", nil, http.StatusNotFound},
		{"unknown route", http.MethodPut, "/auth/auth.example.com/config", map[string]any{
			"route": "/nope", "mode": "protect", "title": "x",
		}, http.StatusNotFound},
		{"bad mode", http.MethodPost, "/auth/auth.example.com/users", map[string]any{
			"route": "/admin", "mode": "digest", "username": "bob", "password": "x",
		}, http.StatusBadRequest},
		{"bad username", http.MethodPost, "/auth/auth.example.com/users", map[string]any{
			"route": "/admin", "mode": "protect", "username": "bad/name", "password": "x",
		}, http.StatusBadRequest},
		{"empty password", http.MethodPost, "/auth/auth.example.com/users", map[string]any{
			"route": "/admin", "mode": "protect", "username": "bob", "password": "",
		}, http.StatusBadRequest},
		{"unknown user reset", http.MethodPut, "/auth/auth.example.com/users", map[string]any{
			"route": "/admin", "mode": "protect", "username": "nobody", "password": "x",
		}, http.StatusNotFound},
		{"no config fields", http.MethodPut, "/auth/auth.example.com/config", map[string]any{
			"route": "/admin", "mode": "protect",
		}, http.StatusBadRequest},
		{"wildcard protect", http.MethodPost, "/auth/auth.example.com/users", map[string]any{
			"route": "/admin/*", "mode": "protect", "username": "bob", "password": "x",
		}, http.StatusBadRequest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := doAuthRequest(t, env.router, tc.method, tc.target, tc.body)
			if w.Code != tc.want {
				t.Fatalf("want %d, got %d — %s", tc.want, w.Code, w.Body.String())
			}
		})
	}
}

func TestAuthAPI_AddBasicUserBackedByKeeper(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  basic_auth {
    enabled = "on"
    realm   = "Admin"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodPost, "/auth/auth.example.com/users", map[string]any{
		"route": "/admin", "mode": "basic", "username": "ops", "password": "basic-pass!",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("add basic user: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var added map[string]any
	decodeAuthResponse(t, w, &added)
	key, _ := added["keeper_key"].(string)
	if key == "" || !strings.HasPrefix(key, "auth/auth.example.com/admin/basic/") {
		t.Fatalf("unexpected keeper key %q", key)
	}

	hcl := env.hostHCL(t)
	if !strings.Contains(hcl, `"ops:ss://`+key+`"`) {
		t.Fatalf("basic_auth entry does not reference Keeper:\n%s", hcl)
	}
	hash, err := env.store.Get(key)
	if err != nil {
		t.Fatalf("keeper Get: %v", err)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte("basic-pass!")) != nil {
		t.Fatal("keeper value does not match the new password")
	}
}

func TestAuthAPI_UpdateProtectConfig(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled     = "on"
    title       = "Old title"
    users       = ["alice:`+authTestHash+`"]
    session_ttl = "1h"
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodPut, "/auth/auth.example.com/config", map[string]any{
		"route":       "/admin",
		"mode":        "protect",
		"enabled":     true,
		"title":       "New login",
		"session_ttl": "4h",
		"cookie_name": "custom_admin_sess",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("PUT protect config: want 200, got %d — %s", w.Code, w.Body.String())
	}

	w = doAuthRequest(t, env.router, http.MethodGet, "/auth/auth.example.com", nil)
	var view authHostView
	decodeAuthResponse(t, w, &view)
	ag := view.Routes[0].Protect
	if !ag.Enabled || ag.Title != "New login" || ag.CookieName != "custom_admin_sess" {
		t.Fatalf("protect view not updated: %+v", ag)
	}
	if ag.SessionTTL != "4h0m0s" {
		t.Fatalf("session_ttl = %q, want 4h0m0s", ag.SessionTTL)
	}

	hcl := env.hostHCL(t)
	for _, want := range []string{`title       = "New login"`, `session_ttl = "4h"`, `cookie_name = "custom_admin_sess"`} {
		if !strings.Contains(hcl, want) {
			t.Errorf("HCL missing %q after protect config update:\n%s", want, hcl)
		}
	}
	if !strings.Contains(hcl, `"alice:`+authTestHash+`"`) {
		t.Fatalf("settings update erased users:\n%s", hcl)
	}
}

func TestAuthAPI_GetReturnsEveryRouteOnHost(t *testing.T) {
	env := setupAuthAPI(t, `domains = ["auth.example.com"]

route "/admin" {
  protect {
    enabled = "on"
    users   = ["alice:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8080" }
  }
}

route "/public" {
  basic_auth {
    enabled = "on"
    realm   = "Public"
    users   = ["guest:`+authTestHash+`"]
  }

  backend {
    server { address = "http://127.0.0.1:8081" }
  }
}

route "/api/v1" {
  backend {
    server { address = "http://127.0.0.1:8082" }
  }
}
`)

	w := doAuthRequest(t, env.router, http.MethodGet, "/auth/auth.example.com", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: want 200, got %d — %s", w.Code, w.Body.String())
	}
	var view authHostView
	decodeAuthResponse(t, w, &view)

	got := map[string]authRouteView{}
	for _, route := range view.Routes {
		got[route.Path] = route
	}
	if len(got) != 3 {
		t.Fatalf("expected all 3 routes, got %d: %+v", len(got), got)
	}
	if !got["/admin"].Protect.Enabled || got["/admin"].BasicAuth.Enabled {
		t.Fatalf("/admin auth view = %+v", got["/admin"])
	}
	if !got["/public"].BasicAuth.Enabled || got["/public"].Protect.Enabled {
		t.Fatalf("/public auth view = %+v", got["/public"])
	}
	if got["/api/v1"].BasicAuth.Enabled || got["/api/v1"].Protect.Enabled {
		t.Fatalf("/api/v1 should have no auth enabled: %+v", got["/api/v1"])
	}
}
