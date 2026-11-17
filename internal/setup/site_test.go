package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

func parseSite(t *testing.T, sess *session, root string) string {
	t.Helper()
	raw := siteHostConfig(sess, root)
	f := filepath.Join(t.TempDir(), "site.hcl")
	if err := os.WriteFile(f, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseHostConfig(f); err != nil {
		t.Fatalf("generated host does not parse: %v\n%s", err, raw)
	}
	return string(raw)
}

func TestSiteHostConfigLocal(t *testing.T) {
	sess := &session{SiteMode: def.SiteModeLocal}
	raw := parseSite(t, sess, "/srv/web")
	for _, want := range []string{`"web.localhost"`, `mode = "auto"`, `root    = "/srv/web"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("missing %q:\n%s", want, raw)
		}
	}
	if siteHostFileName(sess) != "web.hcl" {
		t.Fatalf("local file = %q", siteHostFileName(sess))
	}
}

func TestSiteHostConfigWebWithLE(t *testing.T) {
	sess := &session{SiteMode: def.SiteModeWeb, SiteDomain: "app.example.com", SiteRoot: "/srv/app", LEEmail: "ops@example.com"}
	raw := parseSite(t, sess, "/unused")
	for _, want := range []string{`domains = ["app.example.com"]`, `mode = "letsencrypt"`, `root    = "/srv/app"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("missing %q:\n%s", want, raw)
		}
	}
	if siteHostFileName(sess) != "app.example.com.hcl" {
		t.Fatalf("file = %q", siteHostFileName(sess))
	}
}

func TestSiteHostConfigProxy(t *testing.T) {
	sess := &session{SiteMode: def.SiteModeProxy, SiteDomain: "api.example.com", SiteUpstream: "http://127.0.0.1:3000"}
	raw := parseSite(t, sess, "/unused")
	for _, want := range []string{`domains = ["api.example.com"]`, `address = "http://127.0.0.1:3000"`, `streaming`} {
		if !strings.Contains(raw, want) {
			t.Errorf("missing %q:\n%s", want, raw)
		}
	}
}
