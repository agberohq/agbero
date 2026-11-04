package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/agberohq/agbero/internal/pkg/parser"
)

func TestGeneratedGlobalTemplateParses(t *testing.T) {
	dir := t.TempDir()
	replacements := map[string]string{
		"{HOST_DIR}":                 filepath.Join(dir, "hosts.d"),
		"{CERTS_DIR}":                filepath.Join(dir, "certs.d"),
		"{DATA_DIR}":                 filepath.Join(dir, "data.d"),
		"{LOGS_DIR}":                 filepath.Join(dir, "logs.d"),
		"{WORK_DIR}":                 filepath.Join(dir, "work.d"),
		"{WEB_ROOT}":                 filepath.Join(dir, "www"),
		"{INTERNAL_AUTH_KEY}":        "vault://key/internal",
		"{CLUSTER_SECRET_KEY}":       "vault://key/cluster",
		"{LE_ENABLED}":               def.Off,
		"{LE_EMAIL}":                 "",
		"{KEEPER_ENABLED}":           def.On,
		"{TOTP_ENABLED}":             def.Off,
		"{KEEPER_PASSPHRASE_CONFIG}": `passphrase_file = "` + filepath.ToSlash(filepath.Join(dir, "keeper.passphrase")) + `"`,
	}

	content := ConfigTmpl
	for k, v := range replacements {
		content = strings.ReplaceAll(content, k, v)
	}

	path := filepath.Join(dir, def.DefaultConfigName)
	if err := os.WriteFile(path, []byte(content), def.ConfigFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.LoadGlobal(path); err != nil {
		t.Fatalf("generated global config does not parse: %v", err)
	}
	g, err := parser.LoadGlobal(path)
	if err != nil {
		t.Fatal(err)
	}
	woos.DefaultApply(g, path)
	if err := g.Validate(); err != nil {
		t.Fatalf("generated global config is invalid: %v", err)
	}
}

func TestGeneratedWebTemplateParses(t *testing.T) {
	dir := t.TempDir()
	content := strings.ReplaceAll(string(TplWebHcl), "{WEB_ROOT}", filepath.ToSlash(filepath.Join(dir, "www")))

	path := filepath.Join(dir, "web.hcl")
	if err := os.WriteFile(path, []byte(content), def.ConfigFilePerm); err != nil {
		t.Fatal(err)
	}
	if _, err := parser.ParseHostConfig(path); err != nil {
		t.Fatalf("generated web host config does not parse: %v", err)
	}
	h, err := parser.ParseHostConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	woos.DefaultHost(h)
	if err := h.Validate(); err != nil {
		t.Fatalf("generated web host config is invalid: %v", err)
	}
}

func TestGeneratedAdminTemplateParses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.hcl")
	if err := os.WriteFile(path, TplAdminHcl, def.ConfigFilePerm); err != nil {
		t.Fatal(err)
	}
	h, err := parser.ParseHostConfig(path)
	if err != nil {
		t.Fatalf("generated admin host config does not parse: %v", err)
	}
	woos.DefaultHost(h)
	if err := h.Validate(); err != nil {
		t.Fatalf("generated admin host config is invalid: %v", err)
	}
}
