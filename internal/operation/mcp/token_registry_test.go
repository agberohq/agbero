package mcp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokenRegistryMetadataOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-tokens.json")
	reg, err := OpenTokenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := TokenRecord{
		User: "alice", Scope: "mcp:read", JTI: "jti-1",
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := reg.Add(rec); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "eyJ") {
		t.Fatal("registry contains a JWT")
	}
	if len(reg.List()) != 1 || reg.List()[0].JTI != "jti-1" {
		t.Fatalf("records = %+v", reg.List())
	}

	other, err := OpenTokenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := rec
	rec2.JTI = "jti-2"
	if err := other.Add(rec2); err != nil {
		t.Fatal(err)
	}
	if err := reg.Reload(); err != nil {
		t.Fatal(err)
	}
	if len(reg.List()) != 2 {
		t.Fatalf("reloaded records = %+v", reg.List())
	}
}

func TestTokenRegistrySkipsExpired(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp-tokens.json")
	reg, _ := OpenTokenRegistry(path)
	_ = reg.Add(TokenRecord{JTI: "old", CreatedAt: time.Now().Add(-10 * 24 * time.Hour), ExpiresAt: time.Now().Add(-9 * 24 * time.Hour)})
	_ = reg.Add(TokenRecord{JTI: "new", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if got := reg.List(); len(got) != 1 || got[0].JTI != "new" {
		t.Fatalf("records = %+v", got)
	}
}
