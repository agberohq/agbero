package mcp

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/agberohq/oshodi"
)

func TestTokenRegistryMetadataOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revoked.db")
	db, err := oshodi.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := OpenTokenRegistryBucket(db)
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
	if len(reg.List()) != 1 || reg.List()[0].JTI != "jti-1" {
		t.Fatalf("records = %+v", reg.List())
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db2, err := oshodi.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	other, err := OpenTokenRegistryBucket(db2)
	if err != nil {
		t.Fatal(err)
	}
	rec2 := rec
	rec2.JTI = "jti-2"
	if err := other.Add(rec2); err != nil {
		t.Fatal(err)
	}
	if len(other.List()) != 2 {
		t.Fatalf("records = %+v", other.List())
	}
}

func TestTokenRegistrySkipsExpired(t *testing.T) {
	db, err := oshodi.Open(filepath.Join(t.TempDir(), "revoked.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	reg, err := OpenTokenRegistryBucket(db)
	if err != nil {
		t.Fatal(err)
	}
	_ = reg.Add(TokenRecord{JTI: "old", CreatedAt: time.Now().Add(-10 * 24 * time.Hour), ExpiresAt: time.Now().Add(-9 * 24 * time.Hour)})
	_ = reg.Add(TokenRecord{JTI: "new", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if got := reg.List(); len(got) != 1 || got[0].JTI != "new" {
		t.Fatalf("records = %+v", got)
	}
}
