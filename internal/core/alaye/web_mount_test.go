package alaye

import (
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/expect"
)

func TestWebMount_Validate(t *testing.T) {
	valid := []WebMount{
		{Path: "/site1", Root: "/var/www/site1"},
		{Path: "/site1/", Root: "/var/www/site1"},
		{Path: "/nested/site2", Root: "/var/www/site2"},
		{
			Path: "/site3",
			Git: Git{
				Enabled:  expect.Active,
				ID:       "site3",
				URL:      "https://example.com/site3.git",
				Interval: expect.Duration(time.Minute),
			},
		},
	}
	for _, m := range valid {
		mm := m
		if err := mm.Validate(); err != nil {
			t.Errorf("Validate(%q) = %v", m.Path, err)
		}
	}

	invalid := []WebMount{
		{Path: "", Root: "/var/www/x"},
		{Path: "site1", Root: "/var/www/x"},
		{Path: "/", Root: "/var/www/x"},
		{Path: "/site1"},
		{Path: "/site 1", Root: "/var/www/x"},
		{Path: "/site*", Root: "/var/www/x"},
		{Path: "/site1/../admin", Root: "/var/www/x"},
	}
	for _, m := range invalid {
		mm := m
		if err := mm.Validate(); err == nil {
			t.Errorf("Validate(%q) accepted an invalid mount", m.Path)
		}
	}
}

func TestWeb_ValidateMounts(t *testing.T) {
	w := Web{
		Enabled: expect.Active,
		Mounts: []WebMount{
			{Path: "/site1", Root: "/var/www/site1"},
			{Path: "/site2", Root: "/var/www/site2"},
		},
	}
	if err := w.Validate(); err != nil {
		t.Fatalf("mount-only web config rejected: %v", err)
	}

	w.Mounts = append(w.Mounts, WebMount{Path: "/site1/", Root: "/var/www/other"})
	if err := w.Validate(); err == nil {
		t.Fatal("duplicate mount path accepted")
	}
}

func TestWeb_ValidateMountGitIDsUnique(t *testing.T) {
	gitCfg := Git{
		Enabled:  expect.Active,
		ID:       "same-id",
		URL:      "https://example.com/site.git",
		Interval: expect.Duration(time.Minute),
		Mode:     "pull",
	}
	w := Web{
		Enabled: expect.Active,
		Mounts: []WebMount{
			{Path: "/site1", Git: gitCfg},
			{Path: "/site2", Git: gitCfg},
		},
	}
	if err := w.Validate(); err == nil {
		t.Fatal("duplicate mount git id accepted")
	}
}

func TestRoute_ValidateMountOnlyWebRoute(t *testing.T) {
	r := Route{
		Path: "/",
		Web: Web{
			Enabled: expect.Active,
			Mounts: []WebMount{
				{Path: "/site1", Root: "/var/www/site1"},
			},
		},
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("mount-only web route rejected: %v", err)
	}
}
