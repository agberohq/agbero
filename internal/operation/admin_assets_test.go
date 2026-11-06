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
