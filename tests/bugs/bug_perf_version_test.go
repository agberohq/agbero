package bugs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Fixed guards for the admin UI data/performance findings.

// The header must use the binary build version from GET /api/v1/system, not
// the HCL `version` attribute in the global block.
func TestAdminHeaderUsesBuildVersion(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "js", "main.js"))
	if err != nil {
		t.Skipf("main.js not readable: %v", err)
	}
	s := string(src)

	if strings.Contains(s, "config.global?.version") {
		t.Fatal("main.js still sources sys.version from config.global.version")
	}
	for _, want := range []string{"fetchSystem", "system?.version"} {
		if !strings.Contains(s, want) {
			t.Fatalf("main.js does not use the build version (%q missing)", want)
		}
	}
}

// js/perf-chart.js was dead code (no importer); it should be gone.
func TestPerfChartModuleRemoved(t *testing.T) {
	p := filepath.Join(adminRoot, "js", "perf-chart.js")
	if _, err := os.Stat(p); err == nil {
		t.Fatal("js/perf-chart.js still exists; it is dead code")
	}
}

// A metrics tick with unchanged topology must not call processData(); the
// render path gates on a config-only signature and refreshes stats in place.
func TestMapGraphGatesIngestOnTopology(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "js", "graph.js"))
	if err != nil {
		t.Skipf("graph.js not readable: %v", err)
	}
	s := string(src)

	for _, want := range []string{
		"_configSignature(config)",
		"sig === this._topoSig",
		"_refreshStats(stats || {})",
		"this._topoSig = sig;",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("graph.js render gating missing %q", want)
		}
	}
}

// metrics.js must compare serialized payloads before writing the large
// hostsData/git/cluster objects; a fresh object identity always notifies.
func TestMetricsStoreWritesAreGuarded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(adminRoot, "js", "metrics.js"))
	if err != nil {
		t.Skipf("metrics.js not readable: %v", err)
	}
	s := string(src)

	if !strings.Contains(s, "function setIfChanged(") {
		t.Fatal("metrics.js has no setIfChanged helper")
	}
	if strings.Contains(s, "store.set('hostsData', { stats: hosts });") {
		t.Fatal("metrics.js still writes hostsData with a fresh object every poll")
	}
	for _, want := range []string{
		"setIfChanged(store, 'hostsData'",
		"setIfChanged(store, 'gitStats'",
		"setIfChanged(store, 'lastCluster'",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("metrics.js is missing %q", want)
		}
	}
}
