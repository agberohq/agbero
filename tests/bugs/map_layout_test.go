package bugs

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// adminRoot is relative to the tests package directory (tests/bugs).
const adminRoot = "../../internal/operation/admin"

// layoutHarness loads js/graph-layout.js in a bare VM context (no DOM, no
// dependencies) and reports geometry invariants as JSON.
const layoutHarness = `import fs from 'node:fs';
import vm from 'node:vm';

const src = fs.readFileSync(process.argv[2], 'utf8');
const ctx = {};
vm.createContext(ctx);
vm.runInContext(src, ctx);
const computeLayout = vm.runInContext('computeLayout', ctx);
const computeForceLayout = vm.runInContext('computeForceLayout', ctx);

const nodes = [
  { id: 'AGBERO', type: 'root' },
  { id: 'a.example', type: 'host' },
  { id: 'a.example|/', type: 'route' },
  { id: 'a.example|/|be1', type: 'backend' },
  { id: 'a.example|/|be2', type: 'backend' },
  { id: 'a.example|/api', type: 'route' },
  { id: 'a.example|/api|be3', type: 'backend' },
  { id: 'b.example', type: 'host' },
  { id: 'b.example|tcp|:5432', type: 'route' },
  { id: 'b.example|tcp|:5432|be4', type: 'backend' }
];
const links = [
  { source: 'AGBERO', target: 'a.example' },
  { source: 'a.example', target: 'a.example|/' },
  { source: 'a.example|/', target: 'a.example|/|be1' },
  { source: 'a.example|/', target: 'a.example|/|be2' },
  { source: 'a.example', target: 'a.example|/api' },
  { source: 'a.example|/api', target: 'a.example|/api|be3' },
  { source: 'AGBERO', target: 'b.example' },
  { source: 'b.example', target: 'b.example|tcp|:5432' },
  { source: 'b.example|tcp|:5432', target: 'b.example|tcp|:5432|be4' }
];

const failures = [];
const ids = nodes.map(n => n.id);

const lr = computeLayout(nodes, links, { orientation: 'LR' });
const lrAgain = computeLayout(nodes, links, { orientation: 'LR' });
if (JSON.stringify(lr) !== JSON.stringify(lrAgain)) failures.push('layout is not deterministic');

const tb = computeLayout(nodes, links, { orientation: 'TB' });
if (JSON.stringify(tb.positions) === JSON.stringify(lr.positions)) failures.push('orientation does not change positions');

const wantDepth = { AGBERO: 0, 'a.example': 1, 'a.example|/': 2, 'a.example|/|be1': 3, 'a.example|/api': 2, 'b.example': 1, 'b.example|tcp|:5432': 2 };
for (const [id, d] of Object.entries(wantDepth)) {
  if (lr.positions[id].depth !== d) failures.push('depth for ' + id + ' expected ' + d + ' got ' + lr.positions[id].depth);
}

for (let i = 0; i < ids.length; i++) {
  for (let j = i + 1; j < ids.length; j++) {
    const a = lr.positions[ids[i]], b = lr.positions[ids[j]];
    if (a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h) {
      failures.push('overlap ' + ids[i] + ' / ' + ids[j]);
    }
  }
}

const columnX = {};
for (const id of ids) {
  const p = lr.positions[id];
  if (columnX[p.depth] === undefined) columnX[p.depth] = p.x;
  else if (columnX[p.depth] !== p.x) failures.push('depth ' + p.depth + ' is not a straight column (' + id + ')');
}

const children = new Map(ids.map(id => [id, []]));
links.forEach(l => children.get(l.source).push(l.target));
for (const [id, kids] of children) {
  if (!kids.length) continue;
  const p = lr.positions[id];
  const centres = kids.map(k => lr.positions[k].y + lr.positions[k].h / 2);
  const parentCentre = p.y + p.h / 2;
  const want = (centres[0] + centres[centres.length - 1]) / 2;
  if (Math.abs(parentCentre - want) > 1) {
    failures.push('parent ' + id + ' not centred over children (got ' + parentCentre + ' want ' + want + ')');
  }
}

const geom = lr.edges[0].geom;
const fromBox = lr.positions[lr.edges[0].source];
const toBox = lr.positions[lr.edges[0].target];
if (Math.abs(geom.x1 - (fromBox.x + fromBox.w)) > 1) failures.push('edge does not start at the source right border');
if (Math.abs(geom.x2 - toBox.x) > 1) failures.push('edge does not end at the target left border');

if (!(lr.bounds.width > 0 && lr.bounds.height > 0)) failures.push('bounds are empty');

const empty = computeLayout([], [], {});
if (empty.bounds.width !== 0 || empty.bounds.height !== 0 || empty.edges.length !== 0) failures.push('empty topology is not empty');

// classic (force) view
const fl = computeForceLayout(nodes, links, {});
const flAgain = computeForceLayout(nodes, links, {});
if (JSON.stringify(fl) !== JSON.stringify(flAgain)) failures.push('force layout is not deterministic');

const radii = { root: 14, host: 10, route: 7, backend: 5, serverless: 6 };
const fids = fl.order;
if (fids.length !== nodes.length) failures.push('force layout dropped nodes');
for (let i = 0; i < fids.length; i++) {
  for (let j = i + 1; j < fids.length; j++) {
    const p = fl.positions[fids[i]], q = fl.positions[fids[j]];
    const need = (radii[p.type] || 5) + (radii[q.type] || 5);
    if (Math.hypot(p.x - q.x, p.y - q.y) < need) failures.push('force nodes overlap: ' + fids[i] + ' / ' + fids[j]);
  }
}
if (!(fl.bounds.width > 0 && fl.bounds.height > 0)) failures.push('force bounds are empty');
if (fl.edges.length !== links.length) failures.push('force layout dropped edges');
const fEmpty = computeForceLayout([], [], {});
if (fEmpty.order.length !== 0 || fEmpty.edges.length !== 0) failures.push('empty force topology is not empty');

console.log(JSON.stringify({ failures, nodes: lr.order.length, edges: lr.edges.length, bounds: lr.bounds, forceNodes: fl.order.length }));
`

// TestMAP_LayoutIsDeterministicHierarchical guards the map's geometry: the layout
// replaced D3's force simulation, so it is now the thing that decides whether
// the topology is readable. Runs only when node is available (same convention as
// the tinygo-gated wasm tests).
func TestMAP_LayoutIsDeterministicHierarchical(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed: skipping map layout harness")
	}
	layoutPath, err := filepath.Abs(filepath.Join(adminRoot, "js", "graph-layout.js"))
	if err != nil {
		t.Fatalf("resolve layout path: %v", err)
	}
	if _, err := os.Stat(layoutPath); err != nil {
		t.Fatalf("graph-layout.js not found at %s: %v", layoutPath, err)
	}

	script := filepath.Join(t.TempDir(), "layout-harness.mjs")
	if err := os.WriteFile(script, []byte(layoutHarness), 0o600); err != nil {
		t.Fatalf("write harness: %v", err)
	}

	out, err := exec.Command(node, script, layoutPath).CombinedOutput()
	if err != nil {
		t.Fatalf("layout harness failed: %v\n%s", err, out)
	}

	var result struct {
		Failures []string `json:"failures"`
		Nodes    int      `json:"nodes"`
		Edges    int      `json:"edges"`
	}
	if err := json.Unmarshal(out, &result); err != nil {
		t.Fatalf("harness output is not JSON: %v\n%s", err, out)
	}
	if len(result.Failures) > 0 {
		t.Fatalf("layout invariants broken:\n  %s", strings.Join(result.Failures, "\n  "))
	}
	if result.Nodes != 10 || result.Edges != 9 {
		t.Fatalf("expected 10 nodes / 9 edges, got %d / %d", result.Nodes, result.Edges)
	}
}

// TestMAP_PageHasNoExternalScripts keeps the map page air-gapped: the graph used
// to load D3 from d3js.org, which meant a third-party script origin in the admin
// CSP and a blank page whenever the CDN was unreachable.
func TestMAP_PageHasNoExternalScripts(t *testing.T) {
	files := []string{
		filepath.Join(adminRoot, "pages", "map.js"),
		filepath.Join(adminRoot, "pages", "map.html"),
		filepath.Join(adminRoot, "js", "graph.js"),
		filepath.Join(adminRoot, "js", "graph-layout.js"),
	}
	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		src := string(body)
		for _, bad := range []string{"d3js.org", "cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com"} {
			if strings.Contains(src, bad) {
				t.Errorf("%s references the external CDN %q — the admin UI must work offline", f, bad)
			}
		}
		if strings.Contains(src, "<script src=\"http") {
			t.Errorf("%s loads a script from an absolute URL", f)
		}
	}
}
