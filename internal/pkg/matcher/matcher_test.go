package matcher

import (
	"strconv"
	"strings"
	"testing"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
)

// paths
const (
	pSlash     = woos.Slash
	pApi       = "/api"
	pApi2      = "/api2"
	pApiID     = "/api/id"
	pApis      = "/apis"
	pApiSlash  = "/api/"
	pApiX      = "/api/x"
	pApiIDMore = "/api/id/anything"
	pUnknown   = "/unknown"
)

// helpers
func mkRoute(path string) *alaye.Route {
	return &alaye.Route{Path: path}
}

func buildBasicTree(tb testing.TB) (*Tree, map[string]*alaye.Route) {
	tb.Helper()

	routes := map[string]*alaye.Route{
		pSlash: mkRoute(pSlash),
		pApi:   mkRoute(pApi),
		pApi2:  mkRoute(pApi2),
		pApiID: mkRoute(pApiID),
	}

	tr := NewTree()
	for p, r := range routes {
		if err := tr.Insert(p, r); err != nil {
			tb.Fatalf("Insert(%q) failed: %v", p, err)
		}
	}
	return tr, routes
}

//
// Tests
//

func TestMatcher_OrderAndFallback(t *testing.T) {
	tr, routes := buildBasicTree(t)

	type tc struct {
		path string
		want *alaye.Route
	}
	tests := []tc{
		{pSlash, routes[pSlash]},
		{pApi, routes[pApi]},
		{pApiSlash, routes[pApi]},    // prefix routing
		{pApiID, routes[pApiID]},     // deeper wins
		{pApiIDMore, routes[pApiID]}, // deeper prefix routing
		{pApi2, routes[pApi2]},
		{pApis, routes[pSlash]},    // boundary safety
		{pUnknown, routes[pSlash]}, // fallback
		{pApiX, routes[pApi]},      // parent fallback within subtree
	}

	for _, tt := range tests {
		got := tr.Find(tt.path)
		if got.Route != tt.want {
			gotPath := "<nil>"
			if got.Route != nil {
				gotPath = got.Route.Path
			}
			wantPath := "<nil>"
			if tt.want != nil {
				wantPath = tt.want.Path
			}
			t.Fatalf("Find(%q) => route=%s params=%v; want route=%s",
				tt.path, gotPath, got.Params, wantPath)
		}
	}
}

func TestMatcher_TemplateAndRegex(t *testing.T) {
	const (
		pUser     = "/u/{id}"
		pDigits   = "/d/{id:[0-9]+}"
		pRegexSeg = "/r/~[a-z]+"

		pUserHit    = "/u/alice"
		pDigitsHit  = "/d/123"
		pDigitsMiss = "/d/abc"
		pRegexHit   = "/r/hello"
		pRegexMiss  = "/r/HELLO"
	)

	tr := NewTree()

	rRoot := mkRoute(pSlash)
	rUser := mkRoute(pUser)
	rDigits := mkRoute(pDigits)
	rRegex := mkRoute(pRegexSeg)

	if err := tr.Insert(pSlash, rRoot); err != nil {
		t.Fatalf("Insert(%q) failed: %v", pSlash, err)
	}
	if err := tr.Insert(pUser, rUser); err != nil {
		t.Fatalf("Insert(%q) failed: %v", pUser, err)
	}
	if err := tr.Insert(pDigits, rDigits); err != nil {
		t.Fatalf("Insert(%q) failed: %v", pDigits, err)
	}
	if err := tr.Insert(pRegexSeg, rRegex); err != nil {
		t.Fatalf("Insert(%q) failed: %v", pRegexSeg, err)
	}

	{
		got := tr.Find(pUserHit)
		if got.Route != rUser || got.Params == nil || got.Params["id"] != "alice" {
			t.Fatalf("template capture failed: path=%q route=%v params=%v",
				pUserHit, got.Route, got.Params)
		}
	}

	{
		got := tr.Find(pDigitsHit)
		if got.Route != rDigits || got.Params == nil || got.Params["id"] != "123" {
			t.Fatalf("template regex accept failed: path=%q route=%v params=%v",
				pDigitsHit, got.Route, got.Params)
		}
	}

	{
		got := tr.Find(pDigitsMiss)
		if got.Route != rRoot {
			gotPath := "<nil>"
			if got.Route != nil {
				gotPath = got.Route.Path
			}
			t.Fatalf("template regex reject failed: path=%q got=%s params=%v want=%q",
				pDigitsMiss, gotPath, got.Params, pSlash)
		}
	}

	{
		got := tr.Find(pRegexHit)
		if got.Route != rRegex {
			t.Fatalf("regex segment match failed: path=%q route=%v params=%v",
				pRegexHit, got.Route, got.Params)
		}
	}

	{
		got := tr.Find(pRegexMiss)
		if got.Route != rRoot {
			t.Fatalf("regex segment reject failed: path=%q route=%v params=%v want=%q",
				pRegexMiss, got.Route, got.Params, pSlash)
		}
	}
}

func TestMatcher_CatchAll(t *testing.T) {
	const (
		pAll = "/files/*"
		pHit = "/files/a/b/c"
	)

	tr := NewTree()
	rRoot := mkRoute(pSlash)
	rAll := mkRoute(pAll)

	_ = tr.Insert(pSlash, rRoot)
	_ = tr.Insert(pAll, rAll)

	got := tr.Find(pHit)
	if got.Route != rAll {
		t.Fatalf("catch-all route failed: path=%q route=%v params=%v", pHit, got.Route, got.Params)
	}
	if got.Params == nil {
		t.Fatalf("catch-all params missing: path=%q", pHit)
	}

	v, ok := got.Params[woos.TemplateWildcardKey]
	if !ok || v == woos.Empty {
		t.Fatalf("catch-all wildcard missing/Empty: path=%q params=%v", pHit, got.Params)
	}

	// Depending on implementation choice, wildcard may or may not include leading Slash.
	// We accept both; but it must contain the remaining path.
	const want1 = "a/b/c"
	const want2 = "/a/b/c"
	if v != want1 && v != want2 {
		t.Fatalf("catch-all wildcard unexpected: got=%q want=%q or %q", v, want1, want2)
	}
}

//
// Benchmarks
//

// Old matcher (your deprecated code)
func oldMatch(requestPath, pattern string) bool {
	if pattern == woos.Star {
		return true
	}

	if before, ok := strings.CutSuffix(pattern, woos.Star); ok {
		prefix := before
		return strings.HasPrefix(requestPath, prefix)
	}

	return requestPath == pattern
}

// Old-router-style scan: check all patterns, pick the longest match.
func oldRouterFind(requestPath string, patterns []string) string {
	best := woos.Empty
	bestLen := -1

	for _, p := range patterns {
		if !oldMatch(requestPath, p) {
			continue
		}
		if len(p) > bestLen {
			best = p
			bestLen = len(p)
		}
	}
	return best
}

func BenchmarkRouter_NewTree_FastPathExact(b *testing.B) {
	tr := NewTree()
	_ = tr.Insert(pApi, mkRoute(pApi))
	_ = tr.Insert(pApi2, mkRoute(pApi2))
	_ = tr.Insert(pApiID, mkRoute(pApiID))
	_ = tr.Insert(pSlash, mkRoute(pSlash))

	path := pApiID // exact literal

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tr.Find(path)
	}
}

func BenchmarkRouter_NewTree_PrefixTraversal(b *testing.B) {
	tr, _ := buildBasicTree(b)

	path := pApiSlash // requires tree prefix behavior

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tr.Find(path)
	}
}

func BenchmarkRouter_NewTree_ColdTraversalUnique(b *testing.B) {
	tr, _ := buildBasicTree(b)

	const base = "/api/x/"

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = tr.Find(base + strconv.Itoa(i))
	}
}

func BenchmarkRouter_OldMatch_Scan(b *testing.B) {
	const (
		pApiStar = "/api*"
	)
	patterns := []string{pSlash, pApiStar, pApi2, pApiID}

	path := pApiIDMore

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = oldRouterFind(path, patterns)
	}
}
