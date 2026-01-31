package matcher

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/errors"
)

const (
	Empty               = ""
	Slash               = "/"
	Star                = "*"
	SlashStar           = "/*"
	SlashByte           = '/'
	RegexPrefix         = "~"
	TemplateOpen        = "{"
	TemplateClose       = "}"
	TemplateSep         = ":"
	TemplateWildcardKey = "*"
)

const (
	cacheMax = int64(10_000)
)

type kind uint8

const (
	kindLiteral  kind = iota // literal segment: "/api"
	kindTemplate             // template segment: "/{id}" or "/{id:[0-9]+}"
	kindRegex                // regex segment: "/~[0-9]+"
	kindCatchAll             // "/*"
)

// MatchResult returned from Find
type MatchResult struct {
	Route  *alaye.Route
	Params map[string]string // {id: "123", userId: "alice", ...}
}

// Node — single segment in the tree
type Node struct {
	prefix   string // literal segment: "/api", template: "/{id}", regex: "/~[0-9]+", catch-all: "/*"
	kind     kind
	re       *regexp.Regexp // for kindRegex or template with :regex
	paramKey string         // for kindTemplate
	children []*Node
	route    *alaye.Route // can be set on any node (prefix routing)

	// quick checks (not correctness-critical)
	hasCatchAll bool
	hasParams   bool
}

// Tree — per-host route tree
type Tree struct {
	root      *Node
	cache     sync.Map // map[string]MatchResult
	cacheSize atomic.Int64
	fastPaths map[string]*Node // map[fullPattern]*Node for O(1) exact/prefix matches

	mu sync.RWMutex
}

func NewTree() *Tree {
	return &Tree{
		root:      &Node{prefix: Empty, kind: kindLiteral},
		fastPaths: make(map[string]*Node),
	}
}

// Insert pattern → Route
func (t *Tree) Insert(pattern string, route *alaye.Route) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	// FIX: Normalize "/*" to "/" at the root level using constants.
	if pattern == SlashStar {
		pattern = Slash
	}

	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)
	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		_ = t.insertFastPath(pattern, route)
	}

	return t.insertRecursive(t.root, pattern, route)
}

// Find matches request path with O(1) fast path for common literal patterns.
func (t *Tree) Find(path string) MatchResult {
	path = cleanPattern(path)

	// 1. Root Exact Match optimization
	if path == Slash {
		t.mu.RLock()
		r := t.root.route
		t.mu.RUnlock()
		return MatchResult{Route: r, Params: nil}
	}

	// 2. Fast path (Exact/Prefix nodes)
	t.mu.RLock()
	if node, ok := t.fastPaths[path]; ok && node != nil && node.route != nil {
		t.mu.RUnlock()
		return MatchResult{Route: node.route, Params: nil}
	}
	t.mu.RUnlock()

	// 3. Cache lookup
	if cached, ok := t.cache.Load(path); ok {
		return cached.(MatchResult)
	}

	// 4. Tree Traversal
	t.mu.RLock()
	result := t.findWithBacktrack(t.root, path, nil)
	t.mu.RUnlock()

	// Cache
	if result.Route != nil {
		for {
			cur := t.cacheSize.Load()
			if cur >= cacheMax {
				break
			}
			if t.cacheSize.CompareAndSwap(cur, cur+1) {
				t.cache.Store(path, result)
				break
			}
		}
	}

	return result
}

// ClearCache clears all cached results.
func (t *Tree) ClearCache() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cache.Range(func(key, _ any) bool {
		t.cache.Delete(key)
		return true
	})
	t.cacheSize.Store(0)
}

// Stats returns tree statistics for debugging/monitoring.
func (t *Tree) Stats() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := make(map[string]any)
	stats["fast_paths"] = len(t.fastPaths)
	stats["cache_size"] = t.cacheSize.Load()
	stats["node_count"] = t.countNodes(t.root)
	stats["route_count"] = t.countRoutes(t.root)
	return stats
}

// BulkInsert inserts multiple routes with validation.
func (t *Tree) BulkInsert(routes map[string]*alaye.Route) []error {
	var errs []error
	for pattern, route := range routes {
		if err := t.Insert(pattern, route); err != nil {
			errs = append(errs, errors.Newf("pattern %q: %w", pattern, err))
		}
	}
	return errs
}

// GetPatterns returns all registered patterns (for debugging).
func (t *Tree) GetPatterns() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var patterns []string
	t.collectPatterns(t.root, Empty, &patterns)
	return patterns
}

func (t *Tree) countNodes(n *Node) int {
	count := 1
	for _, child := range n.children {
		count += t.countNodes(child)
	}
	return count
}

func (t *Tree) countRoutes(n *Node) int {
	count := 0
	if n.route != nil {
		count++
	}
	for _, child := range n.children {
		count += t.countRoutes(child)
	}
	return count
}

func (t *Tree) collectPatterns(n *Node, current string, patterns *[]string) {
	if n.route != nil {
		*patterns = append(*patterns, current)
	}
	for _, child := range n.children {
		next := current + child.prefix
		t.collectPatterns(child, next, patterns)
	}
}

// Rebuild clears and rebuilds the tree from a slice.
func (t *Tree) Rebuild(routes []alaye.Route) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.root = &Node{prefix: Empty, kind: kindLiteral}
	t.fastPaths = make(map[string]*Node)
	t.cache = sync.Map{}
	t.cacheSize.Store(0)

	for i := range routes {
		r := &routes[i]
		_ = t.insertLocked(r.Path, r)
	}
}

// insertLocked assumes the caller holds t.mu (write lock).
func (t *Tree) insertLocked(pattern string, route *alaye.Route) error {
	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)
	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		return t.insertFastPath(pattern, route)
	}
	return t.insertRecursive(t.root, pattern, route)
}

func (t *Tree) validatePattern(pattern string) error {
	if pattern == Empty {
		return woos.ErrEmptyPattern
	}

	// Catch-all rules.
	starCount := strings.Count(pattern, SlashStar)
	if starCount > 1 {
		return woos.ErrMultipleCatchAllsMsg
	}
	if starCount == 1 && !strings.HasSuffix(pattern, SlashStar) {
		return woos.ErrCatchAllNotAtEndMsg
	}

	return t.validateParamNames(pattern)
}

func (t *Tree) validateParamNames(pattern string) error {
	paramNames := t.extractParamNames(pattern)
	seen := make(map[string]bool)

	for _, name := range paramNames {
		if name == Empty {
			return woos.ErrEmptyParamName
		}
		if seen[name] {
			return errors.Newf("%w: %q", woos.ErrDuplicateParamName, name)
		}
		seen[name] = true
	}
	return nil
}

func (t *Tree) extractParamNames(pattern string) []string {
	var names []string
	start := -1

	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case TemplateOpen[0]:
			start = i + 1
		case TemplateClose[0]:
			if start == -1 {
				continue
			}
			param := pattern[start:i]
			if param == Empty {
				start = -1
				continue
			}
			if idx := strings.Index(param, TemplateSep); idx >= 0 {
				param = param[:idx]
			}
			names = append(names, param)
			start = -1
		}
	}
	return names
}

func (t *Tree) isFastPath(pattern string) bool {
	// literal-only: no templates, regex prefix, or wildcard.
	return !strings.Contains(pattern, TemplateOpen) &&
		!strings.Contains(pattern, RegexPrefix) &&
		!strings.Contains(pattern, Star)
}

func (t *Tree) insertFastPath(pattern string, route *alaye.Route) error {
	// Fast paths are literal prefix routes too, so we store them as nodes.
	t.fastPaths[pattern] = &Node{
		prefix: pattern,
		kind:   kindLiteral,
		route:  route,
	}
	return nil
}

func (t *Tree) insertRecursive(parent *Node, path string, route *alaye.Route) error {
	// IMPORTANT: root route
	if path == Slash {
		if parent.route != nil {
			return errors.Newf("%w for pattern %q", woos.ErrDuplicateRoute, Slash)
		}
		parent.route = route
		return nil
	}

	// Pattern fully consumed: set the route here.
	if path == Empty {
		if parent.route != nil {
			return errors.Newf("%w for pattern %q", woos.ErrDuplicateRoute, parent.prefix)
		}
		parent.route = route
		return nil
	}

	seg, rest, segKind, err := t.parseSegment(path)
	if err != nil {
		return errors.Newf("failed to parse segment in %q: %w", path, err)
	}

	// Optimization flags.
	if segKind == kindCatchAll {
		parent.hasCatchAll = true
	} else if segKind == kindTemplate || segKind == kindRegex {
		parent.hasParams = true
	}

	child := parent.findChild(seg, segKind)
	if child == nil {
		child, err = t.createNode(seg, segKind)
		if err != nil {
			return err
		}
		parent.children = append(parent.children, child)

		// Keep children sorted by priority: literal > template > regex > catch-all.
		sort.Slice(parent.children, func(i, j int) bool {
			return scoreKind(parent.children[i].kind) > scoreKind(parent.children[j].kind)
		})
	}

	// Catch-all ends the pattern; route should attach to that node.
	if segKind == kindCatchAll {
		if child.route != nil {
			return errors.Newf("%w for pattern %q", woos.ErrDuplicateRoute, seg)
		}
		child.route = route
		return nil
	}

	return t.insertRecursive(child, rest, route)
}

func (t *Tree) findWithBacktrack(node *Node, remaining string, params map[string]string) MatchResult {
	// The current node's route is our "Best Match So Far" (Fallback).
	// If we are at root ("/"), node.route is the route for "/".
	// If children don't match, we return this. This effectively makes "/" a catch-all.
	best := MatchResult{Route: node.route, Params: params}

	if remaining == Empty {
		return best
	}

	// Iterate children sorted by priority (Literal > Template > Regex > CatchAll)
	for _, child := range node.children {
		ok, consumed, captured := child.match(remaining)
		if !ok {
			continue
		}

		nextParams := params
		if len(captured) > 0 {
			nextParams = make(map[string]string, len(params)+len(captured))
			for k, v := range params {
				nextParams[k] = v
			}
			for k, v := range captured {
				nextParams[k] = v
			}
		}

		// Recurse
		result := t.findWithBacktrack(child, remaining[consumed:], nextParams)
		if result.Route != nil {
			return result
		}
	}

	// Standard Catch-All Node Check (e.g. /api/*)
	// Note: Root fallback is handled by 'best' above, this handles explicit catch-alls deep in the tree.
	if node.hasCatchAll {
		for _, child := range node.children {
			if child.kind != kindCatchAll {
				continue
			}
			if child.route == nil {
				continue
			}

			out := params
			if out == nil {
				out = make(map[string]string, 1)
			} else {
				cp := make(map[string]string, len(out)+1)
				for k, v := range out {
					cp[k] = v
				}
				out = cp
			}
			out[TemplateWildcardKey] = remaining
			return MatchResult{Route: child.route, Params: out}
		}
	}

	return best
}

func (t *Tree) clearCacheForPattern(pattern string) {
	// Assumes caller holds write lock.
	delete(t.fastPaths, pattern)

	t.cache.Range(func(key, _ any) bool {
		t.cache.Delete(key)
		return true
	})
	t.cacheSize.Store(0)
}

func (t *Tree) createNode(seg string, k kind) (*Node, error) {
	n := &Node{prefix: seg, kind: k}

	switch k {
	case kindRegex:
		// seg is "/~expr"
		expr := strings.TrimPrefix(seg, Slash+RegexPrefix)
		if expr == Empty {
			return nil, errors.Newf("%w: %q", woos.ErrEmptyRegexPatternSegment, seg)
		}

		// Anchor the regex to the segment value (not including leading Slash).
		expr = ensureAnchors(expr)

		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, errors.Newf("invalid regex %q: %w", expr, err)
		}
		n.re = re

	case kindTemplate:
		// seg is "/{name}" or "/{name:regex}"
		content := strings.TrimPrefix(seg, Slash+TemplateOpen)
		content = strings.TrimSuffix(content, TemplateClose)

		if content == Empty {
			return nil, errors.Newf("%w in segment %q", woos.ErrEmptyTemplateParam, seg)
		}

		parts := strings.SplitN(content, TemplateSep, 2)
		n.paramKey = parts[0]
		if n.paramKey == Empty {
			return nil, errors.Newf("%w in template %q", woos.ErrEmptyParamName, seg)
		}

		if len(parts) == 2 && parts[1] != Empty {
			expr := ensureAnchors(parts[1])
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, errors.Newf("invalid regex in template %q: %w", seg, err)
			}
			n.re = re
		}

	case kindCatchAll:
		n.prefix = SlashStar
		n.hasCatchAll = true

	case kindLiteral:
		// no-op
	}

	return n, nil
}

func (n *Node) match(path string) (bool, int, map[string]string) {
	if path == Empty {
		return false, 0, nil
	}
	if path[0] != SlashByte {
		return false, 0, nil
	}

	switch n.kind {
	case kindLiteral:
		// Segment-boundary match: "/api" matches "/api" and "/api/...", but not "/apis".
		if !strings.HasPrefix(path, n.prefix) {
			return false, 0, nil
		}
		consumed := len(n.prefix)

		// Boundary check.
		if len(path) == consumed {
			return true, consumed, nil
		}
		if path[consumed] == SlashByte {
			return true, consumed, nil
		}
		return false, 0, nil

	case kindTemplate, kindRegex:
		// Segment is everything after the leading Slash up to next Slash (or end).
		end := len(path)
		if idx := strings.IndexByte(path[1:], SlashByte); idx >= 0 {
			end = 1 + idx
		}

		// Value without leading Slash.
		value := path[1:end]
		if value == Empty {
			return false, 0, nil
		}

		// Validate against regex if present.
		if n.re != nil && !n.re.MatchString(value) {
			return false, 0, nil
		}

		consumed := end

		if n.kind == kindTemplate {
			params := make(map[string]string, 1)
			params[n.paramKey] = value
			return true, consumed, params
		}
		return true, consumed, nil

	case kindCatchAll:
		// path starts with "/"
		rest := path
		if strings.HasPrefix(rest, Slash) {
			rest = rest[1:] // store without leading Slash
		}
		params := make(map[string]string, 1)
		params[TemplateWildcardKey] = rest
		return true, len(path), params

	default:
		return false, 0, nil
	}
}

func (n *Node) findChild(seg string, k kind) *Node {
	for _, c := range n.children {
		if c.kind == k && c.prefix == seg {
			return c
		}
	}
	return nil
}

func (t *Tree) parseSegment(path string) (seg, rest string, k kind, err error) {
	if path == Empty {
		return Empty, Empty, 0, woos.ErrEmptyPath
	}
	if path[0] != SlashByte {
		return Empty, Empty, 0, errors.Newf("%w: path must start with %q", woos.ErrInvalidPath, Slash)
	}

	// Catch-all.
	if path == SlashStar || strings.HasPrefix(path, SlashStar) {
		return SlashStar, Empty, kindCatchAll, nil
	}

	// Find end of current segment.
	end := len(path)
	if idx := strings.IndexByte(path[1:], SlashByte); idx >= 0 {
		end = 1 + idx
	}

	seg = path[:end]
	rest = path[end:]

	// Determine segment kind.
	switch {
	case strings.HasPrefix(seg, Slash+RegexPrefix):
		k = kindRegex

	case strings.Contains(seg, TemplateOpen):
		// Template must be exactly one "{...}" block in the segment.
		if !strings.Contains(seg, TemplateClose) {
			return Empty, Empty, 0, errors.Newf("%w in segment %q", woos.ErrUnclosedTemplate, seg)
		}
		if strings.Count(seg, TemplateOpen) != 1 || strings.Count(seg, TemplateClose) != 1 {
			return Empty, Empty, 0, errors.Newf("%w in segment %q", woos.ErrInvalidTemplateBraces, seg)
		}
		k = kindTemplate

	default:
		k = kindLiteral
	}

	return seg, rest, k, nil
}

func cleanPattern(p string) string {
	p = strings.TrimSpace(p)
	if p == Empty || p == Slash {
		return Slash
	}
	if !strings.HasPrefix(p, Slash) {
		p = Slash + p
	}
	// Preserve trailing Slash (caller decides semantics).
	return p
}

func scoreKind(k kind) int {
	switch k {
	case kindLiteral:
		return 4
	case kindTemplate:
		return 3
	case kindRegex:
		return 2
	case kindCatchAll:
		return 1
	default:
		return 0
	}
}

func ensureAnchors(expr string) string {
	if !strings.HasPrefix(expr, "^") {
		expr = "^" + expr
	}
	if !strings.HasSuffix(expr, "$") {
		expr = expr + "$"
	}
	return expr
}
