package matcher

import (
	"maps"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/woos"
	"github.com/olekukonko/errors"
	"github.com/olekukonko/mappo"
)

// Result returned from Find
type Result struct {
	Route  *alaye.Route
	Params map[string]string
}

// Node — single segment in the tree
type Node struct {
	prefix   string
	kind     woos.Kind
	re       *regexp.Regexp
	paramKey string
	children []*Node
	route    *alaye.Route

	hasCatchAll bool
	hasParams   bool
}

// Tree — per-host route tree
type Tree struct {
	root atomic.Pointer[Node]

	// Use typed LRU cache to eliminate heap escapes and type assertions
	cache *mappo.LRU[string, Result]

	// Use Sharded map for fast paths to avoid copy-on-write
	fastPaths *mappo.Sharded[string, *Node]

	mu sync.RWMutex
}

// NewTree returns an empty Tree
func NewTree() *Tree {
	t := &Tree{
		cache:     mappo.NewLRU[string, Result](woos.CacheMax),
		fastPaths: mappo.NewShardedWithConfig[string, *Node](mappo.ShardedConfig{ShardCount: 16}),
	}

	root := &Node{prefix: woos.Empty, kind: woos.KindLiteral}
	t.root.Store(root)

	return t
}

// Insert adds a pattern → route mapping
func (t *Tree) Insert(pattern string, route *alaye.Route) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if pattern == woos.SlashStar {
		pattern = woos.Slash
	}

	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)

	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		t.fastPaths.Set(pattern, &Node{prefix: pattern, kind: woos.KindLiteral, route: route})
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

// Find returns the best match for a path
func (t *Tree) Find(path string) Result {
	path = cleanPattern(path)

	// 1. Root exact match
	root := t.root.Load()
	if path == woos.Slash {
		return Result{Route: root.route, Params: nil}
	}

	// 2. Fast path map - lock-free lookup
	if node, ok := t.fastPaths.Get(path); ok && node != nil && node.route != nil {
		return Result{Route: node.route, Params: nil}
	}

	// 3. Cache - strictly typed, no allocations
	if val, ok := t.cache.Get(path); ok {
		return val
	}

	// 4. Tree traversal (read-only, RLock sufficient)
	t.mu.RLock()
	result := t.findWithBacktrack(root, path, nil)
	t.mu.RUnlock()

	if result.Route != nil {
		t.cache.Set(path, result)
	}

	return result
}

// ClearCache clears all cached results
func (t *Tree) ClearCache() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cache.Clear()
	t.fastPaths.Clear()
}

// Stats returns tree statistics
func (t *Tree) Stats() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := make(map[string]any)
	root := t.root.Load()
	stats["fast_paths"] = t.fastPaths.Len()
	stats["cache_size"] = t.cache.Len()
	stats["node_count"] = t.countNodes(root)
	stats["route_count"] = t.countRoutes(root)
	return stats
}

// Bulk inserts multiple routes
func (t *Tree) Bulk(routes map[string]*alaye.Route) []error {
	var errs []error
	for pattern, route := range routes {
		if err := t.Insert(pattern, route); err != nil {
			errs = append(errs, errors.Newf("pattern %q: %w", pattern, err))
		}
	}
	return errs
}

// GetPatterns returns all registered patterns
func (t *Tree) GetPatterns() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var patterns []string
	t.collectPatterns(t.root.Load(), woos.Empty, &patterns)
	return patterns
}

// Rebuild clears and rebuilds the tree
func (t *Tree) Rebuild(routes []alaye.Route) {
	t.mu.Lock()
	defer t.mu.Unlock()

	root := &Node{prefix: woos.Empty, kind: woos.KindLiteral}
	t.root.Store(root)

	t.fastPaths.Clear()
	t.cache.Clear()

	for i := range routes {
		r := &routes[i]
		_ = t.insertLocked(r.Path, r)
	}
}

// ------------------ Internal Helpers ------------------

func (t *Tree) insertLocked(pattern string, route *alaye.Route) error {
	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)
	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		t.fastPaths.Set(pattern, &Node{prefix: pattern, kind: woos.KindLiteral, route: route})
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

func (t *Tree) insertRecursive(parent *Node, path string, route *alaye.Route) error {
	if path == woos.Slash || path == woos.Empty {
		if parent.route != nil {
			return errors.Newf("%w for pattern %q", woos.ErrDuplicateRoute, path)
		}
		parent.route = route
		return nil
	}

	seg, rest, segKind, err := t.parseSegment(path)
	if err != nil {
		return errors.Newf("failed to parse segment in %q: %w", path, err)
	}

	if segKind == woos.KindCatchAll {
		parent.hasCatchAll = true
	} else if segKind == woos.KindTemplate || segKind == woos.KindRegex {
		parent.hasParams = true
	}

	child := parent.findChild(seg, segKind)
	if child == nil {
		child, err = t.createNode(seg, segKind)
		if err != nil {
			return err
		}
		parent.children = append(parent.children, child)
		sort.Slice(parent.children, func(i, j int) bool {
			return scoreKind(parent.children[i].kind) > scoreKind(parent.children[j].kind)
		})
	}

	if segKind == woos.KindCatchAll {
		if child.route != nil {
			return errors.Newf("%w for pattern %q", woos.ErrDuplicateRoute, seg)
		}
		child.route = route
		return nil
	}

	return t.insertRecursive(child, rest, route)
}

func (t *Tree) findWithBacktrack(node *Node, remaining string, params map[string]string) Result {
	best := Result{Route: node.route, Params: params}
	if remaining == woos.Empty {
		return best
	}

	for _, child := range node.children {
		ok, consumed, captured := child.match(remaining)
		if !ok {
			continue
		}

		var nextParams map[string]string
		if len(captured) > 0 {
			if params == nil {
				nextParams = captured
			} else {
				nextParams = make(map[string]string, len(params)+len(captured))
				maps.Copy(nextParams, params)
				maps.Copy(nextParams, captured)
			}
		} else {
			nextParams = params
		}

		result := t.findWithBacktrack(child, remaining[consumed:], nextParams)
		if result.Route != nil {
			return result
		}
	}

	if node.hasCatchAll {
		for _, child := range node.children {
			if child.kind == woos.KindCatchAll && child.route != nil {
				var out map[string]string
				if params == nil {
					out = map[string]string{woos.TemplateWildcardKey: remaining}
				} else {
					out = make(map[string]string, len(params)+1)
					maps.Copy(out, params)
					out[woos.TemplateWildcardKey] = remaining
				}
				return Result{Route: child.route, Params: out}
			}
		}
	}

	return best
}

func (t *Tree) clearCacheForPattern(pattern string) {
	t.fastPaths.Delete(pattern)
	t.cache.Clear()
}

func (t *Tree) createNode(seg string, k woos.Kind) (*Node, error) {
	n := &Node{prefix: seg, kind: k}
	switch k {
	case woos.KindRegex:
		expr := strings.TrimPrefix(seg, woos.Slash+woos.RegexPrefix)
		if expr == woos.Empty {
			return nil, errors.Newf("%w: %q", woos.ErrEmptyRegexPatternSegment, seg)
		}
		expr = ensureAnchors(expr)
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, errors.Newf("invalid regex %q: %w", expr, err)
		}
		n.re = re
	case woos.KindTemplate:
		content := strings.TrimPrefix(seg, woos.Slash+woos.TemplateOpen)
		content = strings.TrimSuffix(content, woos.TemplateClose)
		if content == woos.Empty {
			return nil, errors.Newf("%w in segment %q", woos.ErrEmptyTemplateParam, seg)
		}
		parts := strings.SplitN(content, woos.TemplateSep, 2)
		n.paramKey = parts[0]
		if n.paramKey == woos.Empty {
			return nil, errors.Newf("%w in template %q", woos.ErrEmptyParamName, seg)
		}
		if len(parts) == 2 && parts[1] != woos.Empty {
			re, err := regexp.Compile(ensureAnchors(parts[1]))
			if err != nil {
				return nil, errors.Newf("invalid regex in template %q: %w", seg, err)
			}
			n.re = re
		}
	case woos.KindCatchAll:
		n.prefix = woos.SlashStar
		n.hasCatchAll = true
	}
	return n, nil
}

func (n *Node) match(path string) (bool, int, map[string]string) {
	if path == woos.Empty || path[0] != woos.SlashByte {
		return false, 0, nil
	}

	switch n.kind {
	case woos.KindLiteral:
		if !strings.HasPrefix(path, n.prefix) {
			return false, 0, nil
		}
		consumed := len(n.prefix)
		if len(path) == consumed || path[consumed] == woos.SlashByte {
			return true, consumed, nil
		}
		return false, 0, nil
	case woos.KindTemplate, woos.KindRegex:
		end := len(path)
		if idx := strings.IndexByte(path[1:], woos.SlashByte); idx >= 0 {
			end = 1 + idx
		}
		value := path[1:end]
		if value == woos.Empty {
			return false, 0, nil
		}
		if n.re != nil && !n.re.MatchString(value) {
			return false, 0, nil
		}
		consumed := end
		if n.kind == woos.KindTemplate {
			return true, consumed, map[string]string{n.paramKey: value}
		}
		return true, consumed, nil
	case woos.KindCatchAll:
		rest := path
		if strings.HasPrefix(rest, woos.Slash) {
			rest = rest[1:]
		}
		return true, len(path), map[string]string{woos.TemplateWildcardKey: rest}
	}
	return false, 0, nil
}

func (n *Node) findChild(seg string, k woos.Kind) *Node {
	for _, c := range n.children {
		if c.kind == k && c.prefix == seg {
			return c
		}
	}
	return nil
}

func (t *Tree) countNodes(n *Node) int {
	count := 1
	for _, c := range n.children {
		count += t.countNodes(c)
	}
	return count
}

func (t *Tree) countRoutes(n *Node) int {
	count := 0
	if n.route != nil {
		count++
	}
	for _, c := range n.children {
		count += t.countRoutes(c)
	}
	return count
}

func (t *Tree) collectPatterns(n *Node, current string, patterns *[]string) {
	if n.route != nil {
		*patterns = append(*patterns, current)
	}
	for _, c := range n.children {
		t.collectPatterns(c, current+c.prefix, patterns)
	}
}

func (t *Tree) parseSegment(path string) (seg, rest string, k woos.Kind, err error) {
	if path == woos.Empty || path[0] != woos.SlashByte {
		return woos.Empty, woos.Empty, 0, errors.Newf("%w: must start with /", woos.ErrInvalidPath)
	}
	if path == woos.SlashStar || strings.HasPrefix(path, woos.SlashStar) {
		return woos.SlashStar, woos.Empty, woos.KindCatchAll, nil
	}
	end := len(path)
	if idx := strings.IndexByte(path[1:], woos.SlashByte); idx >= 0 {
		end = 1 + idx
	}
	seg = path[:end]
	rest = path[end:]
	switch {
	case strings.HasPrefix(seg, woos.Slash+woos.RegexPrefix):
		k = woos.KindRegex
	case strings.Contains(seg, woos.TemplateOpen):
		if strings.Count(seg, woos.TemplateOpen) != 1 || strings.Count(seg, woos.TemplateClose) != 1 {
			return woos.Empty, woos.Empty, 0, errors.Newf("%w in segment %q", woos.ErrInvalidTemplateBraces, seg)
		}
		k = woos.KindTemplate
	default:
		k = woos.KindLiteral
	}
	return
}

func (t *Tree) validatePattern(pattern string) error {
	if pattern == woos.Empty {
		return woos.ErrEmptyPattern
	}
	if strings.Count(pattern, woos.SlashStar) > 1 {
		return woos.ErrMultipleCatchAllsMsg
	}
	if strings.Contains(pattern, woos.SlashStar) && !strings.HasSuffix(pattern, woos.SlashStar) {
		return woos.ErrCatchAllNotAtEndMsg
	}
	return t.validateParamNames(pattern)
}

func (t *Tree) validateParamNames(pattern string) error {
	seen := make(map[string]bool)
	for _, name := range t.extractParamNames(pattern) {
		if name == woos.Empty {
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
		case woos.TemplateOpen[0]:
			start = i + 1
		case woos.TemplateClose[0]:
			if start != -1 {
				param := pattern[start:i]
				if idx := strings.Index(param, woos.TemplateSep); idx >= 0 {
					param = param[:idx]
				}
				if param != woos.Empty {
					names = append(names, param)
				}
				start = -1
			}
		}
	}
	return names
}

func (t *Tree) isFastPath(pattern string) bool {
	return !strings.Contains(pattern, woos.TemplateOpen) &&
		!strings.Contains(pattern, woos.RegexPrefix) &&
		!strings.Contains(pattern, woos.Star)
}

func cleanPattern(p string) string {
	p = strings.TrimSpace(p)
	if p == woos.Empty || p == woos.Slash {
		return woos.Slash
	}
	if !strings.HasPrefix(p, woos.Slash) {
		p = woos.Slash + p
	}
	return p
}

func scoreKind(k woos.Kind) int {
	switch k {
	case woos.KindLiteral:
		return 4
	case woos.KindTemplate:
		return 3
	case woos.KindRegex:
		return 2
	case woos.KindCatchAll:
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
		expr += "$"
	}
	return expr
}
