package matcher

import (
	"maps"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
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
	kind     def.Kind
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
		cache:     mappo.NewLRU[string, Result](def.CacheMax),
		fastPaths: mappo.NewShardedWithConfig[string, *Node](mappo.ShardedConfig{ShardCount: 16}),
	}

	root := &Node{prefix: def.Empty, kind: def.KindLiteral}
	t.root.Store(root)

	return t
}

// Insert adds a pattern → route mapping
func (t *Tree) Insert(pattern string, route *alaye.Route) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if pattern == def.SlashStar {
		pattern = def.Slash
	}

	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)

	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		t.fastPaths.Set(pattern, &Node{prefix: pattern, kind: def.KindLiteral, route: route})
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

// Find returns the best match for a path
func (t *Tree) Find(path string) Result {
	path = cleanPattern(path)

	// Root exact match
	root := t.root.Load()
	if path == def.Slash {
		return Result{Route: root.route, Params: nil}
	}

	// Fast path map - lock-free lookup
	if node, ok := t.fastPaths.Get(path); ok && node != nil && node.route != nil {
		return Result{Route: node.route, Params: nil}
	}

	// Cache - strictly typed, no allocations
	if val, ok := t.cache.Get(path); ok {
		return val
	}

	// Tree traversal (read-only, RLock sufficient)
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
	t.collectPatterns(t.root.Load(), def.Empty, &patterns)
	return patterns
}

// Rebuild clears and rebuilds the tree
func (t *Tree) Rebuild(routes []alaye.Route) {
	t.mu.Lock()
	defer t.mu.Unlock()

	root := &Node{prefix: def.Empty, kind: def.KindLiteral}
	t.root.Store(root)

	t.fastPaths.Clear()
	t.cache.Clear()

	for i := range routes {
		r := &routes[i]
		_ = t.insertLocked(r.Path, r)
	}
}

// Internal Helpers

func (t *Tree) insertLocked(pattern string, route *alaye.Route) error {
	if err := t.validatePattern(pattern); err != nil {
		return errors.Newf("invalid route pattern %q: %w", pattern, err)
	}

	pattern = cleanPattern(pattern)
	t.clearCacheForPattern(pattern)

	if t.isFastPath(pattern) {
		t.fastPaths.Set(pattern, &Node{prefix: pattern, kind: def.KindLiteral, route: route})
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

func (t *Tree) insertRecursive(parent *Node, path string, route *alaye.Route) error {
	if path == def.Slash || path == def.Empty {
		if parent.route != nil {
			return errors.Newf("%w for pattern %q", def.ErrDuplicateRoute, path)
		}
		parent.route = route
		return nil
	}

	seg, rest, segKind, err := t.parseSegment(path)
	if err != nil {
		return errors.Newf("failed to parse segment in %q: %w", path, err)
	}

	if segKind == def.KindCatchAll {
		parent.hasCatchAll = true
	} else if segKind == def.KindTemplate || segKind == def.KindRegex {
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

	if segKind == def.KindCatchAll {
		if child.route != nil {
			return errors.Newf("%w for pattern %q", def.ErrDuplicateRoute, seg)
		}
		child.route = route
		return nil
	}

	return t.insertRecursive(child, rest, route)
}

func (t *Tree) findWithBacktrack(node *Node, remaining string, params map[string]string) Result {
	best := Result{Route: node.route, Params: params}
	if remaining == def.Empty {
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
			if child.kind == def.KindCatchAll && child.route != nil {
				var out map[string]string
				if params == nil {
					out = map[string]string{def.TemplateWildcardKey: remaining}
				} else {
					out = make(map[string]string, len(params)+1)
					maps.Copy(out, params)
					out[def.TemplateWildcardKey] = remaining
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

func (t *Tree) createNode(seg string, k def.Kind) (*Node, error) {
	n := &Node{prefix: seg, kind: k}
	switch k {
	case def.KindRegex:
		expr := strings.TrimPrefix(seg, def.Slash+def.RegexPrefix)
		if expr == def.Empty {
			return nil, errors.Newf("%w: %q", def.ErrEmptyRegexPatternSegment, seg)
		}
		expr = ensureAnchors(expr)
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, errors.Newf("invalid regex %q: %w", expr, err)
		}
		n.re = re
	case def.KindTemplate:
		content := strings.TrimPrefix(seg, def.Slash+def.TemplateOpen)
		content = strings.TrimSuffix(content, def.TemplateClose)
		if content == def.Empty {
			return nil, errors.Newf("%w in segment %q", def.ErrEmptyTemplateParam, seg)
		}
		parts := strings.SplitN(content, def.TemplateSep, 2)
		n.paramKey = parts[0]
		if n.paramKey == def.Empty {
			return nil, errors.Newf("%w in template %q", def.ErrEmptyParamName, seg)
		}
		if len(parts) == 2 && parts[1] != def.Empty {
			re, err := regexp.Compile(ensureAnchors(parts[1]))
			if err != nil {
				return nil, errors.Newf("invalid regex in template %q: %w", seg, err)
			}
			n.re = re
		}
	case def.KindCatchAll:
		n.prefix = def.SlashStar
		n.hasCatchAll = true
	}
	return n, nil
}

func (n *Node) match(path string) (bool, int, map[string]string) {
	if path == def.Empty || path[0] != def.SlashByte {
		return false, 0, nil
	}

	switch n.kind {
	case def.KindLiteral:
		if !strings.HasPrefix(path, n.prefix) {
			return false, 0, nil
		}
		consumed := len(n.prefix)
		if len(path) == consumed || path[consumed] == def.SlashByte {
			return true, consumed, nil
		}
		return false, 0, nil
	case def.KindTemplate, def.KindRegex:
		end := len(path)
		if idx := strings.IndexByte(path[1:], def.SlashByte); idx >= 0 {
			end = 1 + idx
		}
		value := path[1:end]
		if value == def.Empty {
			return false, 0, nil
		}
		if n.re != nil && !n.re.MatchString(value) {
			return false, 0, nil
		}
		consumed := end
		if n.kind == def.KindTemplate {
			return true, consumed, map[string]string{n.paramKey: value}
		}
		return true, consumed, nil
	case def.KindCatchAll:
		rest := path
		if strings.HasPrefix(rest, def.Slash) {
			rest = rest[1:]
		}
		return true, len(path), map[string]string{def.TemplateWildcardKey: rest}
	}
	return false, 0, nil
}

func (n *Node) findChild(seg string, k def.Kind) *Node {
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

func (t *Tree) parseSegment(path string) (seg, rest string, k def.Kind, err error) {
	if path == def.Empty || path[0] != def.SlashByte {
		return def.Empty, def.Empty, 0, errors.Newf("%w: must start with /", def.ErrInvalidPath)
	}
	if path == def.SlashStar || strings.HasPrefix(path, def.SlashStar) {
		return def.SlashStar, def.Empty, def.KindCatchAll, nil
	}
	end := len(path)
	if idx := strings.IndexByte(path[1:], def.SlashByte); idx >= 0 {
		end = 1 + idx
	}
	seg = path[:end]
	rest = path[end:]
	switch {
	case strings.HasPrefix(seg, def.Slash+def.RegexPrefix):
		k = def.KindRegex
	case strings.Contains(seg, def.TemplateOpen):
		if strings.Count(seg, def.TemplateOpen) != 1 || strings.Count(seg, def.TemplateClose) != 1 {
			return def.Empty, def.Empty, 0, errors.Newf("%w in segment %q", def.ErrInvalidTemplateBraces, seg)
		}
		k = def.KindTemplate
	default:
		k = def.KindLiteral
	}
	return
}

func (t *Tree) validatePattern(pattern string) error {
	if pattern == def.Empty {
		return def.ErrEmptyPattern
	}
	if strings.Count(pattern, def.SlashStar) > 1 {
		return def.ErrMultipleCatchAllsMsg
	}
	if strings.Contains(pattern, def.SlashStar) && !strings.HasSuffix(pattern, def.SlashStar) {
		return def.ErrCatchAllNotAtEndMsg
	}
	return t.validateParamNames(pattern)
}

func (t *Tree) validateParamNames(pattern string) error {
	seen := make(map[string]bool)
	for _, name := range t.extractParamNames(pattern) {
		if name == def.Empty {
			return def.ErrEmptyParamName
		}
		if seen[name] {
			return errors.Newf("%w: %q", def.ErrDuplicateParamName, name)
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
		case def.TemplateOpen[0]:
			start = i + 1
		case def.TemplateClose[0]:
			if start != -1 {
				param := pattern[start:i]
				if idx := strings.Index(param, def.TemplateSep); idx >= 0 {
					param = param[:idx]
				}
				if param != def.Empty {
					names = append(names, param)
				}
				start = -1
			}
		}
	}
	return names
}

func (t *Tree) isFastPath(pattern string) bool {
	return !strings.Contains(pattern, def.TemplateOpen) &&
		!strings.Contains(pattern, def.RegexPrefix) &&
		!strings.Contains(pattern, def.Star)
}

func cleanPattern(p string) string {
	p = strings.TrimSpace(p)
	if p == def.Empty || p == def.Slash {
		return def.Slash
	}
	if !strings.HasPrefix(p, def.Slash) {
		p = def.Slash + p
	}
	return p
}

func scoreKind(k def.Kind) int {
	switch k {
	case def.KindLiteral:
		return 4
	case def.KindTemplate:
		return 3
	case def.KindRegex:
		return 2
	case def.KindCatchAll:
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
