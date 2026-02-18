package matcher

import (
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/errors"
)

// MatchResult returned from Find
type MatchResult struct {
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

	cache     sync.Map
	cacheSize atomic.Int64
	fastPaths atomic.Pointer[map[string]*Node]

	mu sync.RWMutex
}

// NewTree returns an empty Tree
func NewTree() *Tree {
	t := &Tree{}
	root := &Node{prefix: woos.Empty, kind: woos.KindLiteral}
	t.root.Store(root)

	fast := make(map[string]*Node)
	t.fastPaths.Store(&fast)
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
		t.insertFastPath(pattern, route)
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

// Find returns the best match for a path
func (t *Tree) Find(path string) MatchResult {
	path = cleanPattern(path)

	// 1. Root exact match
	root := t.root.Load()
	if path == woos.Slash {
		return MatchResult{Route: root.route, Params: nil}
	}

	// 2. Fast path map
	fp := t.fastPaths.Load()
	if node, ok := (*fp)[path]; ok && node != nil && node.route != nil {
		return MatchResult{Route: node.route, Params: nil}
	}

	// 3. Cache
	if cached, ok := t.cache.Load(path); ok {
		return cached.(MatchResult)
	}

	// 4. Tree traversal (read-only)
	t.mu.RLock()
	result := t.findWithBacktrack(root, path, nil)
	t.mu.RUnlock()

	if result.Route != nil {
		for {
			cur := t.cacheSize.Load()
			if cur >= woos.CacheMax {
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

// ClearCache clears all cached results
func (t *Tree) ClearCache() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.cache.Range(func(key, _ any) bool {
		t.cache.Delete(key)
		return true
	})
	t.cacheSize.Store(0)
	fp := make(map[string]*Node)
	t.fastPaths.Store(&fp)
}

// Stats returns tree statistics
func (t *Tree) Stats() map[string]any {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats := make(map[string]any)
	root := t.root.Load()
	stats["fast_paths"] = len(*t.fastPaths.Load())
	stats["cache_size"] = t.cacheSize.Load()
	stats["node_count"] = t.countNodes(root)
	stats["route_count"] = t.countRoutes(root)
	return stats
}

// BulkInsert inserts multiple routes
func (t *Tree) BulkInsert(routes map[string]*alaye.Route) []error {
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

	fp := make(map[string]*Node)
	t.fastPaths.Store(&fp)
	t.cache = sync.Map{}
	t.cacheSize.Store(0)

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
		t.insertFastPath(pattern, route)
	}

	return t.insertRecursive(t.root.Load(), pattern, route)
}

func (t *Tree) insertFastPath(pattern string, route *alaye.Route) {
	fp := *t.fastPaths.Load()
	fp[pattern] = &Node{prefix: pattern, kind: woos.KindLiteral, route: route}
	t.fastPaths.Store(&fp)
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

func (t *Tree) findWithBacktrack(node *Node, remaining string, params map[string]string) MatchResult {
	best := MatchResult{Route: node.route, Params: params}
	if remaining == woos.Empty {
		return best
	}

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
		result := t.findWithBacktrack(child, remaining[consumed:], nextParams)
		if result.Route != nil {
			return result
		}
	}

	if node.hasCatchAll {
		for _, child := range node.children {
			if child.kind == woos.KindCatchAll && child.route != nil {
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
				out[woos.TemplateWildcardKey] = remaining
				return MatchResult{Route: child.route, Params: out}
			}
		}
	}

	return best
}

func (t *Tree) clearCacheForPattern(pattern string) {
	delete(*t.fastPaths.Load(), pattern)
	t.cache.Range(func(key, _ any) bool { t.cache.Delete(key); return true })
	t.cacheSize.Store(0)
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

// ---------------- Node Methods ----------------

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

// ---------------- Tree Utilities ----------------

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

// ---------------- Validation ----------------

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

// ---------------- Utility ----------------

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

func (t *Tree) isFastPath(pattern string) bool {
	return !strings.Contains(pattern, woos.TemplateOpen) &&
		!strings.Contains(pattern, woos.RegexPrefix) &&
		!strings.Contains(pattern, woos.Star)
}
