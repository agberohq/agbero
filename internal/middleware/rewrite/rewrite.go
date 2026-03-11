package rewrite

import (
	"net/http"
	"regexp"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

// stripRule holds pre-computed prefix stripping data
type stripRule struct {
	prefix string
	length int
}

// rewriteRule holds validated rewrite with pre-computed fields
type rewriteRule struct {
	pattern *regexp.Regexp
	target  string
}

// Middleware holds compiled configuration for zero-allocation hot path
type Middleware struct {
	stripRules   []stripRule
	rewriteRules []rewriteRule
	logger       *ll.Logger
}

// New returns a middleware that rewrites request paths.
// Optimized for hot path: all work done at construction time.
func New(logger *ll.Logger, stripPrefixes []string, rewrites []alaye.Rewrite) func(http.Handler) http.Handler {
	// Fast path: no work needed
	if len(stripPrefixes) == 0 && len(rewrites) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	m := &Middleware{
		logger: logger,
	}

	// Pre-compile strip rules
	if len(stripPrefixes) > 0 {
		m.stripRules = make([]stripRule, len(stripPrefixes))
		for i, p := range stripPrefixes {
			m.stripRules[i] = stripRule{prefix: p, length: len(p)}
		}
	}

	// Pre-compile and validate rewrite rules
	if len(rewrites) > 0 {
		m.rewriteRules = make([]rewriteRule, 0, len(rewrites))
		for _, r := range rewrites {
			if r.Regex == nil {
				logger.Warn("rewrite rule skipped: missing compiled regex", "pattern", r.Pattern)
				continue
			}
			m.rewriteRules = append(m.rewriteRules, rewriteRule{
				pattern: r.Regex,
				target:  r.Target,
			})
		}
	}

	return m.handle
}

func (m *Middleware) handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		originalPath := path
		modified := false

		// Strip prefix: O(n) scan, first match wins
		for _, rule := range m.stripRules {
			if len(path) >= rule.length && path[:rule.length] == rule.prefix {
				path = path[rule.length:]
				if path == "" {
					path = "/"
				} else if path[0] != '/' {
					path = "/" + path
				}
				modified = true
				m.logger.Debug("strip prefix applied", "prefix", rule.prefix, "from", originalPath, "to", path)
				break
			}
		}

		// Regex rewrite: O(n) scan, first match wins
		for _, rule := range m.rewriteRules {
			if loc := rule.pattern.FindStringIndex(path); loc != nil {
				// Use ReplaceAllString but only when matched (avoids alloc on no-match)
				newPath := rule.pattern.ReplaceAllString(path, rule.target)
				m.logger.Debug("rewrite rule applied", "from", path, "to", newPath)

				path = newPath
				modified = true
				break
			}
		}

		if modified {
			r.URL.Path = path
			r.URL.RawPath = ""
			r.Header.Set("X-Agbero-Rewrite", "true")
			m.logger.Info("path rewritten", "from", originalPath, "to", path, "method", r.Method)

		}

		next.ServeHTTP(w, r)
	})
}
