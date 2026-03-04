package rewrite

import (
	"net/http"
	"strings"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/olekukonko/ll"
)

// New returns a middleware that rewrites request paths.
// Order: strip prefixes first, then regex rewrites (first match wins).
func New(logger *ll.Logger, stripPrefixes []string, rewrites []alaye.Rewrite) func(http.Handler) http.Handler {
	if len(stripPrefixes) == 0 && len(rewrites) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	validRewrites := make([]alaye.Rewrite, 0, len(rewrites))
	for _, r := range rewrites {
		if r.Regex != nil {
			validRewrites = append(validRewrites, r)
		} else {
			logger.Warn("rewrite rule skipped: missing compiled regex", "pattern", r.Pattern)
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			originalPath := path

			for _, prefix := range stripPrefixes {
				if strings.HasPrefix(path, prefix) {
					path = strings.TrimPrefix(path, prefix)
					if path == "" {
						path = "/"
					} else if !strings.HasPrefix(path, "/") {
						path = "/" + path
					}

					logger.Debug("strip prefix applied",
						"prefix", prefix,
						"from", originalPath,
						"to", path)

					break
				}
			}

			for _, rule := range validRewrites {
				if rule.Regex.MatchString(path) {
					newPath := rule.Regex.ReplaceAllString(path, rule.Target)

					logger.Debug("rewrite rule applied",
						"pattern", rule.Pattern,
						"target", rule.Target,
						"from", path,
						"to", newPath)

					path = newPath
					break
				}
			}

			if path != originalPath {
				r.URL.Path = path
				r.URL.RawPath = ""
				r.Header.Set("X-Agbero-Rewrite", "true")

				logger.Info("path rewritten",
					"from", originalPath,
					"to", path,
					"method", r.Method)

			}

			next.ServeHTTP(w, r)
		})
	}
}
