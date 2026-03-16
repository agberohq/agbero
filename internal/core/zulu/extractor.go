package zulu

import (
	"net/http"
	"strings"
)

// Extractor creates a composite extractor from multiple key configurations
func Extractor(keys []string) func(*http.Request) string {
	if len(keys) == 0 {
		return IP.ClientIP
	}

	// Build individual extractors
	var extractors []func(*http.Request) string

	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}

		switch {
		case strings.EqualFold(key, "ip"):
			extractors = append(extractors, IP.ClientIP)

		case strings.HasPrefix(strings.ToLower(key), "cookie:"):
			// Format: cookie:name
			cookieName := strings.TrimPrefix(key, "cookie:")
			cookieName = strings.TrimPrefix(cookieName, "Cookie:")
			cookieName = strings.TrimSpace(cookieName)
			extractors = append(extractors, func(r *http.Request) string {
				if cookie, err := r.Cookie(cookieName); err == nil {
					return cookie.Value
				}
				return ""
			})

		case strings.HasPrefix(strings.ToLower(key), "header:"):
			// Format: header:name or header:name:prefix
			headerPart := strings.TrimPrefix(key, "header:")
			headerPart = strings.TrimPrefix(headerPart, "Header:")
			headerPart = strings.TrimSpace(headerPart)

			var headerName, prefix string
			if before, after, ok := strings.Cut(headerPart, ":"); ok {
				headerName = strings.TrimSpace(before)
				prefix = strings.TrimSpace(after)
			} else {
				headerName = headerPart
			}

			extractors = append(extractors, func(r *http.Request) string {
				val := r.Header.Get(headerName)
				if val != "" && prefix != "" && strings.HasPrefix(val, prefix) {
					val = strings.TrimPrefix(val, prefix)
				}
				return val
			})

		case strings.HasPrefix(strings.ToLower(key), "query:"):
			// Format: query:name
			queryName := strings.TrimPrefix(key, "query:")
			queryName = strings.TrimPrefix(queryName, "Query:")
			queryName = strings.TrimSpace(queryName)
			extractors = append(extractors, func(r *http.Request) string {
				return r.URL.Query().Get(queryName)
			})

		default:
			// Assume it's a header name for backward compatibility
			headerName := key
			extractors = append(extractors, func(r *http.Request) string {
				return r.Header.Get(headerName)
			})
		}
	}

	if len(extractors) == 0 {
		return IP.ClientIP
	}

	// Return composite extractor
	return func(r *http.Request) string {
		var parts []string
		for _, extract := range extractors {
			if val := extract(r); val != "" {
				parts = append(parts, val)
			}
		}

		if len(parts) == 0 {
			return ""
		}
		if len(parts) == 1 {
			return parts[0]
		}
		return strings.Join(parts, "||")
	}
}
