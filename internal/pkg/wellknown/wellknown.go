package wellknown

import (
	"path/filepath"
	"strings"

	"github.com/olekukonko/mappo"
)

// Type represents different types of well-known URIs
type Type string

const (
	ACMEChallenge       Type = "acme-challenge"
	SecurityTXT         Type = "security.txt"
	ChangePassword      Type = "change-password"
	OpenIDConfiguration Type = "openid-configuration"
	HostMeta            Type = "host-meta"
	NodeInfo            Type = "nodeinfo"
	Agbero              Type = "agbero"
)

// Path represents a parsed .well-known path
type Path struct {
	FullPath string   // cleaned absolute path (e.g. /.well-known/acme-challenge/token)
	Type     Type     // well-known resource type
	SubPath  string   // remaining path after the type
	Segments []string // split path segments
}

// concurrent sharded cache storing parsed paths for hot lookups
var pathPool = mappo.NewSharded[string, *Path]()

// NewPathInfo parses a given path and returns a structured Path object.
// Uses caching so repeated hot paths avoid re-parsing.
func NewPathInfo(path string) *Path {
	if cached, ok := pathPool.Get(path); ok {
		return cached
	}

	// normalize the path
	cleaned := filepath.Clean("/" + strings.TrimPrefix(path, "/"))
	segments := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")

	// Handle edge case: filepath.Clean removes trailing slash
	// So "/.well-known/" becomes "/.well-known" with only 1 segment
	if len(segments) == 1 && segments[0] == ".well-known" {
		segments = append(segments, "")
	}

	// ensure the path is a valid .well-known path
	if len(segments) < 2 || segments[0] != ".well-known" {
		return nil
	}

	info := &Path{
		FullPath: cleaned,
		Segments: segments,
	}

	// extract the type and subpath
	if len(segments) > 1 {
		info.Type = Type(segments[1])
		if len(segments) > 2 {
			info.SubPath = strings.Join(segments[2:], "/")
		}
	}

	// store parsed result in cache
	pathPool.Set(path, info)
	return info
}

// HasPrefix checks if the Path type starts with the given prefix.
func (p *Path) HasPrefix(prefix string) bool {
	return strings.HasPrefix(string(p.Type), prefix)
}

// IsType checks whether the path matches a specific well-known type.
func (p *Path) IsType(t Type) bool {
	return p.Type == t
}

// IsACMEChallenge checks whether the path is an ACME challenge endpoint.
func (p *Path) IsACMEChallenge() bool {
	return p.Type == ACMEChallenge
}

// GetACMEToken extracts the ACME challenge token from the path if present.
func (p *Path) GetACMEToken() (string, bool) {
	if p.IsACMEChallenge() && p.SubPath != "" {
		return p.SubPath, true
	}
	return "", false
}

// IsAgberoWebhook checks whether the path is an Agbero git webhook.
func (p *Path) IsAgberoWebhook() bool {
	return p.Type == Agbero && strings.HasPrefix(p.SubPath, "webhook/git/")
}

// GetWebhookRouteKey extracts the route key from a webhook path.
func (p *Path) GetWebhookRouteKey() (string, bool) {
	if p.IsAgberoWebhook() {
		return strings.TrimPrefix(p.SubPath, "webhook/git/"), true
	}
	return "", false
}

// BuildPath constructs a .well-known path from a type and optional subpaths.
func BuildPath(t Type, subPath ...string) string {
	components := []string{".well-known", string(t)}
	for _, s := range subPath {
		if s != "" {
			components = append(components, s)
		}
	}
	return "/" + strings.Join(components, "/")
}

// Builder provides a fluent API for constructing .well-known paths.
type Builder struct {
	pathSegments []string
}

// NewBuilder creates a new builder initialized with ".well-known".
func NewBuilder() *Builder {
	return &Builder{pathSegments: []string{".well-known"}}
}

// WithType adds the well-known resource type to the builder.
func (b *Builder) WithType(t Type) *Builder {
	b.pathSegments = append(b.pathSegments, string(t))
	return b
}

// WithSegment appends a single path segment if it is not empty.
func (b *Builder) WithSegment(segment string) *Builder {
	if segment != "" {
		b.pathSegments = append(b.pathSegments, segment)
	}
	return b
}

// WithSegments appends multiple path segments, skipping empty ones.
func (b *Builder) WithSegments(segments ...string) *Builder {
	for _, s := range segments {
		if s != "" {
			b.pathSegments = append(b.pathSegments, s)
		}
	}
	return b
}

// Build generates the final well-known path string.
func (b *Builder) Build() string {
	return "/" + strings.Join(b.pathSegments, "/")
}

// String returns the built path (implements fmt.Stringer).
func (b *Builder) String() string {
	return b.Build()
}

// IsPath checks whether a given path starts with ".well-known/".
func IsPath(path string) bool {
	return strings.HasPrefix(strings.TrimPrefix(path, "/"), ".well-known/")
}

// GetType extracts the well-known type from a path.
func GetType(path string) (Type, bool) {
	info := NewPathInfo(path)
	if info == nil {
		return "", false
	}
	return info.Type, true
}

// ACMEChallengePath builds a valid ACME challenge path with a token.
func ACMEChallengePath(token string) string {
	return BuildPath(ACMEChallenge, token)
}

// ParseACMEChallengePath parses an ACME challenge path and returns the token.
func ParseACMEChallengePath(path string) (string, bool) {
	info := NewPathInfo(path)
	if info == nil {
		return "", false
	}
	return info.GetACMEToken()
}

// GetACMETokenRaw extracts the raw token from an ACME challenge path.
func GetACMETokenRaw(path string) (string, bool) {
	info := NewPathInfo(path)
	if info == nil || !info.IsACMEChallenge() {
		return "", false
	}
	return info.SubPath, true
}

// IsACMEChallengePrefix checks if the path begins with the ACME challenge prefix.
func IsACMEChallengePrefix(path string) bool {
	return strings.HasPrefix(strings.TrimPrefix(path, "/"), ".well-known/acme-challenge")
}
