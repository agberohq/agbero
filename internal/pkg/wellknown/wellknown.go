// wellknown.go
package wellknown

import (
	"path/filepath"
	"strings"
	"unsafe"

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
)

// Path represents a parsed .well-known path
type Path struct {
	FullPath string
	Type     Type
	SubPath  string
	Segments []string
}

var pathPool = mappo.NewSharded[string, *Path]()

// NewPathInfo creates a Path from a full path using caching for hot paths
func NewPathInfo(path string) *Path {
	if cached, ok := pathPool.Get(path); ok {
		return cached
	}

	cleaned := filepath.Clean("/" + strings.TrimPrefix(path, "/"))
	segments := strings.Split(strings.TrimPrefix(cleaned, "/"), "/")

	// Handle edge case: filepath.Clean removes trailing slash
	// So "/.well-known/" becomes "/.well-known" with only 1 segment
	if len(segments) == 1 && segments[0] == ".well-known" {
		segments = append(segments, "")
	}

	if len(segments) < 2 || segments[0] != ".well-known" {
		return nil
	}

	info := &Path{
		FullPath: cleaned,
		Segments: segments,
	}

	if len(segments) > 1 {
		info.Type = Type(segments[1])
		if len(segments) > 2 {
			info.SubPath = strings.Join(segments[2:], "/")
		}
	}

	pathPool.Set(path, info)
	return info
}

func (p *Path) HasPrefix(prefix string) bool {
	return strings.HasPrefix(string(p.Type), prefix)
}

func (p *Path) IsType(t Type) bool {
	return p.Type == t
}

func (p *Path) IsACMEChallenge() bool {
	return p.Type == ACMEChallenge
}

func (p *Path) GetACMEToken() (string, bool) {
	if p.IsACMEChallenge() && p.SubPath != "" {
		return p.SubPath, true
	}
	return "", false
}

func BuildPath(t Type, subPath ...string) string {
	components := []string{".well-known", string(t)}
	for _, s := range subPath {
		if s != "" {
			components = append(components, s)
		}
	}
	return "/" + strings.Join(components, "/")
}

type Builder struct {
	pathSegments []string
}

func NewBuilder() *Builder {
	return &Builder{pathSegments: []string{".well-known"}}
}

func (b *Builder) WithType(t Type) *Builder {
	b.pathSegments = append(b.pathSegments, string(t))
	return b
}

func (b *Builder) WithSegment(segment string) *Builder {
	if segment != "" {
		b.pathSegments = append(b.pathSegments, segment)
	}
	return b
}

func (b *Builder) WithSegments(segments ...string) *Builder {
	for _, s := range segments {
		if s != "" {
			b.pathSegments = append(b.pathSegments, s)
		}
	}
	return b
}

func (b *Builder) Build() string {
	return "/" + strings.Join(b.pathSegments, "/")
}

func (b *Builder) String() string {
	return b.Build()
}

func IsPath(path string) bool {
	return strings.HasPrefix(strings.TrimPrefix(path, "/"), ".well-known/")
}

func GetType(path string) (Type, bool) {
	info := NewPathInfo(path)
	if info == nil {
		return "", false
	}
	return info.Type, true
}

func ACMEChallengePath(token string) string {
	return BuildPath(ACMEChallenge, token)
}

func ParseACMEChallengePath(path string) (string, bool) {
	info := NewPathInfo(path)
	if info == nil {
		return "", false
	}
	return info.GetACMEToken()
}

func GetACMETokenRaw(path string) (string, bool) {
	info := NewPathInfo(path)
	if info == nil || !info.IsACMEChallenge() {
		return "", false
	}
	return info.SubPath, true
}

func IsACMEChallengePrefix(path string) bool {
	return strings.HasPrefix(strings.TrimPrefix(path, "/"), ".well-known/acme-challenge")
}

func fastString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
