package alaye

import (
	"path"
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled expect.Toggle `hcl:"enabled,attr"  json:"enabled"`
	Root    WebRoot       `hcl:"root,attr"     json:"root"`
	Index   []string      `hcl:"index,optional" json:"index,omitempty"`
	Listing expect.Toggle `hcl:"listing,attr"  json:"listing"`
	SPA     expect.Toggle `hcl:"spa,attr"      json:"spa"`
	NoCache expect.Toggle `hcl:"no_cache,attr" json:"no_cache"`

	// CacheControl overrides the default Cache-Control header for all static
	// responses served by this route. Leave empty to use built-in defaults
	// (immutable for fingerprinted files, max-age=300 for everything else).
	// Example: "public, max-age=31536000, s-maxage=604800"
	CacheControl string `hcl:"cache_control,attr" json:"cache_control,omitempty"`

	PHP      PHP        `hcl:"php,block,omitempty"      json:"php,omitempty"`
	Git      Git        `hcl:"git,block,omitempty"      json:"git,omitempty"`
	Markdown Markdown   `hcl:"markdown,block,omitempty" json:"markdown,omitempty"`
	Nonce    WebNonce   `hcl:"nonce,block,omitempty"    json:"nonce,omitempty"`
	Mounts   []WebMount `hcl:"mount,block"             json:"mounts,omitempty"`
}

// WebMount serves a path prefix from its own root or Git deployment. Mounts are
// matched longest-prefix-first and the matched prefix is stripped before the
// request is resolved against the mount root.
type WebMount struct {
	Path string  `hcl:"path,label" json:"path"`
	Root WebRoot `hcl:"root,attr" json:"root,omitempty"`
	Git  Git     `hcl:"git,block,omitempty" json:"git,omitempty"`
}

func (m *WebMount) Validate() error {
	m.Path = strings.TrimSpace(m.Path)
	if m.Path == "" {
		return errors.New("web mount: path is required")
	}
	if !strings.HasPrefix(m.Path, "/") {
		return errors.Newf("web mount %q: path must start with '/'", m.Path)
	}
	if strings.ContainsAny(m.Path, "*?{}#\\ \t\r\n") {
		return errors.Newf("web mount %q: path contains unsupported characters", m.Path)
	}
	for _, part := range strings.Split(m.Path, "/") {
		if part == ".." {
			return errors.Newf("web mount %q: path must not contain '..'", m.Path)
		}
	}
	m.Path = path.Clean(m.Path)
	if m.Path == "/" {
		return errors.New("web mount: path must not be '/' (use the web root for the primary mount)")
	}
	if err := m.Git.Validate(); err != nil {
		return errors.Newf("web mount %q: git: %w", m.Path, err)
	}
	if m.Git.Enabled.NotActive() && !m.Root.IsSet() {
		return errors.Newf("web mount %q: root or an enabled git block is required", m.Path)
	}
	return nil
}

func (m WebMount) IsZero() bool { return m.Path == "" && !m.Root.IsSet() && m.Git.IsZero() }

func (w *Web) Validate() error {
	if w.Enabled.NotActive() {
		return nil
	}
	if err := w.Git.Validate(); err != nil {
		return errors.Newf("git: %w", err)
	}
	seenMounts := make(map[string]bool, len(w.Mounts))
	seenGitIDs := make(map[string]bool, len(w.Mounts)+1)
	if w.Git.Enabled.Active() {
		seenGitIDs[w.Git.ID] = true
	}
	for i := range w.Mounts {
		m := &w.Mounts[i]
		if err := m.Validate(); err != nil {
			return err
		}
		if seenMounts[m.Path] {
			return errors.Newf("web mount %q: duplicate path", m.Path)
		}
		seenMounts[m.Path] = true
		if m.Git.Enabled.Active() {
			if seenGitIDs[m.Git.ID] {
				return errors.Newf("web mount %q: duplicate git id %q", m.Path, m.Git.ID)
			}
			seenGitIDs[m.Git.ID] = true
		}
	}
	if w.Git.Enabled.NotActive() && !w.Root.IsSet() && len(w.Mounts) == 0 {
		return def.ErrRootRequired
	}
	for _, idx := range w.Index {
		if strings.Contains(idx, def.Slash) {
			return def.ErrIndexPath
		}
	}
	if err := w.PHP.Validate(); err != nil {
		return errors.Newf("php: %w", err)
	}
	if w.Nonce.Enabled.Active() && len(w.Nonce.Endpoints) == 0 {
		return errors.New("web nonce: at least one endpoint name is required")
	}
	return nil
}

func (w Web) IsZero() bool {
	return w.Enabled.IsZero() &&
		!w.Root.IsSet() &&
		len(w.Index) == 0 &&
		w.Listing.IsZero() &&
		w.SPA.IsZero() &&
		w.NoCache.IsZero() &&
		w.CacheControl == "" &&
		w.PHP.IsZero() &&
		w.Git.IsZero() &&
		w.Markdown.IsZero() &&
		w.Nonce.IsZero() &&
		len(w.Mounts) == 0
}

// WebNonce configures single-use nonce injection for replay authentication.
// When enabled, the web handler generates one nonce per listed endpoint and
// injects <meta name="agbero-replay-nonce" data-endpoint="…" content="…">
// before </head> in every HTML response it serves.
type WebNonce struct {
	Enabled   expect.Toggle `hcl:"enabled,attr"   json:"enabled"`
	Endpoints []string      `hcl:"endpoints,attr" json:"endpoints"`
}

func (n WebNonce) IsZero() bool { return n.Enabled.IsZero() && len(n.Endpoints) == 0 }

type WebRoot string

func (w WebRoot) IsSet() bool {
	return strings.TrimSpace(string(w)) != ""
}

func (w WebRoot) String() string {
	if !w.IsSet() {
		return "."
	}
	return string(w)
}
