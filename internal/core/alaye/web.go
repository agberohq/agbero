package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Root     WebRoot       `hcl:"root,attr" json:"root"`
	Index    []string      `hcl:"index,optional" json:"index,omitempty"`
	Listing  expect.Toggle `hcl:"listing,attr" json:"listing"`
	SPA      expect.Toggle `hcl:"spa,attr" json:"spa"`
	NoCache  expect.Toggle `hcl:"no_cache,attr" json:"no_cache"`
	PHP      PHP           `hcl:"php,block,omitempty" json:"php,omitempty"`
	Git      Git           `hcl:"git,block,omitempty" json:"git,omitempty"`
	Markdown Markdown      `hcl:"markdown,block,omitempty" json:"markdown,omitempty"`
	Nonce    WebNonce      `hcl:"nonce,block,omitempty"    json:"nonce,omitempty"`
}

func (w *Web) Validate() error {
	if w.Enabled.NotActive() {
		return nil
	}
	if err := w.Git.Validate(); err != nil {
		return errors.Newf("git: %w", err)
	}
	if w.Git.Enabled.NotActive() && !w.Root.IsSet() {
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
		w.PHP.IsZero() &&
		w.Git.IsZero() &&
		w.Markdown.IsZero() &&
		w.Nonce.IsZero()
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
