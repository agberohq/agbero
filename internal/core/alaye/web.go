package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Root     WebRoot       `hcl:"root,attr" json:"root"`
	Index    []string      `hcl:"index,optional" json:"index"`
	Listing  expect.Toggle `hcl:"listing,attr" json:"listing"`
	SPA      expect.Toggle `hcl:"spa,attr" json:"spa"`
	NoCache  expect.Toggle `hcl:"no_cache,attr" json:"no_cache"`
	PHP      PHP           `hcl:"php,block" json:"php"`
	Git      Git           `hcl:"git,block" json:"git"`
	Markdown Markdown      `hcl:"markdown,block" json:"markdown"`
	Nonce    WebNonce      `hcl:"nonce,block"    json:"nonce"`
}

func (w *Web) Validate() error {
	if w.Enabled.NotActive() {
		return nil
	}
	if err := w.Git.Validate(); err != nil {
		return errors.Newf("git: %w", err)
	}
	if w.Git.Enabled.NotActive() && !w.Root.IsSet() {
		return ErrRootRequired
	}
	for _, idx := range w.Index {
		if strings.Contains(idx, Slash) {
			return ErrIndexPath
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

// WebNonce configures single-use nonce injection for replay authentication.
// When enabled, the web handler generates one nonce per listed endpoint and
// injects <meta name="agbero-replay-nonce" data-endpoint="…" content="…">
// before </head> in every HTML response it serves.
type WebNonce struct {
	Enabled   expect.Toggle `hcl:"enabled,attr"   json:"enabled"`
	Endpoints []string      `hcl:"endpoints,attr" json:"endpoints"`
}

type GitAuth struct {
	Type             string       `hcl:"type,attr" json:"type"`
	Username         string       `hcl:"username,attr" json:"username"`
	Password         expect.Value `hcl:"password,attr" json:"password"`
	SSHKey           expect.Value `hcl:"ssh_key,attr" json:"ssh_key"`
	SSHKeyPassphrase expect.Value `hcl:"ssh_key_passphrase,attr" json:"ssh_key_passphrase"`
}

func (a *GitAuth) Validate() error {
	if a.Type != "" {
		switch strings.ToLower(a.Type) {
		case "basic", "ssh-key", "ssh-agent":
		default:
			return errors.New("git auth type must be 'basic', 'ssh-key', or 'ssh-agent'")
		}
	}
	return nil
}

type Git struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	ID       string        `hcl:"id,attr" json:"id"`
	URL      string        `hcl:"url,attr" json:"url"`
	Branch   string        `hcl:"branch,attr" json:"branch"`
	Secret   expect.Value  `hcl:"secret,attr" json:"secret"`
	Interval Duration      `hcl:"interval,attr" json:"interval"`
	WorkDir  expect.Folder `hcl:"work_dir,attr" json:"work_dir"`
	SubDir   string        `hcl:"sub_dir,attr" json:"sub_dir"`
	Auth     GitAuth       `hcl:"auth,block" json:"auth"`

	// Populated by defaultGit():
	//   "pull"  — interval is set, no secret
	//   "push"  — secret is set, no interval
	//   "both"  — both interval and secret are set
	Mode string `hcl:"-" json:"mode,omitempty"`
}

func (g *Git) Validate() error {
	if g.Enabled.NotActive() {
		return nil
	}
	if g.ID == "" {
		return errors.New("git: id is required when git is enabled")
	}
	// pull and both modes need a URL to clone from
	if g.IsPull() && g.URL == "" {
		return errors.New("git: url is required for pull mode")
	}

	// must declare at least one mode
	if g.Interval == 0 && g.Secret.String() == "" {
		return errors.New("git: must set interval (pull), secret (push), or both")
	}
	return g.Auth.Validate()
}

// IsPull reports whether polling is active for this git config.
func (g *Git) IsPull() bool { return g.Mode == GitModePull || g.Mode == GitModeBoth }

// IsPush reports whether webhook delivery is active for this git config.
func (g *Git) IsPush() bool { return g.Mode == GitModePush || g.Mode == GitModeBoth }

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

type Markdown struct {
	Enabled         expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	UnsafeHTML      expect.Toggle `hcl:"unsafe,attr" json:"unsafe"`
	TableOfContents expect.Toggle `hcl:"toc,attr" json:"toc,omitempty"`
	SyntaxHighlight Highlight     `hcl:"highlight,block" json:"highlight"`
	Extensions      []string      `hcl:"extensions,attr" json:"extensions,omitempty"`
	Template        string        `hcl:"template,attr" json:"template,omitempty"`
	View            string        `hcl:"view,attr" json:"view,omitempty"`
}

type Highlight struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Theme   string        `hcl:"theme,attr" json:"theme,omitempty"`
}
