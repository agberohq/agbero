package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled  Enabled  `hcl:"enabled,attr" json:"enabled"`
	Root     WebRoot  `hcl:"root,attr" json:"root"`
	Index    []string `hcl:"index,optional" json:"index"`
	Listing  bool     `hcl:"listing,attr" json:"listing"`
	SPA      bool     `hcl:"spa,attr" json:"spa"`
	NoCache  bool     `hcl:"no_cache,attr" json:"no_cache"`
	PHP      PHP      `hcl:"php,block" json:"php"`
	Git      Git      `hcl:"git,block" json:"git"`
	Markdown Markdown `hcl:"markdown,block" json:"markdown"`
}

// Validate checks root presence, index format, and delegates to PHP and Git validation.
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
	return nil
}

type GitAuth struct {
	Type             string       `hcl:"type,attr" json:"type"`
	Username         string       `hcl:"username,attr" json:"username"`
	Password         expect.Value `hcl:"password,attr" json:"password"`
	SSHKey           expect.Value `hcl:"ssh_key,attr" json:"ssh_key"`
	SSHKeyPassphrase expect.Value `hcl:"ssh_key_passphrase,attr" json:"ssh_key_passphrase"`
}

// Validate checks that the auth type is one of the accepted values.
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
	Enabled  Enabled      `hcl:"enabled,attr" json:"enabled"`
	ID       string       `hcl:"id,attr" json:"id"`
	URL      string       `hcl:"url,attr" json:"url"`
	Branch   string       `hcl:"branch,attr" json:"branch"`
	Secret   expect.Value `hcl:"secret,attr" json:"secret"`
	Interval Duration     `hcl:"interval,attr" json:"interval"`
	WorkDir  string       `hcl:"work_dir,attr" json:"work_dir"`
	SubDir   string       `hcl:"sub_dir,attr" json:"sub_dir"`
	Auth     GitAuth      `hcl:"auth,block" json:"auth"`
}

// Validate checks that ID and URL are present when git serving is enabled.
func (g *Git) Validate() error {
	if g.Enabled.NotActive() {
		return nil
	}
	if g.ID == "" {
		return errors.New("git id is required when git is enabled")
	}
	if g.URL == "" {
		return errors.New("git url is required when git is enabled")
	}
	return g.Auth.Validate()
}

type WebRoot string

// IsSet reports whether the web root has been configured.
func (w WebRoot) IsSet() bool {
	return strings.TrimSpace(string(w)) != ""
}

// String returns the web root path, defaulting to "." when unset.
func (w WebRoot) String() string {
	if !w.IsSet() {
		return "."
	}
	return string(w)
}

type Markdown struct {
	Enabled         Enabled   `hcl:"enabled,attr" json:"enabled"`
	UnsafeHTML      Enabled   `hcl:"unsafe,attr" json:"unsafe"`
	TableOfContents Enabled   `hcl:"toc,attr" json:"toc,omitempty"`
	SyntaxHighlight Highlight `hcl:"highlight,block" json:"highlight"`
	Extensions      []string  `hcl:"extensions,attr" json:"extensions,omitempty"`
	Template        string    `hcl:"template,attr" json:"template,omitempty"`
	View            string    `hcl:"view,attr" json:"view,omitempty"`
}

type Highlight struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
	Theme   string  `hcl:"theme,attr" json:"theme,omitempty"`
}
