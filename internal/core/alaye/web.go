package alaye

import (
	"strings"
	"time"

	"github.com/olekukonko/errors"
)

type Web struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Root     WebRoot  `hcl:"root,optional" json:"root"`
	Index    string   `hcl:"index,optional" json:"index"`
	Listing  bool     `hcl:"listing,optional" json:"listing"`
	SPA      bool     `hcl:"spa,optional" json:"spa"`
	PHP      PHP      `hcl:"php,block" json:"php"`
	Git      Git      `hcl:"git,block" json:"git"`
	Markdown Markdown `hcl:"markdown,block" json:"markdown"`
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

	if w.Index != "" && strings.Contains(w.Index, Slash) {
		return ErrIndexPath
	}

	if err := w.PHP.Validate(); err != nil {
		return errors.Newf("php: %w", err)
	}

	return nil
}

type GitAuth struct {
	Type             string `hcl:"type,optional" json:"type"`
	Username         string `hcl:"username,optional" json:"username"`
	Password         Value  `hcl:"password,optional" json:"password"`
	SSHKey           Value  `hcl:"ssh_key,optional" json:"ssh_key"`
	SSHKeyPassphrase Value  `hcl:"ssh_key_passphrase,optional" json:"ssh_key_passphrase"`
}

func (a *GitAuth) Validate() error {
	if a.Type != "" {
		a.Type = strings.ToLower(a.Type)
		switch a.Type {
		case "basic", "ssh-key", "ssh-agent":
		default:
			return errors.New("git auth type must be 'basic', 'ssh-key', or 'ssh-agent'")
		}
	}
	return nil
}

type Git struct {
	Enabled  Enabled       `hcl:"enabled,optional" json:"enabled"`
	ID       string        `hcl:"id" json:"id"`
	URL      string        `hcl:"url" json:"url"`
	Branch   string        `hcl:"branch,optional" json:"branch"`
	Secret   Value         `hcl:"secret,optional" json:"secret"`
	Interval time.Duration `hcl:"interval,optional" json:"interval"`
	WorkDir  string        `hcl:"work_dir,optional" json:"work_dir"`
	SubDir   string        `hcl:"sub_dir,optional" json:"sub_dir"`
	Auth     GitAuth       `hcl:"auth,block" json:"auth"`
}

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
	if err := g.Auth.Validate(); err != nil {
		return err
	}
	return nil
}

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
	Enabled         Enabled   `hcl:"enabled,optional"   json:"enabled"`
	UnsafeHTML      Enabled   `hcl:"unsafe,optional"    json:"unsafe"`
	TableOfContents Enabled   `hcl:"toc,optional"       json:"toc,omitempty"`
	SyntaxHighlight Highlight `hcl:"highlight,block"    json:"highlight,omitempty"`
	Extensions      []string  `hcl:"extensions,optional" json:"extensions,omitempty"`
	Template        string    `hcl:"template,optional"  json:"template,omitempty"`
	View            string    `hcl:"view,optional"      json:"view,omitempty"`
}

type Highlight struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Theme   string  `hcl:"theme,optional"   json:"theme,omitempty"`
}
