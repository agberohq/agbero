package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

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

func (a GitAuth) IsZero() bool {
	return a.Type == "" &&
		a.Username == "" &&
		a.Password == "" &&
		a.SSHKey == "" &&
		a.SSHKeyPassphrase == ""
}

type Git struct {
	Enabled  expect.Toggle   `hcl:"enabled,attr" json:"enabled"`
	ID       string          `hcl:"id,attr" json:"id"`
	URL      string          `hcl:"url,attr" json:"url"`
	Branch   string          `hcl:"branch,attr" json:"branch"`
	Secret   expect.Value    `hcl:"secret,attr" json:"secret"`
	Interval expect.Duration `hcl:"interval,attr" json:"interval"`
	WorkDir  expect.Folder   `hcl:"work_dir,attr" json:"work_dir"`
	SubDir   string          `hcl:"sub_dir,attr" json:"sub_dir"`
	Auth     GitAuth         `hcl:"auth,block" json:"auth"`

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
func (g *Git) IsPull() bool { return g.Mode == def.GitModePull || g.Mode == def.GitModeBoth }

// IsPush reports whether webhook delivery is active for this git config.
func (g *Git) IsPush() bool { return g.Mode == def.GitModePush || g.Mode == def.GitModeBoth }

func (g Git) IsZero() bool {
	return g.Enabled.IsZero() &&
		g.ID == "" &&
		g.URL == "" &&
		g.Branch == "" &&
		g.Secret == "" &&
		g.Interval == 0 &&
		!g.WorkDir.IsSet() &&
		g.SubDir == "" &&
		g.Auth.IsZero()
}
