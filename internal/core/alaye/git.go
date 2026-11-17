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

	// Mode makes the deployment trigger explicit:
	//
	//   auto — derive pull/push/both from interval and secret (default;
	//          preserves the original behaviour)
	//   pull — interval polling; requires url + interval
	//   push — webhook deployment; requires secret; url may be empty for
	//          push-only payload delivery
	//   both — interval polling and webhook; requires url + interval + secret
	//
	// Auto is applied by defaultGit when the attribute is omitted.
	Mode string `hcl:"mode,attr" json:"mode,omitempty"`
}

func (g *Git) Validate() error {
	g.Mode = strings.ToLower(strings.TrimSpace(g.Mode))
	if g.Enabled.NotActive() {
		return nil
	}
	if g.ID == "" {
		return errors.New("git: id is required when git is enabled")
	}

	hasSecret := g.Secret.String() != ""
	switch g.Mode {
	case "", def.GitModeAuto:
		// Preserve the historical behaviour: derive the mode from the fields
		// that were set. Auto is the default and never rejects a config that
		// worked before the mode attribute existed.
		mode := g.EffectiveMode()
		if mode == def.GitModeAuto {
			return errors.New("git: must set interval (pull), secret (push), or both")
		}
		if (mode == def.GitModePull || mode == def.GitModeBoth) && g.URL == "" {
			return errors.New("git: url is required for pull mode")
		}
	case def.GitModePull:
		if g.Interval <= 0 {
			return errors.New("git: mode \"pull\" requires a positive interval")
		}
		if g.URL == "" {
			return errors.New("git: mode \"pull\" requires url")
		}
		if hasSecret {
			return errors.New("git: mode \"pull\" cannot set secret; use mode \"both\"")
		}
	case def.GitModePush:
		if !hasSecret {
			return errors.New("git: mode \"push\" requires secret")
		}
		if g.Interval > 0 {
			return errors.New("git: mode \"push\" cannot set interval; use mode \"both\"")
		}
	case def.GitModeBoth:
		if g.URL == "" {
			return errors.New("git: mode \"both\" requires url")
		}
		if g.Interval <= 0 {
			return errors.New("git: mode \"both\" requires a positive interval")
		}
		if !hasSecret {
			return errors.New("git: mode \"both\" requires secret")
		}
	default:
		return errors.Newf("git: mode must be one of %q, %q, %q, %q (got %q)",
			def.GitModeAuto, def.GitModePull, def.GitModePush, def.GitModeBoth, g.Mode)
	}
	return g.Auth.Validate()
}

// EffectiveMode returns the mode that should actually run. An explicit
// pull/push/both is honoured; empty and "auto" derive the mode from interval
// and secret exactly as earlier versions did.
func (g *Git) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(g.Mode))
	if mode != "" && mode != def.GitModeAuto {
		return mode
	}

	hasPull := g.Interval > 0
	hasPush := g.Secret.String() != ""
	switch {
	case hasPull && hasPush:
		return def.GitModeBoth
	case hasPush:
		return def.GitModePush
	case hasPull:
		return def.GitModePull
	default:
		return def.GitModeAuto
	}
}

// IsPull reports whether polling is active for this git config.
func (g *Git) IsPull() bool {
	mode := g.EffectiveMode()
	return mode == def.GitModePull || mode == def.GitModeBoth
}

// IsPush reports whether webhook delivery is active for this git config.
func (g *Git) IsPush() bool {
	mode := g.EffectiveMode()
	return mode == def.GitModePush || mode == def.GitModeBoth
}

func (g Git) IsZero() bool {
	return g.Enabled.IsZero() &&
		g.ID == "" &&
		g.URL == "" &&
		g.Branch == "" &&
		g.Secret == "" &&
		g.Interval == 0 &&
		!g.WorkDir.IsSet() &&
		g.SubDir == "" &&
		g.Mode == "" &&
		g.Auth.IsZero()
}
