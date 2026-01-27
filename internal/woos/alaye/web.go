package alaye

import (
	"strings"

	"github.com/olekukonko/errors"
)

type Web struct {
	Root    WebRoot `hcl:"root,optional"`
	Index   string  `hcl:"index,optional"`
	Listing bool    `hcl:"listing,optional"` // list files

	PHP PHP `hcl:"php,block,optional"`
}

func (w *Web) Validate() error {
	if !w.Root.IsSet() {
		return errors.New("root is required for web block")
	}

	if w.Index != "" && strings.Contains(w.Index, "/") {
		return errors.New("index cannot contain path separators")
	}

	if w.PHP.Enabled {
		if err := w.PHP.Validate(); err != nil {
			return errors.Newf("php: %w", err)
		}
	}
	return nil
}

type PHP struct {
	Enabled bool   `hcl:"enabled,optional"`
	Address string `hcl:"address,optional"` // unix:/path/to.sock OR 127.0.0.1:9000
	Index   string `hcl:"index,optional"`   // default: index.php
}

func (p *PHP) Validate() error {
	if !p.Enabled {
		return nil
	}

	addr := strings.TrimSpace(p.Address)
	if addr == "" {
		// allow default (we’ll choose in code), or you can force it required.
		return nil
	}

	// Accept either unix:/path.sock or host:port
	if strings.HasPrefix(addr, "unix:") {
		if len(strings.TrimSpace(strings.TrimPrefix(addr, "unix:"))) == 0 {
			return errors.New("address unix:... cannot be empty")
		}
		return nil
	}

	// Very light check; real dial will validate host:port
	if !strings.Contains(addr, ":") {
		return errors.New("address must be unix:/path.sock or host:port")
	}

	if p.Index != "" && strings.Contains(p.Index, "/") {
		return errors.New("index cannot contain path separators")
	}

	return nil
}

type WebRoot string

func (w WebRoot) IsSet() bool {
	return strings.TrimSpace(string(w)) != ""
}

// Display-only; do not use for presence.
func (w WebRoot) String() string {
	if !w.IsSet() {
		return "."
	}
	return string(w)
}
