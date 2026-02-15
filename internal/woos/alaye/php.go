package alaye

import "strings"

type PHP struct {
	Status  Status `hcl:"enabled,optional" json:"enabled"`
	Address string `hcl:"address,optional" json:"address"` // unix:/path/to.sock OR 127.0.0.1:9000
	Index   string `hcl:"index,optional" json:"index"`     // default: index.php
}

func (p *PHP) Validate() error {
	if !p.Status.Enabled() {
		return nil
	}

	addr := strings.TrimSpace(p.Address)
	if addr == "" {
		// allow default (we’ll choose in code), or you can force it required.
		return nil
	}

	// Accept either unix:/path.sock or host:port
	if strings.HasPrefix(addr, UNIXPrefix) {
		if len(strings.TrimSpace(strings.TrimPrefix(addr, UNIXPrefix))) == 0 {
			return ErrNoAddress
		}
		return nil
	}

	// Very light check; real dial will validate host:port
	if !strings.Contains(addr, ":") {
		return ErrBadAddress
	}

	if p.Index != "" && strings.Contains(p.Index, Slash) {
		return ErrIndexPath
	}

	return nil
}
