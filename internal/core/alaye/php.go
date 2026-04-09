package alaye

import (
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
)

type PHP struct {
	Enabled expect.Toggle `hcl:"enabled,optional" json:"enabled"`
	Address string        `hcl:"address,optional" json:"address"` // unix:/path/to.sock OR 127.0.0.1:9000
}

func (p *PHP) Validate() error {
	if p.Enabled.Inactive() {
		return nil
	}
	addr := strings.TrimSpace(p.Address)
	if addr == "" {
		// allow default (we’ll choose in code), or you can force it required.
		return nil
	}

	// Accept either unix:/path.sock or host:port
	if after, ok := strings.CutPrefix(addr, UNIXPrefix); ok {
		if len(strings.TrimSpace(after)) == 0 {
			return ErrNoAddress
		}
		return nil
	}

	// Very light check; real dial will validate host:port
	if !strings.Contains(addr, ":") {
		return ErrBadAddress
	}

	return nil
}
