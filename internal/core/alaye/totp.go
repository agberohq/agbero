package alaye

import "github.com/agberohq/agbero/internal/core/expect"

type TOTP struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	// Users      []TOTPUser `hcl:"user,block" json:"users"`
	Issuer     string `hcl:"issuer,attr" json:"issuer"`
	Algorithm  string `hcl:"algorithm,attr" json:"algorithm"`
	Digits     int    `hcl:"digits,attr" json:"digits"`
	Period     int    `hcl:"period,attr" json:"period"`
	WindowSize int    `hcl:"window_size,attr" json:"window_size"`
}

func (t *TOTP) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	return nil
}
