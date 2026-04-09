package alaye

import "github.com/agberohq/agbero/internal/core/expect"

type Timeout struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Read       Duration      `hcl:"read,attr" json:"read"`
	Write      Duration      `hcl:"write,attr" json:"write"`
	Idle       Duration      `hcl:"idle,attr" json:"idle"`
	ReadHeader Duration      `hcl:"read_header,attr" json:"read_header"`
}

// Validate checks that all timeout values are non-negative when timeouts are enabled.
func (t *Timeout) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	if t.Read < 0 {
		return ErrNegativeReadTimeout
	}
	if t.Write < 0 {
		return ErrNegativeWriteTimeout
	}
	if t.Idle < 0 {
		return ErrNegativeIdleTimeout
	}
	if t.ReadHeader < 0 {
		return ErrNegativeReadHeaderTimeout
	}
	return nil
}

type TimeoutRoute struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Request Duration      `hcl:"request,attr" json:"request"`
}

// Validate checks that the request timeout is non-negative when enabled.
func (t *TimeoutRoute) Validate() error {
	if t.Enabled.NotActive() {
		return nil
	}
	if t.Request < 0 {
		return ErrNegativeRequestTimeout
	}
	return nil
}
