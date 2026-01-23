package alaye

import "github.com/olekukonko/errors"

type Limit struct {
	MaxBodySize int64 `hcl:"max_body_size,optional"`
}

func (l *Limit) Validate() error {
	// MaxBodySize is optional, but if set must be positive
	if l.MaxBodySize < 0 {
		return errors.New("max_body_size cannot be negative")
	}
	return nil
}
