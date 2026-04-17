package alaye

import "github.com/agberohq/agbero/internal/core/def"

type Limit struct {
	MaxBodySize int64 `hcl:"max_body_size,attr" json:"max_body_size"`
}

// Validate checks that max_body_size is not negative.
func (l *Limit) Validate() error {
	if l.MaxBodySize < 0 {
		return def.ErrNegativeMacBodySize
	}
	return nil
}

func (l Limit) IsZero() bool { return l.MaxBodySize == 0 }
