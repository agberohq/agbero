package alaye

type Limit struct {
	MaxBodySize int64 `hcl:"max_body_size,optional" json:"max_body_size"`
}

func (l *Limit) Validate() error {
	// MaxBodySize is optional, but if set must be positive
	if l.MaxBodySize < 0 {
		return ErrNegativeMacBodySize
	}
	return nil
}
