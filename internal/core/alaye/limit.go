package alaye

type Limit struct {
	MaxBodySize int64 `hcl:"max_body_size,attr" json:"max_body_size"`
}

// Validate checks that max_body_size is not negative.
func (l *Limit) Validate() error {
	if l.MaxBodySize < 0 {
		return ErrNegativeMacBodySize
	}
	return nil
}
