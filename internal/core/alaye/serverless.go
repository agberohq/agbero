package alaye

// Serverless acts as a high-level container for logic-based request handling.
// It groups labeled REST proxies and managed OS processes within a single engine.
type Serverless struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`

	Root string `hcl:"root,attr" json:"root"`

	RESTs []REST `hcl:"rest,block" json:"rests"`

	Workers []Work `hcl:"work,block" json:"workers"`
}

// Validate ensures all sub-components of the serverless engine are valid.
// It iterates through grouped REST and Work blocks to verify individual settings.
func (s *Serverless) Validate() error {
	if s.Enabled.NotActive() {
		return nil
	}
	for _, r := range s.RESTs {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	for _, w := range s.Workers {
		if err := w.Validate(); err != nil {
			return err
		}
	}
	return nil
}
