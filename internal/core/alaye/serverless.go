package alaye

import "github.com/agberohq/agbero/internal/core/expect"

// Serverless acts as a high-level container for logic-based request handling.
// It groups labeled Replay proxies and managed OS processes within a single engine.
type Serverless struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Root    string        `hcl:"root,attr" json:"root"`
	Git     Git           `hcl:"git,block" json:"git"`
	Replay  []Replay      `hcl:"replay,block" json:"replay"`
	Workers []Work        `hcl:"work,block" json:"workers"`
}

// Validate ensures all sub-components of the serverless engine are valid.
// It iterates through grouped Replay and Work blocks to verify individual settings.
// NOTE: git-backed serverless is gated at server startup via Security.AllowServerlessGit,
// not here, so that the error can reference the config knob and print a startup warning.
func (s *Serverless) Validate() error {
	if s.Enabled.NotActive() {
		return nil
	}
	for _, r := range s.Replay {
		if err := r.Validate(); err != nil {
			return err
		}
	}
	for _, w := range s.Workers {
		if err := w.Validate(); err != nil {
			return err
		}
	}
	return s.Git.Validate()
}

func (s Serverless) IsZero() bool {
	return s.Enabled.IsZero() &&
		s.Root == "" &&
		s.Git.IsZero() &&
		len(s.Replay) == 0 &&
		len(s.Workers) == 0
}
