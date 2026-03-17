package alaye

import "github.com/olekukonko/errors"

type Headers struct {
	Enabled  Enabled `hcl:"enabled,attr" json:"enabled"`
	Request  Header  `hcl:"request,block" json:"request"`
	Response Header  `hcl:"response,block" json:"response"`
}

// Validate checks that set and add header entries have non-empty keys and values.
func (h *Headers) Validate() error {
	if !h.Enabled.Active() {
		return nil
	}
	if err := h.Request.Validate(); err != nil {
		return errors.Newf("request: %w", err)
	}
	if err := h.Response.Validate(); err != nil {
		return errors.Newf("response: %w", err)
	}
	return nil
}

type Header struct {
	Enabled Enabled           `hcl:"enabled,attr" json:"enabled"`
	Set     map[string]string `hcl:"set,attr" json:"set"`
	Add     map[string]string `hcl:"add,attr" json:"add"`
	Remove  []string          `hcl:"remove,attr" json:"remove"`
}

// Validate checks that all set/add header entries have non-empty keys and values.
func (h *Header) Validate() error {
	if !h.Enabled.Active() {
		return nil
	}
	for k, v := range h.Set {
		if k == "" {
			return ErrSetHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", ErrSetHeaderValueEmpty, k)
		}
	}
	for k, v := range h.Add {
		if k == "" {
			return ErrAddHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", ErrAddHeaderValueEmpty, k)
		}
	}
	for i, name := range h.Remove {
		if name == "" {
			return errors.Newf("remove[%d]: %w", i, ErrHeaderNameEmpty)
		}
	}
	return nil
}
