package alaye

import "github.com/olekukonko/errors"

type Headers struct {
	Enabled  Enabled `hcl:"enabled,optional" json:"enabled"`
	Request  Header  `hcl:"request,block" json:"request"`
	Response Header  `hcl:"response,block" json:"response"`
}

func (h *Headers) Validate() error {
	if h.Enabled.No() {
		return nil
	}
	// Both Request and Response are optional

	if err := h.Request.Validate(); err != nil {
		return errors.Newf("request: %w", err)
	}

	if err := h.Response.Validate(); err != nil {
		return errors.Newf("response: %w", err)
	}

	return nil
}

type Header struct {
	Enabled Enabled           `hcl:"enabled,optional" json:"enabled"`
	Set     map[string]string `hcl:"set,optional" json:"set"`
	Add     map[string]string `hcl:"add,optional" json:"add"`
	Remove  []string          `hcl:"remove,optional" json:"remove"`
}

func (h *Header) Validate() error {
	if h.Enabled.No() {
		return nil
	}

	// Set headers validation
	for k, v := range h.Set {
		if k == "" {
			return ErrSetHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", ErrSetHeaderValueEmpty, k)
		}
	}

	// Add headers validation
	for k, v := range h.Add {
		if k == "" {
			return ErrAddHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", ErrAddHeaderValueEmpty, k)
		}
	}

	// Remove headers validation
	for i, header := range h.Remove {
		if header == "" {
			return errors.Newf("remove[%d]: %w", i, ErrHeaderNameEmpty)
		}
	}

	return nil
}
