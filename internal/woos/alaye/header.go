package alaye

import "github.com/olekukonko/errors"

type Headers struct {
	Request  *Header `hcl:"request,block"`
	Response *Header `hcl:"response,block"`
}

type Header struct {
	Set    map[string]string `hcl:"set,optional"`
	Add    map[string]string `hcl:"add,optional"`
	Remove []string          `hcl:"remove,optional"`
}

func (h *Headers) Validate() error {
	// Both Request and Response are optional
	if h.Request != nil {
		if err := h.Request.Validate(); err != nil {
			return errors.Newf("request: %w", err)
		}
	}
	if h.Response != nil {
		if err := h.Response.Validate(); err != nil {
			return errors.Newf("response: %w", err)
		}
	}
	return nil
}

func (h *Header) Validate() error {
	// All fields are optional, but if provided they should be valid

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
			return AddHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", AddHederValueEmpty, k)
		}
	}

	// Remove headers validation
	for i, header := range h.Remove {
		if header == "" {
			return errors.Newf("remove[%d]: %w", i, HeaderNameEmpty)
		}
	}

	return nil
}
