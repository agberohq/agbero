package alaye

import (
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

type Headers struct {
	Enabled  expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Request  Header        `hcl:"request,block" json:"request"`
	Response Header        `hcl:"response,block" json:"response"`
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

func (h Headers) IsZero() bool {
	return h.Enabled.IsZero() && h.Request.IsZero() && h.Response.IsZero()
}

type Header struct {
	Enabled expect.Toggle     `hcl:"enabled,attr" json:"enabled"`
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
			return def.ErrSetHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", def.ErrSetHeaderValueEmpty, k)
		}
	}
	for k, v := range h.Add {
		if k == "" {
			return def.ErrAddHeaderKeyEmpty
		}
		if v == "" {
			return errors.Newf("%w: %q value cannot be empty", def.ErrAddHeaderValueEmpty, k)
		}
	}
	for i, name := range h.Remove {
		if name == "" {
			return errors.Newf("remove[%d]: %w", i, def.ErrHeaderNameEmpty)
		}
	}
	return nil
}

func (h Header) IsZero() bool {
	return h.Enabled.IsZero() &&
		len(h.Set) == 0 &&
		len(h.Add) == 0 &&
		len(h.Remove) == 0
}
