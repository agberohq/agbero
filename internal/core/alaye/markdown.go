package alaye

import "github.com/agberohq/agbero/internal/core/expect"

type Markdown struct {
	Enabled         expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	UnsafeHTML      expect.Toggle `hcl:"unsafe,attr" json:"unsafe"`
	TableOfContents expect.Toggle `hcl:"toc,attr" json:"toc,omitempty"`
	SyntaxHighlight Highlight     `hcl:"highlight,block" json:"highlight"`
	Extensions      []string      `hcl:"extensions,attr" json:"extensions,omitempty"`
	Template        string        `hcl:"template,attr" json:"template,omitempty"`
	View            string        `hcl:"view,attr" json:"view,omitempty"`
}

func (m Markdown) IsZero() bool {
	return m.Enabled.IsZero() &&
		m.UnsafeHTML.IsZero() &&
		m.TableOfContents.IsZero() &&
		m.SyntaxHighlight.IsZero() &&
		len(m.Extensions) == 0 &&
		m.Template == "" &&
		m.View == ""
}

type Highlight struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Theme   string        `hcl:"theme,attr" json:"theme,omitempty"`
}

func (h Highlight) IsZero() bool { return h.Enabled.IsZero() && h.Theme == "" }
