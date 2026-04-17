package alaye

import (
	"html/template"

	"github.com/agberohq/agbero/internal/core/expect"
)

type Response struct {
	Status       expect.Toggle     `hcl:"enabled,attr" json:"enabled"`
	ContentType  string            `hcl:"content_type,attr" json:"content_type"`
	BodyTemplate string            `hcl:"body_template,attr" json:"body_template"`
	Headers      map[string]string `hcl:"headers,attr" json:"headers"`
	StatusCode   int               `hcl:"status_code,attr" json:"status_code"`

	Template *template.Template `hcl:"-" json:"-"`
}
