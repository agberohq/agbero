package alaye

import "github.com/agberohq/agbero/internal/core/expect"

type Logging struct {
	Enabled     expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Diff        expect.Toggle `hcl:"diff,attr" json:"diff"`
	Deduplicate expect.Toggle `hcl:"deduplicate,attr" json:"deduplicate"`
	Truncate    expect.Toggle `hcl:"truncate,attr" json:"truncate"`
	BotChecker  expect.Toggle `hcl:"bot_checker,attr" json:"bot_checker"`
	Level       string        `hcl:"level,attr" json:"level"`
	Skip        []string      `hcl:"skip,attr" json:"skip"`
	Include     []string      `hcl:"include,attr" json:"include"`

	File       FileLog    `hcl:"file,block" json:"file"`
	Victoria   Victoria   `hcl:"victoria,block" json:"victoria"`
	Prometheus Prometheus `hcl:"prometheus,block" json:"prometheus"`
}

type FileLog struct {
	Enabled    expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Path       string        `hcl:"path,attr" json:"path"`
	BatchSize  int           `hcl:"batch_size,attr" json:"batch_size"`
	RotateSize int64         `hcl:"rotate_size,attr" json:"rotate_size"`
}

type Victoria struct {
	Enabled   expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	URL       string        `hcl:"url,attr" json:"URL"`
	BatchSize int           `hcl:"batch_size,attr" json:"batch_size"`
}

type Prometheus struct {
	Enabled expect.Toggle `hcl:"enabled,attr" json:"enabled"`
	Path    string        `hcl:"path,attr" json:"path"`
}
