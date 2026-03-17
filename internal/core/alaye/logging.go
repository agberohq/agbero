package alaye

type Logging struct {
	Enabled     Enabled  `hcl:"enabled,attr" json:"enabled"`
	Diff        Enabled  `hcl:"diff,attr" json:"diff"`
	Deduplicate Enabled  `hcl:"deduplicate,attr" json:"deduplicate"`
	Truncate    Enabled  `hcl:"truncate,attr" json:"truncate"`
	BotChecker  Enabled  `hcl:"bot_checker,attr" json:"bot_checker"`
	Level       string   `hcl:"level,attr" json:"level"`
	Skip        []string `hcl:"skip,attr" json:"skip"`
	Include     []string `hcl:"include,attr" json:"include"`

	File       FileLog    `hcl:"file,block" json:"file"`
	Victoria   Victoria   `hcl:"victoria,block" json:"victoria"`
	Prometheus Prometheus `hcl:"prometheus,block" json:"prometheus"`
}

type FileLog struct {
	Enabled    Enabled `hcl:"enabled,attr" json:"enabled"`
	Path       string  `hcl:"path,attr" json:"path"`
	BatchSize  int     `hcl:"batch_size,attr" json:"batch_size"`
	RotateSize int64   `hcl:"rotate_size,attr" json:"rotate_size"`
}

type Victoria struct {
	Enabled   Enabled `hcl:"enabled,attr" json:"enabled"`
	URL       string  `hcl:"url,attr" json:"URL"`
	BatchSize int     `hcl:"batch_size,attr" json:"batch_size"`
}

type Prometheus struct {
	Enabled Enabled `hcl:"enabled,attr" json:"enabled"`
	Path    string  `hcl:"path,attr" json:"path"`
}
