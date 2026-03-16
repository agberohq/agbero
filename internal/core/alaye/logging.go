package alaye

type Logging struct {
	Enabled     Enabled  `hcl:"enabled,optional" json:"enabled"`
	Diff        Enabled  `hcl:"diff,optional" json:"diff"`
	Deduplicate Enabled  `hcl:"deduplicate,optional" json:"deduplicate"`
	Level       string   `hcl:"level,optional" json:"level"`
	Skip        []string `hcl:"skip,optional"`

	File       FileLog    `hcl:"file,block" json:"file"`
	Victoria   Victoria   `hcl:"victoria,block" json:"victoria"`
	Include    []string   `hcl:"include,optional" json:"include"`
	Prometheus Prometheus `hcl:"prometheus,block" json:"prometheus"`
}

type FileLog struct {
	Enabled    Enabled `hcl:"enabled,optional" json:"enabled"`
	Path       string  `hcl:"path,optional" json:"path"`
	BatchSize  int     `hcl:"batch_size,optional" json:"batch_size"`
	RotateSize int64   `hcl:"rotate_size,optional" json:"rotate_size"`
}

type Victoria struct {
	Enabled   Enabled `hcl:"enabled,optional" json:"enabled"`
	URL       string  `hcl:"url,optional" json:"URL"`
	BatchSize int     `hcl:"batch_size,optional" json:"batch_size"`
}

type Prometheus struct {
	Enabled Enabled `hcl:"enabled,optional" json:"enabled"`
	Path    string  `hcl:"path,optional" json:"path"` // Default: "/metrics"
}
