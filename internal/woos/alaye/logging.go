package alaye

type Logging struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Level    string   `hcl:"level,optional" json:"level"`
	File     string   `hcl:"file,optional" json:"file"`
	Skip     []string `hcl:"skip,optional"`
	Victoria Victoria `hcl:"victoria,block" json:"victoria"`
	Include  []string `hcl:"include,optional" json:"include"`
}

type Victoria struct {
	Enabled   Enabled `hcl:"enabled,optional" json:"enabled"`
	URL       string  `hcl:"url,optional" json:"URL"`
	BatchSize int     `hcl:"batch_size,optional" json:"batch_size"`
}
