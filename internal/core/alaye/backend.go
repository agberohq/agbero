package alaye

type Backend struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Strategy string   `hcl:"strategy,optional" json:"strategy"`
	Servers  []Server `hcl:"server,block" json:"servers"`
}
