package alaye

type Backend struct {
	Enabled  Enabled  `hcl:"enabled,optional" json:"enabled"`
	Strategy string   `hcl:"strategy,optional" json:"strategy"`
	Keys     []string `hcl:"keys,optional" json:"keys"` // used for sticky strategy, in order
	Servers  []Server `hcl:"server,block" json:"servers"`
}
