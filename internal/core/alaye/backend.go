package alaye

type Backend struct {
	Enabled  Enabled `hcl:"enabled,optional" json:"enabled"`
	Strategy string  `hcl:"strategy,optional" json:"strategy"`

	// Keys defines the priority list for extracting values for sticky sessions or consistent hashing.
	// Examples: "cookie:session_id", "header:Authorization", "query:id", "ip"
	Keys []string `hcl:"keys,optional" json:"keys"`

	Servers []Server `hcl:"server,block" json:"servers"`
}
