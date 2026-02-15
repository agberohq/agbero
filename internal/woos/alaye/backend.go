package alaye

type Backend struct {
	Status     Status   `hcl:"enabled,optional" json:"enabled"`
	LBStrategy string   `hcl:"lb_strategy,optional" json:"lb_strategy"`
	Servers    []Server `hcl:"server,block" json:"servers"`
}
