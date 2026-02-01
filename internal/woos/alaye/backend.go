package alaye

type Backend struct {
	LBStrategy string   `hcl:"lb_strategy,optional" json:"lb_strategy"`
	Servers    []Server `hcl:"server,block" json:"servers"`
}

func MakeBackend(address ...string) Backend {
	b := make([]Server, len(address))
	for i, addr := range address {
		b[i] = NewServer(addr)
	}
	return Backend{
		Servers: b,
	}
}
