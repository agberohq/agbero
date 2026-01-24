package alaye

type Backend struct {
	LBStrategy string   `hcl:"lb_strategy,optional"`
	Servers    []Server `hcl:"server,block"`
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
