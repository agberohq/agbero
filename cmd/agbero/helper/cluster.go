package helper

type Cluster struct {
	p *Helper
}

func (c *Cluster) StartArgs() (joinIP, secret string) {
	return "", c.p.Cfg.ClusterSecret
}

func (c *Cluster) JoinArgs() (joinIP, secret string) {
	return c.p.Cfg.ClusterJoinIP, c.p.Cfg.ClusterSecret
}
