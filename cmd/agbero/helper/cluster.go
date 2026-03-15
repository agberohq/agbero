package helper

type ClusterHelper struct {
	p *Helper
}

func (c *ClusterHelper) StartArgs() (joinIP, secret string) {
	return "", c.p.Cfg.ClusterSecret
}

func (c *ClusterHelper) JoinArgs() (joinIP, secret string) {
	return c.p.Cfg.ClusterJoinIP, c.p.Cfg.ClusterSecret
}
