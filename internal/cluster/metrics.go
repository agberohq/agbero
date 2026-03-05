package cluster

type Metrics interface {
	IncUpdatesReceived()
	IncUpdatesIgnored() // LWW conflict
	IncDeletes()
	IncJoin()
	IncLeave()
}

type noopMetrics struct{}

func (n *noopMetrics) IncUpdatesReceived() {}
func (n *noopMetrics) IncUpdatesIgnored()  {}
func (n *noopMetrics) IncDeletes()         {}
func (n *noopMetrics) IncJoin()            {}
func (n *noopMetrics) IncLeave()           {}
