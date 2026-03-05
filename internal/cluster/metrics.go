package cluster

import "sync/atomic"

type Metrics interface {
	IncUpdatesReceived()
	IncUpdatesIgnored()
	IncDeletes()
	IncJoin()
	IncLeave()
	Snapshot() map[string]uint64
}

type RealMetrics struct {
	updatesReceived atomic.Uint64
	updatesIgnored  atomic.Uint64
	deletes         atomic.Uint64
	joins           atomic.Uint64
	leaves          atomic.Uint64
}

func NewMetrics() *RealMetrics {
	return &RealMetrics{}
}

func (m *RealMetrics) IncUpdatesReceived() {
	m.updatesReceived.Add(1)
}

func (m *RealMetrics) IncUpdatesIgnored() {
	m.updatesIgnored.Add(1)
}

func (m *RealMetrics) IncDeletes() {
	m.deletes.Add(1)
}

func (m *RealMetrics) IncJoin() {
	m.joins.Add(1)
}

func (m *RealMetrics) IncLeave() {
	m.leaves.Add(1)
}

func (m *RealMetrics) Snapshot() map[string]uint64 {
	return map[string]uint64{
		"updates_received": m.updatesReceived.Load(),
		"updates_ignored":  m.updatesIgnored.Load(),
		"deletes":          m.deletes.Load(),
		"joins":            m.joins.Load(),
		"leaves":           m.leaves.Load(),
	}
}
