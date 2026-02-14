package balancer

import (
	"math/rand/v2"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/cespare/xxhash/v2"
)

// Activity provides metrics for backend selection
type Activity interface {
	InFlight() int64
	ResponseTime() int64 // microseconds, 0 if no data
}

// Backend is the interface for load balancer targets
type Backend interface {
	Activity
	Alive() bool
	Weight() int
}

// Strategy defines the load balancing algorithm
type Strategy uint8

const (
	StrategyRoundRobin Strategy = iota
	StrategyRandom
	StrategyLeastConn
	StrategyWeightedLeastConn
	StrategyIPHash
	StrategyURLHash
	StrategyLeastResponseTime
	StrategyPowerOfTwoChoices
	StrategyConsistentHash
)

var rngPool = sync.Pool{
	New: func() any {
		return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	},
}

// HashString uses xxhash for consistent string hashing
func HashString(s string) uint64 {
	return xxhash.Sum64String(s)
}

// HashBytes uses xxhash for byte slice hashing
func HashBytes(b []byte) uint64 {
	return xxhash.Sum64(b)
}

// HashUint64 uses xxhash by converting to bytes for better distribution
func HashUint64(x uint64) uint64 {
	b := make([]byte, 8)
	b[0] = byte(x)
	b[1] = byte(x >> 8)
	b[2] = byte(x >> 16)
	b[3] = byte(x >> 24)
	b[4] = byte(x >> 32)
	b[5] = byte(x >> 40)
	b[6] = byte(x >> 48)
	b[7] = byte(x >> 56)
	return xxhash.Sum64(b)
}

func ParseStrategy(s string) Strategy {
	switch s {
	case alaye.StrategyLeastConn:
		return StrategyLeastConn
	case alaye.StrategyRandom:
		return StrategyRandom
	case alaye.StrategyWeightedLeastConn:
		return StrategyWeightedLeastConn
	case alaye.StrategyIPHash:
		return StrategyIPHash
	case alaye.StrategyURLHash:
		return StrategyURLHash
	case alaye.StrategyLeastResponseTime:
		return StrategyLeastResponseTime
	case alaye.StrategyPowerOfTwoChoices:
		return StrategyPowerOfTwoChoices
	case alaye.StrategyConsistentHash:
		return StrategyConsistentHash
	default:
		return StrategyRoundRobin
	}
}
