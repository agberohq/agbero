package lb

import (
	"encoding/binary"
	"net/http"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/dependency"
	"github.com/cespare/xxhash/v2"
)

type Activity interface {
	InFlight() int64
	ResponseTime() int64
}

type Backend interface {
	Activity
	Status(v bool)
	Alive() bool
	IsUsable() bool
	Weight() int
}

type Balancer interface {
	Pick(r *http.Request, keyFunc func() uint64) Backend
	Update(backends []Backend)
	Backends() []Backend
	Stop()
}

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

// HashString processes the payload rapidly targeting the underlying architecture.
// Uses hardware-accelerated CRC32 instructions for routing resolutions.
func HashString(s string) uint64 {
	return dependency.CRC32Hash(s)
}

// HashBytes processes the payload rapidly targeting the underlying architecture.
// Uses hardware-accelerated CRC32 instructions for routing resolutions.
func HashBytes(b []byte) uint64 {
	return dependency.CRC32HashBytes(b)
}

// HashUint64 retains xxhash purely to satisfy distribution qualities required by consistent hashing.
// Evaluates integer placements uniformly avoiding clustered collisions heavily.
func HashUint64(x uint64) uint64 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], x)
	return xxhash.Sum64(buf[:])
}

// ParseStrategy translates string definitions into load balancing enumerators securely.
// Assigns the standard RoundRobin approach if matching configurations fail.
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
