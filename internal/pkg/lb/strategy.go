package lb

import (
	"encoding/binary"
	"math/rand/v2"
	"net/http"
	"sync"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"github.com/cespare/xxhash/v2"
)

type Activity interface {
	InFlight() int64
	ResponseTime() int64
}

type Backend interface {
	Activity
	Alive() bool
	Weight() int
}

type Balancer interface {
	Pick(r *http.Request, keyFunc func() uint64) Backend
	Update(backends []Backend)
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

var rngPool = sync.Pool{
	New: func() any {
		return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
	},
}

func HashString(s string) uint64 {
	return xxhash.Sum64String(s)
}

func HashBytes(b []byte) uint64 {
	return xxhash.Sum64(b)
}

func HashUint64(x uint64) uint64 {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], x)
	return xxhash.Sum64(buf[:])
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
