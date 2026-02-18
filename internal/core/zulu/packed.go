package zulu

import (
	"sync/atomic"
)

// Packed provides atomic operations on a uint64 value
// that can pack multiple fields using bit shifts
type Packed uint64

// NewPacked creates a Packed from components
// bits specifies how many bits to use for each component (from low to high)
// Example: NewPacked([]uint8{32, 32}, timestamp, count) - 32 bits each
func NewPacked(bits []uint8, values ...int64) Packed {
	if len(bits) != len(values) {
		panic("bits and values must have same length")
	}

	var result uint64
	var offset uint8

	for i, b := range bits {
		if offset+b > 64 {
			panic("total bits exceeds 64")
		}
		mask := (uint64(1) << b) - 1
		result |= (uint64(values[i]) & mask) << offset
		offset += b
	}

	return Packed(result)
}

// Extract pulls out components using the same bit specification
func (p Packed) Extract(bits []uint8) []int64 {
	result := make([]int64, len(bits))
	var offset uint8
	var remaining uint64 = uint64(p)

	for i, b := range bits {
		mask := (uint64(1) << b) - 1
		result[i] = int64(remaining & mask)
		remaining >>= b
		offset += b
	}

	return result
}

// AtomicPacked wraps atomic operations on packed uint64
type AtomicPacked struct {
	v atomic.Uint64
}

func (a *AtomicPacked) Load() Packed {
	return Packed(a.v.Load())
}

func (a *AtomicPacked) Store(p Packed) {
	a.v.Store(uint64(p))
}

// CompareAndSwap attempts CAS, returns true if successful
func (a *AtomicPacked) CompareAndSwap(old, new Packed) bool {
	return a.v.CompareAndSwap(uint64(old), uint64(new))
}

// Update performs atomic read-modify-write using the provided function
// fn receives current values, returns new values
// bits specifies the bit layout
// Returns true if update succeeded (may need retry loop externally)
func (a *AtomicPacked) Update(bits []uint8, fn func(values []int64) []int64) bool {
	oldPacked := a.Load()
	oldValues := oldPacked.Extract(bits)
	newValues := fn(oldValues)
	newPacked := NewPacked(bits, newValues...)
	return a.CompareAndSwap(oldPacked, newPacked)
}
