//go:build arm64 || amd64

package asearch

import "golang.org/x/sys/cpu"

var (
	hasAVX2 bool
	hasNEON bool
)

// init detects CPU features at startup to avoid runtime branching.
// Populates flags for AVX2 on amd64 and NEON/ASIMD on arm64.
func init() {
	hasAVX2 = cpu.X86.HasAVX2
	hasNEON = cpu.ARM64.HasASIMD
}
