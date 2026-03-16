package dependency

import "golang.org/x/sys/cpu"

var (
	hasCRC32 bool
	hasAVX2  bool
	hasNEON  bool
)

// init detects CPU features at startup to avoid runtime branching.
// Populates flags for SSE4.2, AVX2, and ARM64 NEON support implicitly.
func init() {
	hasCRC32 = cpu.X86.HasSSE42
	hasAVX2 = cpu.X86.HasAVX2
	hasNEON = cpu.ARM64.HasASIMD
}
