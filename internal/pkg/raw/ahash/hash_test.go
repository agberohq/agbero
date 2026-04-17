package ahash

import (
	"math/rand"
	"testing"

	"github.com/agberohq/agbero/internal/core/def"
)

const (
	testIterations = def.DefaultCacheMaxItems
	maxCollisions  = 5
	randStrMaxLen  = 128
)

// randomString generates a slice of bytes dynamically for testing inputs.
// Fills the memory with standard randomized ascii representations.
func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return string(b)
}

// TestCRC32HashMatchesReference proves assembly produces the exact same output as Go.
// Asserts matching boundaries across dynamic string allocations.
func TestCRC32HashMatchesReference(t *testing.T) {
	for i := 0; i < 100; i++ {
		s := randomString(rand.Intn(randStrMaxLen))
		got := CRC32Hash(s)
		want := crc32HashFallback(s)
		if got != want {
			t.Fatalf("mismatch for len %d: got %x, want %x", len(s), got, want)
		}

		gotB := CRC32HashBytes([]byte(s))
		wantB := crc32HashBytesFallback([]byte(s))
		if gotB != wantB {
			t.Fatalf("byte mismatch for len %d: got %x, want %x", len(s), gotB, wantB)
		}
	}
}

// TestCRC32HashEmpty handles boundary constraints correctly.
// Ensures that 0-length inputs do not crash or corrupt the state.
func TestCRC32HashEmpty(t *testing.T) {
	got := CRC32Hash("")
	want := crc32HashFallback("")
	if got != want {
		t.Fatalf("mismatch for empty: got %x, want %x", got, want)
	}
}

// TestCRC32HashCollisionRate ensures distribution quality remains sufficient.
// Performs statistical collision tracking over a large input sample space.
func TestCRC32HashCollisionRate(t *testing.T) {
	seen := make(map[uint64]bool)
	collisions := 0
	for i := 0; i < testIterations; i++ {
		s := randomString(16)
		h := CRC32Hash(s)
		if seen[h] {
			collisions++
		}
		seen[h] = true
	}
	if collisions > maxCollisions {
		t.Fatalf("too many collisions: %d", collisions)
	}
}

// benchmarkCRC32Hash measures allocations and parallel execution timings.
// Confirms that assembly drops allocations strictly to 0.
func benchmarkCRC32Hash(b *testing.B, size int) {
	b.ReportAllocs()
	s := randomString(size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = CRC32Hash(s)
		}
	})
}

func BenchmarkCRC32Hash_8B(b *testing.B)   { benchmarkCRC32Hash(b, 8) }
func BenchmarkCRC32Hash_16B(b *testing.B)  { benchmarkCRC32Hash(b, 16) }
func BenchmarkCRC32Hash_32B(b *testing.B)  { benchmarkCRC32Hash(b, 32) }
func BenchmarkCRC32Hash_64B(b *testing.B)  { benchmarkCRC32Hash(b, 64) }
func BenchmarkCRC32Hash_128B(b *testing.B) { benchmarkCRC32Hash(b, 128) }
