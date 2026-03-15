package metrics

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// BenchmarkLatencyRecordOnly - baseline mutex contention
func BenchmarkLatencyRecordOnly(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			lt.Record(int64(100 + i%900))
			i++
		}
	})
}

// BenchmarkActivityRecord - full activity lifecycle
func BenchmarkActivityRecord(b *testing.B) {
	activity := NewActivity()
	defer activity.Latency.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			activity.StartRequest()
			activity.EndRequest(int64(100+i%900), false)
			i++
		}
	})
}

// BenchmarkLatencySnapshot - health check polling
func BenchmarkLatencySnapshot(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	for i := 0; i < 10000; i++ {
		lt.Record(int64(100 + i%900))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lt.Snapshot()
	}
}

// BenchmarkMixedLoad - concurrent writes with periodic reads
func BenchmarkMixedLoad(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	var wg sync.WaitGroup
	done := make(chan struct{})

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j := 0
			for {
				select {
				case <-done:
					return
				default:
					lt.Record(int64(100 + j%900))
					j++
				}
			}
		}()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lt.Snapshot()
		time.Sleep(time.Millisecond)
	}
	b.StopTimer()

	close(done)
	wg.Wait()
}

// BenchmarkRegistryGetOrRegister - registry hot path
func BenchmarkRegistryGetOrRegister(b *testing.B) {
	reg := NewRegistry()
	defer reg.Close()

	keys := make([]alaye.BackendKey, 100)
	for i := range keys {
		keys[i] = alaye.BackendKey{Addr: fmt.Sprintf("host:%d", i)}
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			key := keys[i%len(keys)]
			_ = reg.GetOrRegister(key)
			i++
		}
	})
}

// BenchmarkEndToEnd - full request lifecycle
func BenchmarkEndToEnd(b *testing.B) {
	reg := NewRegistry()
	defer reg.Close()

	key := alaye.BackendKey{Addr: "backend1:8080"}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			stats := reg.GetOrRegister(key)
			stats.Activity.StartRequest()
			stats.Activity.EndRequest(int64(100+i%900), false)
			i++
		}
	})
}

// BenchmarkContentionLevels - scaling test
func BenchmarkContentionLevels(b *testing.B) {
	for _, workers := range []int{1, 4, 8, 16, 32, 64, 128} {
		b.Run(fmt.Sprintf("workers=%d", workers), func(b *testing.B) {
			lt := NewLatency()
			defer lt.Close()

			var wg sync.WaitGroup
			recordsPerWorker := b.N / workers

			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < recordsPerWorker; i++ {
						lt.Record(int64(100 + i%900))
					}
				}()
			}
			wg.Wait()
		})
	}
}

// BenchmarkRealisticLoad simulates actual HTTP handler patterns with goroutine churn
// This is more realistic: goroutines spawn, do work, record metrics, exit
func BenchmarkRealisticLoad(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		// Simulate 100 concurrent requests
		for j := 0; j < 100; j++ {
			wg.Add(1)
			go func(latency int64) {
				defer wg.Done()
				lt.Record(latency)
				// Simulate some work to cause context switches
				runtime.Gosched()
			}(int64(100 + i%900))
		}
		wg.Wait()
	}
}

// BenchmarkHighChurn simulates rapid goroutine creation/destruction
// This stresses the mutex more due to cache line bouncing between cores
func BenchmarkHighChurn(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Each iteration spawns new goroutine to maximize cache line contention
			done := make(chan struct{})
			go func() {
				lt.Record(int64(500))
				close(done)
			}()
			<-done
		}
	})
}

// BenchmarkBurstPattern simulates traffic spikes
func BenchmarkBurstPattern(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Burst of 1000 records
		var wg sync.WaitGroup
		for j := 0; j < 1000; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				lt.Record(int64(100 + j%900))
			}()
		}
		wg.Wait()
	}
}

// BenchmarkWithWork simulates realistic CPU work between recordings
func BenchmarkWithWork(b *testing.B) {
	lt := NewLatency()
	defer lt.Close()

	work := func() {
		// Simulate some CPU work
		sum := 0
		for i := 0; i < 1000; i++ {
			sum += i
		}
		_ = sum
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			work()
			lt.Record(int64(500))
		}
	})
}
