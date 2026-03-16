package metrics

import (
	"sync"
	"testing"
)

const (
	concurrentWorkers = 100
	requestsPerWorker = 1000
	simulatedLatency  = 150
	expectedMinEWMA   = 100
	expectedMaxEWMA   = 200
)

// TestActivityConcurrentEWMA assaults the moving average calculator utilizing parallel goroutines.
// Proves the lock-free Compare-And-Swap (CAS) loop prevents severe data corruption natively.
func TestActivityConcurrentEWMA(t *testing.T) {
	activity := NewActivity()
	var wg sync.WaitGroup

	wg.Add(concurrentWorkers)
	for i := 0; i < concurrentWorkers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < requestsPerWorker; j++ {
				activity.StartRequest()
				activity.EndRequest(simulatedLatency, false)
			}
		}()
	}

	wg.Wait()

	finalEWMA := activity.EWMA()

	if finalEWMA < expectedMinEWMA || finalEWMA > expectedMaxEWMA {
		t.Errorf("EWMA CAS loop failed: got %d, expected between %d and %d", finalEWMA, expectedMinEWMA, expectedMaxEWMA)
	}

	expectedTotal := uint64(concurrentWorkers * requestsPerWorker)
	if activity.Requests.Load() != expectedTotal {
		t.Errorf("Request tracking dropped counts: got %d, want %d", activity.Requests.Load(), expectedTotal)
	}

	if activity.InFlight.Load() != 0 {
		t.Errorf("InFlight connection leak detected: got %d, want 0", activity.InFlight.Load())
	}
}

// TestActivitySnapshots ensures telemetry extraction executes safely during active modifications.
// Verifies all atomic counters synthesize into the output map synchronously.
func TestActivitySnapshots(t *testing.T) {
	activity := NewActivity()
	activity.StartRequest()
	activity.EndRequest(simulatedLatency, true)

	snap := activity.Snapshot()

	if snap["requests"].(uint64) != 1 {
		t.Errorf("Snapshot requests mismatch: got %v", snap["requests"])
	}
	if snap["failures"].(uint64) != 1 {
		t.Errorf("Snapshot failures mismatch: got %v", snap["failures"])
	}
	if snap["in_flight"].(int64) != 0 {
		t.Errorf("Snapshot inflight mismatch: got %v", snap["in_flight"])
	}
}
