// cmd/oppor/worker_pool.go
package main

import (
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type WorkerPool struct {
	Config         Config
	Metrics        *Metrics
	MsgChan        chan interface{} // tea.Msg
	TotalRequests  uint64
	RequestCounter uint64
}

func NewWorkerPool(cfg Config, metrics *Metrics, msgChan chan interface{}, totalReqs uint64) *WorkerPool {
	return &WorkerPool{
		Config:        cfg,
		Metrics:       metrics,
		MsgChan:       msgChan,
		TotalRequests: totalReqs,
	}
}

func (wp *WorkerPool) Start() {
	var wg sync.WaitGroup

	// Start workers
	workers := make([]*Worker, wp.Config.Concurrency)
	for i := 0; i < wp.Config.Concurrency; i++ {
		worker := NewWorker(i+1, &wp.Config, wp.Metrics, &wp.RequestCounter)
		workers[i] = worker
		wg.Add(1)
		go func(w *Worker) {
			defer wg.Done()
			w.Run()
		}(worker)
	}

	// Send initial empty metrics to trigger UI update
	wp.MsgChan <- metricsMsg{}

	// Metrics ticker
	stopMetrics := make(chan struct{})
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Calc RPS
				total := wp.Metrics.TotalRequests.Load()
				dur := time.Since(startTime).Seconds()
				if dur > 0 {
					rps := uint64(float64(total) / dur)
					wp.Metrics.RequestsPerSec.Store(rps)
				}

				wp.MsgChan <- metricsMsg{}

				// Send progress
				if wp.Config.Requests > 0 {
					completed := atomic.LoadUint64(&wp.RequestCounter)
					wp.MsgChan <- progressMsg{
						completed: completed,
						total:     wp.TotalRequests,
						done:      completed >= wp.TotalRequests,
					}
				}
			case <-stopMetrics:
				return
			}
		}
	}()

	// Log forwarder
	go func() {
		for log := range logQueue {
			wp.MsgChan <- logMsg{text: log}
		}
	}()

	// Wait for OS signals or completion
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	var done bool

	// Wait logic
	if wp.Config.Duration > 0 {
		select {
		case <-time.After(wp.Config.Duration):
			done = true
		case <-sigChan:
			done = true
		}
	} else if wp.Config.Requests > 0 {
		for !done {
			select {
			case <-sigChan:
				done = true
			default:
				if atomic.LoadUint64(&wp.RequestCounter) >= wp.TotalRequests {
					done = true
				} else {
					time.Sleep(50 * time.Millisecond)
				}
			}
		}
	} else {
		// Infinite run
		<-sigChan
		done = true
	}

	// Shutdown
	for _, w := range workers {
		close(w.StopChan)
	}
	close(stopMetrics)
	wg.Wait()

	// Final updates
	if wp.Config.Requests > 0 {
		wp.MsgChan <- progressMsg{
			completed: atomic.LoadUint64(&wp.RequestCounter),
			total:     wp.TotalRequests,
			done:      true,
		}
	}
	wp.MsgChan <- metricsMsg{}

	// Close logs (optional, might cause panic if writes happen after, usually safe to leave or use specialized shutdown)
	// close(logQueue)
}
