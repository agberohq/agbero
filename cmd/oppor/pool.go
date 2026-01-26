// cmd/oppor/worker_pool.go
package main

import (
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type Pool struct {
	Config         Config
	Metrics        *Metrics
	MsgChan        chan tea.Msg // Fixed: explicit type match
	TotalRequests  uint64
	RequestCounter uint64

	stopChan chan struct{}
	workers  []*Worker
	wg       sync.WaitGroup
	running  atomic.Bool
}

func NewWorkerPool(cfg Config, metrics *Metrics, msgChan chan tea.Msg, totalReqs uint64) *Pool {
	return &Pool{
		Config:        cfg,
		Metrics:       metrics,
		MsgChan:       msgChan,
		TotalRequests: totalReqs,
		stopChan:      make(chan struct{}),
	}
}

func (wp *Pool) Start() {
	if !wp.running.CompareAndSwap(false, true) {
		return // Already running
	}

	// Start workers
	wp.workers = make([]*Worker, wp.Config.Concurrency)
	for i := 0; i < wp.Config.Concurrency; i++ {
		worker := NewWorker(i+1, &wp.Config, wp.Metrics, &wp.RequestCounter)
		wp.workers[i] = worker
		wp.wg.Add(1)
		go func(w *Worker) {
			defer wp.wg.Done()
			w.Run()
		}(worker)
	}

	// Metrics ticker
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-wp.stopChan:
				return
			case <-ticker.C:
				// Trigger UI update
				wp.MsgChan <- metricsMsg{}

				if wp.Config.Requests > 0 {
					completed := atomic.LoadUint64(&wp.RequestCounter)
					wp.MsgChan <- progressMsg{
						completed: completed,
						total:     wp.TotalRequests,
						done:      completed >= wp.TotalRequests,
					}
					if completed >= wp.TotalRequests {
						wp.Stop()
						return
					}
				}
			}
		}
	}()

	// Log forwarder
	go func() {
		for {
			select {
			case <-wp.stopChan:
				return
			case log := <-logQueue:
				wp.MsgChan <- logMsg{text: log}
			}
		}
	}()

	// Timer for Duration
	if wp.Config.Duration > 0 {
		go func() {
			select {
			case <-wp.stopChan:
				return
			case <-time.After(wp.Config.Duration):
				wp.Stop()
				wp.MsgChan <- progressMsg{done: true} // Signal UI done
			}
		}()
	}
}

func (wp *Pool) Stop() {
	if !wp.running.CompareAndSwap(true, false) {
		return
	}
	close(wp.stopChan)
	for _, w := range wp.workers {
		close(w.StopChan)
	}
	// Note: We don't wait for wg here to avoid blocking UI,
	// the workers will drain quickly.
}
