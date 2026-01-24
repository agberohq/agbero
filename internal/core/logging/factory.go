package logging

import (
	"os"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

// Setup creates the final logger based on config and returns a cleanup function to flush buffers.
func Setup(cfg alaye.Logging, devMode bool) (*ll.Logger, func(), error) {
	var handlers []lx.Handler
	var closers []func()

	// 1. Terminal Handler (Always on)
	handlers = append(handlers, lh.NewColorizedHandler(os.Stdout, lh.WithColorShowTime(true)))

	// 2. File Handler
	if cfg.File != "" {
		fp, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			return nil, nil, err
		}
		handlers = append(handlers, lh.NewJSONHandler(fp))
		closers = append(closers, func() { fp.Close() })
	}

	// 3. VictoriaLogs Handler (Buffered)
	if cfg.Victoria.Enabled {
		vl := NewVictoriaHandler(cfg.Victoria.URL, devMode)

		batchSize := cfg.Victoria.BatchSize
		if batchSize <= 0 {
			batchSize = 500
		}

		buffered := lh.NewBuffered(vl,
			lh.WithBatchSize(batchSize),
			lh.WithFlushInterval(700*time.Millisecond),
			lh.WithMaxBuffer(12000),
		)
		handlers = append(handlers, buffered)

		// Ensure buffer flushes on shutdown
		closers = append(closers, func() { buffered.Close() })
	}

	multi := lh.NewMultiHandler(handlers...)
	l := ll.New(woos.Name, ll.WithHandler(multi), ll.WithFatalExits(true))

	// Set Level
	switch cfg.Level {
	case "debug":
		l.Level(lx.LevelDebug)
	case "warn":
		l.Level(lx.LevelWarn)
	case "error":
		l.Level(lx.LevelError)
	default:
		l.Level(lx.LevelInfo)
	}

	if devMode {
		l.Level(lx.LevelDebug)
	}

	cleanup := func() {
		for _, c := range closers {
			c()
		}
	}

	return l.Enable(), cleanup, nil
}
