package setup

import (
	"os"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/l3rd/victoria"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

const (
	DefaultFilePerm      = 0o666
	DefaultFlushInterval = 700 * time.Millisecond
	DefaultMaxBuffer     = 12000
	DefaultVictoriaBatch = 500

	LogLevelDebug = "debug"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
	LogLevelInfo  = "info"
)

// Logging creates the final logger based on config and returns a cleanup function to flush buffers.
func Logging(cfg alaye.Logging, devMode bool) (*ll.Logger, func(), error) {
	var handlers []lx.Handler
	var closers []func()

	// 1. Terminal Handler (Always on)
	handlers = append(handlers, lh.NewColorizedHandler(os.Stdout))

	// 2. File Handler
	if cfg.File != "" {
		fp, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, DefaultFilePerm)
		if err != nil {
			return nil, nil, err
		}
		handlers = append(handlers, lh.NewJSONHandler(fp))
		closers = append(closers, func() { fp.Close() })
	}

	// 3. VictoriaLogs Handler (Buffered)
	if cfg.Victoria.Enabled {
		vl, err := victoria.New(victoria.WithURL(cfg.Victoria.URL), victoria.WithDevMode(devMode))
		if err != nil {
			return nil, nil, err
		}

		err = vl.Ping()
		if err != nil {
			return nil, nil, err
		}

		batchSize := cfg.Victoria.BatchSize
		if batchSize <= 0 {
			batchSize = DefaultVictoriaBatch
		}

		buffered := lh.NewBuffered(vl,
			lh.WithBatchSize(batchSize),
			lh.WithFlushInterval(DefaultFlushInterval),
			lh.WithMaxBuffer(DefaultMaxBuffer),
		)
		handlers = append(handlers, buffered)

		// Ensure buffer flushes on shutdown
		closers = append(closers, func() {
			buffered.Close()
		})
	}

	multi := lh.NewMultiHandler(handlers...)
	l := ll.New(woos.Name, ll.WithHandler(multi), ll.WithFatalExits(true))

	// Set Level
	switch cfg.Level {
	case LogLevelDebug:
		l.Level(lx.LevelDebug)
	case LogLevelWarn:
		l.Level(lx.LevelWarn)
	case LogLevelError:
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
