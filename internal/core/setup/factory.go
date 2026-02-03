package setup

import (
	"os"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"git.imaxinacion.net/aibox/agbero/internal/woos/alaye"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/l3rd/victoria"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

// Logging creates the final logger based on config and returns a cleanup function to flush buffers.
func Logging(cfg alaye.Logging, devMode bool, sm *jack.Shutdown) (*ll.Logger, error) {
	var handlers []lx.Handler

	// Terminal (always)
	handlers = append(handlers, lh.NewColorizedHandler(os.Stdout))

	// File
	if cfg.File != "" {
		fp, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, woos.DefaultFilePermFile)
		if err != nil {
			return nil, err
		}
		_ = sm.Register(fp) // io.Closer

		handlers = append(handlers, lh.NewJSONHandler(fp))
	}

	// VictoriaLogs (buffered)
	if cfg.Victoria.Enabled {
		vl, err := victoria.New(
			victoria.WithURL(cfg.Victoria.URL),
			victoria.WithDevMode(devMode),
		)
		if err != nil {
			return nil, err
		}
		if err := vl.Ping(); err != nil {
			return nil, err
		}

		batchSize := cfg.Victoria.BatchSize
		if batchSize <= 0 {
			batchSize = woos.DefaultVictoriaBatch
		}

		buffered := lh.NewBuffered(vl,
			lh.WithBatchSize(batchSize),
			lh.WithFlushInterval(woos.DefaultFlushInterval),
			lh.WithMaxBuffer(woos.DefaultMaxBuffer),
		)

		handlers = append(handlers, buffered)
		_ = sm.Register(buffered) // Close() error => flush + stop worker

		// If vl itself has Close(), register it too (safe if it doesn't)
		_ = sm.Register(vl)
	}

	multi := lh.NewMultiHandler(handlers...)

	// Optional: dedup around multi (good ordering)
	final := lh.NewDedup(multi, 2*time.Second)
	_ = sm.Register(final) // if Dedup has Close() (recommended), this stops its ticker/goroutine

	l := ll.New(woos.Name, ll.WithHandler(final), ll.WithFatalExits(true))

	// Level setup (same intent)
	switch cfg.Level {
	case woos.LogLevelDebug:
		l.Level(lx.LevelDebug)
	case woos.LogLevelWarn:
		l.Level(lx.LevelWarn)
	case woos.LogLevelError:
		l.Level(lx.LevelError)
	default:
		l.Level(lx.LevelInfo)
	}
	if devMode {
		l.Level(lx.LevelDebug)
	}

	return l.Enable(), nil
}
