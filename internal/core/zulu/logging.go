package zulu

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"git.imaxinacion.net/aibox/agbero/internal/core/alaye"
	"git.imaxinacion.net/aibox/agbero/internal/core/woos"
	"github.com/olekukonko/jack"
	"github.com/olekukonko/ll"
	"github.com/olekukonko/ll/l3rd/victoria"
	"github.com/olekukonko/ll/lh"
	"github.com/olekukonko/ll/lx"
)

func Logging(cfg *alaye.Logging, devMode bool, sm *jack.Shutdown) (*ll.Logger, error) {
	var handlers []lx.Handler

	handlers = append(handlers, lh.NewColorizedHandler(os.Stdout))

	// Updated to use nested File struct
	if cfg.File.Enabled.Active() && cfg.File.Path != "" {
		logPath := cfg.File.Path
		logDir := filepath.Dir(logPath)
		if err := os.MkdirAll(logDir, woos.DefaultFilePermDir); err != nil {
			return nil, fmt.Errorf("failed to create log dir %s: %w", logDir, err)
		}

		src := lh.RotateSource{
			Open: func() (io.WriteCloser, error) {
				return os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, woos.DefaultFilePermFile)
			},
			Size: func() (int64, error) {
				fi, err := os.Stat(logPath)
				if err != nil {
					if os.IsNotExist(err) {
						return 0, nil
					}
					return 0, err
				}
				return fi.Size(), nil
			},
			Rotate: func() error {
				timestamp := time.Now().Format("20060102-150405.000000")
				backupName := logPath + "." + timestamp
				if err := os.Rename(logPath, backupName); err != nil {
					return err
				}
				go compressLogFile(backupName)
				return nil
			},
		}

		baseHandler := lh.NewJSONHandler(nil)
		rotator, err := lh.NewRotating(baseHandler, woos.DefaultLogRotateSize, src)
		if err != nil {
			return nil, fmt.Errorf("failed to init log rotation: %w", err)
		}

		_ = sm.Register(rotator)
		handlers = append(handlers, rotator)
	}

	if cfg.Victoria.Enabled.Active() {
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
		_ = sm.Register(buffered)
		_ = sm.Register(vl)
	}

	multi := lh.NewMultiHandler(handlers...)
	final := lh.NewDedup(multi, 5*time.Second, lh.WithDedupIgnore("duration"))
	_ = sm.Register(final)

	l := ll.New(woos.Name, ll.WithHandler(final), ll.WithFatalExits(true))

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

func compressLogFile(srcPath string) {
	dstPath := srcPath + ".gz"

	in, err := os.Open(srcPath)
	if err != nil {
		return
	}
	defer in.Close()

	out, err := os.Create(dstPath)
	if err != nil {
		return
	}
	defer out.Close()

	gw := gzip.NewWriter(out)
	defer gw.Close()

	if _, err := io.Copy(gw, in); err != nil {
		return
	}

	gw.Close()
	in.Close()
	_ = os.Remove(srcPath)
}
