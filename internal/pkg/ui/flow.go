package ui

import (
	"fmt"
	"os"
)

// Flow provides consistent user-facing feedback for CLI actions. It replaces
// logger calls in command handlers so operators see what is happening instead
// of a log line appearing after the fact.
type Flow struct {
	u *UI
}

func NewFlow(opts ...Option) *Flow {
	return &Flow{u: New(opts...)}
}

func (f *Flow) UI() *UI { return f.u }

// Start announces an action in progress.
func (f *Flow) Start(format string, args ...any) *Flow {
	f.u.Step("run", fmt.Sprintf(format, args...))
	f.u.Flush()
	return f
}

// Done marks an action complete.
func (f *Flow) Done(format string, args ...any) *Flow {
	f.u.Step("ok", fmt.Sprintf(format, args...))
	f.u.Flush()
	return f
}

// Info prints supporting information.
func (f *Flow) Info(args ...any) *Flow {
	f.u.InfoLine(fmt.Sprint(args...))
	f.u.Flush()
	return f
}

func (f *Flow) Infof(format string, args ...any) *Flow {
	f.u.InfoLine(fmt.Sprintf(format, args...))
	f.u.Flush()
	return f
}

// Warn prints a non-fatal warning.
func (f *Flow) Warn(args ...any) *Flow {
	f.u.WarnLine(fmt.Sprint(args...))
	f.u.Flush()
	return f
}

func (f *Flow) Warnf(format string, args ...any) *Flow {
	f.u.WarnLine(fmt.Sprintf(format, args...))
	f.u.Flush()
	return f
}

// Error prints an error without exiting.
func (f *Flow) Error(args ...any) *Flow {
	f.u.ErrorLine(fmt.Sprint(args...))
	f.u.Flush()
	return f
}

func (f *Flow) Errorf(format string, args ...any) *Flow {
	f.u.ErrorLine(fmt.Sprintf(format, args...))
	f.u.Flush()
	return f
}

// Abort prints an error and exits with status 1.
func (f *Flow) Abort(args ...any) {
	f.Error(args...)
	os.Exit(1)
}

func (f *Flow) Abortf(format string, args ...any) {
	f.Errorf(format, args...)
	os.Exit(1)
}
