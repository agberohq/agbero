package woos

type Logging interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Fields(args ...any) Logging
}
