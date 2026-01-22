package core

import "github.com/olekukonko/ll"

type anyLogger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Fields(args ...any) anyLogger
}

type tlsLogger struct {
	logger *ll.Logger
}

func NewTLSLogger(logger *ll.Logger) tlsLogger {
	return tlsLogger{logger: logger}
}

func (l tlsLogger) Info(msg string, args ...any) {
	l.logger.Infof(msg, args...)
}

func (l tlsLogger) Warn(msg string, args ...any) {
	l.logger.Warnf(msg, args...)
}

func (l tlsLogger) Error(msg string, args ...any) {
	l.logger.Errorf(msg, args...)
}

func (l tlsLogger) Fields(args ...any) anyLogger {
	return NewTLSLogger(l.logger.Fields(args...).Logger())
}
