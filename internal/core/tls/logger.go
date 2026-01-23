package tls

import (
	"git.imaxinacion.net/aibox/agbero/internal/woos"
	"github.com/olekukonko/ll"
)

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

func (l tlsLogger) Fields(args ...any) woos.TlsLogger {
	return NewTLSLogger(l.logger.Fields(args...).Logger())
}
