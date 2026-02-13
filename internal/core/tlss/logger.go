package tlss

import (
	"github.com/olekukonko/ll"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tlsLogger struct {
	logger *ll.Logger
}

// newTLSLogger creates a zap.Logger instance that integrates with a custom logger for TLS-related logging.
func newTLSLogger(logger *ll.Logger) *zap.Logger {
	// Create a zap logger with a custom core
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)

	wrapper := &tlsLogger{logger: logger.Namespace("zap")}

	// Create a minimal zap core that delegates to your logger
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(config.EncoderConfig),
		zapcore.AddSync(wrapper),
		config.Level,
	)

	return zap.New(core, zap.AddCaller())
}

func (l *tlsLogger) Write(p []byte) (n int, err error) {
	l.logger.Info(string(p))
	return len(p), nil
}

func (l *tlsLogger) Sync() error {
	return nil
}

func (l *tlsLogger) Info(msg string, args ...any) {
	l.logger.Infof(msg, args...)
}

func (l *tlsLogger) Warn(msg string, args ...any) {
	l.logger.Warnf(msg, args...)
}

func (l *tlsLogger) Error(msg string, args ...any) {
	l.logger.Errorf(msg, args...)
}
