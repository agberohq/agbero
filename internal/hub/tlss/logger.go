package tlss

import (
	"github.com/olekukonko/ll"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type tlsLogger struct {
	logger *ll.Logger
}

func newTLSLogger(logger *ll.Logger) *zap.Logger {
	config := zap.NewProductionConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)

	wrapper := &tlsLogger{logger: logger.Namespace("zap")}

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
