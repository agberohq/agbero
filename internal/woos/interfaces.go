package woos

// TlsLogger - Inerface
// The default logger used by the application is ll.Logger.
// However, Agbe uses CertMagic, which requires a logger that
// implements the interface below.
//
// To bridge this gap, we define TlsLogger to adapt our logger
// to CertMagic’s expected logging interface.
type TlsLogger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Fields(args ...any) TlsLogger
}
