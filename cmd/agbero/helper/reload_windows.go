//go:build windows

package helper

// registerReload is a no-op on Windows: SCM does not deliver SIGHUP, and the
// service manager restarts the process instead. `agbero config reload` is
// therefore unavailable on Windows (the CLI reports the error from the pid
// path instead of sending an unsupported signal).
func registerReload(_ func()) func() {
	return func() {}
}
