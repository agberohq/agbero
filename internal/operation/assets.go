package operation

import (
	_ "embed"
	"time"
)

var (
	//go:embed asset/favicon.ico
	Favicon []byte
)

var ModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
