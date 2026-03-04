package xhttp

import (
	"net/http"
	"time"
)

type Config struct {
	Strategy string
	Timeout  time.Duration
	Fallback http.Handler
}
