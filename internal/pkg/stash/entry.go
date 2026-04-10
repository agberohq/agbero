package stash

import (
	"net/http"
	"time"
)

type Entry struct {
	Body        []byte
	Headers     http.Header
	Status      int
	StoredAt    time.Time
	CreatedAt   time.Time
	VaryHeaders map[string]string
	ContentType string
}
