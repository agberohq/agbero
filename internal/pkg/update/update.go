package update

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"
)

// Result holds the outcome of a single update check.
// Implements api.UpdateChecker interface.
type Result struct {
	Current   string
	Latest    string
	Available bool
	CheckedAt time.Time
	Err       string
}

func (r *Result) GetCurrent() string { return r.Current }
func (r *Result) GetLatest() string  { return r.Latest }
func (r *Result) IsAvailable() bool  { return r.Available }

// Checker performs a single non-blocking update check at startup.
// The result is stored atomically — safe to read from any goroutine.
// Implements api.UpdateChecker via Result.
type Checker struct {
	current    string
	releaseURL string
	result     unsafe.Pointer // *Result
}

// New creates a Checker.
// releaseURL must return JSON with a "tag_name" or "version" field.
func New(currentVersion, releaseURL string) *Checker {
	c := &Checker{
		current:    currentVersion,
		releaseURL: releaseURL,
	}
	initial := &Result{Current: currentVersion}
	atomic.StorePointer(&c.result, unsafe.Pointer(initial))
	return c
}

// Start launches a single background check with a 5-second timeout.
// Returns immediately — result becomes available asynchronously.
func (c *Checker) Start() {
	go c.run()
}

func (c *Checker) run() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.releaseURL, nil)
	if err != nil {
		c.store(&Result{Current: c.current, CheckedAt: time.Now(), Err: err.Error()})
		return
	}
	req.Header.Set("User-Agent", "agbero/update-check")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.store(&Result{Current: c.current, CheckedAt: time.Now(), Err: err.Error()})
		return
	}
	defer resp.Body.Close()

	var payload struct {
		TagName string `json:"tag_name"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		c.store(&Result{Current: c.current, CheckedAt: time.Now(), Err: err.Error()})
		return
	}

	latest := payload.TagName
	if latest == "" {
		latest = payload.Version
	}
	latest = strings.TrimPrefix(latest, "v")
	current := strings.TrimPrefix(c.current, "v")

	available := latest != "" &&
		latest != current &&
		latest != "dev" &&
		current != "dev"

	c.store(&Result{
		Current:   c.current,
		Latest:    "v" + latest,
		Available: available,
		CheckedAt: time.Now(),
	})
}

func (c *Checker) store(r *Result) {
	atomic.StorePointer(&c.result, unsafe.Pointer(r))
}

// GetCurrent implements api.UpdateChecker.
func (c *Checker) GetCurrent() string {
	return (*Result)(atomic.LoadPointer(&c.result)).Current
}

// GetLatest implements api.UpdateChecker.
func (c *Checker) GetLatest() string {
	return (*Result)(atomic.LoadPointer(&c.result)).Latest
}

// IsAvailable implements api.UpdateChecker.
func (c *Checker) IsAvailable() bool {
	return (*Result)(atomic.LoadPointer(&c.result)).Available
}
