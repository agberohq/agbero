package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

// Auditor appends JSONL audit records. It records the method/tool name and
// client identity only, never argument values or secret material.
type Auditor struct {
	mu   sync.Mutex
	file *os.File
}

func OpenAuditor(path string) (*Auditor, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &Auditor{file: f}, nil
}

func (a *Auditor) Close() error {
	if a == nil || a.file == nil {
		return nil
	}
	return a.file.Close()
}

func (a *Auditor) Log(entry map[string]any) {
	if a == nil || a.file == nil {
		return
	}
	entry["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	a.mu.Lock()
	_, _ = a.file.Write(append(b, '\n'))
	a.mu.Unlock()
}

// AuditMiddleware records allow/deny decisions with actor, client IP, JSON-RPC
// method, and tool name. It buffers the request body (stateless JSON only) up
// to 4 MiB so the SDK still receives the original bytes.
func AuditMiddleware(a *Auditor) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			method, tool := "", ""
			if r.Method == http.MethodPost && r.Body != nil {
				body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
				r.Body = io.NopCloser(bytes.NewReader(body))
				var env struct {
					Method string `json:"method"`
					Params struct {
						Name string `json:"name"`
					} `json:"params"`
				}
				if json.Unmarshal(body, &env) == nil {
					method = env.Method
					tool = env.Params.Name
				}
			}
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			actor := "anonymous"
			if c := ClaimsFromContext(r.Context()); c != nil && c.Subject != "" {
				actor = c.Subject
			}
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				ip = host
			}
			a.Log(map[string]any{
				"event": "mcp_http", "actor": actor, "client_ip": ip,
				"method": r.Method, "path": r.URL.Path, "rpc_method": method,
				"tool": tool, "status": rec.status,
				"duration_ms": time.Since(start).Milliseconds(),
			})
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
