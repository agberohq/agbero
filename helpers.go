package agbero

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/handlers/xtcp"
	"github.com/olekukonko/ll"
)

// =============================================================================
// Logging Helpers
// =============================================================================

type llWriter struct {
	logger *ll.Logger
}

func (w *llWriter) Write(p []byte) (n int, err error) {
	msg := strings.TrimSpace(string(p))
	w.logger.Fields("source", "std_http").Error(msg)
	return len(p), nil
}

var logArgsPool = sync.Pool{
	New: func() any {
		s := make([]any, 0, 16)
		return &s
	},
}

// =============================================================================
// Connection Tracking
// =============================================================================

type connTracker struct {
	conns sync.Map
	wg    sync.WaitGroup
}

func newConnTracker() *connTracker {
	return &connTracker{}
}

func (ct *connTracker) track(conn net.Conn, state http.ConnState) {
	// Only interact with the map and waitgroup on creation and destruction.
	// Ignore StateActive and StateIdle entirely to avoid bottlenecking Keep-Alive requests.
	switch state {
	case http.StateNew:
		ct.conns.Store(conn, struct{}{})
		ct.wg.Add(1)
	case http.StateClosed, http.StateHijacked:
		if _, loaded := ct.conns.LoadAndDelete(conn); loaded {
			ct.wg.Done()
		}
	}
}

func (ct *connTracker) wait() {
	ct.wg.Wait()
}

func (ct *connTracker) count() int {
	count := 0
	ct.conns.Range(func(key, value any) bool {
		count++
		return true
	})
	return count
}

func anyStreamingEnabled(hosts map[string]*alaye.Host) bool {
	for _, host := range hosts {
		for _, rt := range host.Routes {
			if rt.Backends.Enabled.Active() {
				for _, srv := range rt.Backends.Servers {
					if srv.Streaming.Enabled.Active() {
						return true
					}
				}
			}
		}
	}
	return false
}

func groupTCPRoutesByListen(hosts map[string]*alaye.Host) map[string][]alaye.TCPRoute {
	tcpGroups := make(map[string][]alaye.TCPRoute)
	for _, host := range hosts {
		for i := range host.Proxies {
			p := host.Proxies[i]
			tcpGroups[p.Listen] = append(tcpGroups[p.Listen], p)
		}
	}
	return tcpGroups
}

func findTCPGroupForProxy(tp *xtcp.Proxy, tcpGroups map[string][]alaye.TCPRoute) []alaye.TCPRoute {
	_, port, _ := net.SplitHostPort(tp.Listen)
	if port == "" {
		if strings.HasPrefix(tp.Listen, ":") {
			port = tp.Listen[1:]
		} else {
			return nil
		}
	}

	if group, ok := tcpGroups[tp.Listen]; ok {
		return group
	}

	for l, g := range tcpGroups {
		if strings.HasSuffix(l, ":"+port) {
			return g
		}
	}
	return nil
}

// =============================================================================
// Configuration Sanitization Helpers
// =============================================================================

func sanitizeGlobalConfig(g *alaye.Global) *alaye.Global {
	b, _ := json.Marshal(g)
	var clone alaye.Global
	_ = json.Unmarshal(b, &clone)

	if clone.Gossip.Enabled.Active() {
		clone.Gossip.SecretKey = "***"
	}

	if clone.Admin.Enabled.Active() {
		sanitizeAdminConfig(&clone.Admin)
	}

	if clone.Security.Enabled.Active() {
		for i := range clone.Security.TrustedProxies {
			clone.Security.TrustedProxies[i] = "***"
		}
	}

	if clone.LetsEncrypt.Enabled.Active() {
		clone.LetsEncrypt.Email = "***"
	}

	return &clone
}

func sanitizeAdminConfig(cfg *alaye.Admin) {
	if cfg.BasicAuth.Enabled.Active() {
		for i := range cfg.BasicAuth.Users {
			cfg.BasicAuth.Users[i] = "***"
		}
	}
	if cfg.JWTAuth.Enabled.Active() {
		cfg.JWTAuth.Secret = "***"
	}
	if cfg.ForwardAuth.Enabled.Active() {
		cfg.ForwardAuth.URL = "***"
	}
	if cfg.OAuth.Enabled.Active() {
		cfg.OAuth.ClientSecret = "***"
		cfg.OAuth.CookieSecret = "***"
	}
}

func sanitizeHostConfigs(hosts map[string]*alaye.Host) map[string]*alaye.Host {
	out := make(map[string]*alaye.Host)
	for k, v := range hosts {
		b, _ := json.Marshal(v)
		var clone alaye.Host
		_ = json.Unmarshal(b, &clone)

		for i := range clone.Routes {
			sanitizeRouteConfig(&clone.Routes[i])
		}
		out[k] = &clone
	}
	return out
}

func sanitizeRouteConfig(route *alaye.Route) {
	if route.BasicAuth.Enabled.Active() {
		for j := range route.BasicAuth.Users {
			route.BasicAuth.Users[j] = "***"
		}
	}
	if route.JWTAuth.Enabled.Active() {
		route.JWTAuth.Secret = "***"
	}
	if route.OAuth.Enabled.Active() {
		route.OAuth.ClientSecret = "***"
		route.OAuth.CookieSecret = "***"
	}
	if route.Wasm.Enabled.Active() && len(route.Wasm.Config) > 0 {
		route.Wasm.Config = map[string]string{"***": "***"}
	}
	if route.ForwardAuth.Enabled.Active() {
		route.ForwardAuth.URL = "***"
	}
}

// =============================================================================
// File Reading Helpers
// =============================================================================

func readLastLogLines(filename string, n int) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := stat.Size()
	var lines []string

	const bufSize = 1024
	buf := make([]byte, bufSize)

	var offset int64 = fileSize
	var leftover string

	for offset > 0 && len(lines) < n {
		readSize := min(offset, int64(bufSize))
		offset -= readSize

		_, err := file.Seek(offset, io.SeekStart)
		if err != nil {
			return nil, err
		}

		_, err = file.Read(buf[:readSize])
		if err != nil {
			return nil, err
		}

		chunk := string(buf[:readSize]) + leftover
		parts := strings.Split(chunk, "\n")

		if offset > 0 {
			leftover = parts[0]
			parts = parts[1:]
		}

		for i := len(parts) - 1; i >= 0; i-- {
			line := strings.TrimSpace(parts[i])
			if line != "" {
				lines = append(lines, line)
				if len(lines) >= n {
					break
				}
			}
		}
	}

	return lines, nil
}

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
