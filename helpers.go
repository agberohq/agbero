package agbero

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
)

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
		clone.Security.InternalAuthKey = "***"
		for i := range clone.Security.TrustedProxies {
			clone.Security.TrustedProxies[i] = "***"
		}
	}

	if clone.LetsEncrypt.Enabled.Active() {
		clone.LetsEncrypt.Email = "***"
	}

	clone.Storage.HostsDir = "<configured>"
	clone.Storage.CertsDir = "<configured>"
	clone.Storage.DataDir = "<configured>"
	clone.Storage.WorkDir = "<configured>"

	return &clone
}

func sanitizeAdminConfig(cfg *alaye.Admin) {
	//if cfg.BasicAuth.Enabled.Active() {
	//	for i := range cfg.BasicAuth.Users {
	//		cfg.BasicAuth.Users[i] = "***"
	//	}
	//}
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
		readSize := min(offset, bufSize)
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

// detectFormat reads ?format= or the Accept header to select hcl vs json.
func detectFormat(r *http.Request) string {
	if format := r.URL.Query().Get("format"); format != "" {
		switch strings.ToLower(format) {
		case "hcl":
			return "hcl"
		case "json":
			return "json"
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/hcl") {
		return "hcl"
	}
	return "json"
}
