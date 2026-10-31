package agbero

import (
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/agberohq/agbero/internal/core/alaye"
)

// sanitizeGlobalConfig returns a redacted deep copy of the global configuration.
// The implementation lives in the alaye package so the admin API
// (internal/operation/api) and this package can never drift apart again.
func sanitizeGlobalConfig(g *alaye.Global) *alaye.Global {
	return alaye.RedactGlobal(g)
}

// sanitizeHostConfigs returns redacted deep copies of every host config.
func sanitizeHostConfigs(hosts map[string]*alaye.Host) map[string]*alaye.Host {
	return alaye.RedactHosts(hosts)
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
