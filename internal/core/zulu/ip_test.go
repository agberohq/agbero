package zulu

import (
	"net/http"
	"testing"
)

func TestIPManager_GetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		trusted    []string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "No trusted proxies, return remote",
			trusted:    nil,
			remoteAddr: "1.2.3.4:1234",
			want:       "1.2.3.4",
		},
		{
			name:       "Trusted proxy, valid XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.1"},
			want:       "198.51.100.1",
		},
		{
			name:       "Trusted proxy, XFF with internal hops",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 10.0.0.2"},
			want:       "203.0.113.1",
		},
		{
			name:       "Untrusted remote, ignore XFF",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "1.2.3.4:1234",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1"},
			want:       "1.2.3.4",
		},
		{
			name:       "Trusted proxy, X-Real-IP fallback",
			trusted:    []string{"10.0.0.0/8"},
			remoteAddr: "10.0.0.1:1234",
			headers:    map[string]string{"X-Real-IP": "203.0.113.1"},
			want:       "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewIPManager(tt.trusted)
			req, _ := http.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			if got := m.ClientIP(req); got != tt.want {
				t.Errorf("ClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
