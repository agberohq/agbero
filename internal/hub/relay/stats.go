package relay

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"time"
)

type AgentSnapshot struct {
	ID          string             `json:"id"`
	Remote      string             `json:"remote,omitempty"`
	ConnectedAt time.Time          `json:"connected_at,omitempty"`
	Streams     int                `json:"streams"`
	Reconnects  int64              `json:"reconnects"`
	Exposures   []registeredExpose `json:"exposures,omitempty"`
	BytesIn     int64              `json:"bytes_in"`
	BytesOut    int64              `json:"bytes_out"`
	LastError   string             `json:"last_error,omitempty"`
	LastErrorAt time.Time          `json:"last_error_at,omitempty"`
}

// RouteSnapshot is one entry of the live public route table. A route whose
// session is no longer current is a dead route: public requests that match it
// can only fail, which is exactly the state that used to show up as a
// mysterious 404 or 502.
type RouteSnapshot struct {
	Key       string `json:"key"`
	Agent     string `json:"agent"`
	Subdomain bool   `json:"subdomain"`
	Domain    string `json:"domain,omitempty"`
	LocalPath string `json:"local_path,omitempty"`
	LocalHost string `json:"local_host,omitempty"`
	Live      bool   `json:"live"`
}

type AuthFailure struct {
	Agent     string    `json:"agent"`
	Mode      string    `json:"mode"`
	Presented string    `json:"presented_fingerprint,omitempty"`
	Expected  string    `json:"expected_fingerprint,omitempty"`
	Reason    string    `json:"reason"`
	At        time.Time `json:"at"`
}

type ServerSnapshot struct {
	Name              string          `json:"name"`
	Domain            string          `json:"domain"`
	Listen            string          `json:"listen"`
	Running           bool            `json:"running"`
	StartedAt         time.Time       `json:"started_at,omitempty"`
	Agents            []AgentSnapshot `json:"agents"`
	Routes            []RouteSnapshot `json:"routes"`
	TCPPorts          []int           `json:"tcp_ports,omitempty"`
	UDPPorts          []int           `json:"udp_ports,omitempty"`
	AuthErrors        int64           `json:"auth_errors"`
	LastError         string          `json:"last_error,omitempty"`
	LastErrorAt       time.Time       `json:"last_error_at,omitempty"`
	EnrollFingerprint string          `json:"enroll_fingerprint,omitempty"`
	LastAuth          *AuthFailure    `json:"last_auth,omitempty"`
}

func fingerprint(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

func (s *Server) Snapshot() ServerSnapshot {
	s.mu.RLock()
	out := ServerSnapshot{
		Name: s.cfg.Name, Domain: s.cfg.BaseDomain, Listen: s.cfg.Listen,
		Running: s.ln != nil, StartedAt: s.startedAt,
		AuthErrors: s.authErrors.Load(),
		LastError:  s.lastError, LastErrorAt: s.lastErrorAt, LastAuth: s.lastAuth,
	}
	if s.cfg.EnrollTokenFunc != nil {
		out.EnrollFingerprint = fingerprint(s.cfg.EnrollTokenFunc())
	} else {
		out.EnrollFingerprint = fingerprint(s.cfg.EnrollToken)
	}
	for _, sess := range s.sessions {
		sess.mu.Lock()
		streams, lastErr, lastErrAt := sess.streams, sess.lastError, sess.lastErrorAt
		ag := AgentSnapshot{
			ID: sess.agent, Remote: sess.remote, ConnectedAt: sess.connectedAt,
			Streams: streams, Exposures: sess.reg.Exposes,
			BytesIn: sess.bytesIn.Load(), BytesOut: sess.bytesOut.Load(),
			Reconnects: s.reconnects[sess.agent],
			LastError:  lastErr, LastErrorAt: lastErrAt,
		}
		sess.mu.Unlock()
		out.Agents = append(out.Agents, ag)
	}
	for key, rt := range s.routes {
		rs := RouteSnapshot{
			Key: key, Subdomain: rt.subdomain, Domain: rt.domain,
			LocalPath: rt.localPath, LocalHost: rt.localHost,
		}
		if rt.session != nil {
			rs.Agent = rt.session.agent
			rs.Live = !rt.session.closed() && s.sessions[rt.session.agent] == rt.session
		}
		out.Routes = append(out.Routes, rs)
	}
	for port := range s.tcpListeners {
		out.TCPPorts = append(out.TCPPorts, port)
	}
	for port := range s.udpListeners {
		out.UDPPorts = append(out.UDPPorts, port)
	}
	s.mu.RUnlock()
	sort.Slice(out.Agents, func(i, j int) bool { return out.Agents[i].ID < out.Agents[j].ID })
	sort.Slice(out.Routes, func(i, j int) bool { return out.Routes[i].Key < out.Routes[j].Key })
	sort.Ints(out.TCPPorts)
	sort.Ints(out.UDPPorts)
	return out
}

func (d *Dispatcher) Snapshot() []ServerSnapshot {
	if d == nil {
		return nil
	}
	out := make([]ServerSnapshot, 0, len(d.servers))
	for _, s := range d.servers {
		out = append(out, s.Snapshot())
	}
	return out
}
