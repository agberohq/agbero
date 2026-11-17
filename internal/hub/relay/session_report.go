package relay

import (
	"net"
	"sort"
	"time"
)

// sessionHistoryLimit bounds the per-agent event log kept for diagnostics.
const sessionHistoryLimit = 32

// SessionEvent is one entry of an agent's recent session history on the relay.
// The history is what lets a remote doctor tell a stable session from one that
// is being replaced, and two agents sharing a name from one flaky agent.
type SessionEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // opened, closed, replaced, proxy_error
	Remote string    `json:"remote,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Count  int       `json:"count,omitempty"`
}

// SessionReport is returned on an authenticated check. It carries the relay's
// own view of the agent, so the agent host can diagnose the tunnel without
// access to the relay's admin API.
type SessionReport struct {
	Connected bool            `json:"connected"`
	Agent     *AgentSnapshot  `json:"agent,omitempty"`
	Routes    []RouteSnapshot `json:"routes,omitempty"`
	History   []SessionEvent  `json:"history,omitempty"`
	Now       time.Time       `json:"now"`
}

// recordEventLocked appends to the agent's history. Repeated proxy errors with
// the same reason are folded into one entry so a burst does not push the
// session events out. Callers must hold s.mu.
func (s *Server) recordEventLocked(agent string, ev SessionEvent) {
	if ev.At.IsZero() {
		ev.At = time.Now().UTC()
	}
	h := s.history[agent]
	if n := len(h); n > 0 && ev.Kind == "proxy_error" {
		last := &h[n-1]
		if last.Kind == ev.Kind && last.Reason == ev.Reason && last.Remote == ev.Remote {
			if last.Count == 0 {
				last.Count = 1
			}
			last.Count++
			last.At = ev.At
			return
		}
	}
	h = append(h, ev)
	if len(h) > sessionHistoryLimit {
		h = h[len(h)-sessionHistoryLimit:]
	}
	s.history[agent] = h
}

func (s *Server) recordEvent(agent string, ev SessionEvent) {
	s.mu.Lock()
	s.recordEventLocked(agent, ev)
	s.mu.Unlock()
}

// sessionReport builds the relay's view of one agent.
func (s *Server) sessionReport(agent string) *SessionReport {
	out := &SessionReport{Now: time.Now().UTC()}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if sess := s.sessions[agent]; sess != nil && !sess.closed() {
		sess.mu.Lock()
		out.Agent = &AgentSnapshot{
			ID: sess.agent, Remote: sess.remote, ConnectedAt: sess.connectedAt,
			Streams: sess.streams, Exposures: sess.reg.Exposes,
			BytesIn: sess.bytesIn.Load(), BytesOut: sess.bytesOut.Load(),
			Reconnects: s.reconnects[agent],
			LastError:  sess.lastError, LastErrorAt: sess.lastErrorAt,
		}
		sess.mu.Unlock()
		out.Connected = true
	}
	for key, rt := range s.routes {
		if rt.session == nil || rt.session.agent != agent {
			continue
		}
		out.Routes = append(out.Routes, RouteSnapshot{
			Key: key, Agent: agent, Subdomain: rt.subdomain, Domain: rt.domain,
			LocalPath: rt.localPath, LocalHost: rt.localHost,
			Live: !rt.session.closed() && s.sessions[agent] == rt.session,
		})
	}
	sort.Slice(out.Routes, func(i, j int) bool { return out.Routes[i].Key < out.Routes[j].Key })
	out.History = append([]SessionEvent(nil), s.history[agent]...)
	return out
}

// RemoteHosts returns the distinct source addresses (without ports) that opened
// sessions in the history, oldest first.
func (r *SessionReport) RemoteHosts() []string {
	if r == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, ev := range r.History {
		if ev.Kind != "opened" || ev.Remote == "" {
			continue
		}
		host := ev.Remote
		if h, _, err := net.SplitHostPort(ev.Remote); err == nil {
			host = h
		}
		if !seen[host] {
			seen[host] = true
			out = append(out, host)
		}
	}
	return out
}

// Count returns how many events of kind happened within window of the report.
func (r *SessionReport) Count(kind string, window time.Duration) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, ev := range r.History {
		if ev.Kind == kind && r.Now.Sub(ev.At) <= window {
			if ev.Count > 1 {
				n += ev.Count
			} else {
				n++
			}
		}
	}
	return n
}

// LastEvent returns the most recent event of kind, or nil.
func (r *SessionReport) LastEvent(kind string) *SessionEvent {
	if r == nil {
		return nil
	}
	for i := len(r.History) - 1; i >= 0; i-- {
		if r.History[i].Kind == kind {
			ev := r.History[i]
			return &ev
		}
	}
	return nil
}
