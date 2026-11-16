package relay

import (
	"net/http"
)

// Dispatcher routes a request to the relay server that owns its base domain.
type Dispatcher struct {
	servers []*Server
}

func NewDispatcher(servers []*Server) *Dispatcher {
	return &Dispatcher{servers: servers}
}

func (d *Dispatcher) Matches(r *http.Request) bool {
	if d == nil {
		return false
	}
	for _, s := range d.servers {
		if s.Matches(r) {
			return true
		}
	}
	return false
}

func (d *Dispatcher) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if d == nil {
		http.NotFound(w, r)
		return
	}
	for _, s := range d.servers {
		if s.Matches(r) {
			s.ServeHTTP(w, r)
			return
		}
	}
	http.NotFound(w, r)
}
