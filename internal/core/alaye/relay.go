package alaye

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/agberohq/agbero/internal/core/expect"
	"github.com/olekukonko/errors"
)

// Relay is the remote side of an Agbero-to-Agbero reverse tunnel. Agents dial
// it, enroll, authenticate, and publish paths, subdomains, and ports.
type Relay struct {
	Name   string      `hcl:"name,label" json:"name"`
	Listen RelayListen `hcl:"listen,block" json:"listen"`
	Auth   RelayAuth   `hcl:"auth,block" json:"auth"`
	Policy RelayPolicy `hcl:"policy,block" json:"policy"`
}

type RelayListen struct {
	Address  string `hcl:"address,attr" json:"address"`
	Port     int    `hcl:"port,attr" json:"port"`
	Protocol string `hcl:"protocol,attr" json:"protocol"`
}

type RelayAuth struct {
	Method string       `hcl:"method,attr" json:"method"`
	Token  expect.Value `hcl:"token,attr" json:"token,omitempty"`
}

type RelayPolicy struct {
	Namespace      string   `hcl:"namespace,attr" json:"namespace,omitempty"`
	AllowHTTP      bool     `hcl:"allow_http,attr" json:"allow_http"`
	AllowSubdomain bool     `hcl:"allow_subdomain,attr" json:"allow_subdomain"`
	AllowTCPPorts  []string `hcl:"allow_tcp_ports,attr" json:"allow_tcp_ports,omitempty"`
	AllowUDPPorts  []string `hcl:"allow_udp_ports,attr" json:"allow_udp_ports,omitempty"`
	MaxAgents      int      `hcl:"max_agents,attr" json:"max_agents"`
	MaxStreams     int      `hcl:"max_streams,attr" json:"max_streams"`
}

// Agent is the local side of a reverse tunnel. It makes outbound connections
// only, so the local Agbero never needs a public listener or certificate.
type Agent struct {
	Name          string       `hcl:"name,label" json:"name"`
	Relay         string       `hcl:"relay,attr" json:"relay"`
	Enroll        expect.Value `hcl:"enroll,attr" json:"enroll,omitempty"`
	Token         expect.Value `hcl:"token,attr" json:"token,omitempty"`
	Local         string       `hcl:"local,attr" json:"local"`
	LocalSNI      string       `hcl:"local_sni,attr" json:"local_sni,omitempty"`
	LocalInsecure bool         `hcl:"local_insecure,attr" json:"local_insecure"`
	Insecure      bool         `hcl:"insecure,attr" json:"insecure"`
	Reconnect     bool         `hcl:"reconnect,attr" json:"reconnect"`
	// Pool is retained for configuration compatibility. The mux transport
	// opens work streams on demand, so it is ignored.
	Pool int `hcl:"pool,attr" json:"pool"`
}

// Expose publishes one route to a connected agent. The ID is a single DNS
// label; the remote domain is fixed by the relay, never supplied by the agent.
type Expose struct {
	ID        string       `hcl:"id,label" json:"id"`
	Via       string       `hcl:"via,attr" json:"via"`
	Path      bool         `hcl:"path,attr" json:"path"`
	Subdomain bool         `hcl:"subdomain,attr" json:"subdomain"`
	LocalPath string       `hcl:"local_path,attr" json:"local_path,omitempty"`
	LocalHost string       `hcl:"local_host,attr" json:"local_host,omitempty"`
	TCP       *RelayTarget `hcl:"tcp,block" json:"tcp,omitempty"`
	UDP       *RelayTarget `hcl:"udp,block" json:"udp,omitempty"`
}

type RelayTarget struct {
	PublicPort int    `hcl:"public_port,attr" json:"public_port"`
	Local      string `hcl:"local,attr" json:"local"`
}

var relayIDRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

var relayReservedIDs = map[string]bool{
	"admin": true, "api": true, "www": true, "mail": true,
	"relay": true, "_agbero": true, "well-known": true,
}

func (r *Relay) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return errors.New("relay: name is required")
	}
	if err := r.Listen.Validate(); err != nil {
		return errors.Newf("relay %q: %w", r.Name, err)
	}
	if err := r.Auth.Validate(); err != nil {
		return errors.Newf("relay %q: %w", r.Name, err)
	}
	if err := r.Policy.Validate(); err != nil {
		return errors.Newf("relay %q: %w", r.Name, err)
	}
	return nil
}

func (l *RelayListen) Validate() error {
	l.Address = strings.TrimSpace(l.Address)
	l.Protocol = strings.ToLower(strings.TrimSpace(l.Protocol))
	if l.Address == "" {
		return errors.New("listen.address is required")
	}
	if l.Port < 1 || l.Port > 65535 {
		return errors.Newf("listen.port %d is invalid", l.Port)
	}
	switch l.Protocol {
	case "", "https":
		l.Protocol = "https"
	default:
		return errors.Newf("listen.protocol must be https, got %q", l.Protocol)
	}
	return nil
}

func (a *RelayAuth) Validate() error {
	a.Method = strings.ToLower(strings.TrimSpace(a.Method))
	switch a.Method {
	case "", "enrollment":
		a.Method = "enrollment"
	default:
		return errors.Newf("auth.method must be enrollment, got %q", a.Method)
	}
	if strings.TrimSpace(string(a.Token)) == "" {
		return errors.New("auth.token is required")
	}
	return nil
}

func (p *RelayPolicy) Validate() error {
	p.Namespace = strings.TrimSpace(p.Namespace)
	if p.Namespace != "" {
		return errors.New("policy.namespace is not implemented; use an empty value for global IDs")
	}
	if !p.AllowHTTP && !p.AllowSubdomain && len(p.AllowTCPPorts) == 0 && len(p.AllowUDPPorts) == 0 {
		return errors.New("policy: enable allow_http, allow_subdomain, allow_tcp_ports, or allow_udp_ports")
	}
	for _, raw := range p.AllowTCPPorts {
		if _, err := parsePortRange(raw); err != nil {
			return errors.Newf("policy.allow_tcp_ports: %w", err)
		}
	}
	for _, raw := range p.AllowUDPPorts {
		if _, err := parsePortRange(raw); err != nil {
			return errors.Newf("policy.allow_udp_ports: %w", err)
		}
	}
	if p.MaxAgents < 0 {
		return errors.New("policy.max_agents cannot be negative")
	}
	if p.MaxStreams < 0 {
		return errors.New("policy.max_streams cannot be negative")
	}
	if p.MaxAgents == 0 {
		p.MaxAgents = 100
	}
	if p.MaxStreams == 0 {
		p.MaxStreams = 1000
	}
	return nil
}

func parsePortRange(raw string) ([2]int, error) {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, "-")
	if len(parts) > 2 {
		return [2]int{}, errors.Newf("invalid port range %q", raw)
	}
	start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || start < 1 || start > 65535 {
		return [2]int{}, errors.Newf("invalid port range %q", raw)
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || end < start || end > 65535 {
			return [2]int{}, errors.Newf("invalid port range %q", raw)
		}
	}
	return [2]int{start, end}, nil
}

func (a *Agent) Validate() error {
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" {
		return errors.New("agent: name is required")
	}
	if !relayIDRe.MatchString(a.Name) {
		return errors.Newf("agent %q: name must be a single lowercase DNS label", a.Name)
	}
	u, err := url.Parse(strings.TrimSpace(a.Relay))
	if err != nil || u.Host == "" {
		return errors.Newf("agent %q: relay must be a URL", a.Name)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	default:
		return errors.Newf("agent %q: relay scheme must be https", a.Name)
	}
	if strings.TrimSpace(string(a.Enroll)) == "" && strings.TrimSpace(string(a.Token)) == "" {
		return errors.Newf("agent %q: enroll or token is required", a.Name)
	}
	if strings.TrimSpace(a.Local) != "" {
		local, err := url.Parse(strings.TrimSpace(a.Local))
		if err != nil || local.Host == "" {
			return errors.Newf("agent %q: local must be an http URL", a.Name)
		}
		switch strings.ToLower(local.Scheme) {
		case "http", "https":
		default:
			return errors.Newf("agent %q: local scheme must be http or https", a.Name)
		}
		a.Local = local.String()
	}
	if strings.ContainsAny(a.LocalSNI, "/\\") {
		return errors.Newf("agent %q: local_sni is invalid", a.Name)
	}
	if a.Pool < 0 {
		return errors.Newf("agent %q: pool cannot be negative", a.Name)
	}
	return nil
}

func (e *Expose) Validate() error {
	e.ID = strings.TrimSpace(e.ID)
	if !relayIDRe.MatchString(e.ID) {
		return errors.Newf("expose %q: id must be a single lowercase DNS label", e.ID)
	}
	if relayReservedIDs[e.ID] {
		return errors.Newf("expose %q: id is reserved", e.ID)
	}
	e.Via = strings.TrimSpace(e.Via)
	if e.Via == "" {
		return errors.Newf("expose %q: via is required", e.ID)
	}
	if !e.Path && !e.Subdomain && e.TCP == nil && e.UDP == nil {
		return errors.Newf("expose %q: enable path, subdomain, tcp, or udp", e.ID)
	}
	if e.LocalPath != "" && !strings.HasPrefix(e.LocalPath, "/") {
		return errors.Newf("expose %q: local_path must start with '/'", e.ID)
	}
	if e.LocalHost != "" && strings.ContainsAny(e.LocalHost, "/\\") {
		return errors.Newf("expose %q: local_host is invalid", e.ID)
	}
	if e.TCP != nil {
		if err := e.TCP.Validate(); err != nil {
			return errors.Newf("expose %q: tcp: %w", e.ID, err)
		}
	}
	if e.UDP != nil {
		if err := e.UDP.Validate(); err != nil {
			return errors.Newf("expose %q: udp: %w", e.ID, err)
		}
	}
	return nil
}

func (t *RelayTarget) Validate() error {
	if t.PublicPort < 1 || t.PublicPort > 65535 {
		return errors.Newf("public_port %d is invalid", t.PublicPort)
	}
	host, port, err := net.SplitHostPort(strings.TrimSpace(t.Local))
	if err != nil || host == "" || port == "" {
		return errors.Newf("local %q must be host:port", t.Local)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return errors.Newf("local %q has an invalid port", t.Local)
	}
	return nil
}

func (r Relay) IsZero() bool { return r.Name == "" }
func (a Agent) IsZero() bool { return a.Name == "" && a.Relay == "" && a.Enroll == "" && a.Token == "" }
func (e Expose) IsZero() bool {
	return e.ID == "" && e.Via == "" && !e.Path && !e.Subdomain && e.TCP == nil && e.UDP == nil
}
