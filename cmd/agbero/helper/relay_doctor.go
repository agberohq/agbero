package helper

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/discovery"
	relayhub "github.com/agberohq/agbero/internal/hub/relay"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

// stageRelayURL is the doctor's stage name for endpoint resolution.
const stageRelayURL = "relay URL"

type doctorStatus string

const (
	doctorPass doctorStatus = "PASS"
	doctorWarn doctorStatus = "WARN"
	doctorFail doctorStatus = "FAIL"
	doctorSkip doctorStatus = "SKIP"
)

type doctorStage struct {
	Name    string
	Status  doctorStatus
	Detail  string
	Actions []string
}

type doctorReport struct {
	Agent  string
	Side   string
	Stages []doctorStage
}

func (d *doctorReport) add(name string, status doctorStatus, detail string, actions ...string) {
	d.Stages = append(d.Stages, doctorStage{Name: name, Status: status, Detail: detail, Actions: actions})
}

func (d *doctorReport) counts() (pass, warn, fail, skip int) {
	for _, st := range d.Stages {
		switch st.Status {
		case doctorPass:
			pass++
		case doctorWarn:
			warn++
		case doctorFail:
			fail++
		case doctorSkip:
			skip++
		}
	}
	return
}

func (d *doctorReport) failed() bool { _, _, fail, _ := d.counts(); return fail > 0 }

func (d *doctorReport) print(f *ui.Flow) {
	for _, st := range d.Stages {
		line := fmt.Sprintf("%-14s %-4s  %s", st.Name, st.Status, st.Detail)
		switch st.Status {
		case doctorFail:
			f.Error(line)
		case doctorWarn:
			f.Warn(line)
		default:
			f.Info(line)
		}
		for _, a := range st.Actions {
			f.Info("    next: " + a)
		}
	}
	pass, warn, fail, skip := d.counts()
	summary := fmt.Sprintf("%s: %d passed, %d failed, %d warnings, %d skipped", d.Agent, pass, fail, warn, skip)
	if fail > 0 {
		f.Error(summary)
	} else {
		f.Done("%s", summary)
	}
}

// agentSite is one agent block found in the local configuration.
type agentSite struct {
	HostName      string
	Host          *alaye.Host
	Agent         alaye.Agent
	Exposes       []alaye.Expose
	LocalURL      string
	LocalSNI      string
	LocalInsecure bool
}

func findAgentSites(hosts map[string]*alaye.Host, name string) []agentSite {
	seen := make(map[*alaye.Host]bool, len(hosts))
	var out []agentSite
	for _, h := range hosts {
		if h == nil || seen[h] {
			continue
		}
		seen[h] = true
		for _, a := range h.Agents {
			if !strings.EqualFold(a.Name, name) {
				continue
			}
			site := agentSite{Host: h, Agent: a, HostName: firstDomain(h)}
			for _, route := range h.Routes {
				for _, ex := range route.Exposes {
					if ex.Via == a.Name {
						site.Exposes = append(site.Exposes, ex)
					}
				}
			}
			site.LocalURL, site.LocalSNI, site.LocalInsecure = relayhub.ResolveLocal(h, a)
			out = append(out, site)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].HostName < out[j].HostName })
	return out
}

func firstDomain(h *alaye.Host) string {
	if h == nil || len(h.Domains) == 0 {
		return ""
	}
	return h.Domains[0]
}

// Doctor diagnoses one agent wherever it can be observed: from the local
// configuration when this host runs the agent, and from the live relay state
// when this host runs the relay. Both sides are checked when both are present.
func (r *Relay) Doctor(configPath, name string, opts ProbeOptions) bool {
	f := r.p.UI()
	opts = opts.normalize()
	name = strings.TrimSpace(name)
	global, err := LoadGlobal(configPath)
	if err != nil {
		f.Abort(def.ErrLoadConfig, err)
	}
	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(r.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		f.Abort(def.ErrLoadHosts, err)
	}

	if name == "" {
		f.Error("agent name is required: agbero relay doctor <agent>")
		servers, _ := fetchRelaySnapshot(global, opts.AdminToken)
		printKnownAgents(f, hosts, servers, nil)
		return false
	}
	sites := findAgentSites(hosts, name)
	servers, snapErr := fetchRelaySnapshot(global, opts.AdminToken)
	var server *relayhub.ServerSnapshot
	var liveAgent *relayhub.AgentSnapshot
	for i := range servers {
		for j := range servers[i].Agents {
			if strings.EqualFold(servers[i].Agents[j].ID, name) {
				server = &servers[i]
				liveAgent = &servers[i].Agents[j]
			}
		}
	}

	if len(sites) == 0 && liveAgent == nil {
		f.Error("agent " + name + " was not found on this host")
		printKnownAgents(f, hosts, servers, snapErr)
		return false
	}

	healthy := true
	for _, site := range sites {
		rep := &doctorReport{Agent: name, Side: "client side, host " + site.HostName}
		f.Infof(fmtDoctorHeader, name, rep.Side)
		r.doctorClient(f, rep, site, global, opts)
		rep.print(f)
		if rep.failed() {
			healthy = false
		}
	}
	if liveAgent != nil {
		rep := &doctorReport{Agent: name, Side: "server side, relay " + server.Domain}
		f.Infof(fmtDoctorHeader, name, rep.Side)
		r.doctorServer(f, rep, server, liveAgent, opts)
		rep.print(f)
		if rep.failed() {
			healthy = false
		}
	} else if snapErr != nil && runsRelay(hosts) {
		f.Info("server side not inspected: " + snapErr.Error())
		f.Info("  pass --admin-token (or set AGBERO_ADMIN_TOKEN) to read this relay's live state")
	}
	return healthy
}

// runsRelay reports whether this host's configuration defines a relay server.
// Only then does the local admin API hold relay state worth reading.
func runsRelay(hosts map[string]*alaye.Host) bool {
	for _, h := range hosts {
		if h != nil && len(h.Relays) > 0 {
			return true
		}
	}
	return false
}

func printKnownAgents(f *ui.Flow, hosts map[string]*alaye.Host, servers []relayhub.ServerSnapshot, snapErr error) {
	var names []string
	seen := map[string]bool{}
	for _, h := range hosts {
		for _, a := range h.Agents {
			if !seen[a.Name] {
				seen[a.Name] = true
				names = append(names, a.Name)
			}
		}
	}
	for _, s := range servers {
		for _, a := range s.Agents {
			if !seen[a.ID] {
				seen[a.ID] = true
				names = append(names, a.ID)
			}
		}
	}
	sort.Strings(names)
	switch {
	case len(names) > 0:
		f.Info("agents known on this host: " + strings.Join(names, ", "))
		f.Info("run: agbero relay doctor <agent>")
	case snapErr != nil:
		f.Info("no agents in the local configs and the relay state is unavailable: " + snapErr.Error())
		f.Info("run this on the agent host, or enable the relay admin API on loopback")
	default:
		f.Info("no agents are configured locally or connected to this relay")
	}
}

func (r *Relay) doctorClient(f *ui.Flow, rep *doctorReport, site agentSite, global *alaye.Global, opts ProbeOptions) {
	// configuration
	detail := fmt.Sprintf("%d expose(s), local %s", len(site.Exposes), site.LocalURL)
	if site.LocalSNI != "" {
		detail += ", sni " + site.LocalSNI
	}
	if len(site.Exposes) == 0 {
		rep.add(stageConfiguration, doctorFail, "agent has no expose blocks in any route", "add an expose block with via = \""+site.Agent.Name+"\"")
	} else {
		rep.add(stageConfiguration, doctorPass, detail)
	}

	// relay URL and enrollment secret
	relayURL, err := url.Parse(site.Agent.Relay)
	if err != nil || relayURL.Hostname() == "" {
		rep.add(stageRelayURL, doctorFail, "invalid relay URL: "+site.Agent.Relay)
		return
	}
	port := relayURL.Port()
	if port == "" {
		port = def.RelayDefaultPort
	}
	hostport := net.JoinHostPort(relayURL.Hostname(), port)
	rep.add(stageRelayURL, doctorPass, hostport)

	raw := strings.TrimSpace(string(site.Agent.Token))
	if raw == "" {
		raw = strings.TrimSpace(string(site.Agent.Enroll))
	}
	secret, secretErr := secretValue(raw, global)
	if secretErr != nil {
		rep.add(stageEnrollment, doctorFail, secretErr.Error(), "check the agent's enroll/token reference and Keeper")
	} else {
		rep.add(stageEnrollment, doctorPass, "enrollment secret resolves")
	}

	// DNS
	addrs, dnsErr := net.LookupHost(relayURL.Hostname())
	if dnsErr != nil {
		rep.add(stageDNS, doctorFail, dnsErr.Error(), "check the relay hostname resolves on this host")
	} else {
		rep.add(stageDNS, doctorPass, strings.Join(addrs, ", "))
	}

	// TLS
	if info, err := probeTLS(hostport, relayURL.Hostname(), site.Agent.Insecure, opts.Timeout); err != nil {
		rep.add(stageTLS, doctorFail, err.Error(), "check the certificate, SNI and that port "+port+" is open")
	} else {
		left := time.Until(info.NotAfter)
		switch {
		case left < 0:
			rep.add(stageTLS, doctorFail, "certificate expired "+info.NotAfter.Format(time.RFC3339), "renew the relay certificate")
		case left < def.RelayCertWarnBefore:
			rep.add(stageTLS, doctorWarn, fmt.Sprintf("certificate for %s expires in %s", info.Subject, humanLeft(left)))
		default:
			rep.add(stageTLS, doctorPass, fmt.Sprintf("%s, issuer %s, expires in %s", info.Subject, info.Issuer, humanLeft(left)))
		}
	}

	// authentication; an authenticated check also returns the relay's view of
	// the agent's session.
	authOK := false
	var session *relayhub.SessionReport
	if secret != "" {
		ctx, cancel := context.WithTimeout(context.Background(), def.RelayAuthTimeout)
		report, err := relayhub.ProbeSession(ctx, site.Agent.Relay, site.Agent.Name, secret, "", site.Agent.Insecure)
		cancel()
		if err != nil {
			rep.add(stageAuth, doctorFail, err.Error(), "verify the enrollment token on the relay and that the agent is not revoked")
		} else {
			authOK = true
			session = report
			rep.add(stageAuth, doctorPass, "relay accepted the credential")
		}
	} else {
		rep.add(stageAuth, doctorSkip, "no enrollment secret available")
	}

	// processes and session: is exactly one agent running, and does the relay
	// hold one stable session for it?
	doctorProcesses(rep, site.Agent.Name, session)
	if authOK {
		var pathIDs []string
		for _, ex := range site.Exposes {
			if ex.Path {
				pathIDs = append(pathIDs, ex.ID)
			}
		}
		doctorSession(rep, site.Agent.Name, pathIDs, addrs, session)
	}

	// local target
	localHost := site.LocalSNI
	if localHost == "" && len(site.Host.Domains) > 0 {
		localHost = site.Host.Domains[0]
	}
	base, err := url.Parse(site.LocalURL)
	var local httpProbe
	if err != nil || base.Host == "" {
		rep.add(stageLocalTarget, doctorFail, "invalid local target: "+site.LocalURL)
	} else {
		local = probeOnce(site.LocalURL, localHost, localHost, site.LocalInsecure, opts.Timeout)
		if local.reached() {
			rep.add(stageLocalTarget, doctorPass, local.brief()+" "+site.LocalURL)
		} else {
			rep.add(stageLocalTarget, doctorFail, local.summary(), "start the local agbero and confirm "+site.LocalURL+" answers")
		}
	}

	// public path for each path exposure
	for _, ex := range site.Exposes {
		if !ex.Path {
			continue
		}
		publicPath := "/" + ex.ID
		publicURL, err := publicExposeURL(site.Agent.Relay, publicPath)
		if err != nil {
			rep.add(stagePublic+" "+publicPath, doctorFail, err.Error())
			continue
		}
		if !authOK {
			rep.add(stagePublic+" "+publicPath, doctorSkip, "skipped: relay authentication failed")
			continue
		}
		var l httpProbe
		if base != nil && base.Host != "" {
			l = probeOnce(localProbeURL(base, ex, publicPath), localHost, localHost, site.LocalInsecure, opts.Timeout)
		}
		// The relay's clock at the authenticated check marks the start of this
		// probe; comparing against the local clock would break under skew.
		var probeStart time.Time
		if session != nil {
			probeStart = session.Now
		}
		pub, history := probeWithRetry(f, stagePublic, publicURL, "", false, opts)
		v := diagnoseClient(l, pub, history, ex.ID, site.LocalURL)
		if session != nil && (!v.OK || v.Flap) {
			// The relay recorded the exact error behind each 502 it served for
			// this probe; that is the cause, not a guess.
			for _, ev := range relayErrorsSince(site.Agent.Relay, site.Agent.Name, secret, site.Agent.Insecure, probeStart) {
				n := ev.Count
				if n == 0 {
					n = 1
				}
				v.Actions = append([]string{fmt.Sprintf("relay error for this probe (%dx): %s", n, ev.Reason)},
					append(explainProxyError(ev.Reason), v.Actions...)...)
			}
		}
		switch {
		case v.OK && !v.Flap:
			rep.add(stagePublic+" "+publicPath, doctorPass, pub.brief()+", payload matched")
		case v.Flap:
			rep.add(stagePublic+" "+publicPath, doctorFail,
				fmt.Sprintf("flapped: %s in %s — the path is not stable", attemptStatuses(history), pub.Took.Round(time.Millisecond)),
				v.Actions...)
		default:
			rep.add(stagePublic+" "+publicPath, doctorFail, v.Summary, v.Actions...)
		}
	}

	// raw TCP targets are dialed locally; UDP cannot be verified without a
	// protocol exchange, so it is reported as skipped.
	for _, ex := range site.Exposes {
		if ex.TCP != nil && ex.TCP.Local != "" {
			conn, err := net.DialTimeout(def.TCP, ex.TCP.Local, opts.Timeout)
			if err != nil {
				rep.add(fmt.Sprintf(fmtTCPPort, ex.TCP.PublicPort), doctorFail,
					fmt.Sprintf("local target %s: %v", ex.TCP.Local, err),
					"start the local service and check the expose's tcp.local")
				continue
			}
			_ = conn.Close()
			rep.add(fmt.Sprintf(fmtTCPPort, ex.TCP.PublicPort), doctorPass, "local target "+ex.TCP.Local+" accepts connections")
		}
		if ex.UDP != nil {
			rep.add(fmt.Sprintf(fmtUDPPort, ex.UDP.PublicPort), doctorSkip, "UDP has no handshake to probe")
		}
	}

	// server side on this host, if it also runs the relay for this agent
	if servers, err := fetchRelaySnapshot(global, opts.AdminToken); err == nil {
		if live := findRelaySnapshot(servers, relayURL.Hostname()); live != nil {
			for i := range live.Agents {
				if strings.EqualFold(live.Agents[i].ID, site.Agent.Name) {
					f.Infof("%s — server side, relay %s", site.Agent.Name, live.Domain)
					r.doctorServer(f, rep, live, &live.Agents[i], opts)
					break
				}
			}
		}
	}
}

func (r *Relay) doctorServer(f *ui.Flow, rep *doctorReport, server *relayhub.ServerSnapshot, agent *relayhub.AgentSnapshot, opts ProbeOptions) {
	detail := fmt.Sprintf("connected %s, streams %d", age(agent.ConnectedAt), agent.Streams)
	if agent.Reconnects > 0 {
		rep.add(stageSession, doctorWarn, fmt.Sprintf("%s, reconnects %d", detail, agent.Reconnects),
			"a rising reconnect count means the control connection is being replaced; check the network path and the relay/agent versions")
	} else {
		rep.add(stageSession, doctorPass, detail+", no reconnects")
	}
	if agent.LastError != "" {
		rep.add("last error", doctorWarn, agent.LastError+" ("+age(agent.LastErrorAt)+")")
	}

	type routeTarget struct {
		rt  relayhub.RouteSnapshot
		url string
	}
	var routes []routeTarget
	for _, rt := range server.Routes {
		if rt.Agent != agent.ID || strings.Contains(rt.Key, ":") {
			continue
		}
		target := "https://" + server.Domain + rt.Key
		if rt.Subdomain {
			target = "https://" + rt.Domain
		}
		routes = append(routes, routeTarget{rt: rt, url: target})
	}
	hasPublic := false
	for _, ex := range agent.Exposures {
		if ex.Path || ex.Subdomain {
			hasPublic = true
		}
	}
	if len(routes) == 0 && hasPublic {
		rep.add("routes", doctorFail, "no live route is registered for this agent",
			"check the agent's registration and the relay log for rejected registrations")
	}
	for _, entry := range routes {
		rt := entry.rt
		if !rt.Live {
			rep.add("route "+rt.Key, doctorFail, "route is bound to a closed session",
				"upgrade the relay so routes follow the live session, or restart the agent")
			continue
		}
		target, err := url.Parse(entry.url)
		if err != nil {
			rep.add("route "+rt.Key, doctorFail, err.Error())
			continue
		}
		pub, history := probeWithRetry(f, stagePublic, target.String(), "", false, opts)
		if pub.ok() && !flapped(history) {
			rep.add("route "+rt.Key, doctorPass, fmt.Sprintf("live, %s", pub.brief()))
			continue
		}
		v := diagnoseServer(pub, history, server, target)
		rep.add("route "+rt.Key, doctorFail, v.Summary, v.Actions...)
	}

	// listeners for raw TCP/UDP exposures
	exposed := map[int]bool{}
	for _, p := range server.TCPPorts {
		exposed[p] = true
	}
	for _, ex := range agent.Exposures {
		if ex.TCPPort > 0 {
			status := doctorPass
			detail := fmt.Sprintf("tcp :%d listening", ex.TCPPort)
			if !exposed[ex.TCPPort] {
				status = doctorFail
				detail = fmt.Sprintf("tcp :%d is not listening", ex.TCPPort)
			}
			rep.add(fmt.Sprintf(fmtTCPPort, ex.TCPPort), status, detail,
				"check allow_tcp_ports and whether the port is already in use")
		}
		if ex.UDPPort > 0 {
			rep.add(fmt.Sprintf(fmtUDPPort, ex.UDPPort), doctorSkip, "udp listener is reported by the relay but not probed")
		}
	}
}

func humanLeft(d time.Duration) string {
	switch {
	case d < 0:
		return "expired"
	case d > 48*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d > time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return d.Round(time.Minute).String()
	}
}

type tlsProbeInfo struct {
	Version  uint16
	Subject  string
	Issuer   string
	NotAfter time.Time
	Names    string
}

func probeTLS(hostport, sni string, insecure bool, timeout time.Duration) (tlsProbeInfo, error) {
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, def.TCP, hostport, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: insecure,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return tlsProbeInfo{}, err
	}
	defer func() { _ = conn.Close() }()
	st := conn.ConnectionState()
	info := tlsProbeInfo{Version: st.Version}
	if len(st.PeerCertificates) > 0 {
		c := st.PeerCertificates[0]
		info.Subject = c.Subject.CommonName
		info.Issuer = c.Issuer.CommonName
		info.NotAfter = c.NotAfter
		info.Names = strings.Join(c.DNSNames, ", ")
	}
	return info, nil
}

// secretValue resolves an enrollment reference without printing, so the doctor
// can report it as a stage rather than a stray log line.
func secretValue(raw string, global *alaye.Global) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("no enrollment token or credential is configured")
	}
	if !strings.HasPrefix(raw, def.SecretScheme) {
		return raw, nil
	}
	client, err := secrets.NewControlClient(global.Storage.DataDir)
	if err != nil {
		return "", fmt.Errorf("Keeper reference %s is not reachable: %w", raw, err)
	}
	key := strings.TrimPrefix(raw, def.SecretScheme)
	value, err := client.Get(key)
	if err != nil || value == "" {
		return "", fmt.Errorf("Keeper key %s is missing", key)
	}
	return value, nil
}
