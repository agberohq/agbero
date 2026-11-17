package helper

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/alaye"
	"github.com/agberohq/agbero/internal/core/def"
	"github.com/agberohq/agbero/internal/hub/discovery"
	relayhub "github.com/agberohq/agbero/internal/hub/relay"
	"github.com/agberohq/agbero/internal/hub/secrets"
	"github.com/agberohq/agbero/internal/pkg/ui"
)

// Labels shared by the check and doctor reports.
const (
	relayAppOrTunnel = "relay or local application"
	stagePublic      = "public"
	stageSession     = "session"
	fmtServed        = "%s served HTTP %d in %s"
	fmtBytes         = " (%d B)"
	fmtDoctorHeader  = "%s — %s"
	stageLocalTarget = "local target"
	stageEnrollment  = "enrollment"
	stageAuth        = "authentication"
	stateLive        = "live"
	stateUnknown     = "unknown"

	fmtTCPPort          = "tcp %d"
	fmtUDPPort          = "udp %d"
	stageConfiguration  = "configuration"
	stageDNS            = "dns"
	stageProcesses      = "processes"
	stageTLS            = "tls"
	wherePublicEndpoint = "public endpoint (DNS, TLS or reachability)"
	whereStaleRoute     = "stale route (reconnect race)"
	actionRestartAgent  = "restarting the agent rebuilds the route"
	actionRelayLog      = "relay access log for the same path and x-request-id"
)

// ProbeOptions controls how the public leg is probed.
type ProbeOptions struct {
	Attempts int
	Wait     time.Duration
	Timeout  time.Duration
	// AdminToken authenticates the read of the relay's live state when the
	// admin API is protected (the admin uses bearer tokens).
	AdminToken string
}

func (o ProbeOptions) normalize() ProbeOptions {
	if o.Attempts <= 0 {
		o.Attempts = def.RelayCheckAttempts
	}
	if o.Wait <= 0 {
		o.Wait = def.RelayCheckWait
	}
	if o.Timeout <= 0 {
		o.Timeout = def.RelayCheckTimeout
	}
	return o
}

type Relay struct {
	p *Helper
}

// Check diagnoses relay client or server configuration end to end. It returns
// false when any stage failed, so the command can exit non-zero in automation.
func (r *Relay) Check(configPath, target string, server, client bool, opts ProbeOptions) bool {
	f := r.p.UI()
	opts = opts.normalize()
	if strings.TrimSpace(target) == "" {
		f.Abort("relay target is required")
	}
	if server == client {
		f.Abort("choose exactly one of --server or --client")
	}
	global, err := LoadGlobal(configPath)
	if err != nil {
		f.Abort(def.ErrLoadConfig, err)
	}
	hm := discovery.NewHost(global.Storage.HostsDir, discovery.WithLogger(r.p.Logger))
	hosts, err := hm.LoadAll()
	if err != nil {
		f.Abort(def.ErrLoadHosts, err)
	}

	var public *url.URL
	if strings.Contains(target, def.ProtocolSeparator) {
		public, err = url.Parse(target)
		if err != nil || public.Host == "" {
			f.Abort("invalid target URL")
		}
	} else {
		public = &url.URL{Scheme: def.Https, Host: target, Path: "/"}
	}
	host := public.Hostname()
	if public.Path == "" {
		public.Path = "/"
	}
	if client {
		return r.checkClient(f, hosts, host, public.Path, global, opts)
	}
	return r.checkServer(f, hosts, public, global, opts)
}

func (r *Relay) checkClient(f *ui.Flow, hosts map[string]*alaye.Host, host, path string, global *alaye.Global, opts ProbeOptions) bool {
	f.Infof("Client check: %s%s", host, path)
	hcfg := findHost(hosts, host)
	exposeID := strings.Trim(path, "/")
	if hcfg == nil && exposeID != "" {
		hcfg = findHostByExpose(hosts, exposeID)
	}
	if hcfg == nil {
		f.Error("no local host config for " + host)
		f.Info("hosts are loaded from the configured hosts.d directory")
		return false
	}

	healthy := true
	agents := make(map[string]alaye.Agent, len(hcfg.Agents))
	for _, a := range hcfg.Agents {
		agents[a.Name] = a
		f.Done("%s", "agent configured: "+a.Name)
		relayURL, err := url.Parse(a.Relay)
		if err != nil || relayURL.Host == "" {
			f.Error("agent relay URL is invalid")
			healthy = false
		} else {
			f.Info("relay endpoint: " + relayURL.Host)
		}
		enrollRaw := strings.TrimSpace(string(a.Enroll))
		tokenRaw := strings.TrimSpace(string(a.Token))
		enrollValue := ""
		ok := false
		if tokenRaw != "" {
			enrollValue = tokenRaw
			ok = true
		} else if enrollRaw != "" {
			enrollValue, ok = resolveSecret(r, f, "agent enrollment", enrollRaw, global)
		} else {
			f.Error("agent has no enrollment token or credential")
			healthy = false
		}
		if ok {
			ctx, cancel := context.WithTimeout(context.Background(), def.RelayAuthTimeout)
			err := relayhub.ProbeAuth(ctx, a.Relay, a.Name, enrollValue, "", a.Insecure)
			cancel()
			if err != nil {
				f.Error("remote authentication rejected: " + err.Error())
				healthy = false
			} else {
				f.Done("remote authentication accepted")
			}
		}
	}

	found := false
	for _, route := range hcfg.Routes {
		for _, ex := range route.Exposes {
			if exposeID != "" && ex.ID != exposeID {
				continue
			}
			found = true
			if ex.Path {
				f.Done("%s", "path exposure: /"+ex.ID)
			}
			if ex.Subdomain {
				f.Done("%s", "subdomain exposure: "+ex.ID+"."+host)
			}
			agent, ok := agents[ex.Via]
			if !ok {
				f.Error("expose " + ex.ID + " references unknown agent " + ex.Via)
				healthy = false
				continue
			}
			localHost := ex.LocalHost
			localURL, resolvedSNI, localInsecure := relayhub.ResolveLocal(hcfg, agent)
			if localHost == "" {
				localHost = resolvedSNI
			}
			if localHost == "" {
				f.Warn("no local_host set; the local route may not match the public Host")
			}
			target, err := url.Parse(localURL)
			if err != nil || target.Host == "" {
				f.Error("agent local target is invalid")
				healthy = false
				continue
			}
			if !ex.Path {
				continue
			}

			// Local control probe: the same path the relay would rewrite to,
			// so a public failure can be attributed to the relay or the target.
			publicPath := "/" + ex.ID
			if strings.HasPrefix(path, publicPath) {
				publicPath = path
			}
			localTarget := localProbeURL(target, ex, publicPath)
			local := probeOnce(localTarget, localHost, localHost, localInsecure, opts.Timeout)
			if local.reached() {
				f.Done("%s", fmt.Sprintf("local %s target responds: %s", target.Scheme, local.describe()))
			} else {
				f.Error("local " + target.Scheme + " target failed: " + local.summary())
				healthy = false
			}

			publicURL, err := publicExposeURL(agent.Relay, publicPath)
			if err != nil {
				f.Error("cannot derive the public URL: " + err.Error())
				healthy = false
				continue
			}
			public, history := probeWithRetry(f, stagePublic, publicURL, "", false, opts)
			v := diagnoseClient(local, public, history, ex.ID, localTarget)
			v.print(f)
			if !v.OK || v.Flap {
				healthy = false
			}
		}
	}
	if !found {
		f.Error("no expose matches " + path)
		for _, route := range hcfg.Routes {
			for _, ex := range route.Exposes {
				f.Info("available expose: /" + ex.ID)
			}
		}
		return false
	}
	return healthy
}

func (r *Relay) checkServer(f *ui.Flow, hosts map[string]*alaye.Host, public *url.URL, global *alaye.Global, opts ProbeOptions) bool {
	f.Infof("Server check: %s", public.String())
	hcfg := findHost(hosts, public.Hostname())
	if hcfg == nil {
		f.Error("no relay host config for " + public.Hostname())
		return false
	}
	if len(hcfg.Relays) == 0 {
		f.Error("host has no relay block")
		return false
	}
	healthy := true
	for _, relay := range hcfg.Relays {
		f.Done("%s", "relay configured: "+relay.Name)
		if relay.Auth.Method == def.AuthMethodEnrollment {
			if checkSecret(r, f, "relay enrollment", strings.TrimSpace(string(relay.Auth.Token)), global) {
				f.Done("relay enrollment token resolves")
			} else {
				healthy = false
			}
		}
		f.Info(fmt.Sprintf("listener: %s:%d", relay.Listen.Address, relay.Listen.Port))
	}

	// The check runs on the relay host, so it can read the live route table and
	// session state instead of guessing from the public status alone.
	var live *relayhub.ServerSnapshot
	if servers, err := fetchRelaySnapshot(global, opts.AdminToken); err != nil {
		f.Warn("live relay state unavailable: " + err.Error())
		f.Warn("start the relay's admin API on loopback to make this check conclusive")
	} else {
		live = findRelaySnapshot(servers, public.Hostname())
		printRelayState(f, live)
	}

	probe, history := probeWithRetry(f, stagePublic, public.String(), "", false, opts)
	v := diagnoseServer(probe, history, live, public)
	v.print(f)
	if !v.OK || v.Flap {
		healthy = false
	}
	return healthy
}

// localProbeURL mirrors the relay's rewrite: strip the expose prefix, then join
// the remainder onto the expose's local path.
func localProbeURL(base *url.URL, ex alaye.Expose, publicPath string) string {
	u := *base
	suffix := strings.TrimPrefix(publicPath, "/"+ex.ID)
	localPath := ex.LocalPath
	if localPath == "" {
		localPath = "/"
	}
	u.Path = joinLocalPath(localPath, suffix)
	u.RawQuery = ""
	return u.String()
}

func joinLocalPath(base, suffix string) string {
	if base == "" {
		base = "/"
	}
	if suffix == "" {
		suffix = "/"
	}
	return strings.TrimRight(base, "/") + "/" + strings.TrimLeft(suffix, "/")
}

func publicExposeURL(relayURL, path string) (string, error) {
	u, err := url.Parse(relayURL)
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("invalid relay URL")
	}
	return def.Https + def.ProtocolSeparator + u.Hostname() + path, nil
}

// httpProbe is one HTTP request made by the check.
type httpProbe struct {
	URL    string
	Status int
	Header http.Header
	Body   []byte
	Took   time.Duration
	Err    error
}

func (p httpProbe) ok() bool { return p.Err == nil && p.Status >= 200 && p.Status < 300 }

// reached reports that the request got an answer from an application, which is
// distinct from a relay-level 404 (no route) and from transport failures.
func (p httpProbe) reached() bool {
	return p.Err == nil && p.Status >= 200 && p.Status < 500 && p.Status != http.StatusNotFound
}

func (p httpProbe) requestID() string {
	if p.Header == nil {
		return ""
	}
	return p.Header.Get("X-Request-Id")
}

func (p httpProbe) bodyLine() string {
	s := strings.Join(strings.Fields(string(p.Body)), " ")
	if len(s) > 120 {
		s = s[:120] + "…"
	}
	return s
}

func (p httpProbe) summary() string {
	if p.Err != nil {
		return "transport error: " + p.Err.Error()
	}
	s := fmt.Sprintf("HTTP %d", p.Status)
	if b := p.bodyLine(); b != "" {
		s += " " + strconv.Quote(b)
	}
	return s + " in " + p.Took.Round(time.Millisecond).String()
}

func (p httpProbe) describe() string {
	s := p.summary()
	if len(p.Body) > 0 {
		s += fmt.Sprintf(fmtBytes, len(p.Body))
	}
	return s
}

// brief is the compact form used by the doctor, without the body text.
func (p httpProbe) brief() string {
	if p.Err != nil {
		return "transport error: " + p.Err.Error()
	}
	s := fmt.Sprintf("HTTP %d in %s", p.Status, p.Took.Round(time.Millisecond))
	if len(p.Body) > 0 {
		s += fmt.Sprintf(fmtBytes, len(p.Body))
	}
	return s
}

func probeOnce(raw, host, sni string, insecure bool, timeout time.Duration) httpProbe {
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return httpProbe{URL: raw, Err: err}
	}
	if host != "" {
		req.Host = host
	}
	req.Header.Set("User-Agent", "agbero-relay-check/1")
	req.Header.Set("Cache-Control", "no-cache")
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig: &tls.Config{
				ServerName:         sni,
				InsecureSkipVerify: insecure,
				MinVersion:         tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return httpProbe{URL: raw, Took: time.Since(start), Err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, def.RelayCheckBodyBytes))
	return httpProbe{URL: raw, Status: resp.StatusCode, Header: resp.Header.Clone(), Body: body, Took: time.Since(start)}
}

func retryable(p httpProbe) bool {
	if p.Err != nil {
		return true
	}
	switch p.Status {
	case http.StatusNotFound, http.StatusTooManyRequests,
		http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

type probeAttempt struct {
	N     int
	Probe httpProbe
	Wait  time.Duration
}

// probeWithRetry retries transient outcomes with exponential backoff and keeps
// the attempt history. A path that fails and then succeeds is flapping, which a
// single request would silently report as either healthy or dead.
func probeWithRetry(f *ui.Flow, label, raw, host string, insecure bool, opts ProbeOptions) (httpProbe, []probeAttempt) {
	var history []probeAttempt
	wait := opts.Wait
	for n := 1; n <= opts.Attempts; n++ {
		p := probeOnce(raw, host, "", insecure, opts.Timeout)
		history = append(history, probeAttempt{N: n, Probe: p})
		if p.ok() || !retryable(p) || n == opts.Attempts {
			break
		}
		f.Infof("%s attempt %d/%d: %s — retrying in %s", label, n, opts.Attempts, p.summary(), wait)
		time.Sleep(wait)
		history[len(history)-1].Wait = wait
		wait *= 2
		if wait > def.RelayCheckMaxWait {
			wait = def.RelayCheckMaxWait
		}
	}
	return history[len(history)-1].Probe, history
}

func attemptHistory(history []probeAttempt) string {
	parts := make([]string, 0, len(history))
	for _, a := range history {
		parts = append(parts, fmt.Sprintf("#%d %s", a.N, a.Probe.summary()))
	}
	return strings.Join(parts, "; ")
}

// attemptStatuses renders the attempt chain, e.g. "502 → 502 → 200".
func attemptStatuses(history []probeAttempt) string {
	parts := make([]string, 0, len(history))
	for _, a := range history {
		if a.Probe.Err != nil {
			parts = append(parts, "error")
			continue
		}
		parts = append(parts, strconv.Itoa(a.Probe.Status))
	}
	return strings.Join(parts, " → ")
}

// attemptWindow is the wall time covered by the probe attempts, including the
// backoff waits, so a verdict can state how long it watched the path.
func attemptWindow(history []probeAttempt) time.Duration {
	var total time.Duration
	for _, a := range history {
		total += a.Probe.Took + a.Wait
	}
	return total
}

func attemptsNote(history []probeAttempt) string {
	if len(history) <= 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts over %s", len(history), attemptWindow(history).Round(100*time.Millisecond))
}

func flapped(history []probeAttempt) bool {
	if len(history) < 2 {
		return false
	}
	if !history[len(history)-1].Probe.ok() {
		return false
	}
	for _, a := range history[:len(history)-1] {
		if !a.Probe.ok() {
			return true
		}
	}
	return false
}

type verdict struct {
	OK      bool
	Flap    bool
	Summary string
	Where   string
	Detail  []string
	Actions []string
}

func (v verdict) print(f *ui.Flow) {
	if v.OK {
		f.Done("%s", v.Summary)
	} else {
		f.Error(v.Summary)
	}
	if v.Where != "" {
		f.Info("  where: " + v.Where)
	}
	for _, d := range v.Detail {
		f.Info("  " + d)
	}
	for _, a := range v.Actions {
		f.Info("  next: " + a)
	}
	if v.Flap {
		f.Warn("the path failed and then recovered — treat this as flapping, not a clean pass")
	}
}

func diagnoseClient(local, public httpProbe, history []probeAttempt, exposeID, localTarget string) verdict {
	v := verdict{Flap: flapped(history)}
	if len(history) > 1 {
		v.Detail = append(v.Detail, "attempts: "+attemptHistory(history))
	}
	v.Detail = append(v.Detail, "local control: "+local.describe()+" "+localTarget)
	if public.Err != nil {
		v.Summary = "public request failed: " + public.Err.Error()
		v.Where = wherePublicEndpoint
		v.Actions = []string{
			"resolve the relay hostname and confirm port 443 completes a TLS handshake",
			"from this host: curl -v " + public.URL,
		}
		return v
	}
	v.Detail = append(v.Detail, "public: "+public.summary())
	if id := public.requestID(); id != "" {
		v.Detail = append(v.Detail, "x-request-id: "+id)
	}

	switch {
	case public.ok():
		v.OK = true
		v.Summary = fmt.Sprintf(fmtServed, public.URL, public.Status, public.Took.Round(time.Millisecond))
		if local.reached() && len(local.Body) > 0 && len(public.Body) == len(local.Body) {
			v.Detail = append(v.Detail, fmt.Sprintf("payload verified end to end: %d bytes match the local target", len(public.Body)))
		} else if local.reached() && len(public.Body) > 0 {
			v.Detail = append(v.Detail, fmt.Sprintf("payload differs from the local target (local %d B, public %d B) — dynamic content or middleware, not a transport failure", len(local.Body), len(public.Body)))
		}
		if v.Flap {
			v.OK = false
			v.Summary = "public path flapped but recovered: " + public.summary()
			v.Where = "relay → agent tunnel (transient)"
			v.Actions = []string{
				"agent log on this host: a 'relay work stream failed' line at the attempt time means the agent closed the stream; no line means the request never reached the agent",
				"the session stage of this doctor (needs the relay redeployed with this build) shows reconnects, replacements and the relay's exact error",
				"the goal is a route that stays live, not one that answers after a retry",
			}
		}
	case public.Status == http.StatusNotFound:
		if local.reached() {
			v.Summary = "relay returned 404 although the local target serves the route"
			v.Where = "relay route table: no live route for /" + exposeID
			v.Actions = []string{
				"relay admin → Relay → Routes: is /" + exposeID + " listed, and is its route marked live?",
				"relay admin → Relay → Agents: is the agent connected, and is `reconnects` climbing?",
				"a route that is missing or bound to a dead session produces exactly this 404",
			}
		} else {
			v.Summary = "local route not found: the direct local probe also returned 404"
			v.Where = "local host/route configuration"
			v.Actions = []string{
				"check local_host and the route path on the local agbero",
				"curl -H 'Host: " + exposeID + "' " + localTarget,
			}
		}
	case public.Status == http.StatusBadGateway || public.Status == http.StatusServiceUnavailable || public.Status == http.StatusGatewayTimeout:
		if local.reached() {
			v.Summary = "relay matched the route but the tunnel failed: " + public.summary()
			v.Where = "relay → agent tunnel (closed or replaced session, or the agent closed the stream)"
			v.Actions = []string{
				"agbero relay doctor <agent>: reports the relay's session history and the exact error behind this 502",
				"agent log: 'relay work stream failed', 'relay control connection closed', 'relay connection failed'",
			}
		} else {
			v.Summary = "local target failed: " + public.summary()
			v.Where = "local target (the direct local probe failed too)"
			v.Actions = []string{"fix the local target first; the relay path cannot succeed while it fails"}
		}
	case public.Status >= 300 && public.Status < 400:
		v.Summary = fmt.Sprintf("public endpoint redirected to %s", public.Header.Get("Location"))
		v.Where = "redirect"
		v.Actions = []string{"check the local route's redirect settings, or use the redirect target as the check target"}
	default:
		v.Summary = "unexpected public response: " + public.summary()
		v.Where = relayAppOrTunnel
		v.Actions = []string{"compare with the local control probe above", actionRelayLog}
	}
	if !v.OK {
		v.Summary += " (" + attemptsNote(history) + ")"
	}
	return v
}

func diagnoseServer(public httpProbe, history []probeAttempt, live *relayhub.ServerSnapshot, target *url.URL) verdict {
	v := verdict{Flap: flapped(history)}
	if len(history) > 1 {
		v.Detail = append(v.Detail, "attempts: "+attemptHistory(history))
	}
	route := routeForPath(live, target.Path)
	if public.Err != nil {
		v.Summary = "public request failed: " + public.Err.Error()
		v.Where = wherePublicEndpoint
		v.Actions = []string{"curl -v " + target.String() + " from this host"}
		return v
	}
	v.Detail = append(v.Detail, "public: "+public.summary())
	if id := public.requestID(); id != "" {
		v.Detail = append(v.Detail, "x-request-id: "+id)
	}
	if route != nil {
		state := stateLive
		if !route.Live {
			state = "dead (bound to a closed session)"
		}
		v.Detail = append(v.Detail, fmt.Sprintf("route %s → agent %s (%s)", route.Key, route.Agent, state))
	}

	switch {
	case public.ok():
		v.OK = true
		v.Summary = fmt.Sprintf(fmtServed, target.String(), public.Status, public.Took.Round(time.Millisecond))
		if route == nil && live != nil {
			v.Detail = append(v.Detail, "no route entry for this path; the response came from the relay's normal routing")
		}
	case public.Status == http.StatusNotFound:
		switch {
		case live == nil:
			v.Summary = "relay returned 404 and live relay state is unavailable"
			v.Where = "relay route table (unknown)"
			v.Actions = []string{"enable the admin API on loopback so this check can read the route table"}
		case route == nil:
			v.Summary = "relay returned 404: no route is registered for " + target.Path
			v.Where = "exposure registration"
			v.Actions = []string{
				"relay admin → Relay → Agents: is the agent connected and does it list this exposure?",
				"agent log: a registration that is rejected or replaced leaves no route",
			}
		case !route.Live:
			v.Summary = "relay returned 404: the route exists but is bound to a closed session"
			v.Where = whereStaleRoute
			v.Actions = []string{"upgrade the relay: route ownership must follow the live session", actionRestartAgent}
		default:
			v.Summary = "relay returned 404 while a live route exists"
			v.Where = "relay host/base-domain matching, not the tunnel"
			v.Actions = []string{"confirm the request Host matches the relay's configured domain", "check that the path prefix matches the expose id"}
		}
	case public.Status == http.StatusBadGateway || public.Status == http.StatusServiceUnavailable || public.Status == http.StatusGatewayTimeout:
		if route != nil && !route.Live {
			v.Summary = "relay matched a route bound to a closed session"
			v.Where = whereStaleRoute
			v.Actions = []string{"upgrade the relay so routes follow the live session", actionRestartAgent}
			break
		}
		if live == nil || len(live.Agents) == 0 {
			v.Summary = "relay matched the route but no agent is connected"
			v.Where = "agent session"
			v.Actions = []string{"agent log: relay authentication and connection errors", "relay admin → Relay → Agents"}
			break
		}
		v.Summary = "relay matched the route but the tunnel failed"
		v.Where = "relay → agent tunnel"
		agent := live.Agents[0]
		if route != nil {
			for _, a := range live.Agents {
				if a.ID == route.Agent {
					agent = a
				}
			}
		}
		if agent.LastError != "" {
			v.Detail = append(v.Detail, "agent last error: "+agent.LastError)
		}
		v.Actions = []string{
			fmt.Sprintf("agent %s: connected since %s, reconnects %d, streams %d", agent.ID, agent.ConnectedAt.Local().Format("15:04:05"), agent.Reconnects, agent.Streams),
			"agent log: 'relay work stream failed'",
		}
	default:
		v.Summary = "unexpected public response: " + public.summary()
		v.Where = relayAppOrTunnel
		v.Actions = []string{actionRelayLog}
	}
	if !v.OK {
		v.Summary += " (" + attemptsNote(history) + ")"
	}
	return v
}

// fetchRelaySnapshot reads the relay's live state from its loopback admin API.
func fetchRelaySnapshot(global *alaye.Global, token string) ([]relayhub.ServerSnapshot, error) {
	if global.Admin.Enabled.NotActive() {
		return nil, fmt.Errorf("admin API is disabled in this configuration")
	}
	addr := strings.TrimSpace(global.Admin.Address)
	if addr == "" {
		return nil, fmt.Errorf("admin address is empty")
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("admin address %q: %w", addr, err)
	}
	switch host {
	case "", def.RelayBindAny, "::", "[::]":
		host = def.IPv4LoopbackSAN
	}
	raw := def.Http + def.ProtocolSeparator + net.JoinHostPort(host, port) + "/api/v1/relay"
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: def.RelayStateTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", raw, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", raw, resp.StatusCode)
	}
	var payload struct {
		Servers []relayhub.ServerSnapshot `json:"servers"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode relay state: %w", err)
	}
	if len(payload.Servers) == 0 {
		return nil, fmt.Errorf("admin returned no relay servers")
	}
	return payload.Servers, nil
}

func findRelaySnapshot(servers []relayhub.ServerSnapshot, host string) *relayhub.ServerSnapshot {
	for i := range servers {
		if strings.EqualFold(servers[i].Domain, host) {
			return &servers[i]
		}
	}
	if len(servers) == 1 {
		return &servers[0]
	}
	return nil
}

func printRelayState(f *ui.Flow, live *relayhub.ServerSnapshot) {
	if live == nil {
		return
	}
	state := def.StateStopped
	if live.Running {
		state = def.StateRunning
	}
	uptime := ""
	if !live.StartedAt.IsZero() {
		uptime = ", up " + age(live.StartedAt)
	}
	f.Info(fmt.Sprintf("live relay state: %s%s, %d agent(s), %d route(s)", state, uptime, len(live.Agents), len(live.Routes)))
	if !live.LastErrorAt.IsZero() {
		f.Info(fmt.Sprintf("  last error: %s (%s ago)", live.LastError, age(live.LastErrorAt)))
	}
	for _, a := range live.Agents {
		line := fmt.Sprintf("  agent %s: connected %s ago, reconnects %d, streams %d",
			a.ID, age(a.ConnectedAt), a.Reconnects, a.Streams)
		if a.LastError != "" {
			line += ", last error " + a.LastError
		}
		f.Info(line)
	}
	for _, r := range live.Routes {
		state := stateLive
		if !r.Live {
			state = "DEAD"
		}
		f.Info(fmt.Sprintf("  route %s → %s (%s)", r.Key, r.Agent, state))
	}
}

func routeForPath(live *relayhub.ServerSnapshot, path string) *relayhub.RouteSnapshot {
	if live == nil {
		return nil
	}
	best := -1
	for i := range live.Routes {
		key := live.Routes[i].Key
		if strings.HasPrefix(key, "sub:") || strings.Contains(key, ":") {
			continue
		}
		if path == key || strings.HasPrefix(path, key+"/") {
			if best < 0 || len(key) > len(live.Routes[best].Key) {
				best = i
			}
		}
	}
	if best < 0 {
		return nil
	}
	return &live.Routes[best]
}

func age(t time.Time) string {
	if t.IsZero() {
		return stateUnknown
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	case d < 24*time.Hour:
		return d.Round(time.Hour).String()
	default:
		return d.Round(24 * time.Hour).String()
	}
}

func findHostByExpose(hosts map[string]*alaye.Host, id string) *alaye.Host {
	for _, h := range hosts {
		for _, route := range h.Routes {
			for _, ex := range route.Exposes {
				if ex.ID == id {
					return h
				}
			}
		}
	}
	return nil
}

func resolveSecret(r *Relay, f *ui.Flow, label, raw string, global *alaye.Global) (string, bool) {
	if raw == "" {
		f.Error(label + " is empty")
		return "", false
	}
	if !strings.HasPrefix(raw, def.SecretScheme) {
		return raw, true
	}
	client, err := secrets.NewControlClient(global.Storage.DataDir)
	if err != nil {
		f.Warn(label + " is a Keeper reference; running service not reachable to verify")
		return "", false
	}
	key := strings.TrimPrefix(raw, def.SecretScheme)
	value, err := client.Get(key)
	if err != nil || value == "" {
		f.Error(label + " Keeper key " + key + " is missing")
		return "", false
	}
	return value, true
}

func checkSecret(r *Relay, f *ui.Flow, label, raw string, global *alaye.Global) bool {
	_, ok := resolveSecret(r, f, label, raw, global)
	return ok
}

func findHost(hosts map[string]*alaye.Host, name string) *alaye.Host {
	for domain, h := range hosts {
		if strings.EqualFold(domain, name) {
			return h
		}
	}
	return nil
}
