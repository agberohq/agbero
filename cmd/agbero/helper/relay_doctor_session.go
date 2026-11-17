package helper

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/agberohq/agbero/internal/core/def"
	relayhub "github.com/agberohq/agbero/internal/hub/relay"
)

// agberoRunSubcommand is the CLI verb that starts the proxy.
const agberoRunSubcommand = "run"

type agberoProcess struct {
	PID  int
	Args string
}

// localAgberoProcesses lists `agbero run` processes on this host. Every such
// process that loads the same configuration connects the same agents, and the
// relay keeps only the newest session per agent name.
func localAgberoProcesses() ([]agberoProcess, error) {
	if runtime.GOOS == "windows" {
		return nil, fmt.Errorf("process listing is not supported on windows")
	}
	out, err := exec.Command("ps", "-axo", "pid=,args=").Output()
	if err != nil {
		return nil, fmt.Errorf("ps: %w", err)
	}
	self := os.Getpid()
	var procs []agberoProcess
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil || pid == self {
			continue
		}
		if filepath.Base(fields[1]) != "agbero" {
			continue
		}
		isRun := false
		for _, a := range fields[2:] {
			if a == agberoRunSubcommand {
				isRun = true
				break
			}
			if !strings.HasPrefix(a, "-") {
				break
			}
		}
		if isRun {
			procs = append(procs, agberoProcess{PID: pid, Args: strings.Join(fields[1:], " ")})
		}
	}
	return procs, nil
}

func describeProcesses(procs []agberoProcess) string {
	parts := make([]string, 0, len(procs))
	for _, p := range procs {
		parts = append(parts, fmt.Sprintf("pid %d: %s", p.PID, p.Args))
	}
	return strings.Join(parts, "; ")
}

// doctorProcesses reports the local agbero processes, cross-checked against
// the relay's session for the agent.
func doctorProcesses(rep *doctorReport, name string, report *relayhub.SessionReport) {
	procs, err := localAgberoProcesses()
	if err != nil {
		rep.add(stageProcesses, doctorSkip, err.Error())
		return
	}
	switch {
	case len(procs) == 0 && report != nil && report.Connected:
		rep.add(stageProcesses, doctorFail,
			fmt.Sprintf("no `agbero run` process on this host, yet the relay has a live session for %s from %s", name, report.Agent.Remote),
			"another host is running agent "+name+"; stop it or give one of them a different agent name")
	case len(procs) == 0:
		rep.add(stageProcesses, doctorFail, "no `agbero run` process on this host, so agent "+name+" is not running here",
			"start agbero on this host")
	case len(procs) > 1:
		rep.add(stageProcesses, doctorFail,
			fmt.Sprintf("%d agbero processes are running (%s)", len(procs), describeProcesses(procs)),
			"each process with this config connects as "+name+" and the relay keeps only the newest session; stop all but one")
	default:
		rep.add(stageProcesses, doctorPass, describeProcesses(procs))
	}
}

// doctorSession turns the relay's session report into stages.
func doctorSession(rep *doctorReport, name string, exposes []string, relayAddrs []string, report *relayhub.SessionReport) {
	if report == nil {
		rep.add(stageSession, doctorSkip, "the relay does not report session state (relay build predates it)",
			"redeploy the relay with this build so the doctor can see the agent's session")
		return
	}
	if !report.Connected {
		detail := "the relay has no live session for " + name
		if ev := report.LastEvent(def.RelayEventClosed); ev != nil {
			detail += fmt.Sprintf("; last session from %s closed %s ago: %s", ev.Remote, ago(report, ev.At), ev.Reason)
		}
		rep.add(stageSession, doctorFail, detail,
			"agbero log on this host: 'relay connection failed' and 'relay control connection closed'")
		return
	}

	ag := report.Agent
	sessAge := report.Now.Sub(ag.ConnectedAt)
	detail := fmt.Sprintf("connected %s ago from %s, streams %d", short(sessAge), ag.Remote, ag.Streams)
	opened := report.Count(def.RelayEventOpened, def.RelayChurnWindow)
	replaced := report.Count("replaced", def.RelayChurnWindow)
	hosts := report.RemoteHosts()
	relaySelf := ""
	for _, h := range hosts {
		hip := net.ParseIP(h)
		for _, a := range relayAddrs {
			if aip := net.ParseIP(a); (hip != nil && aip != nil && hip.Equal(aip)) || strings.EqualFold(h, a) {
				relaySelf = h
			}
		}
	}
	switch {
	case relaySelf != "":
		rep.add(stageSession, doctorFail,
			fmt.Sprintf("%s; a session for %s was opened from %s, which is the relay host's own address", detail, name, relaySelf),
			"an agbero on the relay host has an agent block named "+name+"; remove it there (agbero relay doctor "+name+" on the relay host shows which host config), or rename one of the agents",
			"while both run they replace each other's session and rotate each other's credential, which shows up as auth failures on the relay")
	case len(hosts) > 1:
		rep.add(stageSession, doctorFail,
			fmt.Sprintf("%s; sessions for %s came from %d addresses: %s", detail, name, len(hosts), strings.Join(hosts, ", ")),
			"two agent hosts use the name "+name+" and replace each other; stop one or rename it")
	case replaced >= 2:
		rep.add(stageSession, doctorFail,
			fmt.Sprintf("%s; session replaced %d times in %s", detail, replaced, def.RelayChurnWindow),
			"two processes behind the same address use the name "+name+"; check the processes stage above and any other machine on this network")
	case opened >= 3:
		reason := ""
		if ev := report.LastEvent(def.RelayEventClosed); ev != nil {
			reason = ", last close: " + ev.Reason
		}
		rep.add(stageSession, doctorWarn,
			fmt.Sprintf("%s; reconnected %d times in %s%s", detail, opened, def.RelayChurnWindow, reason),
			"the control connection keeps dropping; agbero log on this host: 'relay control connection closed'")
	case sessAge < def.RelayFreshSessionAge:
		rep.add(stageSession, doctorWarn, detail+"; the session is very new, rerun to see whether it holds")
	default:
		rep.add(stageSession, doctorPass, detail)
	}

	live := map[string]bool{}
	present := map[string]bool{}
	for _, rt := range report.Routes {
		present[rt.Key] = true
		if rt.Live {
			live[rt.Key] = true
		}
	}
	for _, id := range exposes {
		key := "/" + id
		switch {
		case live[key]:
			rep.add("route "+key, doctorPass, "registered on the relay and bound to the live session")
		case present[key]:
			rep.add("route "+key, doctorFail, "registered but bound to a closed session",
				"redeploy the relay; routes must follow the newest session")
		default:
			rep.add("route "+key, doctorFail, "not registered on the relay",
				"check that the running agbero loaded the expose; the relay rejects duplicate or invalid exposures at registration")
		}
	}

	if ev := report.LastEvent(def.RelayEventProxyError); ev != nil && report.Now.Sub(ev.At) <= def.RelayChurnWindow {
		n := ev.Count
		if n == 0 {
			n = 1
		}
		rep.add("relay errors", doctorWarn,
			fmt.Sprintf("%dx %q, last %s ago", n, ev.Reason, ago(report, ev.At)),
			explainProxyError(ev.Reason)...)
	}
}

// relayErrorsSince fetches the session report again after a failed public
// probe and returns the proxy errors the relay recorded for it.
func relayErrorsSince(relayURL, agent, secret string, insecure bool, since time.Time) []relayhub.SessionEvent {
	ctx, cancel := context.WithTimeout(context.Background(), def.RelayAuthTimeout)
	defer cancel()
	report, err := relayhub.ProbeSession(ctx, relayURL, agent, secret, "", insecure)
	if err != nil || report == nil {
		return nil
	}
	var out []relayhub.SessionEvent
	for _, ev := range report.History {
		if ev.Kind == def.RelayEventProxyError && !ev.At.Before(since) {
			out = append(out, ev)
		}
	}
	return out
}

// explainProxyError maps the relay's proxy error to where the failure is.
func explainProxyError(reason string) []string {
	r := strings.ToLower(reason)
	switch {
	case strings.Contains(r, "session closed"):
		return []string{"the request hit a session that had just been closed or replaced; see the session stage"}
	case strings.Contains(r, "stream limit"):
		return []string{"the agent hit the relay's policy max_streams; raise it or find what holds streams open"}
	case strings.Contains(r, "eof"), strings.Contains(r, "reset"), strings.Contains(r, "broken pipe"):
		return []string{"the agent closed the stream without answering; agbero log on this host: 'relay work stream failed' names the cause"}
	case strings.Contains(r, "timeout"), strings.Contains(r, "deadline"):
		return []string{"the agent did not answer in time; check the local target's latency and the agent's network"}
	default:
		return []string{"agbero log on this host: 'relay work stream failed'"}
	}
}

func ago(report *relayhub.SessionReport, t time.Time) string {
	return short(report.Now.Sub(t))
}

func short(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return d.Round(time.Minute).String()
	default:
		return humanLeft(d)
	}
}
