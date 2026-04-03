import { emit } from '../lib/oja.full.esm.js';
import { fetchUptime } from './api.js';

const METRICS_INTERVAL_MS  = 3000; // 3s — industry standard for admin dashboards
const MILLISECONDS_IN_SEC  = 1000;
const MAX_HISTORY_POINTS   = 60;

// startMetricsPolling - polls /uptime every 2s and writes reactive store keys
// /uptime is the single source of truth: system stats, per-host live backend
// health, latency percentiles, and git state. Global stats (total_reqs,
// active_backends, apdex) do not come from the server — they are aggregated
// here from the hosts map. DOM-free: emits events, never touches the DOM.
export function startMetricsPolling(store) {
    let lastReqTotal = 0;
    let lastReqTime  = Date.now();

    const poll = async () => {
        try {
            const data = await fetchUptime();
            // Api returns null on network failure — handled centrally in main.js.
            if (!data) return;

            store.set('sys.isOffline', false);

            // System stats
            const sys = data.system || {};
            store.set('sys.cpu',        sys.cpu_percent   ?? 0);
            store.set('sys.memRss',     sys.mem_rss       ?? 0);
            store.set('sys.memAlloc',   sys.mem_alloc     ?? 0);
            store.set('sys.goroutines', sys.num_goroutine ?? 0);
            store.set('sys.cores',      sys.num_cpu       ?? '—');
            store.set('sys.memUsed',    sys.mem_used      ?? 0);
            store.set('sys.memTotalOs', sys.mem_total_os  ?? 0);

            // Aggregate totals from hosts map
            // /uptime global only has p99 aggregates — everything else must
            // be computed here.
            let totalReqs     = 0;
            let activeBackends = 0;
            let totalErrors    = 0;
            const hosts        = data.hosts || {};

            for (const host of Object.values(hosts)) {
                totalReqs += host.total_reqs || 0;
                for (const route of host.routes || []) {
                    for (const b of route.backends || []) {
                        if (b.alive) activeBackends++;
                        totalErrors += b.failures || 0;
                    }
                }
                for (const proxy of host.proxies || []) {
                    for (const b of proxy.backends || []) {
                        if (b.alive) activeBackends++;
                        totalErrors += b.failures || 0;
                    }
                }
            }

            // RPS (derived from delta between polls)
            const now     = Date.now();
            const diffSec = (now - lastReqTime) / MILLISECONDS_IN_SEC;
            const rps     = (lastReqTotal > 0 && diffSec > 0 && totalReqs > lastReqTotal)
                ? ((totalReqs - lastReqTotal) / diffSec)
                : 0;
            lastReqTotal = totalReqs;
            lastReqTime  = now;

            // Apdex proxy: 1 - (p99_ms / 1000), clamped 0–1
            const p99   = data.global?.avg_p99_ms || 0;
            const apdex = Math.max(0, Math.min(1, 1 - p99 / 1000));

            store.set('stats.total',          totalReqs);
            store.set('stats.errors',         totalErrors);
            store.set('stats.activeBackends', activeBackends);
            store.set('stats.avgMs',          p99 ? p99.toFixed(0) + 'ms' : '0ms');
            store.set('stats.apdex',          apdex.toFixed(2));
            store.set('stats.rps',            rps.toFixed(1));

            // Uptime % — not provided by server, derive from error rate
            const errRate = totalReqs > 0 ? (totalErrors / totalReqs) : 0;
            store.set('stats.uptime', ((1 - errRate) * 100).toFixed(1) + '%');

            // hostsData — hosts map for hosts.html and drawers
            // hosts.html reads this directly; no separate fetch needed there
            store.set('hostsData', { stats: hosts });

            // Sparkline ring buffers — per-host rolling 30-point window
            // Accumulates RPS delta and avg p99 per host for inline sparklines.
            // client-side only — no backend change needed.
            const now30 = Date.now();
            for (const [hostname, host] of Object.entries(hosts)) {
                const sparkKey  = 'sparklines.' + hostname;
                const existing  = store.get(sparkKey) || { rps: [], p99: [], ts: [], lastReqs: 0 };

                // RPS delta — requests since last poll
                const curReqs   = host.total_reqs || 0;
                const elapsed   = (now30 - (existing.lastTs || now30)) / 1000 || 1;
                const hostRps   = existing.lastReqs > 0 && curReqs > existing.lastReqs
                    ? ((curReqs - existing.lastReqs) / elapsed)
                    : 0;

                // Avg p99 across all routes for this host
                let p99sum = 0, p99cnt = 0;
                for (const r of (host.routes || [])) {
                    for (const b of (r.backends || [])) {
                        const v = b.latency_us?.p99;
                        if (v > 0) { p99sum += v / 1000; p99cnt++; }
                    }
                }
                const hostP99 = p99cnt > 0 ? p99sum / p99cnt : 0;

                const MAX_SPARK = 30;
                store.set(sparkKey, {
                    rps:      [...existing.rps.slice(-(MAX_SPARK - 1)),      hostRps],
                    p99:      [...existing.p99.slice(-(MAX_SPARK - 1)),      hostP99],
                    ts:       [...(existing.ts  || []).slice(-(MAX_SPARK - 1)), now30],
                    lastReqs: curReqs,
                    lastTs:   now30,
                });
            }

            // Response time history for dashboard chart
            const history = store.get('metricsHistory') || { all: [], http: [], tcp: [] };
            history.all.push(data.global?.avg_p99_ms  ?? 0);
            history.http.push(data.global?.http_p99_ms ?? 0);
            history.tcp.push(data.global?.tcp_p99_ms  ?? 0);

            for (const k of ['all', 'http', 'tcp']) {
                if (history[k].length > MAX_HISTORY_POINTS) history[k].shift();
            }
            store.set('metricsHistory', history);

            // Git state
            if (data.git) store.set('gitStats', data.git);

            emit('metrics:updated', {
                stats:  { totalReqs, activeBackends, totalErrors, rps, apdex, p99 },
                system: sys,
                history,
                hosts,
                git:    data.git || {},
            });

            emit('cluster:updated', { clusterStats: data.cluster });

        } catch (err) {
            // Log but don't crash the poll loop — Api errors are handled centrally
            if (err?.name !== 'AbortError') {
                console.warn('[agbero/metrics] poll error:', err?.message || err);
            }
            store.set('sys.isOffline', true);
        }
    };

    const id = setInterval(poll, METRICS_INTERVAL_MS);
    poll();
    return () => clearInterval(id);
}
