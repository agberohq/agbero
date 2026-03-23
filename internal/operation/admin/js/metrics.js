import { emit } from '../lib/oja.full.esm.js';
import { fetchUptime } from './api.js';
import { getCreds, clearCredentials } from './store.js';

const METRICS_INTERVAL_MS  = 2000;
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
            const data = await fetchUptime(getCreds());
            if (!data) return;

            if (data.__unauthorized) {
                // 401 = auth failure, NOT an offline state — clear the banner
                store.set('sys.isOffline', false);
                clearCredentials();
                emit('auth:expired');
                return;
            }

            if (data.__offline) {
                store.set('sys.isOffline', true);
                return;
            }

            store.set('sys.isOffline', false);

            // ── System stats ────────────────────────────────────────────────
            const sys = data.system || {};
            store.set('sys.cpu',        sys.cpu_percent   ?? 0);
            store.set('sys.memRss',     sys.mem_rss       ?? 0);
            store.set('sys.memAlloc',   sys.mem_alloc     ?? 0);
            store.set('sys.goroutines', sys.num_goroutine ?? 0);
            store.set('sys.cores',      sys.num_cpu       ?? '—');
            store.set('sys.memUsed',    sys.mem_used      ?? 0);
            store.set('sys.memTotalOs', sys.mem_total_os  ?? 0);

            // ── Aggregate totals from hosts map ─────────────────────────────
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

            // ── RPS (derived from delta between polls) ───────────────────────
            const now     = Date.now();
            const diffSec = (now - lastReqTime) / MILLISECONDS_IN_SEC;
            const rps     = (lastReqTotal > 0 && diffSec > 0 && totalReqs > lastReqTotal)
                ? ((totalReqs - lastReqTotal) / diffSec)
                : 0;
            lastReqTotal = totalReqs;
            lastReqTime  = now;

            // ── Apdex proxy: 1 - (p99_ms / 1000), clamped 0–1 ──────────────
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

            // ── hostsData — hosts map for hosts.html and drawers ─────────────
            // hosts.html reads this directly; no separate fetch needed there
            store.set('hostsData', { stats: hosts });

            // ── Response time history for dashboard chart ────────────────────
            const history = store.get('metricsHistory') || { all: [], http: [], tcp: [] };
            history.all.push(data.global?.avg_p99_ms  ?? 0);
            history.http.push(data.global?.http_p99_ms ?? 0);
            history.tcp.push(data.global?.tcp_p99_ms  ?? 0);

            for (const k of ['all', 'http', 'tcp']) {
                if (history[k].length > MAX_HISTORY_POINTS) history[k].shift();
            }
            store.set('metricsHistory', history);

            // ── Git state ────────────────────────────────────────────────────
            if (data.git) store.set('gitStats', data.git);

            emit('metrics:updated', {
                stats:  { totalReqs, activeBackends, totalErrors, rps, apdex, p99 },
                system: sys,
                history,
                hosts,
                git:    data.git || {},
            });

            emit('cluster:updated', { clusterStats: data.cluster });

        } catch {
            store.set('sys.isOffline', true);
        }
    };

    const id = setInterval(poll, METRICS_INTERVAL_MS);
    poll();
    return () => clearInterval(id);
}
