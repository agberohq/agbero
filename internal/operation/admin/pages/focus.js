/**
 * pages/focus.js — single-host wallboard.
 *
 * Built to be projected: one host, live numbers, nothing about other hosts.
 * Live rates come from consecutive /uptime polls (counter deltas over time),
 * so the Live tab moves every few seconds instead of showing down-sampled
 * hourly history. Stored history is still available on the History tab.
 *
 *   #/focus?host=ore.localhost&window=300&tab=live&kiosk=1
 */
import { chart } from '../lib/oja.full.esm.js';

const POLL_MS = 3000;

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { store, api } = inject('app');
    const params = new URLSearchParams((window.location.hash.replace(/^#/, '').split('?')[1] || ''));
    let host = params.get('host') || '';
    let windowSec = Number(params.get('window')) === 900 ? 900 : 300;
    let tab = ['live', 'backends', 'history', 'logs'].includes(params.get('tab')) ? params.get('tab') : 'live';
    let kiosk = params.get('kiosk') === '1';
    let range = params.get('range') || '1h';
    let paused = false, timer = null, lastLogsAt = 0;

    // Rolling live series for the selected host.
    let prev = null;          // previous counter snapshot
    let series = [];          // [{t, rps, eps, p99, bps}]
    let lastRates = new Map(); // backend key -> req/s
    const live = { rps: null, p99: null, err: null };
    const hist = { reqs: null, p99: null, err: null };

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const fmtNum = n => { n = Number(n || 0); if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B'; if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'; if (n >= 1e4) return (n / 1e3).toFixed(1) + 'k'; return Number.isInteger(n) ? String(n) : n.toFixed(1); };
    const fmtRate = n => { n = Number(n || 0); return n >= 100 ? fmtNum(Math.round(n)) : n.toFixed(n >= 10 ? 1 : 2); };
    const fmtMs = us => { const v = Number(us || 0) / 1000; return v ? (v < 10 ? v.toFixed(1) : Math.round(v)) + 'ms' : '—'; };
    const fmtBytes = n => { n = Number(n || 0); if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + ' GB'; if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MB'; if (n >= 1 << 10) return (n / (1 << 10)).toFixed(1) + ' KB'; return Math.round(n) + ' B'; };
    const clock = t => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

    function setURL() {
        const p = new URLSearchParams();
        if (host) p.set('host', host);
        p.set('window', String(windowSec));
        p.set('tab', tab);
        if (range !== '1h') p.set('range', range);
        if (kiosk) p.set('kiosk', '1');
        history.replaceState(null, '', '#/focus?' + p.toString());
    }

    function setKiosk(v) {
        kiosk = v;
        document.body.classList.toggle('focus-kiosk', kiosk);
        if (kiosk) setTab('live');
        if (kiosk && document.documentElement.requestFullscreen && !document.fullscreenElement) {
            document.documentElement.requestFullscreen().catch(() => {});
        } else if (!kiosk && document.fullscreenElement) {
            document.exitFullscreen().catch(() => {});
        }
        setURL();
    }

    function setTab(name) {
        tab = name;
        findAll('[data-fw-tab]').forEach(b => b.classList.toggle('active', b.dataset.fwTab === tab));
        findAll('[data-fw-panel]').forEach(p => p.classList.toggle('active', p.dataset.fwPanel === tab));
        setURL();
        if (tab === 'history') loadHistory();
        if (tab === 'logs') loadLogs();
    }

    // ── data shaping ────────────────────────────────────────────────────────

    function backendState(b) {
        const s = b.health?.status || '';
        if (b.alive === false || s === 'Dead' || s === 'Unhealthy') return 'down';
        if (s === 'Degraded') return 'warn';
        return 'ok';
    }

    // snapshot flattens one host's stats into counters keyed per backend.
    function snapshot(h) {
        const cfg = (store.get('lastConfig') || {}).hosts?.[host] || {};
        const routes = [];
        let reqs = Number(h.total_reqs || 0), fails = 0, bytes = Number(h.bytes_in || 0) + Number(h.bytes_out || 0);
        let inflight = 0, up = 0, total = 0, p99w = 0, p99n = 0, p99max = 0;
        const add = (kind, list, cfgList) => list.forEach((r, i) => {
            const c = cfgList[i] || {};
            const label = kind === 'proxy' ? (c.name || r.name || r.path || 'proxy') : (c.path || r.path || '/');
            const route = { key: kind + ':' + i, kind, label, strategy: (c.backends?.strategy || r.strategy || '').replace(/_/g, ' '), backends: [] };
            for (const b of (r.backends || [])) {
                const url = b.url || b.address || '—';
                const st = backendState(b);
                total++; if (st !== 'down') up++;
                fails += Number(b.failures || 0);
                inflight += Number(b.in_flight || 0);
                const bReqs = Number(b.total_reqs || 0);
                const p99 = Number(b.latency_us?.p99 || 0);
                if (p99) { p99w += p99 * Math.max(bReqs, 1); p99n += Math.max(bReqs, 1); p99max = Math.max(p99max, p99); }
                route.backends.push({ key: route.key + '|' + url, url, state: st, reqs: bReqs, fails: Number(b.failures || 0), p50: Number(b.latency_us?.p50 || 0), p99, inflight: Number(b.in_flight || 0), bytes: Number(b.bytes_in || 0) + Number(b.bytes_out || 0), health: b.health?.status || '' });
            }
            routes.push(route);
        });
        add('route', h.routes || [], cfg.routes || []);
        add('proxy', h.proxies || [], cfg.proxies || []);
        return { t: Date.now(), reqs, fails, bytes, inflight, up, total, p99: p99n ? p99w / p99n : p99max, routes };
    }

    function hostStatus(s) {
        if (!s.total) return s.reqs ? { cls: 'ok', text: 'Serving' } : { cls: 'idle', text: 'Idle' };
        if (s.up === 0) return { cls: 'down', text: 'Down' };
        const degraded = s.routes.some(r => r.backends.some(b => b.state !== 'ok'));
        return degraded ? { cls: 'warn', text: 'Degraded' } : { cls: 'ok', text: 'Healthy' };
    }

    function ingest(s) {
        if (prev && s.t > prev.t) {
            const dt = (s.t - prev.t) / 1000;
            // Counters reset when the process restarts; treat a drop as zero.
            const d = (a, b) => Math.max(0, a - b) / dt;
            const point = { t: s.t, rps: d(s.reqs, prev.reqs), eps: d(s.fails, prev.fails), bps: d(s.bytes, prev.bytes), p99: s.p99 / 1000 };
            series.push(point);
            const cutoff = s.t - windowSec * 1000;
            series = series.filter(p => p.t >= cutoff);
            const prevB = new Map(prev.routes.flatMap(r => r.backends).map(b => [b.key, b.reqs]));
            lastRates = new Map(s.routes.flatMap(r => r.backends).map(b => [b.key, prevB.has(b.key) ? d(b.reqs, prevB.get(b.key)) : 0]));
        }
        prev = s;
    }

    // ── rendering ───────────────────────────────────────────────────────────

    function kpi(label, value, foot = '', cls = '') {
        return `<div class="fw-kpi ${cls}"><div class="fw-kpi-label">${label}</div><div class="fw-kpi-value">${value}</div>${foot ? `<div class="fw-kpi-foot">${foot}</div>` : ''}</div>`;
    }

    function renderLive(s) {
        const last = series[series.length - 1] || { rps: 0, eps: 0, bps: 0 };
        const winReq = series.reduce((n, p) => n + p.rps, 0), winErr = series.reduce((n, p) => n + p.eps, 0);
        const errPct = winReq ? (winErr / winReq) * 100 : 0;
        const peak = series.reduce((m, p) => Math.max(m, p.rps), 0);
        const st = hostStatus(s);

        const statusEl = find('#fwStatus');
        if (statusEl) { statusEl.className = 'fw-status ' + st.cls; statusEl.textContent = st.text; }
        const sub = find('#fwSub');
        if (sub) sub.textContent = `${fmtNum(s.reqs)} requests since start · updated ${clock(s.t)}${paused ? ' · paused' : ''}`;
        const host$ = find('#fwHost');
        if (host$) host$.textContent = host || '—';

        const kpis = find('#fwKpis');
        if (kpis) kpis.innerHTML = [
            kpi('Requests / sec', series.length ? fmtRate(last.rps) : '…', `peak ${fmtRate(peak)} · ${windowSec / 60}m`),
            kpi('Latency p99', s.p99 ? fmtMs(s.p99) : '—', 'request-weighted across backends', s.p99 > 2e6 ? 'bad' : s.p99 > 5e5 ? 'warn' : ''),
            kpi('Errors', series.length ? errPct.toFixed(errPct < 10 ? 2 : 0) + '<small>%</small>' : '…', `${fmtRate(last.eps)}/s now · ${fmtNum(s.fails)} total`, errPct >= 5 ? 'bad' : errPct >= 1 ? 'warn' : ''),
            kpi('Backends up', s.total ? `${s.up}<small>/ ${s.total}</small>` : '—', s.total ? (s.up === s.total ? 'all healthy' : `${s.total - s.up} down`) : 'served locally', s.total && s.up < s.total ? (s.up ? 'warn' : 'bad') : ''),
            kpi('Throughput', series.length ? fmtBytes(last.bps) + '<small>/s</small>' : '…', fmtBytes(s.bytes) + ' total'),
            kpi('In flight', fmtNum(s.inflight), 'open requests now'),
        ].join('');

        const note = find('#fwRpsNote');
        if (note) note.textContent = series.length ? `now ${fmtRate(last.rps)}/s` : 'warming up…';
        ensureLiveCharts();
        const ts = series.map(p => clock(p.t));
        live.rps?.update(series.map(p => +p.rps.toFixed(2)), ts);
        live.p99?.update(series.map(p => +p.p99.toFixed(1)), ts);
        live.err?.update(series.map(p => +p.eps.toFixed(2)), ts);

        const routesEl = find('#fwRoutes');
        if (!routesEl) return;
        if (!s.routes.length) { routesEl.innerHTML = '<div class="fw-empty">This host has no routes or proxies.</div>'; return; }
        routesEl.innerHTML = s.routes.map(r => {
            const rps = r.backends.reduce((n, b) => n + (lastRates.get(b.key) || 0), 0);
            const totalReqs = r.backends.reduce((n, b) => n + b.reqs, 0) || 1;
            const rows = r.backends.length ? r.backends.map(b => {
                const bRps = lastRates.get(b.key) || 0;
                const share = rps > 0 ? bRps / rps : b.reqs / totalReqs;
                return `<div class="fw-be"><span class="fw-dot ${b.state}" title="${esc(b.health || b.state)}"></span>
                    <span class="fw-be-url" title="${esc(b.url)}">${esc(b.url)}</span>
                    <span class="fw-be-nums">${fmtRate(bRps)}/s · p99 ${fmtMs(b.p99)}${b.inflight ? ' · ⚡' + b.inflight : ''}</span>
                    <span class="fw-share"><i style="width:${Math.round(share * 100)}%"></i></span></div>`;
            }).join('') : '<div class="fw-empty">Served by this host (static, markdown, worker, or relay).</div>';
            const meta = [r.kind === 'proxy' ? 'TCP/UDP' : 'HTTP', r.strategy, r.backends.length ? `${fmtRate(rps)}/s` : ''].filter(Boolean).join(' · ');
            return `<div class="fw-card"><div class="fw-route-head"><span class="fw-route-path">${esc(r.label)}</span><span class="fw-route-meta">${esc(meta)}</span></div>${rows}</div>`;
        }).join('');
    }

    function renderBackends(s) {
        const body = find('#fwBackendTable tbody');
        if (!body) return;
        const rows = s.routes.flatMap(r => r.backends.map(b => ({ r, b })));
        body.innerHTML = rows.length ? rows.map(({ r, b }) => `<tr>
            <td class="mono">${esc(r.label)}</td><td class="mono">${esc(b.url)}</td>
            <td><span class="fw-dot ${b.state}" style="display:inline-block;vertical-align:middle;margin-right:6px;"></span>${esc(b.health || b.state)}</td>
            <td>${fmtRate(lastRates.get(b.key) || 0)}</td><td>${fmtNum(b.reqs)}</td>
            <td style="color:${b.fails ? 'var(--danger)' : 'inherit'}">${fmtNum(b.fails)}</td>
            <td>${fmtMs(b.p50)}</td><td>${fmtMs(b.p99)}</td><td>${b.inflight || '—'}</td><td>${fmtBytes(b.bytes)}</td></tr>`).join('')
            : '<tr><td colspan="10" class="fw-empty">No backends on this host.</td></tr>';
    }

    function ensureLiveCharts() {
        if (live.rps) return;
        live.rps = chart.line('#fwRpsChart', [], [], { unit: '/s', color: 'var(--accent)' });
        live.p99 = chart.line('#fwP99Chart', [], [], { unit: 'ms', color: 'var(--warning)' });
        live.err = chart.line('#fwErrChart', [], [], { unit: '/s', color: 'var(--danger)' });
    }

    async function loadHistory() {
        if (!host) return;
        if (!hist.reqs) {
            hist.reqs = chart.line('#fwHistReqs', [], [], { unit: '/s', color: 'var(--accent)' });
            hist.p99 = chart.line('#fwHistP99', [], [], { unit: 'ms', color: 'var(--warning)' });
            hist.err = chart.line('#fwHistErr', [], [], { unit: '%', color: 'var(--danger)', maxY: 100 });
        }
        const tel = await api.fetchTelemetry(host, range);
        const sm = tel?.samples || [], ts = sm.map(x => x.ts);
        hist.reqs.update(sm.map(x => x.requests_sec), ts);
        hist.p99.update(sm.map(x => x.p99_ms), ts);
        hist.err.update(sm.map(x => x.error_rate), ts);
    }

    async function loadLogs() {
        const el = find('#fwLogs');
        if (!el || !host) return;
        const logs = await api.fetchLogs(400);
        const rows = [];
        for (const raw of (Array.isArray(logs) ? logs : (logs?.logs || []))) {
            let p = raw;
            if (typeof raw === 'string') { try { p = JSON.parse(raw); } catch { p = { msg: raw }; } }
            const f = p?.fields || {};
            if ((f.host || p?.host) !== host) continue;
            const lvl = (p?.lvl || p?.level || 'info').toUpperCase();
            const color = lvl.startsWith('ERR') ? 'var(--danger)' : lvl.startsWith('WARN') ? 'var(--warning)' : 'var(--text-mute)';
            const detail = f.path ? ` ${f.method || ''} ${f.path}${f.status ? ' → ' + f.status : ''}` : '';
            rows.push(`<div class="fw-log-row"><span style="color:${color};">${esc(lvl)}</span> ${esc((p?.msg || p?.message || '') + detail)}</div>`);
            if (rows.length >= 200) break;
        }
        el.innerHTML = rows.length ? rows.join('') : '<div class="fw-empty">No recent log lines for this host.</div>';
    }

    // ── loop ────────────────────────────────────────────────────────────────

    async function tick() {
        const data = await api.fetchUptime();
        const hosts = data?.hosts || {};
        const names = Object.keys(hosts).sort();
        const sel = find('#fwHostSelect');
        if (sel && sel.options.length !== names.length) sel.innerHTML = names.map(h => `<option value="${esc(h)}">${esc(h)}</option>`).join('');
        if (!host && names.length) { host = names[0]; setURL(); }
        if (sel) sel.value = host;
        if (!host || !hosts[host]) {
            const k = find('#fwKpis');
            if (k) k.innerHTML = `<div class="fw-empty">${host ? `No stats for ${esc(host)} yet.` : 'No hosts available.'}</div>`;
            return;
        }
        const s = snapshot(hosts[host]);
        ingest(s);
        renderLive(s);
        renderBackends(s);
        if (tab === 'logs' && Date.now() - lastLogsAt > 15000) { lastLogsAt = Date.now(); loadLogs(); }
    }

    function resetSeries() { prev = null; series = []; lastRates = new Map(); }

    on('#fwHostSelect', 'change', (e, el) => { host = el.value; resetSeries(); setURL(); tick(); });
    on('#fwWindow', 'change', (e, el) => { windowSec = Number(el.value); setURL(); if (prev) renderLive(prev); });
    on('#fwRange', 'change', (e, el) => { range = el.value; setURL(); loadHistory(); });
    on('#fwPause', 'click', (e, btn) => { paused = !paused; btn.textContent = paused ? 'Resume' : 'Pause'; });
    on('#fwKiosk', 'click', () => setKiosk(!kiosk));
    on('#fwOpen', 'click', () => {
        const p = new URLSearchParams({ host, window: String(windowSec), tab: 'live', kiosk: '1' });
        window.open('/#/focus?' + p.toString(), '_blank');
    });
    on('[data-fw-tab]', 'click', (e, btn) => setTab(btn.dataset.fwTab));
    const onKey = e => { if (e.key === 'Escape' && kiosk) setKiosk(false); };
    document.addEventListener('keydown', onKey);

    const winEl = find('#fwWindow'); if (winEl) winEl.value = String(windowSec);
    const rangeEl = find('#fwRange'); if (rangeEl) rangeEl.value = range;
    if (kiosk) document.body.classList.add('focus-kiosk');
    setTab(tab);
    await tick();
    timer = setInterval(() => { if (!paused) tick(); }, POLL_MS);

    onUnmount(() => {
        clearInterval(timer);
        document.removeEventListener('keydown', onKey);
        document.body.classList.remove('focus-kiosk');
    });
    ready();
}
