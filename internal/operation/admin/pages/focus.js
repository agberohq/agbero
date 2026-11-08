/**
 * pages/focus.js — scoped host focus dashboard.
 *
 * Oja uses hash routing:
 *   #/focus?host=ore.localhost&range=1h&tab=overview&kiosk=1
 */
import { chart } from '../lib/oja.full.esm.js';

const BACKEND_COLORS = ['#4f8ef7','#22c55e','#f59e0b','#a855f7','#14b8a6','#f97316','#ec4899','#84cc16','#ef4444','#64748b'];

function backendColor(name) {
    let h = 0;
    for (const ch of String(name)) h = (h * 31 + ch.codePointAt(0)) >>> 0;
    return BACKEND_COLORS[h % BACKEND_COLORS.length];
}

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, oja } = inject('app');
    const params = new URLSearchParams((window.location.hash.replace(/^#/, '').split('?')[1] || ''));
    let host = params.get('host') || '';
    let range = params.get('range') || '1h';
    let tab = params.get('tab') || 'overview';
    let hostSort = params.get('sort') || 'requests';
    if (!['overview', 'backends', 'logs'].includes(tab)) tab = 'overview';
    let kiosk = params.get('kiosk') === '1';
    let paused = false;
    let timer = null;
    let charts = null;
    let backendsChart = null;
    let backendChart = null;
    let backendRows = [];
    let selectedBackend = '';
    let hostsCache = {};

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const fmtNum = n => {
        n = Number(n || 0);
        if (n >= 1e9) return (n/1e9).toFixed(1) + 'B';
        if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n/1e3).toFixed(1) + 'k';
        return String(n);
    };
    const ms = us => {
        const v = Number(us || 0);
        return (v/1000).toFixed(v < 10000 ? 1 : 0) + 'ms';
    };

    function setURL() {
        const p = new URLSearchParams();
        if (host) p.set('host', host);
        p.set('range', range);
        p.set('tab', tab);
        p.set('sort', hostSort);
        if (kiosk) p.set('kiosk', '1');
        history.replaceState(null, '', '#/focus?' + p.toString());
    }

    function setKiosk(value) {
        kiosk = value;
        document.body.classList.toggle('focus-kiosk', kiosk);
        setURL();
    }

    function setTab(name) {
        tab = name;
        document.querySelectorAll('[data-focus-tab]').forEach(b => b.classList.toggle('active', b.dataset.focusTab === tab));
        document.querySelectorAll('[data-focus-panel]').forEach(p => p.classList.toggle('active', p.dataset.focusPanel === tab));
        setURL();
        if (tab === 'backends') loadBackendHistory();
    }

    function ensureCharts() {
        if (charts) return;
        charts = {
            reqs: chart.line('#focusReqsChart', [], [], { unit: '/s', color: 'var(--accent)' }),
            p99: chart.line('#focusP99Chart', [], [], { unit: 'ms', color: 'var(--warning)' }),
            err: chart.line('#focusErrorsChart', [], [], { unit: '%', color: 'var(--danger)', maxY: 100 }),
            be: chart.line('#focusBackendsChart', [], [], { unit: '', color: 'var(--success)', isInt: true }),
        };
    }

    function configForHost() {
        return (store.get('lastConfig') || {}).hosts?.[host] || {};
    }

    function lbFor(cfgHost, kind, index, stat) {
        if (kind === 'proxy') {
            return (stat?.protocol || (cfgHost.proxies || [])[index]?.protocol || 'tcp').toUpperCase();
        }
        const strategy = stat?.strategy || (cfgHost.routes || [])[index]?.backends?.strategy || 'round_robin';
        return String(strategy).replace(/_/g, ' ');
    }

    function backendValue(r) { return r.route + "\x1f" + r.backend; }

    function renderBackendSelect(rows) {
        const sel = find('#focusBackendSelect');
        if (!sel) return;
        const unique = new Map();
        for (const r of rows) unique.set(backendValue(r), r);
        backendRows = [...unique.values()];
        if (!backendRows.length) {
            sel.innerHTML = '<option>No backends</option>';
            selectedBackend = '';
            if (backendChart) { backendChart.update([], []); }
            return;
        }
        if (!backendRows.some(r => backendValue(r) === selectedBackend)) {
            selectedBackend = backendValue(backendRows[0]);
        }
        sel.innerHTML = backendRows.map(r => {
            const v = backendValue(r);
            return `<option value="${esc(v)}"${v === selectedBackend ? ' selected' : ''}>${esc(r.route)} · ${esc(r.backend)}</option>`;
        }).join('');
    }

    function ensureBackendChart() {
        if (!backendChart) {
            backendChart = chart.line('#focusBackendChart', [], [], { unit: '/s', color: 'var(--accent)' });
        }
        return backendChart;
    }

    async function loadBackendHistory() {
        const row = backendRows.find(r => backendValue(r) === selectedBackend);
        if (!row || !host) return;
        const data = await api.fetchBackendTelemetry(host, row.route, row.backend, range);
        const samples = data?.samples || [];
        const c = ensureBackendChart();
        c?.update(samples.map(x => x.requests_sec), samples.map(x => x.ts));
    }

    function hostStats(hosts) {
        const h = hosts?.[host] || {};
        const cfgHost = configForHost();
        let reqs = Number(h.total_reqs || 0);
        let errors = 0;
        let active = 0;
        let p50 = 0, p50n = 0, p99 = 0, p99n = 0;
        const rows = [];
        for (const [kind, list] of [['route', h.routes || []], ['proxy', h.proxies || []]]) {
            list.forEach((r, idx) => {
                for (const b of (r.backends || [])) {
                    if (b.alive) active++;
                    errors += Number(b.failures || 0);
                    if (b.latency_us?.p50) { p50 += b.latency_us.p50; p50n++; }
                    if (b.latency_us?.p99) { p99 += b.latency_us.p99; p99n++; }
                    rows.push({
                        route: kind === 'proxy' ? (r.name || r.path || 'proxy') : (r.path || '/'),
                        backend: b.url || b.address || '—',
                        lb: lbFor(cfgHost, kind, idx, r),
                        state: b.alive === false ? 'down' : (b.health?.status || 'healthy'),
                        p50: b.latency_us?.p50 || 0,
                        p99: b.latency_us?.p99 || 0,
                        inflight: b.in_flight || 0,
                        reqs: b.total_reqs || 0,
                    });
                }
            });
        }
        return { reqs, errors, active, p50: p50n ? p50/p50n : 0, p99: p99n ? p99/p99n : 0, rows };
    }

    function renderKpis(s) {
        const el = find('#focusKpis');
        if (!el) return;
        const cfgHost = configForHost();
        const lb = [...new Set(s.rows.map(r => r.lb).filter(Boolean))].join(', ') || '—';
        const errPct = s.reqs ? (s.errors / s.reqs * 100) : 0;
        el.innerHTML = `
            <div class="metric-card"><div class="metric-label">Requests</div><div class="metric-value">${fmtNum(s.reqs)}</div></div>
            <div class="metric-card"><div class="metric-label">Errors</div><div class="metric-value">${fmtNum(s.errors)} <span style="font-size:11px;color:var(--text-mute);">${errPct.toFixed(2)}%</span></div></div>
            <div class="metric-card"><div class="metric-label">p50 / p99</div><div class="metric-value">${ms(s.p50)} / ${ms(s.p99)}</div></div>
            <div class="metric-card"><div class="metric-label">Active backends</div><div class="metric-value">${s.active}</div></div>
            <div class="metric-card"><div class="metric-label">LB policy</div><div class="metric-value" style="font-size:13px;">${esc(lb)}</div></div>
            <div class="metric-card"><div class="metric-label">TLS</div><div class="metric-value" style="font-size:13px;">${esc(cfgHost.tls?.mode || 'auto')}</div></div>`;
    }

    function renderBackends(s) {
        const body = find('#focusBackendTable tbody');
        if (!body) return;
        if (!s.rows.length) {
            body.innerHTML = `<tr><td colspan="8" class="focus-empty">No route/backend data for this host</td></tr>`;
            return;
        }
        body.innerHTML = s.rows.map(r => `<tr>
            <td class="mono">${esc(r.route)}</td>
            <td class="mono">${esc(r.backend)}</td>
            <td>${esc(r.lb)}</td>
            <td>${esc(r.state)}</td>
            <td>${r.p50 ? ms(r.p50) : '—'}</td>
            <td>${r.p99 ? ms(r.p99) : '—'}</td>
            <td>${r.inflight || '—'}</td>
            <td>${fmtNum(r.reqs)}</td>
        </tr>`).join('');
    }

    function hostErrorCount(hstat) {
        return [...(hstat.routes || []), ...(hstat.proxies || [])]
            .flatMap(r => r.backends || [])
            .reduce((n, b) => n + Number(b.failures || 0), 0);
    }

    function hostRow(h, stats) {
        const hstat = stats[h] || {};
        const reqs = hstat.total_reqs || 0;
        const errs = hostErrorCount(hstat);
        const isActive = h === host;
        return `<div class="focus-host-row${isActive ? ' active' : ''}" data-focus-host="${esc(h)}">
            <span class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(h)}</span>
            <span>${fmtNum(reqs)}</span>
            <span style="color:${errs ? 'var(--danger)' : 'var(--text-mute)'};">${fmtNum(errs)} err</span>
        </div>`;
    }

    function renderHostList(hosts) {
        const names = Object.keys(hosts || {}).sort((a, b) => {
            const av = hostSort === 'errors' ? hostErrorCount(hosts[a] || {}) : (hosts[a]?.total_reqs || 0);
            const bv = hostSort === 'errors' ? hostErrorCount(hosts[b] || {}) : (hosts[b]?.total_reqs || 0);
            return bv - av || a.localeCompare(b);
        });
        const list = find('#focusHostList');
        if (list) list.innerHTML = names.map(h => hostRow(h, hosts)).join('') || '<div class="focus-empty">No hosts available</div>';
        const sortBtn = find('#focusHostSort');
        if (sortBtn) sortBtn.textContent = `Sort: ${hostSort === 'errors' ? 'Errors' : 'Requests'} ⇅`;
    }

    function renderTopBackends(rows) {
        const el = find('#focusTopBackends');
        if (!el) return;
        const grouped = new Map();
        for (const r of rows) {
            const cur = grouped.get(r.backend) || { name: r.backend, reqs: 0 };
            cur.reqs += Number(r.reqs || 0);
            grouped.set(r.backend, cur);
        }
        const top = [...grouped.values()].sort((a, b) => b.reqs - a.reqs).slice(0, 10);
        const legend = find('#focusBackendLegend');
        if (!top.length) {
            if (backendsChart && typeof backendsChart.destroy === 'function') backendsChart.destroy();
            backendsChart = null;
            el.innerHTML = '<div class="focus-empty">No backends for this host</div>';
            if (legend) legend.innerHTML = '';
            return;
        }
        if (backendsChart && typeof backendsChart.destroy === 'function') backendsChart.destroy();
        backendsChart = null;
        el.innerHTML = '';
        const colors = top.map(x => backendColor(x.name));
        backendsChart = chart.bar('#focusTopBackends', top.map(x => x.reqs), {
            unit: '',
            colors,
            label: 'Top backends by requests',
        });
        if (legend) {
            legend.innerHTML = top.map((x, i) =>
                `<span><i style="background:${colors[i]};"></i>${esc(x.name)} · ${fmtNum(x.reqs)} req</span>`
            ).join('');
        }
    }

    function renderCharts(samples) {
        ensureCharts();
        if (!charts) return;
        const ts = samples.map(x => x.ts);
        charts.reqs.update(samples.map(x => x.requests_sec), ts);
        charts.p99.update(samples.map(x => x.p99_ms), ts);
        charts.err.update(samples.map(x => x.error_rate), ts);
        charts.be.update(samples.map(x => x.active_backends), ts);
    }

    function renderLogs(logs) {
        const el = find('#focusLogs');
        if (!el) return;
        const rows = [];
        for (const raw of (Array.isArray(logs) ? logs : (logs?.logs || []))) {
            let p = raw;
            if (typeof raw === 'string') { try { p = JSON.parse(raw); } catch { p = { msg: raw }; } }
            const h = p?.fields?.host || p?.host || '';
            if (host && h && h !== host) continue;
            if (!host && !h) continue;
            const lvl = p?.lvl || p?.level || 'INFO';
            const msg = p?.msg || p?.message || '';
            const f = p?.fields || {};
            const detail = f.path ? ` ${f.method || ''} ${f.path}` : '';
            rows.push(`<div class="focus-log-row"><span class="mono" style="color:var(--text-mute);">${esc(lvl)}</span> ${esc(msg + detail)}</div>`);
            if (rows.length >= 120) break;
        }
        el.innerHTML = rows.length ? rows.join('') : '<div class="focus-empty">No recent log entries for this host</div>';
    }

    async function loadHosts() {
        const data = await api.fetchUptime();
        hostsCache = data?.hosts || {};
        const names = Object.keys(hostsCache).sort();
        const sel = find('#focusHost');
        if (!host && names.length) host = names[0];
        if (sel) sel.innerHTML = names.map(h => `<option value="${esc(h)}"${h === host ? ' selected' : ''}>${esc(h)}</option>`).join('');
        return names;
    }

    async function refresh() {
        const data = await api.fetchUptime();
        hostsCache = data?.hosts || {};
        if (!host && Object.keys(hostsCache).length) { host = Object.keys(hostsCache).sort()[0]; setURL(); }
        const sel = find('#focusHost');
        if (sel && host) sel.value = host;
        const s = hostStats(hostsCache);
        renderKpis(s);
        renderBackends(s);
        renderBackendSelect(s.rows);
        renderHostList(hostsCache);
        renderTopBackends(s.rows);
        const title = find('#focusTitle');
        if (title) title.textContent = host || 'Focus';
        const crumb = find('#focusCrumb');
        if (crumb) crumb.textContent = `host / ${host || '—'}  ·  ${range}  ·  live`;
        if (host) {
            const tel = await api.fetchTelemetry(host, range);
            renderCharts(tel?.samples || []);
            if (tab === 'backends') await loadBackendHistory();
            const logs = await api.fetchLogs(200);
            renderLogs(logs);
        }
    }

    async function boot() {
        if (kiosk) document.body.classList.add('focus-kiosk');
        const rangeEl = find('#focusRange');
        if (rangeEl) rangeEl.value = range;
        const sortBtn = find('#focusHostSort');
        if (sortBtn) sortBtn.textContent = `Sort: ${hostSort === 'errors' ? 'Errors' : 'Requests'} ⇅`;
        setTab(tab);
        await loadHosts();
        if (!host) {
            find('#focusKpis').innerHTML = '<div class="empty-state" style="grid-column:1/-1;">No hosts available</div>';
            ready();
            return;
        }
        setURL();
        await refresh();
        timer = setInterval(() => { if (!paused) refresh(); }, 5000);
    }

    on('#focusHost', 'change', async (e, el) => { host = el.value; setURL(); await refresh(); });
    on('#focusRange', 'change', async (e, el) => { range = el.value; setURL(); await refresh(); });
    on('#focusPauseBtn', 'click', (e, btn) => { paused = !paused; btn.textContent = paused ? 'Resume' : 'Pause'; });
    on('#focusKioskBtn', 'click', () => setKiosk(!kiosk));
    on('#focusOpenBtn', 'click', () => {
        const p = new URLSearchParams({ host, range, tab, sort: hostSort });
        if (kiosk) p.set('kiosk', '1');
        window.open('/#/focus?' + p.toString(), '_blank');
    });
    on('#focusBackendSelect', 'change', async (e, el) => {
        selectedBackend = el.value;
        await loadBackendHistory();
    });
    on('#focusHostSort', 'click', () => {
        hostSort = hostSort === 'requests' ? 'errors' : 'requests';
        setURL();
        renderHostList(hostsCache);
    });
    on('[data-focus-tab]', 'click', (e, btn) => setTab(btn.dataset.focusTab));
    on('[data-focus-host]', 'click', async (e, el) => {
        host = el.dataset.focusHost;
        setURL();
        await refresh();
        // Preserve the normal host interaction: clicking a host opens the
        // standard side drawer as well as changing the dashboard scope.
        oja.emit('drawer:open-route', { host, idx: 0, type: 'route' });
    });

    await boot();
    onUnmount(() => { if (timer) clearInterval(timer); document.body.classList.remove('focus-kiosk'); });
    ready();
}
