/**
 * pages/routes.js — route manager.
 *
 * One place for everything about a single route, in tabs:
 *   Overview · Backends · Access (auth, embedded intercept page) ·
 *   Traffic policy · Cache · HCL
 *
 *   #/routes?host=example.com&route=/api&tab=backends
 *   #/routes?host=example.com&route=proxy:postgres
 */
import { Out, emit, notify, clipboard, chart } from '../lib/oja.full.esm.js';
import { highlightHCL } from '../js/hcl.js';

const TABS = ['overview', 'backends', 'access', 'policy', 'cache', 'hcl'];

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { store, api, utils } = inject('app');
    const isOn = utils?.isOn || (v => v === true || v === 'on' || v === 'true');
    const params = new URLSearchParams((window.location.hash.replace(/^#/, '').split('?')[1] || ''));
    const state = {
        host: params.get('host') || '',
        route: params.get('route') || '',
        tab: TABS.includes(params.get('tab')) ? params.get('tab') : 'overview',
        backend: '', range: '1h', hcl: '',
    };
    let cfg = store.get('lastConfig') || null;
    let uptime = null, beChart = null, timer = null;

    const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    const fmtNum = n => { n = Number(n || 0); return n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e4 ? (n / 1e3).toFixed(1) + 'k' : String(n); };
    const fmtMs = us => { const v = Number(us || 0) / 1000; return v ? (v < 10 ? v.toFixed(1) : Math.round(v)) + 'ms' : '—'; };

    function setURL() {
        const p = new URLSearchParams();
        if (state.host) p.set('host', state.host);
        if (state.route) p.set('route', state.route);
        if (state.tab !== 'overview') p.set('tab', state.tab);
        history.replaceState(null, '', '#/routes?' + p.toString());
    }

    // ── model ───────────────────────────────────────────────────────────────
    const hostCfg = () => cfg?.hosts?.[state.host] || {};
    const hostStat = () => uptime?.hosts?.[state.host] || {};

    function entries() {
        const h = hostCfg();
        return [
            ...(h.routes || []).map((r, i) => ({ id: r.path || '/', kind: 'route', idx: i, cfg: r, label: r.path || '/' })),
            ...(h.proxies || []).map((p, i) => ({ id: 'proxy:' + (p.name || i), kind: 'proxy', idx: i, cfg: p, label: p.name || p.listen || 'proxy' })),
        ];
    }
    function current() {
        const list = entries();
        return list.find(e => e.id === state.route) || list[0] || null;
    }
    function statFor(e) {
        if (!e) return {};
        const s = hostStat();
        return (e.kind === 'proxy' ? s.proxies : s.routes)?.[e.idx] || {};
    }
    function engineOf(e) {
        const r = e.cfg;
        if (e.kind === 'proxy') return (r.protocol || 'tcp').toUpperCase() + ' proxy';
        if (r.serverless && isOn(r.serverless.enabled)) return 'Serverless';
        if (r.web) return isOn(r.web.markdown?.enabled) ? 'Markdown' : 'Static web';
        if (r.backends?.servers?.length) return r.backends.servers.length > 1 ? 'Load balancer' : 'Reverse proxy';
        return 'Route';
    }
    function backendState(b) {
        const s = b.health?.status || '';
        if (b.alive === false || s === 'Dead' || s === 'Unhealthy') return 'down';
        if (s === 'Degraded') return 'warn';
        return 'ok';
    }
    function backends(e) {
        const stat = statFor(e).backends || [];
        const conf = e.kind === 'proxy' ? (e.cfg.backends || []) : (e.cfg.backends?.servers || []);
        const n = Math.max(stat.length, conf.length);
        return Array.from({ length: n }, (_, i) => {
            const s = stat[i] || {}, c = conf[i] || {};
            return { url: s.url || s.address || c.address || '—', weight: c.weight ?? s.weight ?? 1, state: stat[i] ? backendState(s) : 'idle', health: s.health?.status || '', reqs: s.total_reqs || 0, fails: s.failures || 0, p50: s.latency_us?.p50, p99: s.latency_us?.p99, inflight: s.in_flight || 0 };
        });
    }

    // flatten renders any config subtree as dotted key → value rows, so every
    // option set on the route is visible without a bespoke view per block.
    function flatten(obj, prefix = '', out = []) {
        if (obj == null) return out;
        if (Array.isArray(obj)) {
            if (!obj.length) return out;
            if (obj.every(v => v == null || typeof v !== 'object')) { out.push([prefix, obj.join(', ')]); return out; }
            obj.forEach((v, i) => flatten(v, `${prefix}[${i}]`, out));
            return out;
        }
        if (typeof obj === 'object') {
            for (const [k, v] of Object.entries(obj)) flatten(v, prefix ? `${prefix}.${k}` : k, out);
            return out;
        }
        if (obj === '' || obj === 0 || obj === false || obj === 'unknown') return out;
        out.push([prefix, String(obj)]);
        return out;
    }
    // Secrets never come back unredacted from the API; still, never echo
    // anything that looks like one.
    const secretKey = /secret|password|token|key$|passphrase/i;
    function kvBox(title, obj, empty = 'Not configured') {
        const rows = flatten(obj).map(([k, v]) => `<dt>${esc(k)}</dt><dd>${secretKey.test(k) && !/^ss:\/\/|^env\./.test(v) ? '••••••' : esc(v)}</dd>`);
        return `<div class="rm-box"><h3><span>${esc(title)}</span></h3>${rows.length ? `<dl class="rm-kv">${rows.join('')}</dl>` : `<div class="rm-empty">${esc(empty)}</div>`}</div>`;
    }

    // ── render ──────────────────────────────────────────────────────────────
    function renderHead(e) {
        const t = find('#rmTitle'), sub = find('#rmSub');
        if (t) t.textContent = e ? `${state.host}  ${e.label}` : state.host || 'Routes';
        if (sub) sub.textContent = e ? `${engineOf(e)} · ${hostCfg().source_file || 'config'}` : 'This host has no routes.';
        const chips = find('#rmChips');
        if (chips) chips.innerHTML = entries().map(x => `<button class="rm-chip${e && x.id === e.id ? ' active' : ''}" data-rm-route="${esc(x.id)}">${esc(x.label)}<small>${esc(engineOf(x))}</small></button>`).join('');
        const cnt = find('#rmBeCount');
        if (cnt) cnt.textContent = e ? String(backends(e).length || '') : '';
    }

    function renderOverview(e) {
        const el = find('#rmOverview');
        if (!el) return;
        if (!e) { el.innerHTML = '<div class="rm-empty">No routes on this host.</div>'; return; }
        const r = e.cfg, s = statFor(e), bes = backends(e);
        const reqs = bes.reduce((n, b) => n + b.reqs, 0) || s.total_reqs || 0;
        const fails = bes.reduce((n, b) => n + b.fails, 0);
        const up = bes.filter(b => b.state !== 'down').length;
        const p99s = bes.map(b => b.p99).filter(Boolean);
        const engine = e.kind === 'proxy'
            ? { listen: r.listen, protocol: r.protocol, sni: r.sni, strategy: r.strategy, matcher: r.matcher }
            : { web: r.web, backends: r.backends ? { strategy: r.backends.strategy, servers: (r.backends.servers || []).length } : null, serverless: r.serverless };
        const shape = e.kind === 'proxy' ? {} : { strip_prefixes: r.strip_prefixes, rewrites: r.rewrites, timeouts: r.timeouts, env: r.env ? Object.keys(r.env) : null };
        const exposes = (r.exposes || []).map(x => `<span class="badge success">RELAY ${esc(x.via)} → /${esc(x.id)}${x.subdomain ? ' + sub' : ''}</span>`).join('');
        el.innerHTML = `
            <div class="rm-stats">
                <div class="rm-stat"><b>${fmtNum(reqs)}</b><span>Requests</span></div>
                <div class="rm-stat"><b style="color:${fails ? 'var(--danger)' : 'inherit'}">${fmtNum(fails)}</b><span>Failures</span></div>
                <div class="rm-stat"><b>${bes.length ? `${up}/${bes.length}` : '—'}</b><span>Backends up</span></div>
                <div class="rm-stat"><b>${p99s.length ? fmtMs(Math.max(...p99s)) : '—'}</b><span>Worst p99</span></div>
            </div>
            ${exposes ? `<div class="rm-badges" style="margin-bottom:12px;">${exposes}</div>` : ''}
            <div class="rm-grid">${kvBox('Engine', engine)}${kvBox('Request shaping', shape, 'No rewrites, prefix stripping or timeouts')}</div>
            <div class="rm-actions">
                <button class="btn small" data-rm-goto="backends">Backends</button>
                <button class="btn small" data-rm-goto="access">Access</button>
                <button class="btn small" data-rm-goto="policy">Traffic policy</button>
                <button class="btn small" id="rmOpenDrawer">Quick view</button>
            </div>`;
    }

    function renderBackends(e) {
        const body = find('#rmBeTable tbody');
        if (!body) return;
        const bes = e ? backends(e) : [];
        if (!bes.length) { body.innerHTML = `<tr><td colspan="8" class="rm-empty">${e ? 'This route has no upstream backends; it is served by the host itself.' : '—'}</td></tr>`; return; }
        if (!bes.some(b => b.url === state.backend)) state.backend = bes[0].url;
        body.innerHTML = bes.map(b => `<tr class="${b.url === state.backend ? 'sel' : ''}" data-rm-be="${esc(b.url)}">
            <td class="mono"><span class="rm-dot ${b.state}"></span>${esc(b.url)}</td><td>${esc(b.health || b.state)}</td><td>${esc(b.weight)}</td>
            <td>${fmtNum(b.reqs)}</td><td style="color:${b.fails ? 'var(--danger)' : 'inherit'}">${fmtNum(b.fails)}</td>
            <td>${fmtMs(b.p50)}</td><td>${fmtMs(b.p99)}</td><td>${b.inflight || '—'}</td></tr>`).join('');
    }

    async function loadBackendChart(e) {
        if (!e || !state.backend || state.tab !== 'backends') return;
        const title = find('#rmBeChartTitle');
        if (title) title.textContent = `Requests/sec · ${state.backend}`;
        if (!beChart) beChart = chart.line('#rmBeChart', [], [], { unit: '/s', color: 'var(--accent)' });
        const routeKey = e.kind === 'proxy' ? (e.cfg.name || e.label) : e.label;
        const data = await api.fetchBackendTelemetry(state.host, routeKey, state.backend, state.range);
        const sm = data?.samples || [];
        beChart.update(sm.map(x => x.requests_sec), sm.map(x => x.ts));
    }

    function renderPolicy(e) {
        const el = find('#rmPolicy');
        if (!el) return;
        if (!e || e.kind === 'proxy') { el.innerHTML = `<div class="rm-empty">${e ? 'Traffic policy applies to HTTP routes.' : '—'}</div>`; return; }
        const r = e.cfg;
        el.innerHTML = `
            <div class="rm-actions" style="margin-bottom:12px;">
                <button class="btn small" id="rmBlockIp">Block IP…</button>
                <button class="btn small" data-rm-edit>Edit in HCL</button>
            </div>
            <div class="rm-grid">
                ${kvBox('Rate limit', isOn(r.rate_limit?.enabled) ? r.rate_limit : null, 'No rate limit')}
                ${kvBox('IP filter', r.allowed_ips?.length ? { allowed_ips: r.allowed_ips } : null, 'All client IPs allowed')}
                ${kvBox('Firewall / WAF', isOn(r.firewall?.enabled) ? r.firewall : null, 'Route firewall off (global rules still apply)')}
                ${kvBox('CORS', isOn(r.cors?.enabled) ? r.cors : null, 'CORS off')}
                ${kvBox('Headers', r.headers, 'No header changes')}
                ${kvBox('Compression', isOn(r.compression?.enabled) ? r.compression : null, 'Compression off')}
                ${kvBox('Health check', r.backends?.health_check || r.health_check, 'No active health check')}
                ${kvBox('Fallback', isOn(r.fallback?.enabled) ? r.fallback : null, 'No fallback')}
            </div>`;
    }

    async function renderCache(e) {
        const el = find('#rmCache');
        if (!el) return;
        const routeCache = e && e.kind !== 'proxy' && isOn(e.cfg.cache?.enabled) ? e.cfg.cache : null;
        const stats = await api.fetchCacheStats();
        el.innerHTML = `
            <div class="rm-grid">
                ${kvBox('This route', routeCache, 'Caching is off for this route')}
                ${kvBox('Cache store (all routes)', stats || null, 'Cache store not available')}
            </div>
            <div class="rm-box">
                <h3><span>Purge</span></h3>
                <div class="rm-actions">
                    <input id="rmPurgeTag" class="wz-input" placeholder="cache tag" style="max-width:260px;">
                    <button class="btn small" id="rmPurgeBtn">Purge tag</button>
                    <button class="btn small danger" id="rmClearCache">Clear entire cache…</button>
                </div>
            </div>`;
    }

    function extractRouteBlock(hcl, e) {
        if (!hcl || !e) return '';
        const head = e.kind === 'proxy' ? new RegExp(`^\\s*proxy\\s+"${(e.cfg.name || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*\\{`, 'm')
                                       : new RegExp(`^\\s*route\\s+"${e.label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"\\s*\\{`, 'm');
        const m = head.exec(hcl);
        if (!m) return '';
        let depth = 0, i = m.index, inStr = false;
        for (; i < hcl.length; i++) {
            const c = hcl[i];
            if (c === '"' && hcl[i - 1] !== '\\') inStr = !inStr;
            if (inStr) continue;
            if (c === '{') depth++;
            if (c === '}' && --depth === 0) { i++; break; }
        }
        return hcl.slice(m.index, i).replace(/^\s*\n/, '');
    }

    async function renderHCL(e) {
        const el = find('#rmHcl');
        if (!el) return;
        if (!state.hcl) state.hcl = (await api.getHostHCL(state.host)) || '';
        const block = extractRouteBlock(state.hcl, e) || (state.hcl ? '# route block not found — showing the whole host\n' + state.hcl : '# HCL unavailable');
        try { el.innerHTML = highlightHCL(block); } catch { el.textContent = block; }
        el.dataset.raw = block;
    }

    let accessKey = '';
    function renderAccess(e) {
        const el = find('#rmAccess');
        if (!el) return;
        const key = e ? state.host + '\u0000' + e.id : '';
        if (key === accessKey) return;
        accessKey = key;
        if (!e || e.kind === 'proxy') { el.innerHTML = '<div class="rm-empty">Access control applies to HTTP routes.</div>'; return; }
        const slot = document.createElement('div');
        el.replaceChildren(slot);
        Out.to(slot).module('/pages/intercept.js', '/pages/intercept.html', { embedded: true, host: state.host, route: e.label }).render();
    }

    function setTab(name) {
        state.tab = TABS.includes(name) ? name : 'overview';
        findAll('[data-rm-tab]').forEach(b => b.classList.toggle('active', b.dataset.rmTab === state.tab));
        findAll('[data-rm-panel]').forEach(p => p.classList.toggle('active', p.dataset.rmPanel === state.tab));
        setURL();
        renderTab();
    }

    function renderTab() {
        const e = current();
        switch (state.tab) {
            case 'overview': renderOverview(e); break;
            case 'backends': renderBackends(e); loadBackendChart(e); break;
            case 'access':   renderAccess(e); break;
            case 'policy':   renderPolicy(e); break;
            case 'cache':    renderCache(e); break;
            case 'hcl':      renderHCL(e); break;
        }
    }

    function renderAll() {
        const e = current();
        if (e && state.route !== e.id) { state.route = e.id; setURL(); }
        renderHead(e);
        renderTab();
    }

    // ── load ────────────────────────────────────────────────────────────────
    async function loadConfig() {
        const fresh = await api.fetchConfig();
        if (fresh?.hosts) { cfg = fresh; store.set('lastConfig', fresh); }
        const hosts = Object.keys(cfg?.hosts || {}).sort();
        if (!hosts.includes(state.host)) state.host = hosts[0] || '';
        const sel = find('#rmHost');
        if (sel) { sel.innerHTML = hosts.map(h => `<option value="${esc(h)}">${esc(h)}</option>`).join(''); sel.value = state.host; }
    }
    async function loadStats() {
        uptime = await api.fetchUptime();
        if (state.tab === 'overview' || state.tab === 'backends') { const e = current(); renderHead(e); state.tab === 'overview' ? renderOverview(e) : renderBackends(e); }
    }

    // ── events ──────────────────────────────────────────────────────────────
    on('#rmHost', 'change', (ev, el) => { state.host = el.value; state.route = ''; state.hcl = ''; setURL(); loadStats().then(renderAll); });
    on('[data-rm-route]', 'click', (ev, el) => { state.route = el.dataset.rmRoute; state.backend = ''; renderAll(); setURL(); });
    on('[data-rm-tab]', 'click', (ev, el) => setTab(el.dataset.rmTab));
    on('[data-rm-goto]', 'click', (ev, el) => setTab(el.dataset.rmGoto));
    on('[data-rm-be]', 'click', (ev, el) => { state.backend = el.dataset.rmBe; renderBackends(current()); loadBackendChart(current()); });
    on('#rmBeRange', 'change', (ev, el) => { state.range = el.value; loadBackendChart(current()); });
    on('#rmFocus', 'click', () => window.open('/#/focus?host=' + encodeURIComponent(state.host), '_blank'));
    on('#rmOpenDrawer', 'click', () => { const e = current(); if (e) emit('drawer:open-route', { host: state.host, idx: e.idx, type: e.kind }); });
    on('#rmBlockIp', 'click', () => emit('firewall:open-rule', { host: state.host }));
    const editHCL = async () => {
        const hcl = state.hcl || await api.getHostHCL(state.host);
        if (!hcl) { notify.show('Could not load HCL', 'error'); return; }
        emit('host:open-edit-hcl', { domain: state.host, hcl });
    };
    on('#rmEditHcl', 'click', editHCL);
    on('#rmEditHcl2', 'click', editHCL);
    on('[data-rm-edit]', 'click', editHCL);
    on('#rmCopyHcl', 'click', () => clipboard.write(find('#rmHcl')?.dataset.raw || '').then(() => notify.show('Copied', 'success')));
    on('#rmPurgeBtn', 'click', async () => {
        const tag = (find('#rmPurgeTag')?.value || '').trim();
        if (!tag) { notify.show('Enter a cache tag', 'error'); return; }
        const res = await api.purgeCacheTag(tag);
        notify.show(res ? `Purged "${tag}"` : 'Purge failed', res ? 'success' : 'error');
    });
    on('#rmClearCache', 'click', () => emit('app:strict-delete', {
        message: 'Clear <strong>every</strong> cached response for all hosts.',
        targetText: 'clear cache',
        onConfirm: async () => { const res = await api.clearCache(); notify.show(res ? 'Cache cleared' : 'Clear failed', res ? 'success' : 'error'); renderCache(current()); },
    }));

    await loadConfig();
    await loadStats();
    renderAll();
    setTab(state.tab);
    timer = setInterval(loadStats, 5000);
    onUnmount(() => clearInterval(timer));
    ready();
}
