/**
 * js/drawer-listeners.js
 *
 * Route and backend drawer wiring.
 * Each section of the drawer is a named builder function that returns an
 * HTML string. buildRouteHTML and buildBackendHTML compose those sections.
 * No addEventListener loops — all interaction uses on() delegation.
 */

import { listen, emit, on, clipboard, notify, query, queryAll } from '../lib/oja.full.esm.js';
import { store } from './store.js';
import { fmtNum } from './api.js';

// ── Drawer open / close ────────────────────────────────────────────────────────

function openDrawer(id) {
    query('#' + id)?.classList.add('active');
    query('#drawerBackdrop')?.classList.add('active');
}

function closeDrawer(id) {
    query('#' + id)?.classList.remove('active');
    if (!query('.drawer.active')) {
        query('#drawerBackdrop')?.classList.remove('active');
    }
}

on('[data-action="close-drawer"]', 'click', (e, btn) => closeDrawer(btn.dataset.target));

on('#drawerBackdrop', 'click', () => {
    queryAll('.drawer.active').forEach(d => d.classList.remove('active'));
    query('#drawerBackdrop')?.classList.remove('active');
});

// Performance button inside the route drawer
on('#drawerPerfBtn', 'click', () => {
    const hostname = query('#drawerHostName')?.innerText;
    if (hostname) emit('perf:open', { hostname });
});

// ── Delegated drawer interactions — registered once, work across re-renders ───

on('[data-action="open-backend"]', 'click', (e, btn) => {
    emit('drawer:open-backend', {
        host:       btn.dataset.host,
        routeIdx:   parseInt(btn.dataset.routeIdx),
        backendIdx: parseInt(btn.dataset.backendIdx),
        type:       btn.dataset.type,
    });
});

on('[data-action="copy-url"]', 'click', (e, btn) => {
    e.stopPropagation();
    clipboard.write(btn.dataset.url)
        .then(() => notify.show('Copied', 'success'))
        .catch(() => {});
});

// ── Listen for drawer open events ─────────────────────────────────────────────

listen('drawer:open-route', ({ host, idx, type }) => {
    const hostCfg   = (store.get('lastConfig') || {}).hosts?.[host]         || {};
    const hostStats = (store.get('hostsData')  || { stats: {} }).stats?.[host] || {};

    const item      = type === 'proxy' ? hostCfg.proxies?.[idx]  : hostCfg.routes?.[idx];
    if (!item) return;
    const itemStats = type === 'proxy' ? hostStats.proxies?.[idx] : hostStats.routes?.[idx];

    const path = item.path || (item.name ? item.name.replace('*default*', '* (TCP)') : item.protocol || '*');
    const el   = query('#drawerRoutePath');
    const hn   = query('#drawerHostName');
    if (el) el.innerText = path;
    if (hn) hn.innerText = host;

    const body = query('#drawerBody');
    if (body) body.innerHTML = buildRouteHTML(host, item, itemStats || {}, type, store.get('certificates') || [], idx);

    openDrawer('routeDrawer');
});

listen('drawer:open-backend', ({ host, routeIdx, backendIdx, type }) => {
    const hostCfg   = (store.get('lastConfig') || {}).hosts?.[host]         || {};
    const hostStats = (store.get('hostsData')  || { stats: {} }).stats?.[host] || {};

    const cfgItem = type === 'proxy'
        ? (hostCfg.proxies?.[routeIdx]?.backends?.[backendIdx]         || {})
        : (hostCfg.routes?.[routeIdx]?.backends?.servers?.[backendIdx] || {});
    const bStat = type === 'proxy'
        ? (hostStats.proxies?.[routeIdx]?.backends?.[backendIdx]        || {})
        : (hostStats.routes?.[routeIdx]?.backends?.[backendIdx]         || {});

    const url = bStat.url || bStat.address || cfgItem.address || 'Unknown';
    const titleEl = query('#backendDrawerTitle');
    const urlEl   = query('#backendDrawerUrl');
    if (titleEl) titleEl.innerText = 'Backend Activity';
    if (urlEl)   urlEl.innerText   = url;

    const body = query('#backendDrawerBody');
    if (body) body.innerHTML = buildBackendHTML(cfgItem, bStat);

    openDrawer('backendDrawer');
});

// ── Section builders — each returns an HTML string, composable ────────────────

function section(title, content) {
    return `<div class="detail-section">
        <div class="detail-title">${title}</div>
        ${content}
    </div>`;
}

function kvGrid(pairs) {
    const items = pairs
        .filter(([, v]) => v !== null && v !== undefined && v !== '')
        .map(([label, value]) =>
            `<div class="kv-item"><label>${label}</label><div>${value}</div></div>`
        ).join('');
    return `<div class="kv-grid">${items}</div>`;
}

function badge(text, cls = '') {
    return `<span class="badge ${cls}">${text}</span>`;
}

// ── Route section builders ─────────────────────────────────────────────────────

function gitSection(git, hostname) {
    const gitStats = store.get('gitStats') || {};
    const gs       = gitStats[git.id]      || {};
    const state    = gs.state  || 'unknown';
    const commit   = gs.commit ? gs.commit.substring(0, 8) : 'none';
    const sCls     = state === 'healthy' ? 'success' : state === 'unavailable' ? 'warning' : 'error';
    const whUrl    = `${window.location.origin}/.well-known/agbero/webhook/git/${git.id}`;

    return section('🐙 Git Deployment', `
        <div class="handler-card">
            <span class="handler-icon">📦</span>
            <div class="handler-info" style="flex:1;">
                <strong>${git.id}</strong>
                <span>Branch: ${git.branch || 'main'}</span>
                <div style="margin-top:8px;display:flex;gap:10px;flex-wrap:wrap;">
                    ${badge('State: ' + state, sCls)}
                    ${badge('Commit: ' + commit, 'info')}
                    ${badge('Deploys: ' + (gs.deployments || 0))}
                </div>
            </div>
        </div>
        <div class="kv-grid" style="margin-top:10px;">
            <div class="kv-item" style="grid-column:span 2;">
                <label>Webhook URL</label>
                <div style="display:flex;gap:10px;align-items:center;">
                    <span class="mono" style="font-size:10px;padding:6px;background:var(--bg);border:1px solid var(--border);border-radius:4px;flex:1;overflow-x:auto;">${whUrl}</span>
                    <button class="btn small" data-action="copy-url" data-url="${whUrl}">Copy</button>
                </div>
            </div>
        </div>`);
}

function staticSection(web) {
    return section('📂 Static File Handler', `
        <div class="handler-card">
            <span class="handler-icon">📁</span>
            <div class="handler-info">
                <strong>File Server</strong>
                <span>Root: ${web.root}</span>
                <span>Listing: ${web.listing ? 'Enabled' : 'Disabled'}</span>
                ${web.spa                          ? '<span>SPA mode: on</span>'  : ''}
                ${web.markdown?.enabled === 'on'   ? '<span>Markdown: on</span>' : ''}
            </div>
        </div>
        ${web.php?.enabled === 'on' ? `
        <div class="handler-card" style="margin-top:8px;">
            <span class="handler-icon">🐘</span>
            <div class="handler-info">
                <strong>PHP FastCGI</strong>
                <span>${web.php.address || '127.0.0.1:9000'}</span>
            </div>
        </div>` : ''}`);
}

function backendRow(b, cfgB, bStat, hostname, routeIdx, bIdx, type) {
    const url  = bStat.url || bStat.address || cfgB.address || '';
    const w    = cfgB.weight !== undefined ? cfgB.weight : 1;
    const has  = !!bStat.url || !!bStat.address;
    const hSt  = bStat.health?.status || 'Unknown';

    let dc = 'warn', dt = 'No data';
    if (has) {
        if      (!bStat.alive || hSt === 'Dead' || hSt === 'Unhealthy') { dc = 'down'; dt = hSt !== 'Unknown' ? hSt : 'Dead'; }
        else if (hSt === 'Degraded')                                     { dc = 'warn'; dt = 'Degraded'; }
        else if (hSt === 'Healthy')                                      { dc = 'ok';   dt = 'Healthy'; }
        else                                                             { dc = bStat.alive ? 'info' : 'down'; dt = bStat.alive ? 'Unverified' : 'Dead'; }
    }

    const p99  = bStat.latency_us?.p99 ? (bStat.latency_us.p99 / 1000).toFixed(0) + 'ms' : '';
    const inf  = bStat.in_flight  || 0;
    const fail = bStat.failures   || 0;
    const reqs = bStat.total_reqs || 0;
    const wCls = dc === 'ok' ? 'success' : dc === 'warn' ? 'warning' : 'error';

    return `<div class="drawer-row clickable" data-action="open-backend"
            data-host="${hostname}" data-route-idx="${routeIdx}"
            data-backend-idx="${bIdx}" data-type="${type}">
        <div class="drawer-row-top">
            <div class="row-left">
                <span class="dot ${dc}" title="${dt}"></span>
                <span class="mono row-url">${url}</span>
            </div>
            <div class="row-right">
                ${inf  > 0 ? `<span class="be-tag be-tag-warn">⚡ ${inf} in flight</span>` : ''}
                ${fail > 0 ? `<span class="be-tag be-tag-danger">⚠️ ${fmtNum(fail)} fails</span>` : ''}
            </div>
        </div>
        <div class="drawer-row-bottom">
            ${p99 ? `<span class="be-tag be-tag-info">p99: ${p99}</span>` : ''}
            <span class="be-tag be-tag-${wCls}">W: ${w}</span>
            <span class="be-tag">${fmtNum(reqs)} reqs</span>
        </div>
    </div>`;
}

function upstreamsSection(hostname, item, itemStats, routeIdx, type) {
    const configBEs  = item.backends?.servers || [];
    const statBEs    = itemStats.backends     || [];
    const displayBEs = configBEs.length > 0 ? configBEs : statBEs;
    if (!displayBEs.length) return '';

    const rows = displayBEs.map((b, bIdx) =>
        backendRow(b, configBEs[bIdx] || {}, statBEs[bIdx] || {}, hostname, routeIdx, bIdx, type)
    ).join('');

    const lb  = (item.backends?.strategy || 'round_robin')
        .split('_').map(w => w[0].toUpperCase() + w.slice(1)).join(' ');
    const hc  = item.health_check;
    const cb  = item.circuit_breaker;
    const to  = item.timeouts || {};
    const fmt = v => v || 'inherit';
    const isTCP     = type === 'proxy' || item.protocol === 'tcp';
    const protoClass= isTCP ? 'info' : 'success';
    const protoLabel= (isTCP ? '🔌 TCP' : '🌐 HTTP');

    const hcBadge = hc?.enabled === 'on'
        ? badge(`${hc.path || '/health'} | ${hc.interval || '10s'} | ${hc.timeout || '5s'}`, 'success')
        : badge('Not Configured', 'error');
    const cbPairs  = cb?.enabled === 'on'
        ? [['Circuit Breaker', badge(`${cb.threshold || 5} fails → ${cb.duration || '30s'}`, 'warning')]]
        : [];

    return section(
        `${badge(protoLabel, protoClass)} Upstreams &amp; Load Balancing`,
        rows + kvGrid([
            ['Strategy',      badge(lb, 'success')],
            ['Health Check',  hcBadge],
            ...cbPairs,
            ['Read Timeout',  fmt(to.read)],
            ['Write Timeout', fmt(to.write)],
            ['Idle Timeout',  fmt(to.idle)],
        ])
    );
}

function httpFeaturesSection(item) {
    const pairs = [];
    const comp = item.compression_config || {};
    if (comp.enabled === 'on')
        pairs.push(['Compression', badge(`${comp.type || 'gzip'} lvl ${comp.level || 'auto'}`, 'info')]);
    const rl = item.rate_limit;
    if (rl?.enabled === 'on') {
        const r = rl.rule || {};
        pairs.push(['Rate Limit', badge(`${r.requests || 0} / ${r.window || '1m'} (${r.key || 'ip'})`, 'warning')]);
    }
    if (item.cors?.enabled === 'on')
        pairs.push(['CORS', badge((item.cors.allowed_origins || []).join(', ') || '*', 'info')]);
    if (item.strip_prefixes?.length)
        pairs.push(['Strip Prefix', item.strip_prefixes.map(p => badge(p)).join(' ')]);
    if (item.wasm?.enabled === 'on')
        pairs.push(['WASM', badge(item.wasm.module?.split('/').pop() || 'filter.wasm', 'info')]);
    if (item.headers?.enabled === 'on') {
        const rh = item.headers.request || {}, rs = item.headers.response || {};
        const n  = [rh.set, rh.add, rs.set, rs.add].filter(Boolean)
                .reduce((a, o) => a + Object.keys(o).length, 0)
            + (rh.remove?.length || 0) + (rs.remove?.length || 0);
        if (n) pairs.push(['Header Rules', badge(n + ' modifications', 'info')]);
    }
    return pairs.length ? section('⚙️ HTTP Features', kvGrid(pairs)) : '';
}

function authSection(item) {
    const cards = [];
    if (item.basic_auth?.enabled === 'on')
        cards.push(['Basic Auth',    `${item.basic_auth.users?.length || 0} users`,  `Realm: ${item.basic_auth.realm || 'Restricted'}`]);
    if (item.jwt_auth?.enabled === 'on')
        cards.push(['JWT Auth',      item.jwt_auth.issuer || 'No issuer',            `Audience: ${item.jwt_auth.audience || 'any'}`]);
    if (item.oauth?.enabled === 'on')
        cards.push(['OAuth',         item.oauth.provider || 'OIDC',                  (item.oauth.scopes || []).join(', ')]);
    if (item.forward_auth?.enabled === 'on')
        cards.push(['Forward Auth',  item.forward_auth.name || '',                   item.forward_auth.url || '']);
    if (!cards.length) return '';

    const html = cards.map(([head, body, sub]) =>
        `<div class="mw-card security">
            <div class="mw-head">${head}</div>
            <div class="mw-body">${body}</div>
            <div class="mw-sub">${sub}</div>
        </div>`
    ).join('');
    return section('🔑 Authentication', `<div class="mw-grid">${html}</div>`);
}

function certsSection(certificates, hostname) {
    const hostCerts = certificates.filter(c => c.host === hostname);
    if (!hostCerts.length) return '';

    const cards = hostCerts.map(cert => {
        let cls = 'success', txt = cert.daysLeft + 'd';
        if      (cert.daysLeft < 0) { cls = 'error';   txt = 'Expired'; }
        else if (cert.daysLeft < 7) { cls = 'warning';  txt = cert.daysLeft + 'd left'; }
        return `<div class="cert-card">
            <div class="cert-domain">${cert.host}</div>
            <div class="cert-expiry">
                <span>${cert.issuer || "Let's Encrypt"}</span>
                ${badge(txt, cls)}
            </div>
            <div style="font-size:9px;color:var(--text-mute);margin-top:4px;">
                ${new Date(cert.expiry).toLocaleDateString()}
            </div>
        </div>`;
    }).join('');
    return section('🔐 TLS Certificates', `<div class="cert-grid">${cards}</div>`);
}

function rawSection(title, obj, maxHeight = '200px') {
    return section(title,
        `<div class="code-box" style="max-height:${maxHeight};">
            <pre>${JSON.stringify(obj, null, 2)}</pre>
        </div>`
    );
}

// ── Top-level builders — compose sections ──────────────────────────────────────

function buildRouteHTML(hostname, item, itemStats, type, certificates, routeIdx) {
    const isTCP = type === 'proxy' || item.protocol === 'tcp';
    const parts = [];

    // Web handler section (static / git)
    if (!isTCP && item.web) {
        const git = item.web.git;
        if (git?.enabled === 'on' || git?.enabled === true) {
            parts.push(gitSection(git, hostname));
        } else if (item.web.root) {
            parts.push(staticSection(item.web));
        }
    }

    // Upstreams
    parts.push(upstreamsSection(hostname, item, itemStats, routeIdx, type));

    // HTTP-only features
    if (!isTCP) {
        parts.push(httpFeaturesSection(item));
        parts.push(authSection(item));
    }

    // TLS certs
    parts.push(certsSection(certificates, hostname));

    // Raw config
    parts.push(rawSection('📜 Source (read-only)', item));

    return parts.filter(Boolean).join('');
}

function buildBackendHTML(cfg, bStat) {
    const p       = us => us ? (us / 1000).toFixed(1) + 'ms' : '—';
    const lat     = bStat.latency_us || {};
    const h       = bStat.health     || {};
    const hScore  = h.score || (bStat.alive ? 100 : 0);
    const state   = h.status || (bStat.alive ? 'Unverified' : 'Dead');
    const sColor  = hScore > 80 ? 'var(--success)' : hScore > 50 ? 'var(--warning)' : 'var(--danger)';
    const lastOk  = h.last_success ? new Date(h.last_success).toLocaleString() : 'Never';
    const lastFail= h.last_failure ? new Date(h.last_failure).toLocaleString() : 'None';

    const healthSection = section('🏥 Predictive Health', `
        <div class="health-gauge">
            <div class="gauge-circle" style="background:${sColor}">${hScore}</div>
            <div class="gauge-info">
                <div class="gauge-status">${state}</div>
                <div class="gauge-sub">Consecutive Fails: ${h.consecutive_failures || 0}</div>
            </div>
        </div>` +
        kvGrid([
            ['Last Success', lastOk],
            ['Last Failure', lastFail],
            ...(h.downtime ? [['Downtime', badge(h.downtime, 'error')]] : []),
        ])
    );

    const latCard = `
        <div class="handler-card" style="display:grid;grid-template-columns:repeat(4,1fr);text-align:center;padding:10px 15px;gap:5px;">
            ${['Avg','p50','p90','p99'].map((label, i) => {
        const val  = p([lat.avg_us, lat.p50, lat.p90, lat.p99][i]);
        const color= i < 2 ? 'var(--fg)' : i === 2 ? 'var(--warning)' : 'var(--danger)';
        return `<div>
                    <div style="font-size:9px;color:var(--text-mute);text-transform:uppercase;">${label}</div>
                    <div style="font-size:12px;font-family:monospace;margin-top:2px;color:${color};">${val}</div>
                </div>`;
    }).join('')}
        </div>`;

    const trafficSection = section('📊 Traffic &amp; Latency',
        kvGrid([
            ['Total Requests', fmtNum(bStat.total_reqs || 0)],
            ['In-Flight',      badge(bStat.in_flight || 0, 'info')],
            ['Failures',       bStat.failures > 0 ? badge(fmtNum(bStat.failures), 'error') : '0'],
            ['Weight',         cfg.weight || 1],
        ]) + latCard
    );

    const criteriaSection = (cfg.criteria?.source_ips?.length || cfg.criteria?.headers)
        ? section('🎯 Routing Criteria', kvGrid([
            ['Source IPs', cfg.criteria.source_ips?.join(', ') || 'Any'],
            ['Headers',    cfg.criteria.headers ? JSON.stringify(cfg.criteria.headers) : 'None'],
        ]))
        : '';

    return [
        healthSection,
        trafficSection,
        criteriaSection,
        rawSection('📜 Backend Config', cfg, '150px'),
    ].filter(Boolean).join('');
}