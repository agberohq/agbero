/**
 * js/drawer-listeners.js
 *
 * Route and backend drawer wiring.
 *
 * TYPE MAP (from alaye Go structs — critical, do not mix):
 *   Enabled fields → "on" | "off" | "unknown"   — check with isOn(v)
 *   bool fields    → true | false                — check === true
 *
 *   Enabled:  .enabled, protected, web.markdown.enabled, web.markdown.toc,
 *             web.markdown.unsafe, web.markdown.highlight.enabled,
 *             web.git.enabled, web.php.enabled, serverless.enabled,
 *             cache.enabled, cors.enabled, wasm.enabled, rate_limit.enabled,
 *             firewall.status, fallback.enabled, basic_auth.enabled,
 *             jwt_auth.enabled, forward_auth.enabled, oauth.enabled
 *
 *   bool:     web.listing, web.spa, web.no_cache, host.compression,
 *             cors.allow_credentials, health_check.accelerated_probing,
 *             health_check.synthetic_when_idle, rate_limit.ignore_global,
 *             firewall.ignore_global, forward_auth.allow_private
 */

import { listen, emit, on, clipboard, notify, query, modal, countdown } from '../lib/oja.full.esm.js';
import { store } from './store.js';
import { fmtNum } from './api.js';
import { isOn } from './utils.js';

// Drawer open / close
// All opens/closes through Oja modal so the stack stays consistent and
// the backdrop clears automatically when the stack empties.

function openDrawer(id)  { modal.open(id); }
function closeDrawer(id) { modal.closeById(id); }

on('[data-action="close-drawer"]', 'click', (e, btn) => closeDrawer(btn.dataset.target));

on('#drawerPerfBtn', 'click', (e, btn) => {
    const hostname = btn.dataset.hostname || query('#drawerHostName')?.dataset.host;
    if (hostname) emit('perf:open', { hostname });
});

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

on('[data-action="perf-node"]', 'click', (e, btn) => {
    emit('perf:open', { hostname: btn.dataset.hostname });
});

// Listen for drawer open events

listen('drawer:open-route', ({ host, idx, type }) => {
    const hostCfg   = (store.get('lastConfig') || {}).hosts?.[host] || {};
    const hostStats = (store.get('hostsData')  || { stats: {} }).stats?.[host] || {};

    const item      = type === 'proxy' ? hostCfg.proxies?.[idx] : hostCfg.routes?.[idx];
    if (!item) return;
    const itemStats = type === 'proxy' ? hostStats.proxies?.[idx] : hostStats.routes?.[idx];

    const path = item.path || (item.name ? item.name.replace('*default*', '* (TCP)') : item.protocol || '*');
    const el   = query('#drawerRoutePath');
    const hn   = query('#drawerHostName');
    if (el) el.innerText = path;
    if (hn) {
        hn.dataset.host = host;
        const textNode = [...hn.childNodes].find(n => n.nodeType === Node.TEXT_NODE);
        if (textNode) textNode.textContent = host + ' ';
        else hn.firstChild && (hn.firstChild.textContent = host + ' ');
    }

    const body = query('#drawerBody');
    if (body) body.innerHTML = buildRouteHTML(host, item, itemStats || {}, type, store.get('certificates') || [], idx);

    openDrawer('routeDrawer');
});

listen('drawer:open-backend', ({ host, routeIdx, backendIdx, type }) => {
    const hostCfg   = (store.get('lastConfig') || {}).hosts?.[host] || {};
    const hostStats = (store.get('hostsData')  || { stats: {} }).stats?.[host] || {};

    const cfgItem = type === 'proxy'
        ? (hostCfg.proxies?.[routeIdx]?.backends?.[backendIdx]         || {})
        : (hostCfg.routes?.[routeIdx]?.backends?.servers?.[backendIdx] || {});
    const bStat = type === 'proxy'
        ? (hostStats.proxies?.[routeIdx]?.backends?.[backendIdx] || {})
        : (hostStats.routes?.[routeIdx]?.backends?.[backendIdx]  || {});

    const url = bStat.url || bStat.address || cfgItem.address || 'Unknown';
    const titleEl = query('#backendDrawerTitle');
    const urlEl   = query('#backendDrawerUrl');
    if (titleEl) titleEl.innerText = 'Backend Activity';
    if (urlEl)   urlEl.innerText   = url;

    const body = query('#backendDrawerBody');
    if (body) body.innerHTML = buildBackendHTML(cfgItem, bStat);

    openDrawer('backendDrawer');
});

// Primitive builders

function section(title, content) {
    if (!content || content.trim() === '') return '';
    return `<div class="detail-section">
        <div class="detail-title">${title}</div>
        ${content}
    </div>`;
}

function kvGrid(pairs) {
    const items = pairs
        .filter(p => p && p[1] !== null && p[1] !== undefined && p[1] !== '' && p[1] !== false && p[1] !== 0)
        .map(([label, value]) => `<div class="kv-item"><label>${label}</label><div>${value}</div></div>`)
        .join('');
    if (!items) return '';
    return `<div class="kv-grid">${items}</div>`;
}

function badge(text, cls = '') {
    return `<span class="badge ${cls}">${text}</span>`;
}

// Web / static file section
// Guard: web block has meaningful data when it has a root path OR git is enabled.
// DO NOT guard on web.enabled — that field defaults to "unknown" (not "on") in
// most HCL configs, so checking isOn(web.enabled) silently hides everything.

function webSection(web) {
    if (!web) return '';
    // Only render if there is actual web content
    const hasRoot = !!web.root;
    const hasGit  = isOn(web.git?.enabled);
    if (!hasRoot && !hasGit) return '';

    const pairs = [];

    if (web.root)            pairs.push(['Root',    `<code class="mono" style="font-size:11px;word-break:break-all;">${web.root}</code>`]);
    if (web.index?.length)   pairs.push(['Index',   web.index.map(i => `<code>${i}</code>`).join(' ')]);

    // bool fields — check with === true
    if (web.listing)         pairs.push(['Listing',     badge('Directory listing', 'success')]);
    if (web.spa)             pairs.push(['SPA Mode',    badge('On', 'info')]);
    if (web.no_cache)        pairs.push(['No-Cache',    badge('headers set', 'warning')]);

    // Markdown — Enabled type
    const md = web.markdown;
    if (isOn(md?.enabled)) {
        const isBrowse  = md.view === 'browse';
        const mdParts   = [badge(isBrowse ? '📖 Browse' : '🌐 Website', isBrowse ? 'info' : '')];
        if (isOn(md.toc))              mdParts.push(badge('TOC', ''));
        if (isOn(md.unsafe))           mdParts.push(badge('Unsafe HTML', 'warning'));
        if (isOn(md.highlight?.enabled)) {
            mdParts.push(badge(md.highlight.theme || 'highlight', 'info'));
        }
        if (md.extensions?.length)     mdParts.push(`<span style="font-size:10px;color:var(--text-mute);">${md.extensions.join(', ')}</span>`);
        if (md.template)               mdParts.push(`<span style="font-size:10px;color:var(--text-mute);">tpl: ${md.template}</span>`);
        pairs.push(['Markdown', mdParts.join(' ')]);
    }

    // PHP — Enabled type
    if (isOn(web.php?.enabled)) {
        pairs.push(['PHP-FPM', badge(web.php.address || '127.0.0.1:9000', 'info')]);
    }

    const isBrowse = isOn(md?.enabled) && md?.view === 'browse';
    const icon     = isBrowse ? '📖' : hasGit ? '🐙' : '📂';
    const title    = hasGit ? 'Git · Static File Server' : 'Static File Server';

    return section(`${icon} ${title}`, kvGrid(pairs));
}

// Git section

function gitSection(git, hostname) {
    if (!isOn(git?.enabled)) return '';
    const gitStats = store.get('gitStats') || {};
    const gs       = gitStats[git.id]      || {};
    const state    = gs.state  || 'unknown';
    const commit   = gs.commit ? gs.commit.substring(0, 8) : 'none';
    const sCls     = state === 'healthy' ? 'success' : state === 'unavailable' ? 'warning' : 'error';
    const whUrl    = `${window.location.origin}/.well-known/agbero/webhook/git/${git.id}`;

    const pairs = [
        ['ID',       `<code>${git.id}</code>`],
        ['URL',      `<a href="${git.url}" target="_blank" rel="noopener" style="color:var(--accent);word-break:break-all;font-size:11px;">${git.url}</a>`],
        ['Branch',   git.branch || badge('default', '')],
        ['Interval', git.interval && git.interval !== '0s' ? git.interval : badge('webhook only', '')],
        ['State',    badge(state, sCls)],
        ['Commit',   commit !== 'none' ? `<code>${commit}</code>` : badge('none yet', 'warning')],
        ['Deploys',  gs.deployments || 0],
        git.sub_dir    ? ['Sub Dir', `<code>${git.sub_dir}</code>`] : null,
        git.auth?.type ? ['Auth',    badge(git.auth.type, 'info')]  : null,
    ].filter(Boolean);

    const whHtml = `<div style="display:flex;gap:8px;align-items:center;margin-top:8px;">
        <code style="font-size:10px;padding:4px 6px;background:var(--panel-bg);border:1px solid var(--border);border-radius:4px;flex:1;overflow-x:auto;white-space:nowrap;">${whUrl}</code>
        <button class="btn small" data-action="copy-url" data-url="${whUrl}" style="flex-shrink:0;">Copy</button>
    </div>`;

    return section('🐙 Git Deployment', kvGrid(pairs) +
        `<div style="margin-top:8px;"><label style="font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;">Webhook URL</label>${whHtml}</div>`);
}

// Serverless section

function serverlessSection(serverless) {
    if (!isOn(serverless?.enabled)) return '';
    const workers = serverless.workers || [];
    const rests   = serverless.rests   || [];
    if (!workers.length && !rests.length) return '';

    let html = '';

    if (workers.length) {
        html += `<div style="font-size:11px;font-weight:500;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">Workers (${workers.length})</div>`;
        html += workers.map(w => `
            <div class="handler-card" style="margin-bottom:6px;">
                <span class="handler-icon" style="font-size:16px;">⚙️</span>
                <div class="handler-info">
                    <strong>${w.name}</strong>
                    <span style="font-family:var(--font-mono);font-size:11px;word-break:break-all;"><code>${(w.command || []).join(' ')}</code></span>
                    <div style="display:flex;gap:4px;flex-wrap:wrap;margin-top:4px;">
                        ${w.background  ? badge('background', 'info') : ''}
                        ${w.run_once    ? badge('run once', '') : ''}
                        ${w.restart     ? badge('restart: ' + w.restart, '') : ''}
                        ${w.schedule    ? badge('cron: ' + w.schedule, 'warning') : ''}
                        ${w.timeout && w.timeout !== '0s' ? badge('timeout: ' + w.timeout, '') : ''}
                    </div>
                </div>
            </div>`).join('');
    }

    if (rests.length) {
        html += `<div style="font-size:11px;font-weight:500;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;margin:10px 0 6px;">REST Proxies (${rests.length})</div>`;
        html += rests.map(r => `
            <div class="handler-card" style="margin-bottom:6px;">
                <span class="handler-icon" style="font-size:16px;">🔌</span>
                <div class="handler-info">
                    <div style="display:flex;align-items:center;gap:6px;">
                        <strong>${r.name}</strong>
                        ${badge(r.method || 'GET', 'info')}
                    </div>
                    <span style="font-size:11px;word-break:break-all;"><a href="${r.url}" target="_blank" rel="noopener" style="color:var(--accent);">${r.url}</a></span>
                    ${r.timeout && r.timeout !== '0s' ? `<span style="font-size:10px;color:var(--text-mute);">timeout: ${r.timeout}</span>` : ''}
                </div>
            </div>`).join('');
    }

    return section('⚡ Serverless', html);
}

// Upstreams section

function backendRow(b, cfgB, bStat, hostname, routeIdx, bIdx, type) {
    const url  = bStat.url || bStat.address || cfgB.address || '';
    const w    = cfgB.weight !== undefined ? cfgB.weight : (bStat.url || bStat.address ? '—' : 1);
    const hSt  = bStat.health?.status || 'Unknown';

    let dc = 'warn', dt = 'No data';
    if (bStat.url || bStat.address) {
        if (!bStat.alive || hSt === 'Dead' || hSt === 'Unhealthy') { dc = 'down'; dt = hSt !== 'Unknown' ? hSt : 'Dead'; }
        else if (hSt === 'Degraded')                                { dc = 'warn'; dt = 'Degraded'; }
        else if (hSt === 'Healthy')                                 { dc = 'ok';   dt = 'Healthy'; }
        else                                                        { dc = bStat.alive ? 'info' : 'down'; dt = bStat.alive ? 'Unverified' : 'Dead'; }
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
                <span class="mono row-url" style="font-size:11px;word-break:break-all;">${url}</span>
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
    const cfgBEs  = item.backends?.servers || [];
    const statBEs = itemStats?.backends    || [];
    const display = statBEs.length ? statBEs : cfgBEs;
    if (!display.length) return '';

    const strategy  = item.backends?.strategy;
    const stratLabel = strategy
        ? strategy.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
        : 'Round Robin';

    const rows = display.map((b, i) =>
        backendRow(b, cfgBEs[i] || {}, statBEs[i] || {}, hostname, routeIdx, i, type)
    ).join('');

    return section(`⬆️ Upstreams <span class="badge" style="margin-left:4px;">${stratLabel}</span>`, rows);
}

// HTTP features section

function httpFeaturesSection(item) {
    const parts = [];

    // Health check — Enabled type
    if (isOn(item.health_check?.enabled)) {
        const hc = item.health_check;
        const rows = [
            ['Path',     `<code>${hc.path}</code>`],
            ['Interval', hc.interval || '—'],
            ['Timeout',  hc.timeout  || '—'],
            ['Threshold',hc.threshold || '—'],
            ['Method',   hc.method   || 'GET'],
            hc.expected_status?.length ? ['Expected', hc.expected_status.join(', ')] : null,
            hc.accelerated_probing     ? ['Probing',  badge('Accelerated', 'info')] : null,
            hc.synthetic_when_idle     ? ['Idle',     badge('Synthetic', '')]       : null,
        ].filter(Boolean);
        parts.push(section('🩺 Health Check', kvGrid(rows)));
    }

    // Circuit breaker — Enabled type
    if (isOn(item.circuit_breaker?.enabled)) {
        const cb = item.circuit_breaker;
        parts.push(section('⚡ Circuit Breaker', kvGrid([
            ['Threshold',   cb.threshold + ' failures'],
            ['Reset after', cb.duration || '—'],
        ])));
    }

    // Timeouts — Enabled type
    if (isOn(item.timeouts?.enabled) && item.timeouts?.request) {
        parts.push(section('⏱️ Timeout', kvGrid([['Request', item.timeouts.request]])));
    }

    // Rate limit — Enabled type
    if (isOn(item.rate_limit?.enabled)) {
        const rl   = item.rate_limit;
        const rule = rl.rule || {};
        const rParts = [];
        if (rl.use_policy)      rParts.push(badge('policy: ' + rl.use_policy, 'info'));
        if (isOn(rule.enabled)) rParts.push(`${rule.requests}/${rule.window}${rule.burst > rule.requests ? ` burst ${rule.burst}` : ''}`);
        if (rl.ignore_global)   rParts.push(badge('ignores global', 'warning'));
        if (rParts.length) parts.push(section('🚦 Rate Limit', rParts.join(' ')));
    }

    // CORS — Enabled type
    if (isOn(item.cors?.enabled)) {
        const c = item.cors;
        const origins = c.allowed_origins?.length
            ? c.allowed_origins.slice(0, 3).join(', ') + (c.allowed_origins.length > 3 ? '…' : '')
            : '*';
        const corsParts = [badge('On', 'info')];
        if (origins !== '*')     corsParts.push(`<code style="font-size:10px;">${origins}</code>`);
        if (c.allow_credentials) corsParts.push(badge('credentials', 'warning'));
        parts.push(section('🌐 CORS', corsParts.join(' ')));
    }

    // Cache — Enabled type
    if (isOn(item.cache?.enabled)) {
        const ca = item.cache;
        parts.push(section('📦 Cache', [badge(ca.driver || 'memory', 'success'), ca.ttl ? `TTL ${ca.ttl}` : ''].filter(Boolean).join(' ')));
    }

    // Compression — Enabled type
    if (isOn(item.compression?.enabled)) {
        const cc = item.compression;
        parts.push(section('🗜️ Compression', badge(cc.type || 'gzip', '') + (cc.level ? ` level ${cc.level}` : '')));
    }

    // Firewall — uses .status (Enabled type)
    if (isOn(item.firewall?.enabled)) {
        const fw = item.firewall;
        const fwParts = [badge('Enabled', 'danger')];
        if (fw.ignore_global)         fwParts.push(badge('ignores global', 'warning'));
        if (fw.apply_rules?.length)   fwParts.push(`rules: ${fw.apply_rules.join(', ')}`);
        parts.push(section('🛡️ Firewall', fwParts.join(' ')));
    }

    // Fallback — Enabled type
    if (isOn(item.fallback?.enabled)) {
        const fb = item.fallback;
        parts.push(section('🔄 Fallback', badge(fb.type, '') + (fb.redirect_url ? ` → <code style="font-size:11px;">${fb.redirect_url}</code>` : '')));
    }

    // WASM — Enabled type
    if (isOn(item.wasm?.enabled)) {
        const wa = item.wasm;
        parts.push(section('🔮 WASM', kvGrid([
            ['Module', `<code style="font-size:10px;word-break:break-all;">${wa.module}</code>`],
            ['Access', wa.access?.length ? wa.access.join(', ') : 'none'],
        ])));
    }

    // Rewrites
    if (item.rewrites?.length) {
        const rws = item.rewrites.map(r =>
            `<div style="font-size:11px;font-family:var(--font-mono);margin-bottom:3px;"><span style="color:var(--text-mute);">${r.pattern}</span> → <span style="color:var(--accent);">${r.target}</span></div>`
        ).join('');
        parts.push(section(`✏️ Rewrites (${item.rewrites.length})`, rws));
    }

    // Strip prefixes
    if (item.strip_prefixes?.length) {
        parts.push(section('✂️ Strip Prefixes', item.strip_prefixes.map(p => `<code>${p}</code>`).join(' ')));
    }

    // IP filter
    if (item.allowed_ips?.length) {
        parts.push(section('🔒 IP Filter', item.allowed_ips.map(ip => `<code>${ip}</code>`).join(' ')));
    }

    return parts.join('');
}

// Auth section

function authSection(item) {
    const parts = [];

    if (isOn(item.basic_auth?.enabled)) {
        const count = item.basic_auth.users?.length || 0;
        parts.push(`<div class="mw-card security" style="margin-bottom:6px;">
            <div class="mw-head">Basic Auth</div>
            <div class="mw-body">${count} user${count !== 1 ? 's' : ''}</div>
            ${item.basic_auth.realm ? `<div class="mw-sub">realm: ${item.basic_auth.realm}</div>` : ''}
        </div>`);
    }

    if (isOn(item.jwt_auth?.enabled)) {
        const j = item.jwt_auth;
        parts.push(`<div class="mw-card security" style="margin-bottom:6px;">
            <div class="mw-head">JWT Auth</div>
            <div class="mw-body">${badge('Bearer token', 'info')}</div>
            ${j.issuer ? `<div class="mw-sub">issuer: ${j.issuer}</div>` : ''}
        </div>`);
    }

    if (isOn(item.forward_auth?.enabled)) {
        const f = item.forward_auth;
        parts.push(`<div class="mw-card security" style="margin-bottom:6px;">
            <div class="mw-head">Forward Auth</div>
            <div class="mw-body" style="font-size:11px;word-break:break-all;">${f.url}</div>
            <div class="mw-sub">
                ${badge('on_failure: ' + (f.on_failure || 'deny'), f.on_failure === 'allow' ? 'warning' : '')}
                ${f.allow_private ? badge('allow_private', 'warning') : ''}
            </div>
        </div>`);
    }

    if (isOn(item.oauth?.enabled)) {
        const o = item.oauth;
        parts.push(`<div class="mw-card security" style="margin-bottom:6px;">
            <div class="mw-head">OAuth</div>
            <div class="mw-body">${badge(o.provider || 'oidc', 'info')}</div>
        </div>`);
    }

    if (!parts.length) return '';
    return section('🔐 Authentication', `<div class="mw-grid">${parts.join('')}</div>`);
}

// Cert section

function certsSection(hostname, certificates) {
    if (!certificates?.length) return '';
    const cert = certificates.find(c => c.domain === hostname);
    if (!cert) return '';
    const color   = countdown.daysColor(cert.days_left);
    const label   = countdown.daysLabel(cert.days_left);
    const expDate = cert.expires_at ? new Date(cert.expires_at).toLocaleDateString() : '—';
    return section('🔑 Certificate', kvGrid([
        ['Expiry',  `<span style="color:${color};">${label}</span>`],
        ['Expires', expDate],
    ]));
}

// Host-level section

function hostLevelSection(hostname) {
    const hostCfg = (store.get('lastConfig') || {}).hosts?.[hostname] || {};
    const items = [];

    if (hostCfg.compression)                               items.push(['Compression', badge('Enabled', 'success')]);
    if (hostCfg.limits?.max_body_size)                     items.push(['Max Body', hostCfg.limits.max_body_size + ' B']);
    if (hostCfg.not_found_page)                            items.push(['404 Page', `<code style="font-size:10px;">${hostCfg.not_found_page}</code>`]);
    if (Object.keys(hostCfg.error_pages?.pages || {}).length) {
        items.push(['Error Pages', Object.keys(hostCfg.error_pages.pages).join(', ')]);
    }
    if (isOn(hostCfg.headers?.enabled)) {
        const req = Object.keys(hostCfg.headers?.request?.set  || {}).length
                  + Object.keys(hostCfg.headers?.request?.add  || {}).length;
        const res = Object.keys(hostCfg.headers?.response?.set || {}).length
                  + Object.keys(hostCfg.headers?.response?.add || {}).length;
        if (req + res > 0) items.push(['Headers', `${req} req, ${res} resp`]);
    }
    if (hostCfg.bind?.length) items.push(['Bind', hostCfg.bind.map(b => `<code>${b}</code>`).join(' ')]);

    if (!items.length) return '';
    return section('🏠 Host Settings', kvGrid(items));
}

// Raw config section — always shown at the bottom

function rawSection(item) {
    // Strip circular/redundant fields that would make the JSON too noisy
    const clean = JSON.parse(JSON.stringify(item, (k, v) => {
        // Skip zero-value Enabled fields and empty arrays/objects
        if (v === 'unknown' || v === null) return undefined;
        if (Array.isArray(v)   && v.length === 0)           return undefined;
        if (typeof v === 'object' && v !== null && !Array.isArray(v) && Object.keys(v).length === 0) return undefined;
        return v;
    }));
    const j = JSON.stringify(clean, null, 2);
    return section('{ } Raw Config', `
        <pre class="code-box" style="max-height:220px;overflow:auto;font-size:10px;line-height:1.55;margin:0;white-space:pre-wrap;word-break:break-all;">${j.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>`);
}

// Main route drawer builder

function buildRouteHTML(hostname, item, itemStats, type, certificates, routeIdx) {
    // TCP proxy
    if (type === 'proxy') {
        return [
            section('📡 TCP Proxy', kvGrid([
                ['Listen',   `<code>${item.listen}</code>`],
                ['Strategy', item.strategy || 'round_robin'],
                ['SNI',      item.sni ? `<code>${item.sni}</code>` : null],
                ['Max Conn', item.max_connections || null],
            ])),
            upstreamsSection(hostname, item, itemStats, routeIdx, type),
            rawSection(item),
        ].filter(Boolean).join('');
    }

    // HTTP route — show everything, always
    return [
        hostLevelSection(hostname),
        certsSection(hostname, certificates),
        // Web engine — web section and git section are separate:
        // webSection handles root/markdown/php/listing/spa
        // gitSection handles git deployment details
        webSection(item.web),
        gitSection(item.web?.git, hostname),
        serverlessSection(item.serverless),
        upstreamsSection(hostname, item, itemStats, routeIdx, type),
        httpFeaturesSection(item),
        authSection(item),
        // Raw config — always at bottom for power users and debugging
        rawSection(item),
    ].filter(Boolean).join('');
}

// Backend drawer builder

function buildBackendHTML(cfg, stat) {
    const parts = [];

    if (stat.url || stat.address) {
        const p50  = stat.latency_us?.p50  ? (stat.latency_us.p50  / 1000).toFixed(1) + 'ms' : null;
        const p99  = stat.latency_us?.p99  ? (stat.latency_us.p99  / 1000).toFixed(1) + 'ms' : null;
        const p999 = stat.latency_us?.p999 ? (stat.latency_us.p999 / 1000).toFixed(1) + 'ms' : null;
        const hSt  = stat.health?.status || 'Unknown';
        const dotCls = (!stat.alive || hSt === 'Dead' || hSt === 'Unhealthy') ? 'down'
                     : hSt === 'Degraded' ? 'warn'
                     : hSt === 'Healthy'  ? 'ok' : 'info';
        const gaugeColor = dotCls === 'ok' ? 'var(--success)' : dotCls === 'down' ? 'var(--danger)' : 'var(--warning)';

        parts.push(section('📊 Live Metrics', `
            <div class="health-gauge">
                <div class="gauge-circle" style="background:${gaugeColor};">
                    ${stat.health?.score !== undefined ? stat.health.score : '?'}
                </div>
                <div>
                    <div class="gauge-status"><span class="dot ${dotCls}"></span> ${hSt}</div>
                    <div class="gauge-sub">${stat.total_reqs ? fmtNum(stat.total_reqs) + ' total requests' : 'No requests yet'}</div>
                </div>
            </div>
            ${kvGrid([
                ['p50',         p50],
                ['p99',         p99],
                ['p999',        p999],
                ['In Flight',   stat.in_flight  > 0 ? badge(stat.in_flight,            'warning') : null],
                ['Failures',    stat.failures   > 0 ? badge(fmtNum(stat.failures),     'error')   : null],
                ['Consecutive', stat.health?.consecutive_failures > 0 ? stat.health.consecutive_failures + ' fails' : null],
            ])}`));
    }

    parts.push(section('⚙️ Configuration', kvGrid([
        ['Address',  `<code style="word-break:break-all;">${cfg.address || '—'}</code>`],
        ['Weight',   cfg.weight || 1],
        ['Max Conn', cfg.max_connections || null],
        cfg.criteria?.source_ips?.length ? ['Source IPs', cfg.criteria.source_ips.map(ip => `<code>${ip}</code>`).join(' ')] : null,
        cfg.streaming?.enabled ? ['Streaming', badge('Enabled', 'info')] : null,
    ].filter(Boolean))));

    return parts.join('');
}
