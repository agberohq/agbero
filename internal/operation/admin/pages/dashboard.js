/**
 * pages/dashboard.js — Dashboard page.
 */
import { emit, listen, chart, countdown } from '../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { store, api, utils, oja } = inject('app');
    const { modal } = oja;

    let mainChart = null;
    let unsub     = null;

    function buildTimeGradient(n) {
        return Array.from({ length: n }, (_, i) => {
            const t = i / Math.max(n - 1, 1);
            return `rgba(59,130,246,${(0.18 + t * 0.82).toFixed(2)})`;
        });
    }

    function fmtReqs(n) {
        if (!n) return '0';
        if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
        if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
        return String(n);
    }

    function _openCertDetail(cert) {
        const titleEl = find('#certDetailTitle');
        const bodyEl  = find('#certDetailBody');
        if (!titleEl || !bodyEl) return;
        titleEl.textContent = cert.domain;
        const expiry   = cert.expires_at ? new Date(cert.expires_at).toLocaleDateString([], { year:'numeric', month:'short', day:'numeric' }) : '—';
        const issued   = cert.issued_at  ? new Date(cert.issued_at).toLocaleDateString([], { year:'numeric', month:'short', day:'numeric' }) : '—';
        const color    = countdown.daysColor(cert.days_left);
        const daysNum  = cert.days_left !== null && cert.days_left !== undefined
            ? (cert.days_left <= 0 ? 'Expired' : `${cert.days_left} days`)
            : '—';
        const sourceLabel = cert.source === 'letsencrypt' ? "Let's Encrypt" : cert.source === 'local_auto' ? 'Auto (local)' : cert.source === 'custom' ? 'Custom' : '—';
        const keyInfo  = cert.key_type ? `${cert.key_type}${cert.key_bits ? ' ' + cert.key_bits + '-bit' : ''}` : '—';
        const sansHtml = cert.sans?.length
            ? cert.sans.map(s => `<span style="font-family:var(--font-mono);font-size:10px;background:var(--hover-bg);padding:1px 5px;border-radius:3px;margin:1px 2px;display:inline-block;">${s}</span>`).join('')
            : '—';
        bodyEl.innerHTML = [
            ['Domain',     cert.domain],
            ['Status',     cert.is_expired
                ? '<span style="color:var(--danger);font-weight:500;">Expired</span>'
                : cert.days_left !== null && cert.days_left < 7
                    ? '<span style="color:var(--warning);font-weight:500;">Expiring soon</span>'
                    : '<span style="color:var(--success);">Valid</span>'],
            ['Days Left',  `<span style="color:${color};font-weight:500;">${daysNum}</span>`],
            ['Expires',    expiry],
            ['Issued',     issued],
            ['Source',     sourceLabel],
            ['Key',        keyInfo],
            ['Issuer',     cert.issuer  || '—'],
            ['Serial',     cert.serial_number ? `<span style="font-family:var(--font-mono);font-size:10px;">${cert.serial_number}</span>` : '—'],
            ['SANs',       sansHtml],
        ].map(([k,v]) => `<div class="detail-row"><span class="detail-label">${k}</span><span class="detail-value">${v}</span></div>`).join('');
        modal.open('certDetailModal');
    }

    // Cert countdown handles — live ticking for certs expiring <30 days
    const _certCountdowns = new Map();
    function _clearCertCountdowns() {
        for (const h of _certCountdowns.values()) h.destroy();
        _certCountdowns.clear();
    }

    function renderCerts(certs) {
        _clearCertCountdowns();
        const el  = find('#certBriefing');
        const sum = find('#certSummary');
        if (!el) return;
        if (!certs || !certs.length) {
            el.innerHTML = '<div class="brief-empty">No certificates tracked</div>';
            if (sum) sum.textContent = '';
            return;
        }
        const sorted   = [...certs].sort((a, b) => (a.days_left ?? Infinity) - (b.days_left ?? Infinity));
        const expiring = sorted.filter(c => c.days_left !== null && c.days_left < 30).length;
        if (sum) sum.textContent = expiring > 0 ? `${expiring} expiring soon` : `${certs.length} managed`;
        el.innerHTML = sorted.slice(0, 5).map(cert => {
            const color    = countdown.daysColor(cert.days_left);
            const useLive  = cert.days_left !== null && cert.days_left < 30 && cert.expires_at;
            const cdId     = `dash-cert-cd-${cert.domain.replace(/[^a-z0-9]/gi, '_')}`;
            const labelHtml = useLive
                ? `<span id="${cdId}" style="color:${color};font-family:var(--font-mono);font-size:11px;"></span>`
                : `<span style="color:${color};font-family:var(--font-mono);font-size:11px;">${countdown.daysLabel(cert.days_left)}</span>`;
            return `<div class="brief-row brief-row-clickable" data-cert="${encodeURIComponent(JSON.stringify(cert))}">
                <span class="dot" style="background:${color};flex-shrink:0;"></span>
                <span class="brief-row-main">${cert.domain}</span>
                ${labelHtml}
                <span class="brief-row-arrow">›</span>
            </div>`;
        }).join('');
        // Attach live countdowns for expiring certs
        sorted.slice(0, 5).forEach(cert => {
            if (!cert.expires_at || cert.days_left === null || cert.days_left >= 30) return;
            const cdId = `dash-cert-cd-${cert.domain.replace(/[^a-z0-9]/gi, '_')}`;
            const cdEl = find('#' + cdId);
            if (!cdEl) return;
            const expiresMs = new Date(cert.expires_at).getTime();
            const handle = countdown.attach(cdEl, expiresMs, {
                format: (ms) => {
                    if (ms <= 0) return '<span style="color:var(--danger)">expired</span>';
                    const d = Math.floor(ms / 86_400_000);
                    const h = Math.floor((ms % 86_400_000) / 3_600_000);
                    return d > 0
                        ? `<span style="color:${countdown.daysColor(d)}">${d}d ${h}h left</span>`
                        : `<span style="color:var(--danger)">${h}h left</span>`;
                },
            });
            _certCountdowns.set(cert.domain, handle);
        });
        el.querySelectorAll('[data-cert]').forEach(row =>
            row.addEventListener('click', () => _openCertDetail(JSON.parse(decodeURIComponent(row.dataset.cert))))
        );
    }

    function renderTopHosts(hosts) {
        const el  = find('#hostBriefing');
        const sub = find('#hostBriefSub');
        if (!el) return;
        const entries = Object.entries(hosts || {})
            .map(([name, h]) => ({ name, reqs: h.total_reqs || 0 }))
            .filter(h => h.reqs > 0)
            .sort((a, b) => b.reqs - a.reqs);
        if (sub) sub.textContent = entries.length ? `${entries.length} hosts` : '';
        if (!entries.length) { el.innerHTML = '<div class="brief-empty">No traffic yet</div>'; return; }
        const maxReqs = entries[0].reqs;
        el.innerHTML = entries.slice(0, 5).map((h, i) => {
            const pct  = maxReqs > 0 ? Math.round((h.reqs / maxReqs) * 100) : 0;
            const rank = i === 0 ? 'var(--accent)' : i === 1 ? 'var(--info)' : 'var(--border)';
            return `<div class="brief-row" data-hostname="${h.name}" style="flex-direction:column;align-items:stretch;gap:4px;cursor:pointer;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span class="brief-row-main">${h.name}</span>
                    <span class="brief-row-sub" style="font-family:var(--font-mono);">${fmtReqs(h.reqs)}</span>
                </div>
                <div style="height:2px;background:var(--border);border-radius:1px;overflow:hidden;">
                    <div style="width:${pct}%;height:100%;background:${rank};transition:width 0.4s;"></div>
                </div>
            </div>`;
        }).join('');
    }

    function renderErrorHotspots(hosts) {
        const el  = find('#errorBriefing');
        const sub = find('#errorBriefSub');
        if (!el) return;

        // Collect all routes + serverless entries with their p99 and host
        const endpoints = [];
        for (const [hostname, h] of Object.entries(hosts || {})) {
            for (const [rIdx, route] of (h.routes || []).entries()) {
                for (const b of (route.backends || [])) {
                    const p99 = b.latency_us?.p99;
                    if (p99 > 0) endpoints.push({
                        label: route.path || '/',
                        host:  hostname,
                        p99:   p99 / 1000,
                        kind:  'http',
                        alive: b.alive !== false,
                        routeIdx: rIdx,
                    });
                }
                for (const sl of (route.serverless || [])) {
                    const p99 = sl.latency_us?.p99;
                    if (p99 > 0) endpoints.push({
                        label: sl.name,
                        host:  hostname,
                        p99:   p99 / 1000,
                        kind:  sl.kind,
                        alive: true,
                        routeIdx: rIdx,
                    });
                }
            }
        }

        endpoints.sort((a, b) => b.p99 - a.p99);
        if (sub) sub.textContent = endpoints.length ? `top ${Math.min(endpoints.length, 5)} by p99` : '';

        if (!endpoints.length) {
            el.innerHTML = '<div class="brief-empty">No latency data yet</div>';
            return;
        }

        const top = endpoints.slice(0, 5);
        const maxP99 = top[0].p99;
        el.innerHTML = top.map(ep => {
            const pct   = maxP99 > 0 ? Math.round((ep.p99 / maxP99) * 100) : 0;
            const color = ep.p99 > 2000 ? 'var(--danger)' : ep.p99 > 500 ? 'var(--warning)' : 'var(--success)';
            const badge = ep.kind !== 'http' ? `<span class="badge" style="font-size:9px;padding:1px 4px;margin-left:4px;">${ep.kind}</span>` : '';
            return `<div style="padding:8px 14px;border-bottom:1px solid var(--border);cursor:pointer;" data-hostname="${ep.host}" data-route-idx="${ep.routeIdx ?? 0}">
                <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;">
                    <span style="font-family:var(--font-mono);font-size:11px;color:var(--fg);">${ep.label}${badge}</span>
                    <span style="font-family:var(--font-mono);font-size:12px;color:${color};font-weight:500;">${ep.p99.toFixed(0)}ms</span>
                </div>
                <div style="display:flex;align-items:center;gap:8px;">
                    <div style="flex:1;height:2px;background:var(--border);border-radius:1px;">
                        <div style="width:${pct}%;height:100%;background:${color};border-radius:1px;transition:width .3s;"></div>
                    </div>
                    <span style="font-size:10px;color:var(--text-mute);font-family:var(--font-mono);white-space:nowrap;flex-shrink:0;">${ep.host}</span>
                </div>
            </div>`;
        }).join('') + '<div style="height:0;border-bottom:none;"></div>';
    }

    function _openGitDetail(id, s) {
        const titleEl = find('#gitDetailTitle');
        const bodyEl  = find('#gitDetailBody');
        if (!titleEl || !bodyEl) return;
        titleEl.textContent = id;
        const status    = s.status || s.state || 'unknown';
        const isHealthy = status === 'healthy' || status === 'ok';
        const isFailed  = status === 'failed'  || status === 'error';
        const stateColor = isHealthy ? 'var(--success)' : isFailed ? 'var(--danger)' : 'var(--warning)';
        const lastCheck  = s.last_check  ? new Date(s.last_check).toLocaleString()  : '—';
        const rows = [
            ['ID',           id],
            ['Status',       `<span style="color:${stateColor};font-weight:500;">${status}</span>`],
            ['Branch',       s.branch   ? `<span style="font-family:var(--font-mono);">${s.branch}</span>` : '—'],
            ['Commit',       s.commit   ? `<span style="font-family:var(--font-mono);">${s.commit.slice(0,12)}</span>` : '—'],
            ['Path',         s.current_path ? `<span style="font-family:var(--font-mono);font-size:10px;word-break:break-all;">${s.current_path}</span>` : '—'],
            ['Deployments',  s.deployments !== undefined ? String(s.deployments) : '—'],
            ['Last Check',   lastCheck],
            ['Error',        s.error ? `<span style="color:var(--danger);font-size:11px;">${s.error}</span>` : '—'],
        ];
        bodyEl.innerHTML = rows
            .map(([k,v]) => `<div class="detail-row"><span class="detail-label">${k}</span><span class="detail-value">${v}</span></div>`)
            .join('');
        modal.open('gitDetailModal');
    }

    function renderGitDeploys(gitStats) {
        const el  = find('#gitBriefing');
        const sub = find('#gitBriefSub');
        if (!el) return;
        const entries = Object.entries(gitStats || {});
        if (!entries.length) { el.innerHTML = '<div class="brief-empty">No git deploys configured</div>'; if (sub) sub.textContent = ''; return; }
        if (sub) sub.textContent = `${entries.length} deploy${entries.length !== 1 ? 's' : ''}`;
        el.innerHTML = entries.map(([id, s]) => {
            const status    = s.status || s.state || 'unknown';
            const isHealthy = status === 'healthy' || status === 'ok';
            const isFailed  = status === 'failed'  || status === 'error';
            const dotCls    = isHealthy ? 'ok' : isFailed ? 'down' : 'warn';
            const meta      = [s.branch ? `@${s.branch}` : '', s.commit ? s.commit.slice(0,7) : ''].filter(Boolean).join(' · ');
            return `<div class="brief-row brief-row-clickable" data-git-id="${id}" data-git="${encodeURIComponent(JSON.stringify(s))}">
                <span class="dot ${dotCls}" style="flex-shrink:0;"></span>
                <div style="flex:1;min-width:0;">
                    <div class="brief-row-main">${id}</div>
                    ${meta ? `<div style="font-size:10px;color:var(--text-mute);font-family:var(--font-mono);">${meta}</div>` : ''}
                </div>
                <span class="brief-row-sub" style="font-family:var(--font-mono);">${status}</span>
                <span class="brief-row-arrow">›</span>
            </div>`;
        }).join('');
        el.querySelectorAll('[data-git-id]').forEach(row =>
            row.addEventListener('click', () => _openGitDetail(row.dataset.gitId, JSON.parse(decodeURIComponent(row.dataset.git))))
        );
    }

    function renderNotifications(hosts, certs) {
        const listEl  = find('#notifList');
        const countEl = find('#notifCount');
        const panel   = find('#notifPanel');
        if (!listEl) return;

        const items = [];

        // Cert expiry alerts
        (certs || []).forEach(c => {
            if (c.days_left === null || c.days_left === undefined) return;
            if (c.is_expired || c.days_left < 0)
                items.push({ sev: 'danger',  icon: '🔒', msg: `Certificate expired`, sub: c.domain });
            else if (c.days_left < 7)
                items.push({ sev: 'warning', icon: '⏰', msg: `Certificate expiring in ${c.days_left}d`, sub: c.domain });
        });

        // Global error rate — include serverless failures and reqs
        let tReqs = 0, tErrs = 0;
        for (const h of Object.values(hosts || {})) {
            tReqs += h.total_reqs || 0;
            (h.routes  || []).forEach(r => {
                (r.backends   || []).forEach(b  => tErrs += b.failures  || 0);
                (r.serverless || []).forEach(sl => tErrs += sl.failures  || 0);
            });
            (h.proxies || []).forEach(p => (p.backends || []).forEach(b => tErrs += b.failures || 0));
        }
        if (tReqs > 50 && tErrs / tReqs > 0.05)
            items.push({ sev: 'danger', icon: '📈', msg: `High error rate: ${((tErrs / tReqs) * 100).toFixed(1)}%`, sub: `${tErrs} of ${fmtReqs(tReqs)} requests failed` });

        // Dead HTTP backends
        for (const [hostname, h] of Object.entries(hosts || {})) {
            for (const route of (h.routes || [])) {
                for (const b of (route.backends || [])) {
                    if (b.alive === false)
                        items.push({ sev: 'warning', icon: '⚠️', msg: `Dead backend`, sub: `${b.url || b.address || '?'} on ${hostname}` });
                }
            }
        }

        // Dead proxy backends
        for (const [hostname, h] of Object.entries(hosts || {})) {
            for (const proxy of (h.proxies || [])) {
                for (const b of (proxy.backends || [])) {
                    if (b.alive === false)
                        items.push({ sev: 'warning', icon: '⚠️', msg: `Dead proxy backend`, sub: `${b.address || '?'} on ${hostname}` });
                }
            }
        }

        // High per-host p99 (>500ms) — sparklines now include serverless latency
        for (const [hostname] of Object.entries(hosts || {})) {
            const sp = store.get('sparklines.' + hostname);
            if (sp?.p99?.length) {
                const last = sp.p99[sp.p99.length - 1];
                if (last > 500) {
                    const sev = last > 2000 ? 'danger' : 'warning';
                    items.push({ sev, icon: '🐌', msg: `High latency: ${last.toFixed(0)}ms p99`, sub: hostname });
                }
            }
        }

        // Update count badge and border
        if (countEl) {
            if (items.length) { countEl.textContent = items.length; countEl.style.display = ''; }
            else countEl.style.display = 'none';
        }
        if (panel) {
            const hasDanger = items.some(i => i.sev === 'danger');
            panel.style.borderColor = hasDanger ? 'rgba(255,59,48,0.3)' : items.length ? 'rgba(245,166,35,0.3)' : '';
        }

        if (!items.length) {
            listEl.innerHTML = `<div class="notif-empty">
                <span style="font-size:18px;">✅</span>
                <span style="display:block;margin-top:4px;font-weight:500;color:var(--text-main);">All systems healthy</span>
                <span style="display:block;font-size:10px;margin-top:2px;">No cert expiry, no dead backends, no elevated error rates</span>
            </div>`;
            return;
        }

        // Danger first, then warning
        items.sort((a, b) => (a.sev === 'danger' ? -1 : 1));
        listEl.innerHTML = items.map(item => `
            <div class="notif-item notif-${item.sev}">
                <span class="notif-item-icon">${item.icon}</span>
                <div class="notif-item-body">
                    <span class="notif-item-msg">${item.msg}</span>
                    ${item.sub ? `<span class="notif-item-sub">${item.sub}</span>` : ''}
                </div>
            </div>`).join('');
    }

    function refreshChart(history) {
        const h    = history || store.get('metricsHistory') || { all: [], http: [], tcp: [], udp: [], worker: [] };
        const key  = store.get('activeChart') || 'all';
        const vals = [...(h[key] || [])];
        if (vals.length === 0) vals.push(0);

        if (!mainChart) {
            mainChart = chart.bar('#responseGraph', vals, {
                unit: 'ms', warnAt: 500,
                colors: buildTimeGradient(vals.length),
                label: key.toUpperCase(),
            });
        } else {
            mainChart.update(vals, { colors: buildTimeGradient(vals.length), label: key.toUpperCase() });
        }
    }

    function processMetrics(payload) {
        const hosts   = payload.hosts || {};
        const version = store.get('sys.version') || '';
        let hc = 0, rc = 0, tReqs = 0, tErrs = 0;
        for (const h of Object.values(hosts)) {
            hc++; rc += (h.routes || []).length + (h.proxies || []).length;
            tReqs += h.total_reqs || 0;
            (h.routes  || []).forEach(r => (r.backends || []).forEach(b => tErrs += b.failures || 0));
            (h.proxies || []).forEach(p => (p.backends || []).forEach(b => tErrs += b.failures || 0));
        }
        const metaEl = find('#welcomeMeta');
        if (metaEl) metaEl.textContent = [version, payload.system?.uptime || '', `${hc} host${hc !== 1 ? 's' : ''}`, `${rc} route${rc !== 1 ? 's' : ''}`].filter(Boolean).join(' · ');
        const bar = find('#globalHealthBar');
        if (bar) {
            const errPct  = tReqs > 0 ? (tErrs / tReqs) * 100 : 0;
            const succPct = Math.max(0, 100 - errPct);
            bar.innerHTML = `<div class="hb-seg hb-ok" style="width:${succPct}%"></div><div class="hb-seg hb-err" style="width:${errPct}%"></div>`;
            const errText = find('#errorRateText');
            if (errText) errText.textContent = `${tReqs > 0 ? ((tErrs / tReqs) * 100).toFixed(1) : '0.0'}% errors`;
        }
        const timeEl   = find('#lastUpdatedText');
        if (timeEl) timeEl.textContent = 'Updated ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        renderCerts(store.get('certificates') || []);
        renderTopHosts(hosts);
        renderErrorHotspots(hosts);
        renderGitDeploys(payload.git || store.get('gitStats') || {});
        renderNotifications(hosts, store.get('certificates') || []);
        const hist      = payload.history || store.get('metricsHistory') || {};
        const httpEl    = find('#latencyHttpText');
        const tcpEl     = find('#latencyTcpText');
        const udpEl     = find('#latencyUdpText');
        const workerEl  = find('#latencyWorkerText');
        const lastHttp   = hist.http?.length   ? hist.http[hist.http.length - 1]     : 0;
        const lastTcp    = hist.tcp?.length    ? hist.tcp[hist.tcp.length - 1]        : 0;
        const lastUdp    = hist.udp?.length    ? hist.udp[hist.udp.length - 1]        : 0;
        const lastWorker = hist.worker?.length ? hist.worker[hist.worker.length - 1]  : 0;
        if (httpEl)   httpEl.textContent   = lastHttp   > 0 ? `HTTP p99 ${lastHttp.toFixed(0)}ms`   : '';
        if (tcpEl)    tcpEl.textContent    = lastTcp    > 0 ? `TCP p99 ${lastTcp.toFixed(0)}ms`     : '';
        if (udpEl)    udpEl.textContent    = lastUdp    > 0 ? `UDP p99 ${lastUdp.toFixed(0)}ms`     : '';
        if (workerEl) workerEl.textContent = lastWorker > 0 ? `Worker p99 ${lastWorker.toFixed(0)}ms` : '';
        refreshChart(payload.history);
    }

    // Boot — populate immediately from cache before first metrics poll
    const welEl = find('#welcomeName');
    if (welEl) {
        try { const { auth } = inject('app').oja; const user = auth.session.user(); welEl.textContent = (user?.user || user?.sub || 'ADMIN').toUpperCase(); }
        catch { welEl.textContent = 'ADMIN'; }
    }

    // Populate meta from cached config + uptime right away
    const cachedUptime  = store.get('lastUptime');
    const cachedConfig  = store.get('lastConfig');
    const cachedHosts   = (store.get('hostsData') || {}).stats || {};
    const metaEl = find('#welcomeMeta');
    if (metaEl) {
        const version = store.get('sys.version') || (cachedConfig?.global?.version ? 'v' + cachedConfig.global.version : '');
        const uptime  = cachedUptime?.system?.uptime || '';
        const hc      = Object.keys(cachedHosts).length;
        const rc      = Object.values(cachedHosts).reduce((s, h) => s + (h.routes?.length || 0) + (h.proxies?.length || 0), 0);
        metaEl.textContent = [version, uptime, hc ? `${hc} host${hc !== 1 ? 's' : ''}` : '', rc ? `${rc} route${rc !== 1 ? 's' : ''}` : ''].filter(Boolean).join(' · ') || '—';
    }

    renderCerts(store.get('certificates') || []);
    renderNotifications((store.get('hostsData') || {}).stats || {}, store.get('certificates') || []);
    const cachedHistory = store.get('metricsHistory');
    if (cachedHistory) refreshChart(cachedHistory);
    if (cachedUptime) renderGitDeploys(cachedUptime.git || store.get('gitStats') || {});
    if (Object.keys(cachedHosts).length) {
        renderTopHosts(cachedHosts);
        renderErrorHotspots(cachedHosts);
    }

    unsub = listen('metrics:updated', processMetrics);

    // Health bar expand/collapse
    on('#healthBarRow', 'click', () => {
        const detail  = find('#healthDetail');
        const section = find('#healthSection');
        const icon    = find('#healthSection .health-bar-expand-icon');
        if (!detail) return;
        const open = detail.style.display !== 'none';
        detail.style.display = open ? 'none' : 'block';
        // overflow:hidden on .health-section clips the expanded panel — remove it while open
        if (section) section.style.overflow = open ? '' : 'visible';
        if (icon) icon.style.transform = open ? '' : 'rotate(90deg)';
        if (!open) _renderHealthDetail();
    });

    function _renderHealthDetail() {
        const grid  = find('#healthDetailGrid');
        if (!grid) return;
        const hosts = (store.get('hostsData') || {}).stats || {};
        const cfg   = (store.get('lastConfig') || {}).hosts || {};

        const allEntries = Object.entries(hosts)
            .sort((a, b) => (b[1].total_reqs || 0) - (a[1].total_reqs || 0));
        const entries  = allEntries.slice(0, 10);
        const overflow = allEntries.length - entries.length;
        if (!entries.length) {
            grid.innerHTML = '<div class="detail-row"><span class="detail-label" style="color:var(--text-mute);">No hosts</span></div>';
            return;
        }

        grid.innerHTML = entries.map(([hostname, h]) => {
            let tReqs = h.total_reqs || 0;
            let tErrs = 0, dead = 0, alive = 0, p99sum = 0, p99cnt = 0;
            (h.routes || []).forEach(r => {
                (r.backends || []).forEach(b => {
                    tErrs += b.failures || 0;
                    if (b.alive === false) dead++; else alive++;
                    const v = b.latency_us?.p99;
                    if (v > 0) { p99sum += v / 1000; p99cnt++; }
                });
                (r.serverless || []).forEach(sl => {
                    tErrs += sl.failures || 0;
                    const v = sl.latency_us?.p99;
                    if (v > 0) { p99sum += v / 1000; p99cnt++; }
                });
            });
            (h.proxies || []).forEach(p => (p.backends || []).forEach(b => {
                if (b.alive === false) dead++; else alive++;
            }));

            const errRate  = tReqs > 0 ? ((tErrs / tReqs) * 100).toFixed(1) : '0.0';
            const p99      = p99cnt > 0 ? (p99sum / p99cnt).toFixed(0) + 'ms' : '—';
            const errColor = parseFloat(errRate) > 5 ? 'var(--danger)' : parseFloat(errRate) > 1 ? 'var(--warning)' : 'var(--success)';
            const p99Color = p99cnt > 0 && (p99sum / p99cnt) > 2000 ? 'var(--danger)' : p99cnt > 0 && (p99sum / p99cnt) > 500 ? 'var(--warning)' : 'var(--text-main)';
            const beStatus = dead > 0
                ? `<span style="color:var(--danger);">${alive} live / ${dead} dead</span>`
                : `<span style="color:var(--success);">${alive} live</span>`;

            return `<div class="detail-row" style="cursor:pointer;" data-action="open-host-detail" data-hostname="${hostname}">
                <span class="detail-label" style="font-family:var(--font-mono);min-width:120px;">${hostname}</span>
                <span class="detail-value" style="display:flex;gap:14px;justify-content:flex-end;align-items:center;">
                    <span style="font-family:var(--font-mono);color:${errColor};font-size:11px;">${errRate}% err</span>
                    <span style="font-family:var(--font-mono);color:${p99Color};font-size:11px;">${p99} p99</span>
                    <span style="font-size:11px;">${beStatus}</span>
                    <span style="font-size:11px;color:var(--text-mute);font-family:var(--font-mono);">${fmtReqs(tReqs)} reqs</span>
                </span>
            </div>`;
        }).join('');

        if (overflow > 0) {
            grid.innerHTML += `<div style="padding:6px 0;font-size:10px;color:var(--text-mute);text-align:right;font-family:var(--font-mono);">+${overflow} more · <span style="cursor:pointer;color:var(--accent);" data-action="goto-hosts">view all hosts</span></div>`;
        }

        // Click row → open host drawer; click "view all" → navigate to hosts
        grid.querySelectorAll('[data-action="open-host-detail"]').forEach(row =>
            row.addEventListener('click', () =>
                emit('drawer:open-route', { host: row.dataset.hostname, idx: 0, type: 'route' })
            )
        );
        grid.querySelector('[data-action="goto-hosts"]')?.addEventListener('click', () =>
            emit('app:navigate', { path: '/hosts' })
        );
    }

    on('#hostBriefing', 'click', (e) => {
        const row = e.target.closest('[data-hostname]');
        if (!row) return;
        emit('drawer:open-route', { host: row.dataset.hostname, idx: 0, type: 'route' });
    });

    on('#errorBriefing', 'click', (e) => {
        const row = e.target.closest('[data-hostname]');
        if (!row) return;
        emit('drawer:open-route', { host: row.dataset.hostname, idx: parseInt(row.dataset.routeIdx || '0'), type: 'route' });
    });

    on('#hostBriefing', 'contextmenu', (e) => {
        const row = e.target.closest('[data-hostname]');
        if (!row) return;
        e.preventDefault();
        const domain = row.dataset.hostname;
        const { clickmenu } = inject('app').oja;
        clickmenu.show(e.clientX, e.clientY, [
            { label: 'Go to host',   icon: '🔗', action: () => { store.set('searchTerm', domain); emit('app:navigate', { path: '/hosts' }); } },
            { label: 'Performance',  icon: '📈', action: () => emit('perf:open', { hostname: domain }) },
            { separator: true },
            { label: 'Edit config',  icon: '✏️', action: () => { store.set('searchTerm', domain); emit('app:navigate', { path: '/hosts' }); setTimeout(() => emit('host:open-edit', { domain }), 150); } },
        ]);
    });

    on('.chart-tab', 'click', (e) => {
        const tab = e.target.closest('.chart-tab');
        if (!tab) return;
        findAll('.chart-tab').forEach(t => t.classList.remove('active'));
        tab.classList.add('active');
        store.set('activeChart', tab.dataset.type);
        refreshChart();
    });

    // Chart bar tooltip
    // chart.bar renders a static SVG — no built-in hover. We attach a mousemove
    // listener on the wrapper and work out which bar the cursor is over by
    // dividing the inner width by the number of data points.
    let _chartTip = null;
    function _getOrCreateTip() {
        if (_chartTip && _chartTip.isConnected) return _chartTip;
        _chartTip = document.createElement('div');
        _chartTip.style.cssText = [
            'position:fixed',
            'background:var(--panel-bg)',
            'border:1px solid var(--border)',
            'color:var(--fg)',
            'padding:4px 10px',
            'font-size:11px',
            'font-family:var(--font-mono)',
            'pointer-events:none',
            'z-index:10000',
            'white-space:nowrap',
            'display:none',
            'border-radius:4px',
        ].join(';');
        document.body.appendChild(_chartTip);
        return _chartTip;
    }

    const _graphEl = find('#responseGraph');
    let _tipHideTimer = null;

    function _onChartMouseMove(e) {
        const h    = store.get('metricsHistory') || {};
        const key  = store.get('activeChart') || 'all';
        const vals = h[key] || [];
        const ts   = h.timestamps || [];
        if (!vals.length) return;

        const rect  = _graphEl.getBoundingClientRect();
        // PAD values match oja chart.js: left=34, right=10, top=10, bottom=20
        const PAD_L = 34, PAD_R = 10;
        const iW    = rect.width - PAD_L - PAD_R;
        const relX  = e.clientX - rect.left - PAD_L;
        if (relX < 0 || relX > iW) { _hideTip(); return; }

        const n   = vals.length;
        const idx = Math.min(n - 1, Math.max(0, Math.floor((relX / iW) * n)));
        const v   = vals[idx];
        const t   = ts[idx];

        const tip  = _getOrCreateTip();
        const time = t ? new Date(t * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '';
        const min  = Math.min(...vals.filter(v => v > 0));
        const max  = Math.max(...vals);
        tip.innerHTML = `${v.toFixed(0)}ms${time ? '<span style="color:var(--text-mute);margin-left:8px;">' + time + '</span>' : ''}` +
            `<span style="color:var(--text-mute);margin-left:12px;font-size:10px;">min ${min.toFixed(0)} · max ${max.toFixed(0)}</span>`;
        tip.style.display = 'block';
        tip.style.left = (e.clientX + 12) + 'px';
        tip.style.top  = (e.clientY - 28) + 'px';

        clearTimeout(_tipHideTimer);
    }

    function _hideTip() {
        clearTimeout(_tipHideTimer);
        _tipHideTimer = setTimeout(() => { if (_chartTip) _chartTip.style.display = 'none'; }, 80);
    }

    if (_graphEl) {
        _graphEl.addEventListener('mousemove', _onChartMouseMove);
        _graphEl.addEventListener('mouseleave', _hideTip);
    }

    onUnmount(() => {
        if (unsub) unsub();
        _clearCertCountdowns();
        mainChart?.destroy?.();
        mainChart = null;
        unsub = null;
        if (_chartTip) { _chartTip.remove(); _chartTip = null; }
        if (_graphEl) {
            _graphEl.removeEventListener('mousemove', _onChartMouseMove);
            _graphEl.removeEventListener('mouseleave', _hideTip);
        }
    });

    ready();
}
