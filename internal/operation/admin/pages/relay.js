import { getApi, fmtNum, formatBytes } from '../js/api.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { utils } = inject('app');
    const api = getApi();
    let timer = null;
    const esc = (s) => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const age = (iso) => {
        if (!iso) return '—';
        const d = (Date.now() - new Date(iso).getTime()) / 1000;
        if (!isFinite(d) || d < 0) return '—';
        if (d < 60) return Math.round(d) + 's ago';
        if (d < 3600) return Math.round(d / 60) + 'm ago';
        if (d < 86400) return Math.round(d / 3600) + 'h ago';
        return Math.round(d / 86400) + 'd ago';
    };

    function exposures(ex = []) {
        return ex.map(e => {
            const p = [];
            if (e.path) p.push('/' + e.id);
            if (e.subdomain) p.push(e.id + '.');
            if (e.tcp_port) p.push('tcp:' + e.tcp_port);
            if (e.udp_port) p.push('udp:' + e.udp_port);
            return `<span class="badge info">${esc(p.join(' '))}</span>`;
        }).join(' ') || '<span class="badge">none</span>';
    }

    function summary(servers) {
        const agents = servers.reduce((n, s) => n + (s.agents || []).length, 0);
        const streams = servers.reduce((n, s) => n + (s.agents || []).reduce((m, a) => m + (a.streams || 0), 0), 0);
        const bytes = servers.reduce((n, s) => n + (s.agents || []).reduce((m, a) => m + (a.bytes_in || 0) + (a.bytes_out || 0), 0), 0);
        const errors = servers.reduce((n, s) => n + (s.auth_errors || 0), 0);
        return `<div class="config-metrics-grid">
            <div class="metric-card"><div class="metric-label">Relay Servers</div><div class="metric-value">${servers.length}</div></div>
            <div class="metric-card"><div class="metric-label">Connected Agents</div><div class="metric-value">${agents}</div></div>
            <div class="metric-card"><div class="metric-label">Active Streams</div><div class="metric-value">${fmtNum(streams)}</div></div>
            <div class="metric-card"><div class="metric-label">Traffic</div><div class="metric-value">${formatBytes(bytes)}</div></div>
            <div class="metric-card"><div class="metric-label">Auth Failures</div><div class="metric-value" style="color:${errors ? 'var(--danger)' : 'inherit'}">${fmtNum(errors)}</div></div>
        </div>`;
    }

    function routesTable(routes = []) {
        if (!routes.length) return '';
        const rows = routes.map(r => {
            const local = [r.local_host, r.local_path].filter(Boolean).join(' ') || '—';
            return `<tr>
                <td class="mono">${esc(r.key)}</td>
                <td>${esc(r.agent || '—')}</td>
                <td class="mono">${esc(local)}</td>
                <td>${r.live ? '<span class="dot ok"></span> live' : '<span class="dot down"></span> <span style="color:var(--danger)">dead</span>'}</td>
            </tr>`;
        }).join('');
        return `<div style="font-size:12px;color:var(--text-mute);margin:10px 0 4px;">Routes (live public routing table)</div>
            <table class="simple-table">
                <thead><tr><th>Route</th><th>Agent</th><th>Local</th><th>Session</th></tr></thead>
                <tbody>${rows}</tbody>
            </table>`;
    }

    function render(data) {
        const root = find('#relayServers');
        if (!root) return;
        const servers = data?.servers || [];
        if (!servers.length) {
            root.innerHTML = '<div class="empty-state"><span>No relay servers configured</span></div>';
            return;
        }
        let html = summary(servers);
        for (const s of servers) {
            const agents = s.agents || [];
            const rows = agents.map(a => {
                const since = a.connected_at ? new Date(a.connected_at).toLocaleString() : '—';
                const bytes = (a.bytes_in || 0) + (a.bytes_out || 0);
                const reconnects = fmtNum(a.reconnects || 0);
                return `<tr>
                    <td><span class="dot ok"></span> <strong>${esc(a.id)}</strong></td>
                    <td class="mono">${esc(a.remote || '—')}</td>
                    <td title="${esc(since)}">${esc(age(a.connected_at))}</td>
                    <td>${reconnects}</td>
                    <td>${fmtNum(a.streams || 0)}</td>
                    <td>${exposures(a.exposures)}</td>
                    <td>${formatBytes(a.bytes_in || 0)} / ${formatBytes(a.bytes_out || 0)}</td>
                    <td>${a.last_error ? `<span style="color:var(--danger);font-size:11px;" title="${esc(a.last_error_at ? new Date(a.last_error_at).toLocaleString() : '')}">${esc(a.last_error)} (${esc(age(a.last_error_at))})</span>` : '<span class="dot ok"></span>'}</td>
                </tr>`;
            }).join('');

            html += `<div class="detail-section" style="margin-bottom:16px;">
                <div class="detail-title" style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
                    <span class="dot ${s.running ? 'ok' : 'down'}"></span>
                    <span>${esc(s.name)}</span>
                    <span class="badge info">${esc(s.domain)}</span>
                    <span class="badge">${esc(s.listen)}</span>
                    ${s.auth_errors ? `<span class="badge danger">${fmtNum(s.auth_errors)} auth failures</span>` : ''}
                    ${s.enroll_fingerprint ? `<span class="badge" title="Effective enrollment token fingerprint">token ${esc(s.enroll_fingerprint)}</span>` : ''}
                </div>
                ${s.last_error ? `<div style="color:var(--danger);font-size:12px;margin:6px 0;">last error: ${esc(s.last_error)} <span style="color:var(--text-mute);">(${esc(age(s.last_error_at))})</span></div>` : ''}
                ${s.last_auth ? `<div style="color:var(--text-mute);font-size:11px;margin:4px 0;">last auth attempt: ${esc(s.last_auth.agent)} ${esc(s.last_auth.mode)} expected=${esc(s.last_auth.expected_fingerprint || '—')} presented=${esc(s.last_auth.presented_fingerprint || '—')}</div>` : ''}
                ${routesTable(s.routes || [])}
                ${agents.length ? `<table class="simple-table">
                    <thead><tr><th>Agent</th><th>Remote</th><th>Connected</th><th>Reconnects</th><th>Streams</th><th>Exposures</th><th>In / Out</th><th>Status</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>` : '<div class="empty-state" style="padding:16px 0;"><span>No agents connected</span></div>'}
            </div>`;
        }
        root.innerHTML = html;
    }

    async function refresh() {
        try { render(await api.get('/api/v1/relay')); }
        catch (err) {
            const root = find('#relayServers');
            if (root) root.innerHTML = `<div class="empty-state"><span>Failed to load relay status</span><span>${esc(err?.message || '')}</span></div>`;
        }
    }

    on('#relayRefreshBtn', 'click', refresh);
    await refresh();
    timer = setInterval(refresh, 5000);
    onUnmount(() => { if (timer) clearInterval(timer); });
    ready();
}
