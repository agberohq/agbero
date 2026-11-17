/**
 * pages/mcp.js — MCP control-plane page.
 */
import { notify } from '../lib/oja.full.esm.js';
import { MCP_SCOPES, MCP_TRANSPORTS } from '../js/constants.js';

export default async function({ find, findAll, on, ready, inject }) {
    const { api } = inject('app');

    const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    }[c]));

    let lastStatus = null;

    function fmtBytes(n) {
        n = Number(n || 0);
        if (n < 1024) return `${n} B`;
        if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
        if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MiB`;
        return `${(n / 1024 / 1024 / 1024).toFixed(2)} GiB`;
    }

    function card(label, value, mono) {
        return `<div style="background:var(--panel-bg);border:1px solid var(--border);border-radius:8px;padding:14px;">
            <div style="font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.6px;">${esc(label)}</div>
            <div style="font-size:16px;margin-top:6px;${mono ? 'font-family:var(--font-mono);font-size:13px;' : ''}">${esc(value)}</div>
        </div>`;
    }

    function switchTab(name) {
        findAll('.mcp-tab').forEach(btn => {
            const active = btn.dataset.mcpTab === name;
            btn.style.color = active ? 'var(--text)' : 'var(--text-mute)';
            btn.style.borderBottom = active ? '2px solid var(--accent)' : '2px solid transparent';
        });
        findAll('[data-mcp-panel]').forEach(panel => {
            panel.style.display = panel.dataset.mcpPanel === name ? '' : 'none';
        });
    }

    function renderStatus(st) {
        lastStatus = st;
        const badge = find('#mcpStatusBadge');
        if (badge) {
            badge.textContent = st.enabled ? 'enabled' : 'off';
            badge.className = 'badge ' + (st.enabled ? 'success' : '');
        }
        const cards = find('#mcpCards');
        if (cards) {
            cards.innerHTML = [
                card('Transport', st.transport || MCP_TRANSPORTS.STDIO),
                card('Read', st.read?.enabled ? 'on' : 'off'),
                card('Plan', st.plan?.enabled ? 'on' : 'off'),
                card('Rate limit', st.rate_limit || '—'),
                card('Keeper', st.keeper_locked ? 'locked' : 'unlocked'),
                card('Allowed IPs', (st.allowed_ips || []).join(', ') || '—', true),
                card('Direct endpoint', st.admin_url || '—', true),
                card('Requests', st.stats?.requests || 0),
                card('Errors', st.stats?.errors || 0),
                card('Transfer in', fmtBytes(st.stats?.bytes_in)),
                card('Transfer out', fmtBytes(st.stats?.bytes_out)),
            ].join('');
        }

        const hostDetail = find('#mcpHostDetail');
        const hostLink = find('#mcpHostLink');
        const hostBtn = find('#mcpEnableHostBtn');
        const disableBtn = find('#mcpDisableHostBtn');
        if (hostDetail) {
            hostDetail.textContent = st.host_exists
                ? (st.host_managed ? `${st.url} (managed by this page)` : `${st.url} (existing host; not managed by this page)`)
                : 'Not enabled. This page creates the host on request; nothing is written automatically.';
        }
        if (hostLink) {
            hostLink.style.display = st.host_exists ? '' : 'none';
            hostLink.href = st.url || '#';
        }
        if (hostBtn) hostBtn.style.display = st.host_exists ? 'none' : '';
        if (disableBtn) {
            disableBtn.style.display = st.host_exists && st.host_managed ? '' : 'none';
            disableBtn.dataset.confirm = '';
            disableBtn.textContent = 'Remove';
        }

        const tbody = find('#mcpTokensTable tbody');
        if (tbody) {
            tbody.innerHTML = (st.tokens || []).map(t => `<tr>
                <td class="mono">${esc(t.user)}</td>
                <td class="mono">${esc(t.scope)}</td>
                <td class="mono" style="font-size:11px;">${esc(t.jti)}</td>
                <td class="mono" style="font-size:11px;">${esc((t.expires_at || '').replace('T', ' ').slice(0, 19))}</td>
                <td>${t.revoked ? '<span class="badge warning">revoked</span>' : '<span class="badge success">active</span>'}</td>
                <td>${t.revoked ? '—' : `<button class="btn small mcp-revoke-btn" data-jti="${esc(t.jti)}" data-confirm="">Revoke</button>`}</td>
            </tr>`).join('') || '<tr><td colspan="6" class="empty-state">No tokens minted yet</td></tr>';
        }

        const policy = find('#mcpPolicyTable tbody');
        if (policy) {
            policy.innerHTML = (st.capabilities || []).map(c =>
                `<tr><td class="mono">${esc(c.class)}</td><td class="mono">${esc(c.name)}</td><td class="mono">${esc(c.tool)}</td></tr>`
            ).join('') || '<tr><td colspan="3" class="empty-state">No capabilities</td></tr>';
        }
    }

    async function loadStatus() {
        const st = await api.fetchMCPStatus();
        if (st) renderStatus(st);
    }

    async function loadAudit() {
        const res = await api.fetchMCPAudit(200);
        const tbody = find('#mcpAuditTable tbody');
        if (!tbody) return;
        const rows = (res?.entries || []).map(line => {
            try { return JSON.parse(line); } catch { return null; }
        }).filter(Boolean).reverse();
        tbody.innerHTML = rows.map(e => `<tr>
            <td class="mono" style="font-size:11px;">${esc((e.ts || '').replace('T', ' ').slice(0, 19))}</td>
            <td class="mono">${esc(e.event || 'mcp_http')}</td>
            <td class="mono">${esc(e.actor || '—')}</td>
            <td class="mono">${esc(e.client_ip || '—')}</td>
            <td class="mono">${esc(e.tool || e.rpc_method || e.method || '—')}</td>
            <td class="mono">${esc(e.status ?? '—')}</td>
            <td class="mono">${esc(e.duration_ms ?? '—')}</td>
        </tr>`).join('') || '<tr><td colspan="7" class="empty-state">No audit entries</td></tr>';
    }

    function selectedScopes() {
        const out = [];
        if (find('#mcpScopeRead')?.checked) out.push(MCP_SCOPES.READ);
        if (find('#mcpScopePlan')?.checked) out.push(MCP_SCOPES.PLAN);
        if (find('#mcpScopePlan')?.checked && !find('#mcpScopeRead')?.checked) {
            if (find('#mcpScopeRead')) find('#mcpScopeRead').checked = true;
            if (!out.includes(MCP_SCOPES.READ)) out.unshift(MCP_SCOPES.READ);
        }
        return out;
    }

    async function copyToken() {
        const el = find('#mcpTokenValue');
        if (!el || !el.value) return;
        try {
            await navigator.clipboard.writeText(el.value);
            notify.show('Token copied', 'success');
        } catch {
            el.focus(); el.select();
            try { document.execCommand('copy'); notify.show('Token copied', 'success'); }
            catch { notify.show('Select the token and copy manually', 'warn'); }
        }
    }

    on('#mcpRefreshBtn', 'click', () => { loadStatus(); loadAudit(); });
    on('#mcpAuditRefreshBtn', 'click', loadAudit);
    on('#mcpCopyTokenBtn', 'click', copyToken);
    on('#mcpEnableHostBtn', 'click', async () => {
        const res = await api.createMCPHost();
        if (!res || (!res.created && !res.exists)) {
            notify.show('Could not enable https://mcp.localhost', 'error');
            return;
        }
        notify.show(res.created ? 'https://mcp.localhost enabled' : 'https://mcp.localhost already exists', 'success');
        await loadStatus();
    });
    const tokensTable = find('#mcpTokensTable');
    tokensTable?.addEventListener('click', async (e) => {
        const btn = e.target.closest('.mcp-revoke-btn');
        if (!btn) return;
        if (btn.dataset.confirm !== '1') {
            btn.dataset.confirm = '1';
            btn.textContent = 'Confirm revoke';
            setTimeout(() => {
                if (btn.isConnected) { btn.dataset.confirm = ''; btn.textContent = 'Revoke'; }
            }, 4000);
            return;
        }
        const res = await api.revokeMCPToken(btn.dataset.jti);
        if (res && res.ok) {
            notify.show('Token revoked', 'success');
            await loadStatus();
        } else {
            notify.show('Revoke failed', 'error');
        }
    });
    on('#mcpDisableHostBtn', 'click', async (e) => {
        const btn = e.currentTarget;
        if (btn.dataset.confirm !== '1') {
            btn.dataset.confirm = '1';
            btn.textContent = 'Confirm remove';
            setTimeout(() => {
                if (btn.isConnected) { btn.dataset.confirm = ''; btn.textContent = 'Remove'; }
            }, 4000);
            return;
        }
        const res = await api.deleteMCPHost();
        if (!res || !res.removed) {
            notify.show('Could not remove https://mcp.localhost', 'error');
            return;
        }
        btn.dataset.confirm = '';
        btn.textContent = 'Remove';
        notify.show('https://mcp.localhost removed', 'success');
        await loadStatus();
    });
    on('#mcpTokenCreateBtn', 'click', async () => {
        const user  = find('#mcpTokenUser')?.value || '';
        const scope = selectedScopes().join(' ') || MCP_SCOPES.READ;
        const ttl   = find('#mcpTokenTTL')?.value || '8h';
        const res = await api.createMCPToken({ user, scope, ttl });
        if (!res || !res.token) {
            notify.show(api.hostOpError ? api.hostOpError(res, 'Token creation failed') : 'Token creation failed', 'error');
            return;
        }
        const out = find('#mcpTokenOut');
        const tokenEl = find('#mcpTokenValue');
        const meta = find('#mcpTokenMeta');
        if (out) out.style.display = '';
        if (tokenEl) tokenEl.value = res.token;
        if (meta) meta.textContent = `JTI ${res.jti} · expires ${res.expires_at} · scope ${res.scope}`;
        notify.show('Token created — copy it now', 'success');
        await loadStatus();
    });

    findAll('.mcp-tab').forEach(btn => btn.addEventListener('click', () => switchTab(btn.dataset.mcpTab)));
    switchTab('tokens');

    const planScope = find('#mcpScopePlan');
    const readScope = find('#mcpScopeRead');
    planScope?.addEventListener('change', () => {
        if (planScope.checked && readScope) readScope.checked = true;
    });

    await ready();
    await loadStatus();
    await loadAudit();
}
