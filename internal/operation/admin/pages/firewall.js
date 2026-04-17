/**
 * pages/firewall.js — Firewall page.
 * display global firewall mode, inspect settings, action definitions.
 */
import { listen, notify, countdown, emit } from '../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { api, store, oja } = inject('app');
    const { modal } = oja;

    let _rules     = [];
    let _sortKey   = 'created_desc';
    let _confirmIp = null;
    const _countdownHandles = new Map();

    function renderGlobalStatus() {
        const cfg = store.get('lastConfig');
        const fw  = cfg?.global?.security?.firewall;
        const bar = find('#fwStatusBar');
        if (!bar || !fw) return;
        bar.style.display = '';
        const modeEl     = find('#fwMode');
        const inspectEl  = find('#fwInspectBody');
        const dynEl      = find('#fwDefaultDynamic');
        const statEl     = find('#fwDefaultStatic');
        if (modeEl) {
            const mode = fw.mode || 'active';
            modeEl.textContent  = mode;
            modeEl.className    = `badge ${mode === 'active' ? 'success' : 'warning'}`;
        }
        if (inspectEl) {
            inspectEl.textContent = fw.inspect_body ? 'On' : 'Off';
            inspectEl.className   = `badge ${fw.inspect_body ? 'warning' : ''}`;
        }
        if (dynEl) {
            dynEl.textContent = fw.defaults?.dynamic?.action || 'ban_short';
            dynEl.className   = 'badge';
        }
        if (statEl) {
            statEl.textContent = fw.defaults?.static?.action || 'ban_hard';
            statEl.className   = 'badge';
        }
    }

    // Rule rendering
    function emptyRow(html) {
        return `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">${html}</div></td></tr>`;
    }

    function sortRules(rules) {
        const r = [...rules];
        if (_sortKey === 'ip')               r.sort((a, b) => (a.ip || '').localeCompare(b.ip || ''));
        else if (_sortKey === 'created_asc') r.sort((a, b) => new Date(a.created_at || 0) - new Date(b.created_at || 0));
        else                                 r.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
        return r;
    }

    function ruleRow(r) {
        const created    = r.created_at ? new Date(r.created_at) : null;
        const dateStr    = created && !isNaN(created)
            ? created.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
            : '—';
        const ip         = r.ip || '0.0.0.0';
        const expiresAt  = (r.duration_sec && r.duration_sec > 0 && created)
            ? created.getTime() + r.duration_sec * 1000
            : null;
        const expiryCell = expiresAt
            ? `<span class="fw-countdown" data-expires="${expiresAt}"></span>`
            : `<span style="color:var(--text-mute);font-size:11px;">Permanent</span>`;
        return `<tr>
            <td class="mono">${ip}</td>
            <td>${r.reason || '—'}</td>
            <td class="hide-mobile mono" style="font-size:11px;">${r.host || '*'} / ${r.path || '*'}</td>
            <td class="hide-mobile" style="font-family:var(--font-mono);font-size:11px;">${dateStr}<br>${expiryCell}</td>
            <td><button class="btn small error fw-unblock-btn" data-ip="${ip}" data-confirm="">Unblock</button></td>
        </tr>`;
    }

    function _startCountdowns() {
        for (const h of _countdownHandles.values()) h.destroy();
        _countdownHandles.clear();
        find('#firewallTable')?.querySelectorAll('.fw-countdown[data-expires]').forEach(el => {
            const expiresAt = +el.dataset.expires;
            if (!expiresAt) return;
            const handle = countdown.attach(el, expiresAt, {
                format: (ms) => {
                    if (ms <= 0) return '<span style="color:var(--success)">expiring…</span>';
                    const h = Math.floor(ms / 3_600_000), m = Math.floor((ms % 3_600_000) / 60_000), s = Math.floor((ms % 60_000) / 1_000);
                    if (h > 0) return `<span style="color:var(--warning)">${h}h ${m}m left</span>`;
                    if (m > 0) return `<span style="color:var(--warning)">${m}m ${s}s left</span>`;
                    return `<span style="color:var(--danger)">${s}s left</span>`;
                },
                onExpire: () => setTimeout(refresh, 2000),
            });
            _countdownHandles.set(expiresAt, handle);
        });
    }

    function render(data) {
        const tbody   = find('#firewallTable');
        const countEl = find('#fwCount');
        if (!tbody) return;
        if (!data) {
            tbody.innerHTML = emptyRow('⚠️ Firewall unavailable');
            if (countEl) countEl.textContent = '—';
            return;
        }
        if (data.enabled === false) {
            tbody.innerHTML = emptyRow('<span>🛡️ Firewall disabled</span><span>Enable in agbero.hcl to use this feature</span>');
            if (countEl) countEl.textContent = '0';
            return;
        }
        _rules = data.rules || [];
        if (countEl) countEl.textContent = String(_rules.length);
        if (!_rules.length) {
            tbody.innerHTML = emptyRow('<span>✅ No blocked IPs</span><span>All traffic is currently allowed</span>');
            return;
        }
        tbody.innerHTML = sortRules(_rules).map(ruleRow).join('');
    }

    async function refresh() {
        render(await api.fetchFirewall());
        _startCountdowns();
    }

    on('#addRuleBtn', 'click', () => emit('firewall:open-rule', {}));
    on('#fwSortSel',  'change', (e, el) => {
        _sortKey = el.value;
        render({ enabled: true, rules: _rules });
    });

    on('.fw-unblock-btn', 'click', async (e, btn) => {
        const ip = btn.dataset.ip;
        if (!ip) return;
        if (btn.dataset.confirm === '1') {
            _confirmIp = null;
            btn.disabled = true;
            btn.textContent = '…';
            try {
                await api.deleteFirewallRule(ip);
                notify.show(`${ip} unblocked`, 'success');
                refresh();
            } catch {
                btn.disabled = false;
                btn.textContent = 'Unblock';
                btn.className = 'btn small error fw-unblock-btn';
                btn.dataset.confirm = '';
                notify.show('Failed to unblock', 'error');
            }
        } else {
            if (_confirmIp && _confirmIp !== ip) {
                const prev = find(`.fw-unblock-btn[data-ip="${_confirmIp}"]`);
                if (prev) {
                    prev.textContent = 'Unblock';
                    prev.className   = 'btn small error fw-unblock-btn';
                    prev.dataset.confirm = '';
                    prev.style.cssText   = '';
                }
            }
            _confirmIp = ip;
            btn.dataset.confirm = '1';
            btn.textContent = 'Sure?';
            btn.className   = 'btn small fw-unblock-btn';
            btn.style.background   = 'var(--warning)';
            btn.style.color        = '#fff';
            btn.style.borderColor  = 'var(--warning)';
            setTimeout(() => {
                if (btn.dataset.confirm === '1') {
                    btn.dataset.confirm  = '';
                    btn.textContent      = 'Unblock';
                    btn.className        = 'btn small error fw-unblock-btn';
                    btn.style.cssText    = '';
                    _confirmIp = null;
                }
            }, 3000);
        }
    });

    const unsubRefresh = listen('firewall:refresh', refresh);

    renderGlobalStatus();

    // Skeleton while loading
    const tbody = find('#firewallTable');
    if (tbody) tbody.innerHTML = `<tr><td colspan="5"><div class="loading-rows"><div class="loading-row"></div><div class="loading-row"></div></div></td></tr>`;
    refresh();

    onUnmount(() => {
        unsubRefresh();
        for (const h of _countdownHandles.values()) h.destroy();
        _countdownHandles.clear();
    });

    ready();
}
