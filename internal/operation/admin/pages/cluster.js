/**
 * pages/cluster.js — Cluster page.
 */
import { listen } from '../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, utils, oja } = inject('app');
    const { fmtNum } = utils;
    const { modal } = oja;
    let pollTimer = null;

    function render(clusterStats) {
        const grid    = find('#clusterMetricsGrid');
        const section = find('#clusterNodesSection');
        const cards   = find('#clusterNodeCards');
        if (!grid || !cards) return;
        if (!clusterStats?.enabled) {
            grid.innerHTML = `<div class="empty-state" style="grid-column:1/-1;"><span>Cluster mode is disabled</span><span>Enable gossip in agbero.hcl to use clustering</span></div>`;
            if (section) section.style.display = 'none';
            return;
        }
        const members = clusterStats.members || [];
        const metrics = clusterStats.metrics || {};
        grid.innerHTML = `
            <div class="metric-card"><div class="metric-label">Active Nodes</div><div class="metric-value">${members.length}</div></div>
            <div class="metric-card"><div class="metric-label">Updates Received</div><div class="metric-value">${fmtNum(metrics.updates_received||0)}</div></div>
            <div class="metric-card"><div class="metric-label">Total Deletes</div><div class="metric-value">${fmtNum(metrics.deletes||0)}</div></div>
            <div class="metric-card"><div class="metric-label">Ignored Updates</div><div class="metric-value">${fmtNum(metrics.updates_ignored||0)}</div></div>`;
        if (section) section.style.display = members.length ? '' : 'none';
        if (!members.length) { cards.innerHTML = ''; return; }
        cards.innerHTML = members.map(m => {
            const name     = typeof m === 'string' ? m : (m.name || m.addr || JSON.stringify(m));
            const addr     = typeof m === 'object' ? (m.addr || '') : '';
            const role     = typeof m === 'object' ? (m.role || 'member') : 'member';
            const isLeader = role === 'leader' || role === 'primary';
            const seen     = typeof m === 'object' && m.last_seen ? new Date(m.last_seen).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : null;
            return `<div class="config-detail-item" style="display:flex;flex-direction:column;gap:6px;">
                <div style="display:flex;align-items:center;gap:8px;">
                    <span class="dot ok"></span>
                    <span class="mono" style="font-size:12px;font-weight:500;flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${name}</span>
                    ${isLeader ? '<span class="badge info" style="flex-shrink:0;">leader</span>' : '<span class="badge" style="flex-shrink:0;">member</span>'}
                </div>
                ${addr ? `<div style="font-size:11px;color:var(--text-mute);font-family:var(--font-mono);">${addr}</div>` : ''}
                ${seen ? `<div style="font-size:10px;color:var(--text-mute);">last seen ${seen}</div>` : ''}
            </div>`;
        }).join('');
    }

    async function refresh() { const data = await api.fetchUptime(); render(data?.cluster); }

    const unsub = listen('cluster:updated', ({ clusterStats }) => render(clusterStats));
    on('#addClusterRouteBtn', 'click', () => modal.open('clusterRouteModal'));

    // Boot from cache using dedicated lastCluster key
    const cached = store.get('lastCluster');
    if (cached) render(cached);
    refresh();
    pollTimer = setInterval(refresh, 10000);

    onUnmount(() => { unsub(); if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } });
    ready();
}
