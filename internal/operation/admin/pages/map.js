/**
 * pages/map.js — Map / route graph page.
 */
import { clickmenu } from '../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, oja } = inject('app');
    const { emit, listen, clipboard, notify } = oja;
    let graph = null, paused = true, pollTimer = null;

    // Load D3 + graph.js
    async function loadGraphDeps() {
        if (window.RouteGraph) return;
        const load = src => new Promise((res, rej) => {
            const s = document.createElement('script');
            s.src = src; s.onload = res; s.onerror = rej;
            document.head.appendChild(s);
        });
        await load('https://d3js.org/d3.v7.min.js');
        await load('js/graph.js');
    }

    function hideLoading() { const el = find('#mapLoading'); if (el) el.style.display = 'none'; }

    function showEmpty() {
        hideLoading();
        const el = find('#graphContainer');
        if (el) el.innerHTML = `<div class="empty-state" style="margin-top:80px;">
            <span>🗺️ No routes configured</span>
            <span>Add a host to see the route graph</span>
            <button class="btn primary small" style="margin-top:12px;" id="mapAddHostBtn">+ Add Host</button>
        </div>`;
        on('#mapAddHostBtn', 'click', () => emit('app:navigate', { path: '/add-host' }));
    }

    // Info panel
    function _row(label, val) {
        if (val === undefined || val === null || val === '' || val === '—') return '';
        return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value" style="font-family:var(--font-mono);font-size:11px;">${val}</span></div>`;
    }

    function _statusBadge(alive, health) {
        if (alive === false) return `<span style="color:var(--danger);font-weight:500;">Dead</span>`;
        if (health?.status === 'degraded') return `<span style="color:var(--warning);font-weight:500;">Degraded</span>`;
        return `<span style="color:var(--success);">Healthy</span>`;
    }

    function buildNodeInfo(node) {
        const rows = [];
        const hostsData = store.get('hostsData')?.stats || {};

        if (node.type === 'host') {
            const hStat = hostsData[node.meta?.hostname] || {};
            rows.push(_row('Status',     _statusBadge(node.alive)));
            rows.push(_row('Total Reqs', hStat.total_reqs?.toLocaleString()));
            rows.push(_row('Routes',     (hStat.routes?.length || 0) + (hStat.proxies?.length || 0) || null));
            if (node.latency_us?.p50) rows.push(_row('p50', (node.latency_us.p50/1000).toFixed(1)+'ms'));
            if (node.latency_us?.p99) rows.push(_row('p99', (node.latency_us.p99/1000).toFixed(1)+'ms'));
        }

        if (node.type === 'route' && node.meta?.hostname) {
            const hStat = hostsData[node.meta.hostname] || {};
            if (node.meta.routeType === 'route') {
                const r = hStat.routes?.[node.meta.routeIdx];
                if (r) {
                    rows.push(_row('Status',   _statusBadge(node.alive)));
                    rows.push(_row('Path',     r.path));
                    rows.push(_row('Reqs',     r.total_reqs?.toLocaleString()));
                    const alive = (r.backends||[]).filter(b=>b.alive!==false).length;
                    const total = (r.backends||[]).length;
                    if (total) rows.push(_row('Backends', `${alive}/${total} alive`));
                }
            } else {
                const p = hStat.proxies?.[node.meta.routeIdx];
                if (p) {
                    rows.push(_row('Listen',   p.name));
                    rows.push(_row('Sessions', p.active_sessions > 0 ? p.active_sessions : null));
                    rows.push(_row('Protocol', node.protocol?.toUpperCase()));
                }
            }
        }

        if (node.type === 'backend' && node.meta?.hostname) {
            const hStat   = hostsData[node.meta.hostname] || {};
            const isProxy = node.meta.routeType === 'proxy';
            const rArr    = isProxy ? (hStat.proxies||[]) : (hStat.routes||[]);
            const r       = rArr[node.meta.routeIdx];
            const b       = r?.backends?.[node.meta.backendIdx];
            if (b) {
                rows.push(_row('Status',   _statusBadge(b.alive, b.health)));
                rows.push(_row('Score',    b.health?.score !== undefined ? b.health.score.toFixed(2) : null));
                rows.push(_row('Reqs',     b.total_reqs?.toLocaleString()));
                if (b.failures > 0) rows.push(_row('Failures', `<span style="color:var(--danger)">${b.failures}</span>`));
                if (b.latency_us?.p50) rows.push(_row('p50', (b.latency_us.p50/1000).toFixed(1)+'ms'));
                if (b.latency_us?.p99) rows.push(_row('p99', (b.latency_us.p99/1000).toFixed(1)+'ms'));
            }
        }

        return rows.join('') || `<div style="color:var(--text-mute);">No data available</div>`;
    }

    function buildNodeActions(node) {
        const actions = [];
        if (node.type === 'host' && node.meta?.hostname) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="perf-node" data-hostname="${node.meta.hostname}">📈 Performance History</button>`);
            actions.push(`<button class="btn small" style="width:100%;" data-action="edit-host-hcl" data-hostname="${node.meta.hostname}">✏️ Edit HCL</button>`);
        }
        if (node.type === 'route' && node.meta) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="open-route-drawer" data-hostname="${node.meta.hostname}" data-idx="${node.meta.routeIdx}" data-routetype="${node.meta.routeType}">🔍 View Details</button>`);
        }
        if (node.type === 'backend' && node.meta) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="open-backend-drawer" data-hostname="${node.meta.hostname}" data-routeidx="${node.meta.routeIdx}" data-backendidx="${node.meta.backendIdx}" data-routetype="${node.meta.routeType}">🔍 View Details</button>`);
        }
        return actions.join('');
    }

    function openInfoPanel(node) {
        const panel     = find('#mapInfoPanel');
        const titleEl   = find('#mapInfoTitle');
        const subtitleEl= find('#mapInfoSubtitle');
        const bodyEl    = find('#mapInfoBody');
        const actionsEl = find('#mapInfoActions');
        if (!panel) return;
        titleEl.textContent    = node.label || node.id || 'Node';
        subtitleEl.textContent = node.type.charAt(0).toUpperCase() + node.type.slice(1) + (node.protocol ? ` · ${node.protocol.toUpperCase()}` : '');
        bodyEl.innerHTML       = buildNodeInfo(node);
        actionsEl.innerHTML    = buildNodeActions(node);
        panel.style.display    = 'flex';
        panel.style.flexDirection = 'column';
    }

    // Context menu
    function showNodeContextMenu(event, node) {
        const items = [];

        if (node.type === 'host' && node.meta?.hostname) {
            const h = node.meta.hostname;
            items.push({ label: 'View Details',       icon: '🔍', action: () => openInfoPanel(node) });
            items.push({ label: 'Performance History',icon: '📈', action: () => emit('perf:open', { hostname: h }) });
            items.push({ label: 'Edit HCL',           icon: '✏️',  action: async () => {
                    const hcl = await api.getHostHCL(h);
                    if (hcl) emit('host:open-edit-hcl', { domain: h, hcl });
                    else notify.show('Could not load HCL', 'error');
                }});
            items.push({ separator: true });
            items.push({ label: 'Copy Hostname', icon: '📋', action: () => clipboard.write(h).then(() => notify.show('Copied', 'success')) });
            items.push({ label: 'Block IP…',     icon: '🛡️', action: () => emit('firewall:open-rule', { host: h }) });
        }

        if (node.type === 'route' && node.meta) {
            items.push({ label: 'View Details', icon: '🔍', action: () => openInfoPanel(node) });
            items.push({ label: 'Open Drawer',  icon: '↗️',  action: () => emit('drawer:open-route', { host: node.meta.hostname, idx: node.meta.routeIdx, type: node.meta.routeType }) });
        }

        if (node.type === 'backend' && node.meta) {
            items.push({ label: 'View Details', icon: '🔍', action: () => openInfoPanel(node) });
            items.push({ label: 'Open Drawer',  icon: '↗️',  action: () => emit('drawer:open-backend', { host: node.meta.hostname, routeIdx: node.meta.routeIdx, backendIdx: node.meta.backendIdx, type: node.meta.routeType }) });
            if (node.label) items.push({ label: 'Copy URL', icon: '📋', action: () => clipboard.write(node.label).then(() => notify.show('Copied', 'success')) });
        }

        items.push({ separator: true });
        items.push({ label: 'Reset View', icon: '⊙', action: () => graph?.resetZoom() });

        clickmenu.show(event.clientX, event.clientY, items);
    }

    // Search
    let _searchTerm = '';

    function _applySearch(term) {
        _searchTerm = term.toLowerCase().trim();
        if (!graph?.data?.nodes) return;
        const svg = document.querySelector('#graphContainer svg');
        if (!svg) return;
        svg.querySelectorAll('.node-group').forEach(el => {
            const label = (el.dataset.label || '').toLowerCase();
            const id    = (el.dataset.id    || '').toLowerCase();
            const match = !_searchTerm || label.includes(_searchTerm) || id.includes(_searchTerm);
            el.style.opacity = match ? '1' : '0.15';
        });
    }

    on('#mapSearch', 'input', (e, inp) => {
        const clearBtn = find('#mapSearchClear');
        if (clearBtn) clearBtn.style.display = inp.value ? '' : 'none';
        _applySearch(inp.value);
    });

    on('#mapSearchClear', 'click', () => {
        const inp = find('#mapSearch');
        if (inp) { inp.value = ''; inp.focus(); }
        find('#mapSearchClear').style.display = 'none';
        _applySearch('');
    });

    // Refresh
    async function refresh() {
        if (!graph) return;
        const config = store.get('lastConfig') || await api.fetchConfig();
        const uptime = await api.fetchUptime();
        if (!config || !uptime) return;
        if (Object.keys(config.hosts || {}).length === 0) { showEmpty(); return; }
        graph.render(config, uptime.hosts || {});
        hideLoading();
        // Re-apply search after render
        if (_searchTerm) _applySearch(_searchTerm);
        // Add data-label and data-id to node groups for search
        requestAnimationFrame(() => {
            document.querySelectorAll('#graphContainer .node').forEach(el => {
                el.classList.add('node-group');
                const d = el.__data__;
                if (d) { el.dataset.label = d.label || ''; el.dataset.id = d.id || ''; }
            });
        });
    }

    // Init
    async function init() {
        try { await loadGraphDeps(); }
        catch (err) {
            hideLoading();
            const el = find('#graphContainer');
            if (el) el.innerHTML = `<div class="empty-state" style="margin-top:60px;">⚠️ Failed to load graph: ${err.message}</div>`;
            return;
        }
        graph = new RouteGraph('graphContainer');

        graph._onClick = function(d) {
            openInfoPanel(d);
            if (d.type === 'route'   && d.meta) emit('drawer:open-route',   { host: d.meta.hostname, idx: d.meta.routeIdx, type: d.meta.routeType });
            if (d.type === 'backend' && d.meta) emit('drawer:open-backend', { host: d.meta.hostname, routeIdx: d.meta.routeIdx, backendIdx: d.meta.backendIdx, type: d.meta.routeType });
            if (d.type === 'host'    && d.meta) emit('perf:open', { hostname: d.meta.hostname });
        };

        graph._onRightClick = function(event, d) {
            showNodeContextMenu(event, d);
        };

        await refresh();
    }

    // Info panel action delegation
    on('[data-action="perf-node"]',        'click', (e, btn) => emit('perf:open', { hostname: btn.dataset.hostname }));
    on('[data-action="open-route-drawer"]','click', (e, btn) => emit('drawer:open-route',   { host: btn.dataset.hostname, idx: parseInt(btn.dataset.idx), type: btn.dataset.routetype }));
    on('[data-action="open-backend-drawer"]','click',(e,btn) => emit('drawer:open-backend', { host: btn.dataset.hostname, routeIdx: parseInt(btn.dataset.routeidx), backendIdx: parseInt(btn.dataset.backendidx), type: btn.dataset.routetype }));
    on('[data-action="edit-host-hcl"]',    'click', async (e, btn) => {
        const h   = btn.dataset.hostname;
        const hcl = await api.getHostHCL(h);
        if (hcl) emit('host:open-edit-hcl', { domain: h, hcl });
        else notify.show('Could not load HCL', 'error');
    });

    init();

    // Live updates
    const unsub = listen('metrics:updated', ({ hosts }) => {
        if (paused || !graph) return;
        const config = store.get('lastConfig');
        if (config) {
            if (typeof graph.update === 'function') graph.update(config, hosts || {});
            else graph.render(config, hosts || {});
        }
    });

    on('#mapPauseBtn', 'click', (e, btn) => {
        paused = !paused;
        if (btn) btn.textContent = paused ? '▶ Resume' : '⏸ Pause';
        if (!paused) refresh();
    });

    on('#resetZoomBtn', 'click', () => graph?.resetZoom());

    on('#mapInfoClose', 'click', () => {
        const p = find('#mapInfoPanel');
        if (p) p.style.display = 'none';
    });

    pollTimer = setInterval(() => { if (!paused) refresh(); }, 30_000);
    onUnmount(() => {
        unsub?.();
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    });
    ready();
}
