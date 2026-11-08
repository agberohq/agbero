/**
 * pages/map.js — Map / route graph page.
 *
 * The graph renders with native SVG (js/graph.js + js/graph-layout.js). There is
 * no D3 and no CDN: the whole page works offline and the admin CSP does not
 * have to allow a third-party script origin.
 */
import { clickmenu } from '../lib/oja.full.esm.js';
import { storeLocal } from '../js/store.js';
import { ROUTE_PROTOCOLS } from '../js/constants.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, oja } = inject('app');
    const { emit, listen, clipboard, notify } = oja;
    let graph = null, paused = true, pollTimer = null;

    // preferences
    const PREFS_KEY = 'mapPrefs';
    const DEFAULTS = { view: 'force', orientation: 'LR', density: 'detailed', animate: true };
    let prefs = Object.assign({}, DEFAULTS, storeLocal.get(PREFS_KEY) || {});

    function savePrefs(patch) {
        prefs = Object.assign({}, prefs, patch);
        storeLocal.set(PREFS_KEY, prefs);
    }

    // Load the layout engine then the renderer (both served from the admin FS).
    async function loadGraphDeps() {
        if (!window.ROUTE_PROTOCOLS) window.ROUTE_PROTOCOLS = ROUTE_PROTOCOLS;
        if (window.RouteGraph && window.GraphLayout) return;
        const load = src => new Promise((res, rej) => {
            const s = document.createElement('script');
            s.src = src;
            s.onload = res;
            s.onerror = () => rej(new Error(`failed to load ${src}`));
            document.head.appendChild(s);
        });
        if (!window.GraphLayout) await load('js/graph-layout.js');
        if (!window.RouteGraph)  await load('js/graph.js');
    }

    function hideLoading() { const el = find('#mapLoading'); if (el) el.style.display = 'none'; }

    function setLoading(msg) {
        const el = find('#mapLoading');
        if (!el) return;
        const textEl = el.querySelector('div > div:last-child');
        if (textEl) textEl.textContent = msg || 'Loading route graph…';
        el.style.display = 'flex';
    }

    function showEmpty() {
        hideLoading();
        if (graph) { graph.destroy(); graph = null; }
        const el = find('#graphContainer');
        if (el) el.innerHTML = `<div class="empty-state" style="margin-top:80px;">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" style="opacity:0.4;margin-bottom:8px;">
                <rect x="4" y="4" width="40" height="40" rx="8" stroke="var(--text-mute)" stroke-width="2" fill="none"/>
                <path d="M14 24h20M24 14v20" stroke="var(--text-mute)" stroke-width="2" stroke-linecap="round"/>
            </svg>
            <div style="font-weight:500;">No routes configured</div>
            <div style="color:var(--text-mute);font-size:12px;margin-top:4px;">Add a host to see the route graph</div>
            <button class="btn primary small" style="margin-top:12px;" id="mapAddHostBtn">+ Add Host</button>
        </div>`;
        on('#mapAddHostBtn', 'click', () => emit('app:navigate', { path: '/add-host' }));
    }

    // Info panel
    // Values here come from config (hostnames, paths, proxy names), so they stay
    // escaped unless the caller passes HTML this module built.
    function _esc(v) {
        return String(v).replace(/[&<>"']/g, c => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        }[c]));
    }

    function _row(label, val, raw) {
        if (val === undefined || val === null || val === '' || val === '—') return '';
        const out = raw ? val : _esc(val);
        return `<div class="detail-row"><span class="detail-label">${_esc(label)}</span><span class="detail-value" style="font-family:var(--font-mono);font-size:11px;">${out}</span></div>`;
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
            rows.push(_row('Status',     _statusBadge(node.alive), true));
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
                    rows.push(_row('Status',   _statusBadge(node.alive), true));
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
                rows.push(_row('Status',   _statusBadge(b.alive, b.health), true));
                rows.push(_row('Score',    b.health?.score !== undefined ? b.health.score.toFixed(2) : null));
                rows.push(_row('Reqs',     b.total_reqs?.toLocaleString()));
                if (b.failures > 0) rows.push(_row('Failures', `<span style="color:var(--danger)">${b.failures}</span>`, true));
                if (b.latency_us?.p50) rows.push(_row('p50', (b.latency_us.p50/1000).toFixed(1)+'ms'));
                if (b.latency_us?.p99) rows.push(_row('p99', (b.latency_us.p99/1000).toFixed(1)+'ms'));
            }
        }

        return rows.join('') || `<div style="color:var(--text-mute);">No data available</div>`;
    }

    function buildNodeActions(node) {
        const actions = [];
        const host = _esc(node.meta?.hostname || '');
        const routeType = _esc(node.meta?.routeType || '');
        if (node.type === 'host' && node.meta?.hostname) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="perf-node" data-hostname="${host}">📈 Performance History</button>`);
            actions.push(`<button class="btn small" style="width:100%;" data-action="edit-host-hcl" data-hostname="${host}">✏️ Edit HCL</button>`);
        }
        if (node.type === 'route' && node.meta) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="open-route-drawer" data-hostname="${host}" data-idx="${_esc(node.meta.routeIdx)}" data-routetype="${routeType}">🔍 View Details</button>`);
        }
        if (node.type === 'backend' && node.meta) {
            actions.push(`<button class="btn small" style="width:100%;" data-action="open-backend-drawer" data-hostname="${host}" data-routeidx="${_esc(node.meta.routeIdx)}" data-backendidx="${_esc(node.meta.backendIdx)}" data-routetype="${routeType}">🔍 View Details</button>`);
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

    // Search with debounce
    let _searchTerm = '';
    let _searchTimer = null;
    let _legendFilter = null;  // node type filtered via legend click
    let _healthFilter = false; // show only unhealthy nodes

    function _updateNodeVisibility() {
        if (!graph?.data?.nodes) return;
        const svg = document.querySelector('#graphContainer svg');
        if (!svg) return;
        const visible = new Set();
        svg.querySelectorAll('.gnode').forEach(el => {
            const label = (el.dataset.label || '').toLowerCase();
            const id    = (el.dataset.id    || '').toLowerCase();
            const cls   = el.classList;
            const nodeType = cls.contains('gnode--host') || cls.contains('gdot--host') ? 'host' :
                            cls.contains('gnode--route') || cls.contains('gdot--route') ? 'route' :
                            cls.contains('gnode--backend') || cls.contains('gdot--backend') ? 'backend' :
                            cls.contains('gnode--root') || cls.contains('gdot--root') ? 'root' :
                            cls.contains('gnode--serverless') || cls.contains('gdot--serverless') ? 'serverless' : '';
            const protocol = (el.dataset.protocol || '').toLowerCase();
            const kind     = (el.dataset.kind || '').toLowerCase();
            const status = cls.contains('status--dead') ? 'dead' :
                          cls.contains('status--degraded') ? 'degraded' : 'ok';
            let match = true;
            if (_searchTerm) {
                match = label.includes(_searchTerm) || id.includes(_searchTerm);
            }
            if (_legendFilter) {
                if (_legendFilter === 'proxy') {
                    match = match && nodeType === 'route' && protocol === 'tcp';
                } else if (_legendFilter === 'proxy-udp') {
                    match = match && nodeType === 'route' && protocol === 'udp';
                } else if (_legendFilter === 'route') {
                    match = match && nodeType === 'route' && protocol === ROUTE_PROTOCOLS.HTTP;
                } else if (_legendFilter === ROUTE_PROTOCOLS.MCP) {
                    match = match && nodeType === 'route' && protocol === ROUTE_PROTOCOLS.MCP;
                } else if (_legendFilter === 'replay') {
                    match = match && nodeType === 'serverless' && kind === 'replay';
                } else {
                    match = match && nodeType === _legendFilter;
                }
            }
            if (_healthFilter) {
                match = match && (status === 'dead' || status === 'degraded');
            }
            if (match) visible.add(el.dataset.id);
            el.style.opacity = match ? '1' : '0.15';
        });
        svg.querySelectorAll('.gedge, .gedge-flow').forEach(el => {
            const target = el.dataset.target || '';
            const source = el.dataset.source || '';
            const match = !_searchTerm && !_legendFilter && !_healthFilter
                || visible.has(target) || visible.has(source);
            el.style.opacity = match ? '' : '0.08';
        });
    }

    function _applySearch(term) {
        _searchTerm = term.toLowerCase().trim();
        _updateNodeVisibility();
    }

    function _updateSummary() {
        const el = find('#mapSummary');
        if (!el || !graph?.data?.nodes) return;
        const nodes = graph.data.nodes;
        const counts = { host: 0, route: 0, backend: 0, serverless: 0 };
        nodes.forEach(n => { if (counts.hasOwnProperty(n.type)) counts[n.type]++; });
        const parts = [];
        if (counts.host) parts.push(counts.host + ' host' + (counts.host > 1 ? 's' : ''));
        if (counts.route) parts.push(counts.route + ' route' + (counts.route > 1 ? 's' : ''));
        if (counts.backend) parts.push(counts.backend + ' backend' + (counts.backend > 1 ? 's' : ''));
        if (counts.serverless) parts.push(counts.serverless + ' worker' + (counts.serverless > 1 ? 's' : ''));
        el.textContent = parts.join(' · ');
    }

    function _updateLastUpdated() {
        const el = find('#mapLastUpdated');
        if (!el) return;
        const now = new Date();
        const h = now.getHours().toString().padStart(2, '0');
        const m = now.getMinutes().toString().padStart(2, '0');
        const s = now.getSeconds().toString().padStart(2, '0');
        el.textContent = 'Updated ' + h + ':' + m + ':' + s;
    }

    on('#mapSearch', 'input', (e, inp) => {
        const clearBtn = find('#mapSearchClear');
        if (clearBtn) clearBtn.style.display = inp.value ? '' : 'none';
        if (_searchTimer) clearTimeout(_searchTimer);
        _searchTimer = setTimeout(() => _applySearch(inp.value), 150);
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
        setLoading('Refreshing data…');
        const config = store.get('lastConfig') || await api.fetchConfig();
        const uptime = await api.fetchUptime();
        if (!config || !uptime) return;
        if (Object.keys(config.hosts || {}).length === 0) { showEmpty(); return; }
        if (!graph) {
            // The empty state destroyed the instance; rebuild on the first host.
            if (typeof RouteGraph === 'undefined') return;
            createGraph();
        }
        // update() is a no-op relayout-free refresh when the topology is unchanged.
        graph.update(config, uptime.hosts || {});
        hideLoading();
        if (_searchTerm) _applySearch(_searchTerm);
        _updateSummary();
        _updateLastUpdated();
    }

    // Create (or recreate) the graph instance with its page callbacks.
    function createGraph() {
        graph = new RouteGraph('graphContainer', {
            mode: prefs.view,
            orientation: prefs.orientation,
            density: prefs.density,
            animate: prefs.animate
        });

        graph._onZoom = function (k) {
            const el = find('#mapZoomPct');
            if (el) el.textContent = Math.round(k * 100) + '%';
        };

        // The topology can be wider than the canvas at a readable scale; say so
        // instead of silently shrinking the graph into illegibility.
        graph._onOverflow = function (overflow) {
            const hint = find('#mapHint');
            if (!hint) return;
            hint.textContent = overflow
                ? (prefs.view === 'topology' ? 'Drag to pan · Collapse hosts to fit the view' : 'Drag to pan · Zoom out to see everything')
                : '';
        };

        graph._onClick = function(d) {
            openInfoPanel(d);
            if (d.type === 'route'   && d.meta) emit('drawer:open-route',   { host: d.meta.hostname, idx: d.meta.routeIdx, type: d.meta.routeType });
            if (d.type === 'backend' && d.meta) emit('drawer:open-backend', { host: d.meta.hostname, routeIdx: d.meta.routeIdx, backendIdx: d.meta.backendIdx, type: d.meta.routeType });
            if (d.type === 'host'    && d.meta) emit('perf:open', { hostname: d.meta.hostname });
        };

        graph._onRightClick = function(event, d) {
            showNodeContextMenu(event, d);
        };

        return graph;
    }

    // Init
    async function init() {
        try { await loadGraphDeps(); }
        catch (err) {
            hideLoading();
            const el = find('#graphContainer');
            if (el) el.innerHTML = `<div class="empty-state" style="margin-top:60px;">
                <div style="color:var(--danger);font-weight:500;margin-bottom:8px;">Failed to load graph</div>
                <div style="color:var(--text-mute);font-size:12px;margin-bottom:12px;">${err.message}</div>
                <button class="btn small" id="mapRetryBtn">Retry</button>
            </div>`;
            on('#mapRetryBtn', 'click', () => {
                const el = find('#graphContainer');
                if (el) el.innerHTML = '';
                setLoading('Loading graph scripts…');
                init();
            });
            return;
        }

        createGraph();

        // Reflect saved prefs in the toolbar.
        const orientSel = find('#mapOrientation');
        if (orientSel) orientSel.value = prefs.orientation;
        const animChk = find('#mapAnimate');
        if (animChk) animChk.checked = !!prefs.animate;
        _syncDensityButtons();
        _syncViewTabs();

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

    // graph controls

    function _syncViewTabs() {
        document.querySelectorAll('#mapViewTabs [data-view]').forEach(btn => {
            const active = btn.dataset.view === prefs.view;
            btn.classList.toggle('active', active);
            btn.setAttribute('aria-selected', String(active));
        });
        const controls = find('#topologyControls');
        if (controls) controls.style.display = prefs.view === 'topology' ? '' : 'none';
    }

    function _syncDensityButtons() {
        document.querySelectorAll('#mapDensity [data-density]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.density === prefs.density);
            btn.setAttribute('aria-pressed', String(btn.dataset.density === prefs.density));
        });
    }

    on('#mapViewTabs [data-view]', 'click', (e, btn) => {
        const view = btn.dataset.view === 'topology' ? 'topology' : 'force';
        if (view === prefs.view) return;
        savePrefs({ view });
        _syncViewTabs();
        graph?.setOptions({ mode: view });
        _reflow();
    });

    on('#mapCollapseBtn', 'click', () => { graph?.collapseAll(); _reflow(); });
    on('#mapExpandBtn',   'click', () => { graph?.expandAll();   _reflow(); });

    // Interactive legend — click to filter by node type, click again to clear
    on('.legend-item', 'click', (e, item) => {
        const type = item.dataset.type;
        const status = item.dataset.status;
        if (type) {
            _legendFilter = (_legendFilter === type) ? null : type;
        } else if (status) {
            _healthFilter = !_healthFilter;
        }
        // Update visual feedback
        document.querySelectorAll('.legend-item').forEach(li => {
            li.style.fontWeight = (li === item) && (_legendFilter || _healthFilter) ? '600' : '';
        });
        _updateNodeVisibility();
    });

    // Health filter toggle
    on('#mapHealthFilter', 'change', (e, chk) => {
        _healthFilter = !!chk.checked;
        _updateNodeVisibility();
    });

    // Export as SVG
    on('#mapExportBtn', 'click', () => {
        const svg = document.querySelector('#graphContainer svg');
        if (!svg) return;
        const clone = svg.cloneNode(true);
        clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        const data = new XMLSerializer().serializeToString(clone);
        const blob = new Blob([data], { type: 'image/svg+xml' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'agbero-topology.svg';
        a.click();
        URL.revokeObjectURL(url);
    });

    // Fit to selection
    on('#mapFitSelection', 'click', () => {
        if (!graph || !graph._selected) return;
        const nodeEl = graph._nodeEls.get(graph._selected);
        if (!nodeEl || !graph.layout?.positions) return;
        const pos = graph.layout.positions[graph._selected];
        if (!pos) return;
        // Zoom to center on the selected node
        const box = graph._svg.getBoundingClientRect();
        const z = graph._zoom;
        const targetK = Math.min(box.width / 300, box.height / 200, 3);
        graph._userZoom = true;
        graph._zoom = {
            k: targetK,
            x: box.width / 2 - (pos.x + (pos.w || 50) / 2) * targetK,
            y: box.height / 2 - (pos.y + (pos.h || 50) / 2) * targetK
        };
        graph._applyTransform();
    });

    // A mode swap changes the canvas bounds; re-apply the current search filter.
    function _reflow() {
        requestAnimationFrame(() => {
            graph?.fit();
            _updateNodeVisibility();
            _updateSummary();
        });
    }

    on('#mapOrientation', 'change', (e, sel) => {
        savePrefs({ orientation: sel.value === 'TB' ? 'TB' : 'LR' });
        graph?.setOptions({ orientation: prefs.orientation });
    });

    on('#mapDensity [data-density]', 'click', (e, btn) => {
        savePrefs({ density: btn.dataset.density });
        _syncDensityButtons();
        graph?.setOptions({ density: prefs.density });
    });

    on('#mapAnimate', 'change', (e, box) => {
        savePrefs({ animate: !!box.checked });
        graph?.setOptions({ animate: prefs.animate });
    });

    on('#mapFitBtn',   'click', () => graph?.fit());
    on('#mapZoomIn',   'click', () => graph?.zoomBy(1.25));
    on('#mapZoomOut',  'click', () => graph?.zoomBy(0.8));

    on('#mapInfoClose', 'click', () => {
        closeInfoPanel();
    });

    function closeInfoPanel() {
        const p = find('#mapInfoPanel');
        if (p) p.style.display = 'none';
        graph?.clearSelection();
    }

    // Keyboard shortcuts for the map page
    on(document, 'keydown', (e) => {
        // Escape closes the info panel
        if (e.key === 'Escape') {
            const panel = find('#mapInfoPanel');
            if (panel && panel.style.display !== 'none') {
                e.preventDefault();
                closeInfoPanel();
                return;
            }
        }
        // Ctrl+Shift+F focuses the search input
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'F') {
            e.preventDefault();
            const inp = find('#mapSearch');
            if (inp) inp.focus();
        }
        // C collapses all, E expands all (when not in an input)
        if (!e.ctrlKey && !e.metaKey && !e.altKey) {
            const tag = (e.target.tagName || '').toLowerCase();
            if (tag !== 'input' && tag !== 'textarea' && tag !== 'select') {
                if (e.key === 'c' || e.key === 'C') {
                    e.preventDefault();
                    graph?.collapseAll();
                    _reflow();
                }
                if (e.key === 'e' || e.key === 'E') {
                    e.preventDefault();
                    graph?.expandAll();
                    _reflow();
                }
            }
        }
    });

    // Reset preferences
    on('#mapResetPrefsBtn', 'click', () => {
        storeLocal.remove(PREFS_KEY);
        prefs = Object.assign({}, DEFAULTS);
        _syncViewTabs();
        _syncDensityButtons();
        const orientSel = find('#mapOrientation');
        if (orientSel) orientSel.value = prefs.orientation;
        const animChk = find('#mapAnimate');
        if (animChk) animChk.checked = prefs.animate;
        graph?.setOptions({ mode: prefs.view, orientation: prefs.orientation, density: prefs.density, animate: prefs.animate });
        _reflow();
    });

    pollTimer = setInterval(() => { if (!paused) refresh(); }, 30_000);
    onUnmount(() => {
        unsub?.();
        if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
        if (graph) { graph.destroy(); graph = null; }
    });
    ready();
}
