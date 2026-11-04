/**
 * js/graph.js — topology map renderer (native SVG, no D3, no CDN).
 *
 * Public surface (kept compatible with pages/map.js):
 *   new RouteGraph(containerId, options?)
 *   render(config, stats)      — first paint / topology change
 *   update(config, stats)      — statistics refresh; no rebuild when the
 *                                topology is unchanged
 *   setOptions({ orientation, density, animate, showLabels, draggable })
 *   select(id) / clearSelection()
 *   fit() / resetZoom() / zoomBy(factor)
 *   destroy()
 *   _onClick(node) / _onRightClick(event, node)   — assigned by the page
 *
 * Design notes:
 *   - Layout comes from js/graph-layout.js (deterministic hierarchy). The graph
 *     is never rebuilt for a metrics tick: only labels, statuses and edge
 *     thickness change, so node positions stay put.
 *   - Traffic numbers are derived from successive cumulative `total_reqs`
 *     samples. With a single sample there is no rate, so connections stay
 *     static — no invented traffic.
 *   - Tooltip content is built with textContent: config values (hostnames,
 *     upstream URLs) never reach innerHTML.
 */
(function () {
    'use strict';

    var NS = 'http://www.w3.org/2000/svg';

    var GLYPH = { root: '\u25C8', host: '\u25A4', route: '\u21E2', backend: '\u25CF', serverless: '\u2699' };
    var TYPE_LABEL = {
        root: 'Load Balancer', host: 'Virtual Host', route: 'Route',
        backend: 'Backend', serverless: 'Worker'
    };
    var STATUS_LABEL = { ok: 'Healthy', degraded: 'Degraded', dead: 'Down', unverified: 'Unverified' };
    var MIN_REFRESH = 0.5;   // seconds — below this an rps sample is too noisy
    var MIN_FIT = 0.55;      // fit() never scales below this; pan/collapse instead
    var AUTO_COLLAPSE_AT = 18;  // topology nodes before hosts start collapsed

    function el(name, attrs) {
        var node = document.createElementNS(NS, name);
        if (attrs) {
            for (var k in attrs) {
                if (attrs[k] === null || attrs[k] === undefined) continue;
                node.setAttribute(k, attrs[k]);
            }
        }
        return node;
    }

    function clamp(n, lo, hi) { return n < lo ? lo : (n > hi ? hi : n); }

    // processData() emits links with plain string endpoints (D3 used to resolve
    // them into node objects). Everything downstream must accept both shapes.
    function endpointId(end) {
        return end && typeof end === 'object' ? end.id : end;
    }

    function truncate(s, max) {
        s = String(s == null ? '' : s);
        if (s.length <= max) return s;
        return max <= 1 ? '\u2026' : s.slice(0, max - 1) + '\u2026';
    }

    function fmtNum(n) {
        if (n === null || n === undefined || isNaN(n)) return '';
        if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
        if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
        return String(Math.round(n));
    }

    function fmtRate(rps) {
        if (rps === null || rps === undefined) return '';
        if (rps >= 10) return fmtNum(rps) + '/s';
        if (rps >= 0.1) return rps.toFixed(1) + '/s';
        return '';
    }

    function fmtMs(us) {
        if (!us) return '';
        var ms = us / 1000;
        return ms >= 100 ? Math.round(ms) + 'ms' : ms.toFixed(1) + 'ms';
    }

    class RouteGraph {
        constructor(containerId, options) {
            this.containerId = containerId;
            this.container = document.getElementById(containerId);
            this.options = Object.assign({
                mode: 'force',          // 'force' = classic view, 'topology' = cards
                orientation: 'LR',
                density: 'detailed',
                animate: true,
                showLabels: true,
                draggable: true
            }, options || {});

            this._collapsed = new Set();     // host ids collapsed in the topology view
            this._children = new Map();
            this._descendants = new Map();
            this._autoCollapsed = false;
            this._forcePositions = null;
            this._forceSig = '';
            this._userZoom = false;
            this._overflow = false;
            this._onZoom = null;

            this.data = null;          // { nodes, links } from processData()
            this.layout = null;        // computeLayout() result
            this._hostsData = {};      // raw stats for tooltips
            this._nodeIndex = new Map(); // id -> node for O(1) lookup
            this._sig = '';            // topology signature
            this._selected = null;
            this._rps = new Map();     // node id → requests/sec
            this._prevTotals = new Map();
            this._prevAt = 0;
            this._zoom = { k: 1, x: 0, y: 0 };
            this._nodeEls = new Map();
            this._edgeEls = [];
            this._edgeByNode = new Map();
            this._ac = null;
            this._tooltip = null;
            this._drag = null;

            this._onClick = null;
            this._onRightClick = null;
        }

        // public API

        render(config, stats) {
            if (!config || !this.container) return;
            this._ingest(config, stats);
            this._autoCollapseIfCrowded();
            var sig = this._signature();
            if (this._root && sig === this._sig) { this._updateStats(); return; }
            this._sig = sig;
            this._draw();
        }

        update(config, stats) {
            this.render(config, stats);
        }

        setOptions(patch) {
            if (!patch) return;
            var relayout = false;
            if (patch.mode && patch.mode !== this.options.mode) {
                this.options.mode = patch.mode === 'topology' ? 'topology' : 'force';
                this._clearDragState();
                this._autoCollapsed = false;   // re-evaluate collapse for the new view
                if (this.options.mode === 'topology') this._autoCollapseIfCrowded();
                relayout = true;
            }
            if (patch.orientation && patch.orientation !== this.options.orientation) {
                this.options.orientation = patch.orientation === 'TB' ? 'TB' : 'LR';
                relayout = true;
            }
            if (patch.density && patch.density !== this.options.density) {
                this.options.density = patch.density;
                relayout = true;
            }
            if ('animate' in patch) this.options.animate = !!patch.animate;
            if ('showLabels' in patch) this.options.showLabels = !!patch.showLabels;
            if ('draggable' in patch) this.options.draggable = !!patch.draggable;

            if (relayout && this.data) this._draw(true);
            else { this._applyModeClasses(); this._updateStats(); }
        }

        select(id) {
            this._selected = id || null;
            this._applySelection();
        }

        clearSelection() {
            this.select(null);
        }

        resetZoom() { this.fit(); }

        zoomBy(factor) {
            if (!this._svg) return;
            this._userZoom = true;
            var box = this._svg.getBoundingClientRect();
            this._zoomAt(box.width / 2, box.height / 2, factor);
        }

        fit() {
            if (!this._svg || !this.layout) return;
            this._userZoom = false;

            var box = this._svg.getBoundingClientRect();
            var w = box.width || this.container.clientWidth || 800;
            var h = box.height || this.container.clientHeight || 600;
            var b = this.layout.bounds;
            if (!b.width || !b.height) { this._zoom = { k: 1, x: 0, y: 0 }; this._applyTransform(); return; }

            var pad = 28;
            var kx = (w - pad) / b.width;
            var ky = (h - pad) / b.height;
            // Fit the whole graph in both modes, whatever the orientation.
            var k = Math.min(kx, ky);
            // Never shrink below readable: past this point the operator pans and
            // uses collapse/expand instead of squinting at 15% zoom.
            k = clamp(k, MIN_FIT, 1.15);

            this._zoom.k = k;
            var overflowX = b.width * k > w - pad;
            var overflowY = b.height * k > h - pad;
            this._zoom.x = overflowX ? pad - b.minX * k : (w - b.width * k) / 2 - b.minX * k;
            this._zoom.y = overflowY ? pad - b.minY * k : (h - b.height * k) / 2 - b.minY * k;
            this._overflow = overflowX || overflowY;
            this._applyTransform();
        }

        destroy() {
            if (this._ro) { this._ro.disconnect(); this._ro = null; }
            if (this._roTimer) { clearTimeout(this._roTimer); this._roTimer = null; }
            if (this._ac) { this._ac.abort(); this._ac = null; }
            if (this._tooltip && this._tooltip.parentNode) this._tooltip.parentNode.removeChild(this._tooltip);
            this._tooltip = null;
            this._nodeEls.clear();
            this._edgeEls = [];
            this._edgeByNode.clear();
            if (this.container) this.container.innerHTML = '';
            this._root = this._svg = this._vp = null;
            this._nodeLayer = this._edgeLayer = null;
            this.data = null;
            this.layout = null;
            this._nodeIndex = new Map();
            this._sig = '';
            this._prevTotals.clear();
            this._rps.clear();
            this._prevAt = 0;
        }

        // data

        _ingest(config, stats) {
            this._hostsData = stats || {};
            this._hostTotal = config && config.hosts ? Object.keys(config.hosts).length : 0;
            this.data = this.processData(config, stats);
            this._annotate();
            this._computeRps(Date.now());
        }

        // Child counts and the descendant map are rendering details, so they stay
        // out of processData(). The descendant count is what the topology view
        // shows on a collapsed host ("+12").
        _annotate() {
            var self = this;
            this._children = new Map();
            this.data.nodes.forEach(function (node) { self._children.set(node.id, []); });

            this.data.links.forEach(function (link) {
                var sid = endpointId(link.source);
                var tid = endpointId(link.target);
                if (!self._children.has(sid) || !self._children.has(tid)) return;
                self._children.get(sid).push(tid);
            });

            this._descendants = new Map();
            var count = function (id, seen) {
                if (self._descendants.has(id)) return self._descendants.get(id);
                var kids = self._children.get(id) || [];
                var total = kids.length;
                kids.forEach(function (kid) {
                    if (seen.has(kid)) return;
                    seen.add(kid);
                    total += count(kid, seen);
                });
                self._descendants.set(id, total);
                return total;
            };

            this.data.nodes.forEach(function (node) {
                var kids = self._children.get(node.id) || [];
                node.childCount = kids.length;
                node.collapsible = kids.length > 0;
                node.hiddenCount = count(node.id, new Set([node.id]));
            });
            return self;
        }

        // Nodes/links after collapse filtering. Only the topology view collapses:
        // the classic view has always shown everything.
        _view() {
            if (!this.data) return { nodes: [], links: [] };
            if (this.options.mode !== 'topology' || this._collapsed.size === 0) return this.data;

            var hidden = new Set();
            var self = this;
            var hideFrom = function (id) {
                (self._children.get(id) || []).forEach(function (kid) {
                    if (hidden.has(kid)) return;
                    hidden.add(kid);
                    hideFrom(kid);
                });
            };
            this._collapsed.forEach(hideFrom);

            var nodes = this.data.nodes.filter(function (n) { return !hidden.has(n.id); });
            var visible = new Set(nodes.map(function (n) { return n.id; }));
            var links = this.data.links.filter(function (l) {
                return visible.has(endpointId(l.source)) && visible.has(endpointId(l.target));
            });
            return { nodes: nodes, links: links };
        }

        // A topology with dozens of hosts is unreadable when every route and
        // upstream is expanded. Collapse the big subtrees on the first topology
        // pass; the operator can expand whatever they are inspecting.
        _autoCollapseIfCrowded() {
            if (this._autoCollapsed) return;
            if (this.options.mode !== 'topology') return;
            this._autoCollapsed = true;
            if (this.data.nodes.length <= AUTO_COLLAPSE_AT) return;
            var self = this;
            this.data.nodes.forEach(function (node) {
                if (node.type === 'host' && node.hiddenCount > 3) self._collapsed.add(node.id);
                // Collapse routes with many backends
                if (node.type === 'route' && node.childCount > 4) self._collapsed.add(node.id);
            });
            if (this._collapsed.size) {
                this._lastAutoCollapse = this._collapsed.size;
            }
        }

        toggleNode(id) {
            if (this.options.mode !== 'topology') return;
            if (!this._children.get(id) || !this._children.get(id).length) return;
            if (this._collapsed.has(id)) this._collapsed.delete(id);
            else this._collapsed.add(id);
            this._draw(true);
        }

        collapseAll() {
            if (!this.data) return;
            this._collapsed.clear();
            var self = this;
            this.data.nodes.forEach(function (node) {
                if (node.type === 'host' || node.type === 'route') self._collapsed.add(node.id);
            });
            this._draw(true);
        }

        expandAll() {
            this._collapsed.clear();
            if (this.data) this._draw(true);
        }

        // Topology identity: everything that affects positions. Statuses and
        // counters are deliberately excluded so a metrics tick never relayouts.
        _signature() {
            if (!this.data) return '';
            var parts = [this.options.mode, this.options.orientation, this.options.density,
                         Array.from(this._collapsed).sort().join(',')];
            for (var i = 0; i < this.data.nodes.length; i++) {
                var n = this.data.nodes[i];
                parts.push(n.id + '|' + n.label + '|' + n.type);
            }
            for (var j = 0; j < this.data.links.length; j++) {
                var l = this.data.links[j];
                parts.push(endpointId(l.source) + '>' + endpointId(l.target));
            }
            return parts.join('\u0001');
        }

        _computeRps(now) {
            var dt = this._prevAt ? (now - this._prevAt) / 1000 : 0;
            var sample = new Map();
            for (var i = 0; i < this.data.nodes.length; i++) {
                var node = this.data.nodes[i];
                if (typeof node.total === 'number') sample.set(node.id, node.total);
            }

            // First sample (or a too-fast refresh): remember the totals but do not
            // invent a rate. The next sample that is far enough away computes it.
            if (dt < MIN_REFRESH) {
                sample.forEach(function (v, k) { this._prevTotals.set(k, v); }, this);
                // Anchor the clock on the very first sample so the next one can
                // compute a rate instead of dividing by the epoch.
                if (!this._prevAt) this._prevAt = now;
                return;
            }

            var next = new Map();
            var self = this;
            sample.forEach(function (total, id) {
                var prev = self._prevTotals.get(id);
                if (typeof prev === 'number' && total >= prev) next.set(id, (total - prev) / dt);
            });

            this._rps = next;
            this._prevTotals = sample;
            this._prevAt = now;
        }

        // canvas

        _draw(refit) {
            this._ensureSvg();
            this._nodeLayer.textContent = '';
            this._edgeLayer.textContent = '';
            this._nodeEls.clear();
            this._edgeEls = [];
            this._edgeByNode = new Map();

            this._sig = this._signature();
            var view = this._view();
            // Build O(1) index for _nodeById lookups
            this._nodeIndex = new Map();
            view.nodes.forEach(function (n) { this._nodeIndex.set(n.id, n); }.bind(this));
            this.layout = this._computeLayout(view.nodes, view.links);

            this._drawEdges();
            this._drawNodes();
            this._applyModeClasses();
            this._applySelection();
            this._updateStats();

            // The viewport is only fitted automatically on the first paint or an
            // explicit relayout (orientation/density change); a topology change
            // from a config reload keeps the operator's zoom and pan.
            if (refit || !this._fitted) { this.fit(); this._fitted = true; }
        }

        _ensureSvg() {
            if (this._svg && this._svg.parentNode === this.container) return;

            // The page may have replaced the container contents (empty state), so
            // any previous SVG is detached: drop its listeners and start again.
            if (this._ac) { this._ac.abort(); this._ac = null; }
            this._svg = this._vp = this._edgeLayer = this._nodeLayer = null;

            var self = this;
            this._ac = new AbortController();
            var signal = this._ac.signal;

            var svg = el('svg', {
                'class': 'graph-canvas',
                'width': '100%', 'height': '100%',
                'role': 'img',
                'aria-label': 'Agbero topology'
            });
            // Arrowheads for the classic (line) edges. One per health state.
            var defs = el('defs');
            [['graph-arrow-default', 'var(--text-mute)'],
             ['graph-arrow-dead', 'var(--danger)'],
             ['graph-arrow-degraded', 'var(--warning)']].forEach(function (pair) {
                var marker = el('marker', {
                    'id': pair[0], 'viewBox': '0 -4 8 8', 'refX': 8, 'refY': 0,
                    'markerWidth': 5, 'markerHeight': 5, 'orient': 'auto'
                });
                marker.appendChild(el('path', { 'd': 'M0,-4L8,0L0,4Z', 'fill': pair[1] }));
                defs.appendChild(marker);
            });
            svg.appendChild(defs);

            var vp = el('g', { 'class': 'graph-viewport' });
            var edgeLayer = el('g', { 'class': 'graph-edges' });
            var nodeLayer = el('g', { 'class': 'graph-nodes' });
            vp.appendChild(edgeLayer);
            vp.appendChild(nodeLayer);
            svg.appendChild(vp);
            this.container.appendChild(svg);

            this._root = this.container;
            this._svg = svg;
            this._vp = vp;
            this._edgeLayer = edgeLayer;
            this._nodeLayer = nodeLayer;

            // Tooltip lives in the container, outside the SVG transform.
            var tip = document.createElement('div');
            tip.className = 'graph-node-tooltip';
            tip.style.display = 'none';
            this.container.appendChild(tip);
            this._tooltip = tip;

            svg.addEventListener('wheel', function (ev) { self._onWheel(ev); }, { passive: false, signal: signal });
            svg.addEventListener('pointerdown', function (ev) { self._onPointerDown(ev); }, { signal: signal });
            svg.addEventListener('pointermove', function (ev) { self._onPointerMove(ev); }, { signal: signal });
            svg.addEventListener('pointerup', function (ev) { self._onPointerUp(ev); }, { signal: signal });
            svg.addEventListener('pointercancel', function (ev) { self._onPointerUp(ev); }, { signal: signal });
            svg.addEventListener('pointerleave', function () { if (self._tooltip) self._tooltip.style.display = 'none'; }, { signal: signal });

            // Side panels change the canvas width; refit only while the operator
            // has not taken manual control of the viewport.
            if (typeof ResizeObserver === 'function') {
                this._ro = new ResizeObserver(function () {
                    if (self._userZoom) return;
                    if (self._roTimer) clearTimeout(self._roTimer);
                    self._roTimer = setTimeout(function () { self.fit(); }, 80);
                });
                this._ro.observe(this.container);
            }
        }

        _applyTransform() {
            if (!this._vp) return;
            var z = this._zoom;
            this._vp.setAttribute('transform', 'translate(' + z.x + ',' + z.y + ') scale(' + z.k + ')');
            this._applyModeClasses();
            if (this._root) this._root.classList.toggle('graph--overflow', !!this._overflow);
            if (typeof this._onZoom === 'function') this._onZoom(z.k);
            if (typeof this._onOverflow === 'function') this._onOverflow(!!this._overflow);
        }

        _applyModeClasses() {
            if (!this._root) return;
            var d = this.options.density;
            this._root.classList.toggle('density--compact', d === 'compact');
            this._root.classList.toggle('density--detailed', d === 'detailed');
            this._root.classList.toggle('density--inspect', d === 'inspect');
            this._root.classList.toggle('no-animation', !this.options.animate);
            this._root.classList.toggle('no-labels', !this.options.showLabels);
            this._root.classList.toggle('zoom--far', this._zoom.k < 0.45);
            this._root.classList.toggle('zoom--near', this._zoom.k > 1.15);
        }

        _applySelection() {
            if (!this._root) return;
            var selected = this._selected;
            this._root.classList.toggle('graph--focused', !!selected);
            var self = this;
            this._nodeEls.forEach(function (node, id) {
                node.classList.toggle('is-selected', id === selected);
                node.classList.toggle('is-related', !!selected && self._isRelated(id, selected));
            });
            this._edgeEls.forEach(function (edge) {
                var active = !!selected && (edge.source === selected || edge.target === selected);
                edge.path.classList.toggle('is-active', active);
                if (edge.flow) edge.flow.classList.toggle('is-active', active);
            });
        }

        _isRelated(id, selected) {
            if (!this.data) return false;
            for (var i = 0; i < this.data.links.length; i++) {
                var l = this.data.links[i];
                var s = endpointId(l.source), t = endpointId(l.target);
                if ((s === selected && t === id) || (t === selected && s === id)) return true;
            }
            return false;
        }

        // layout

        _computeLayout(nodes, links) {
            // Classic view: a full deterministic solve, like the original map, which
            // re-ran its simulation whenever the topology changed. Statistics ticks
            // never reach here (render() fast-paths on the topology signature).
            if (this.options.mode === 'force') return computeForceLayout(nodes, links);
            return computeLayout(nodes, links, this.options);
        }

        // edges

        _drawEdges() {
            var self = this;
            var force = this.options.mode === 'force';

            this.layout.edges.forEach(function (edge) {
                var rec = { path: null, flow: null, source: edge.source, target: edge.target, raw: edge.raw };

                if (force) {
                    // Classic view: a straight line with an arrowhead, plus a flow overlay for traffic animation.
                    rec.path = el('line', {
                        'class': 'gedge gedge--line',
                        'x1': edge.geom.x1, 'y1': edge.geom.y1,
                        'x2': edge.geom.x2, 'y2': edge.geom.y2,
                        'data-source': edge.source,
                        'data-target': edge.target
                    });
                    // Flow overlay — same path as the line, uses CSS dash animation.
                    rec.flow = el('line', {
                        'class': 'gedge-flow',
                        'x1': edge.geom.x1, 'y1': edge.geom.y1,
                        'x2': edge.geom.x2, 'y2': edge.geom.y2,
                        'data-target': edge.target
                    });
                    self._edgeLayer.appendChild(rec.path);
                    self._edgeLayer.appendChild(rec.flow);
                } else {
                    rec.path = el('path', {
                        'class': 'gedge',
                        'd': edge.geom.path,
                        'fill': 'none',
                        'data-source': edge.source,
                        'data-target': edge.target
                    });
                    rec.flow = el('path', {
                        'class': 'gedge-flow',
                        'd': edge.geom.path,
                        'fill': 'none',
                        'data-target': edge.target
                    });
                    self._edgeLayer.appendChild(rec.path);
                    self._edgeLayer.appendChild(rec.flow);
                }

                self._edgeEls.push(rec);
                [edge.source, edge.target].forEach(function (id) {
                    if (!self._edgeByNode.has(id)) self._edgeByNode.set(id, []);
                    self._edgeByNode.get(id).push(rec);
                });
            });
        }

        _edgeWidth(rec) {
            var rps = this._rps.get(rec.target);
            if (typeof rps === 'number' && rps > 0) return 1 + Math.min(3.2, Math.log10(rps + 1) * 1.7);
            var weight = (rec.raw && rec.raw.weight) || 0;
            if (weight > 0) return 1 + Math.min(2.2, Math.log10(weight + 1) * 0.9);
            return 1;
        }

        _edgeStatus(rec) {
            var node = this._nodeById(rec.target);
            return (node && node.status) || 'ok';
        }

        _nodeById(id) {
            return this._nodeIndex.get(id) || null;
        }

        // nodes

        _drawNodes() {
            var self = this;
            var force = this.options.mode === 'force';
            this.data.nodes.forEach(function (node) {
                var pos = self.layout.positions[node.id];
                if (!pos) return;
                var g = force ? self._buildDot(node, pos) : self._buildCard(node, pos);
                if (!g) return;
                g.__node = node;
                self._nodeLayer.appendChild(g);
                self._nodeEls.set(node.id, g);
                self._wireNode(g, node);
            });
        }

        // Classic view: the circle-with-side-label look the map always had.
        _buildDot(node, pos) {
            var self = this;
            var r = pos.radius || 6;
            var cx = pos.x + r;
            var cy = pos.y + r;
            var g = el('g', {
                'class': 'gnode gdot gdot--' + node.type + ' status--' + node.status,
                'transform': 'translate(' + pos.x + ',' + pos.y + ')',
                'data-id': node.id,
                'data-label': node.label || '',
                'data-protocol': node.protocol || '',
                'tabindex': '0',
                'role': 'button'
            });

            g.appendChild(el('circle', { 'class': 'gdot-ring', 'cx': r, 'cy': r, 'r': r + 5 }));
            g.appendChild(el('circle', { 'class': 'gdot-core', 'cx': r, 'cy': r, 'r': r }));
            if (node.type === 'backend') {
                g.appendChild(el('circle', { 'class': 'gdot-inner', 'cx': r, 'cy': r, 'r': 2 }));
            }

            // Determine label position: render to the left for nodes near the right edge.
            var labelSide = 'right';
            var box = this._svg.getBoundingClientRect();
            var screenX = (pos.x + this._zoom.x) * this._zoom.k;
            var labelW = (node.label || '').length * 6.6 + 20;
            if (screenX + r * 2 + labelW > box.width - 20) {
                labelSide = 'left';
            }

            // Halo + label, so the text stays readable over connections.
            var label = node.label || '';
            var labelX, labelAnchor;
            if (labelSide === 'left') {
                labelX = -(r + 7);
                labelAnchor = 'end';
            } else {
                labelX = r * 2 + 7;
                labelAnchor = 'start';
            }
            var halo = el('text', { 'class': 'gdot-halo', 'x': labelX, 'y': r + 4, 'text-anchor': labelAnchor });
            halo.textContent = label;
            g.appendChild(halo);
            var text = el('text', { 'class': 'gdot-label', 'x': labelX, 'y': r + 4, 'text-anchor': labelAnchor });
            text.textContent = label;
            g.appendChild(text);

            // Small rate badge next to the dot (Detailed/Inspect density)
            var rateBadge = el('text', { 'class': 'gdot-rate', 'x': labelX, 'y': r + 16, 'text-anchor': labelAnchor });
            var rate = fmtRate(this._rps.get(node.id));
            rateBadge.textContent = rate;
            rateBadge.style.display = rate ? '' : 'none';
            g.appendChild(rateBadge);

            return g;
        }

        _buildCard(node, pos) {
            var self = this;
            var g = el('g', {
                'class': 'gnode gcard gnode--' + node.type + ' status--' + node.status,
                'transform': 'translate(' + pos.x + ',' + pos.y + ')',
                'data-id': node.id,
                'data-label': node.label || '',
                'tabindex': '0',
                'role': 'button'
            });

            var w = pos.w, h = pos.h;
            g.appendChild(el('rect', { 'class': 'gnode-card', 'width': w, 'height': h, 'rx': 10, 'ry': 10 }));
            g.appendChild(el('rect', { 'class': 'gnode-stripe', 'width': 4, 'height': Math.max(0, h - 16), 'x': 0, 'y': 8, 'rx': 2, 'ry': 2 }));

            var glyph = el('text', { 'class': 'gnode-glyph', 'x': 18, 'y': self._titleY(node) });
            glyph.textContent = GLYPH[node.type] || '\u25CF';
            g.appendChild(glyph);

            var title = el('text', { 'class': 'gnode-title', 'x': 40, 'y': self._titleY(node) });
            title.textContent = truncate(node.label, self._titleChars(node, w));
            g.appendChild(title);

            var sub = el('text', { 'class': 'gnode-sub', 'x': 40, 'y': self._subY(node) });
            sub.textContent = truncate(self._subtitle(node), self._subChars(node, w));
            g.appendChild(sub);

            var metric = el('text', { 'class': 'gnode-metric', 'x': 40, 'y': h - 10 });
            g.appendChild(metric);

            g.appendChild(el('circle', { 'class': 'gnode-dot', 'r': 4, 'cx': w - 16, 'cy': 16 }));

            // Collapse affordance — only rendered when the node has hidden children.
            if (node.collapsible) {
                var isCollapsed = self._collapsed.has(node.id);
                var toggle = el('g', { 'class': 'gnode-toggle' + (isCollapsed ? ' is-collapsed' : ''), 'transform': 'translate(' + (w - 16) + ',' + (h - 16) + ')' });
                toggle.appendChild(el('circle', { 'r': 7 }));
                var sign = el('text', { 'x': 0, 'y': 3.5, 'text-anchor': 'middle' });
                sign.textContent = isCollapsed ? '+' + node.hiddenCount : '−';
                toggle.appendChild(sign);
                g.appendChild(toggle);
            }

            return g;
        }

        _wireNode(g, node) {
            var self = this;
            g.setAttribute('aria-label', (node.label || node.id) + ' — ' +
                (TYPE_LABEL[node.type] || node.type) + ', ' + (STATUS_LABEL[node.status] || node.status));

            g.addEventListener('click', function (ev) {
                if (ev.defaultPrevented || self._suppressClick) { self._suppressClick = false; return; }
                if (ev.target.closest && ev.target.closest('.gnode-toggle')) {
                    self.toggleNode(node.id);
                    return;
                }
                self.select(node.id);
                if (typeof self._onClick === 'function') self._onClick(g.__node);
            });
            g.addEventListener('keydown', function (ev) {
                if (ev.key !== 'Enter' && ev.key !== ' ') return;
                ev.preventDefault();
                self.select(node.id);
                if (typeof self._onClick === 'function') self._onClick(g.__node);
            });
            g.addEventListener('contextmenu', function (ev) {
                ev.preventDefault();
                ev.stopPropagation();
                if (typeof self._onRightClick === 'function') self._onRightClick(ev, g.__node);
            });
            g.addEventListener('pointerenter', function (ev) { self._showTooltip(ev, g.__node); });
            g.addEventListener('pointermove', function (ev) { self._positionTooltip(ev); });
            g.addEventListener('pointerleave', function () { if (self._tooltip) self._tooltip.style.display = 'none'; });
        }

        _titleY(node) { return node.type === 'root' ? 30 : 24; }

        _subY(node) {
            if (node.type === 'root') return 52;
            if (node.type === 'host') return 44;
            if (node.type === 'route') return 42;
            return 40;
        }

        _titleChars(node, w) { return Math.max(6, Math.floor((w - 52) / 6.6)); }
        _subChars(node, w) { return Math.max(8, Math.floor((w - 52) / 5.6)); }

        _subtitle(node) {
            var proto = (node.protocol || '').toUpperCase();
            switch (node.type) {
                case 'root':
                    return 'Routing engine' + (this._hostTotal ? ' \u00B7 ' + this._hostTotal + ' hosts' : '');
                case 'host':
                    return (node.protocol === 'https' ? 'HTTPS \u00B7 TLS' : 'HTTP') +
                        (node.childCount ? ' \u00B7 ' + node.childCount + ' listeners' : '');
                case 'route':
                    return proto ? proto + ' listener' + (node.childCount ? ' \u00B7 ' + node.childCount + ' up' : '')
                                 : 'HTTP route' + (node.childCount ? ' \u00B7 ' + node.childCount + ' backends' : '');
                case 'backend':
                    return (proto || 'HTTP') + ' upstream';
                case 'serverless':
                    return node.kind === 'replay' ? 'Replay proxy' : 'Worker process';
            }
            return '';
        }

        _metricText(node) {
            var density = this.options.density;
            if (density === 'compact') return '';
            var parts = [];
            var rate = fmtRate(this._rps.get(node.id));
            if (rate) parts.push(rate);
            else if (typeof node.total === 'number' && node.total > 0) parts.push(fmtNum(node.total) + ' req');
            if (density === 'inspect') {
                if (node.latency_us && node.latency_us.p99) parts.push('p99 ' + fmtMs(node.latency_us.p99));
                if (node.failures > 0) parts.push(node.failures + ' fail');
                if (node.status && node.status !== 'ok') parts.push(STATUS_LABEL[node.status] || node.status);
            }
            return parts.join(' \u00B7 ');
        }

        // statistics

        _updateStats() {
            if (!this._root || !this.data || !this.layout) return;
            var self = this;
            var force = this.options.mode === 'force';

            this.data.nodes.forEach(function (node) {
                var g = self._nodeEls.get(node.id);
                if (!g) return;
                var status = node.status || 'ok';
                g.classList.remove('status--ok', 'status--degraded', 'status--dead', 'status--unverified');
                g.classList.add('status--' + status);
                g.setAttribute('aria-label', (node.label || node.id) + ' — ' +
                    (TYPE_LABEL[node.type] || node.type) + ', ' + (STATUS_LABEL[status] || status));

                var pos = self.layout.positions[node.id];

                if (force) {
                    var label = g.querySelector('.gdot-label');
                    if (label) label.textContent = truncate(node.label, 42);
                    // Update rate badge if present
                    var rateBadge = g.querySelector('.gdot-rate');
                    if (rateBadge) {
                        var rate = fmtRate(self._rps.get(node.id));
                        rateBadge.textContent = rate;
                        rateBadge.style.display = rate ? '' : 'none';
                    }
                    return;
                }

                var sub = g.querySelector('.gnode-sub');
                if (sub && pos) sub.textContent = truncate(self._subtitle(node), self._subChars(node, pos.w));

                var metric = g.querySelector('.gnode-metric');
                var text = self._metricText(node);
                if (metric) metric.textContent = text;
                g.classList.toggle('has-metric', !!text);

                var toggle = g.querySelector('.gnode-toggle');
                if (toggle) {
                    toggle.classList.toggle('is-collapsed', self._collapsed.has(node.id));
                    var sign = toggle.querySelector('text');
                    if (sign) sign.textContent = self._collapsed.has(node.id) ? '+' + node.hiddenCount : '−';
                }
            });

            this._edgeEls.forEach(function (rec) {
                var status = self._edgeStatus(rec);
                rec.path.classList.remove('status--ok', 'status--degraded', 'status--dead', 'status--unverified');
                rec.path.classList.add('status--' + status);
                rec.path.setAttribute('stroke-width', self._edgeWidth(rec).toFixed(2));

                if (force) {
                    rec.path.setAttribute('marker-end', self._edgeMarker(status));
                    // Apply flow animation to force mode edges too
                    if (rec.flow) {
                        rec.flow.classList.remove('status--ok', 'status--degraded', 'status--dead', 'status--unverified');
                        rec.flow.classList.add('status--' + status);
                        var rpsForce = self._rps.get(rec.target) || 0;
                        var activeForce = rpsForce > 0 && status !== 'dead' && self.options.animate;
                        rec.flow.classList.toggle('is-idle', !activeForce);
                        if (activeForce) {
                            var durForce = clamp(6 / (1 + Math.log10(rpsForce + 1) * 2.2), 0.8, 5.5);
                            rec.flow.style.animationDuration = durForce.toFixed(2) + 's';
                            rec.flow.setAttribute('stroke-width', Math.max(2, self._edgeWidth(rec) * 1.5).toFixed(2));
                        }
                    }
                    return;
                }

                var rps = self._rps.get(rec.target) || 0;
                var active = rps > 0 && status !== 'dead' && self.options.animate;
                rec.flow.classList.toggle('is-idle', !active);
                if (active) {
                    var dur = clamp(6 / (1 + Math.log10(rps + 1) * 2.2), 0.8, 5.5);
                    rec.flow.style.animationDuration = dur.toFixed(2) + 's';
                    rec.flow.setAttribute('stroke-width', Math.max(2, self._edgeWidth(rec) * 1.5).toFixed(2));
                }
            });

            this._applyModeClasses();
        }

        _edgeMarker(status) {
            if (status === 'dead') return 'url(#graph-arrow-dead)';
            if (status === 'degraded') return 'url(#graph-arrow-degraded)';
            return 'url(#graph-arrow-default)';
        }

        // tooltip

        _tipRow(label, value) {
            if (value === null || value === undefined || value === '' || value === '\u2014') return null;
            var row = document.createElement('div');
            row.className = 'gtt-row';
            var l = document.createElement('span');
            l.className = 'gtt-label';
            l.textContent = label;
            var v = document.createElement('span');
            v.className = 'gtt-val';
            v.textContent = String(value);
            row.appendChild(l);
            row.appendChild(v);
            return row;
        }

        _showTooltip(ev, node) {
            var tip = this._tooltip;
            if (!tip || !node) return;
            tip.textContent = '';

            var title = document.createElement('div');
            title.className = 'gtt-title';
            title.textContent = node.label || node.id;
            tip.appendChild(title);

            var type = document.createElement('div');
            type.className = 'gtt-type';
            var proto = node.protocol ? ' \u00B7 ' + String(node.protocol).toUpperCase() : '';
            type.textContent = (TYPE_LABEL[node.type] || node.type) + proto;
            tip.appendChild(type);

            var rows = [];
            rows.push(this._tipRow('Status', STATUS_LABEL[node.status] || node.status));
            var rate = fmtRate(this._rps.get(node.id));
            if (rate) rows.push(this._tipRow('Rate', rate));
            if (typeof node.total === 'number' && node.total > 0) rows.push(this._tipRow('Requests', node.total.toLocaleString()));
            if (node.failures > 0) rows.push(this._tipRow('Failures', node.failures));
            if (node.latency_us && node.latency_us.p50) rows.push(this._tipRow('p50', fmtMs(node.latency_us.p50)));
            if (node.latency_us && node.latency_us.p99) rows.push(this._tipRow('p99', fmtMs(node.latency_us.p99)));

            if (node.type === 'host' && node.meta) {
                var h = this._hostsData[node.meta.hostname] || {};
                var listeners = (h.routes ? h.routes.length : 0) + (h.proxies ? h.proxies.length : 0);
                rows.push(this._tipRow('Listeners', listeners || null));
            }
            if (node.type === 'route' && node.meta && node.meta.routeType === 'proxy') {
                var hp = this._hostsData[node.meta.hostname] || {};
                var p = (hp.proxies || [])[node.meta.routeIdx];
                if (p && p.active_sessions > 0) rows.push(this._tipRow('Sessions', p.active_sessions.toLocaleString()));
            }
            if (node.childCount) rows.push(this._tipRow('Connections', node.childCount));

            rows.forEach(function (row) { if (row) tip.appendChild(row); });

            tip.style.display = 'block';
            this._positionTooltip(ev);
        }

        _positionTooltip(ev) {
            var tip = this._tooltip;
            if (!tip || !this.container) return;
            var rect = this.container.getBoundingClientRect();
            var tw = tip.offsetWidth || 180;
            var th = tip.offsetHeight || 80;
            var x = ev.clientX - rect.left + 16;
            var y = ev.clientY - rect.top - 12;
            if (x + tw > rect.width - 8) x = ev.clientX - rect.left - tw - 16;
            if (y + th > rect.height - 8) y = ev.clientY - rect.top - th - 12;
            if (x < 8) x = 8;
            if (y < 8) y = 8;
            tip.style.left = x + 'px';
            tip.style.top = y + 'px';
        }

        // zoom / pan / drag

        _onWheel(ev) {
            ev.preventDefault();
            this._userZoom = true;
            var rect = this._svg.getBoundingClientRect();
            var factor = Math.exp(-ev.deltaY * (ev.deltaMode === 1 ? 0.05 : 0.0018));
            this._zoomAt(ev.clientX - rect.left, ev.clientY - rect.top, factor);
        }

        _zoomAt(px, py, factor) {
            var z = this._zoom;
            var k = clamp(z.k * factor, 0.15, 3);
            if (k === z.k) return;
            var scale = k / z.k;
            z.x = px - scale * (px - z.x);
            z.y = py - scale * (py - z.y);
            z.k = k;
            this._applyTransform();
        }

        _onPointerDown(ev) {
            if (ev.button !== 0) return;
            var nodeEl = ev.target.closest ? ev.target.closest('.gnode') : null;
            var nodeId = nodeEl && nodeEl.dataset ? nodeEl.dataset.id : null;
            if (nodeId && this.options.draggable && !nodeEl.classList.contains('gnode--root')) {
                var pos = this.layout && this.layout.positions[nodeId];
                if (!pos) return;
                this._drag = { id: nodeId, el: nodeEl, startX: ev.clientX, startY: ev.clientY, x0: pos.x, y0: pos.y, moved: false };
            } else {
                this._drag = { pan: true, startX: ev.clientX, startY: ev.clientY, x0: this._zoom.x, y0: this._zoom.y, moved: false };
            }
            // Capture ONLY for canvas panning. Capturing on a pointerdown that
            // started on a node retargets the following pointerup/click to the
            // <svg>, which silently swallowed the node click and therefore the
            // info panel and the drawer callbacks.
            if (this._drag.pan && this._svg.setPointerCapture && ev.pointerId != null) {
                try { this._svg.setPointerCapture(ev.pointerId); } catch (e) { /* ignore */ }
            }
        }

        _onPointerMove(ev) {
            var drag = this._drag;
            if (!drag) return;
            var dx = ev.clientX - drag.startX;
            var dy = ev.clientY - drag.startY;
            if (!drag.moved && Math.abs(dx) < 3 && Math.abs(dy) < 3) return;
            drag.moved = true;

            if (drag.pan) {
                this._userZoom = true;
                this._zoom.x = drag.x0 + dx;
                this._zoom.y = drag.y0 + dy;
                this._applyTransform();
                return;
            }

            // Node drag: move the card and re-route its incident edges. Positions
            // are otherwise untouched, so the hierarchy stays intact.
            var pos = this.layout.positions[drag.id];
            if (!pos) return;
            pos.x = drag.x0 + dx / this._zoom.k;
            pos.y = drag.y0 + dy / this._zoom.k;
            drag.el.setAttribute('transform', 'translate(' + Math.round(pos.x) + ',' + Math.round(pos.y) + ')');
            this._rerouteNode(drag.id);
        }

        _onPointerUp() {
            var drag = this._drag;
            this._drag = null;
            if (!drag || !drag.moved) return;
            // The click event fires after pointerup: flag it so a drag does not
            // also select the node / open the info panel.
            var self = this;
            this._suppressClick = true;
            setTimeout(function () { self._suppressClick = false; }, 0);
        }

        _rerouteNode(id) {
            var recs = this._edgeByNode.get(id) || [];
            var force = this.options.mode === 'force';
            for (var i = 0; i < recs.length; i++) {
                var rec = recs[i];
                var a = this.layout.positions[rec.source];
                var b = this.layout.positions[rec.target];
                if (!a || !b) continue;

                if (force) {
                    var line = GraphLayout.forceEdge(a, b);
                    rec.path.setAttribute('x1', line.x1);
                    rec.path.setAttribute('y1', line.y1);
                    rec.path.setAttribute('x2', line.x2);
                    rec.path.setAttribute('y2', line.y2);
                    continue;
                }

                var geom = GraphLayout.edgeGeometry(a, b, this.options.orientation === 'TB');
                rec.path.setAttribute('d', geom.path);
                if (rec.flow) rec.flow.setAttribute('d', geom.path);
            }
        }

        _clearDragState() {
            this._drag = null;
            this._selected = null;
            if (this._forcePositions) { this._forcePositions = null; this._forceSig = ''; }
        }

        // data processing (unchanged shape, extra stats carried along)

        processData(config, stats) {
            var nodes = [];
            var links = [];
            var nodeSet = new Set();

            var addNode = function (id, label, type, status, meta, extra) {
                if (nodeSet.has(id)) return;
                var node = { id: id, label: label, type: type, status: status || 'ok', meta: meta || null };
                if (extra) {
                    for (var k in extra) node[k] = extra[k];
                }
                nodes.push(node);
                nodeSet.add(id);
            };

            var addLink = function (source, target, weight, status) {
                links.push({ source: source, target: target, weight: weight || 0, status: status || 'ok' });
            };

            var beStatus = function (backendStats, bIdx) {
                if (!backendStats[bIdx]) return 'unverified';
                var bStat = backendStats[bIdx];
                var hStat = (bStat.health && bStat.health.status) || 'Unknown';
                if (bStat.alive === false || hStat === 'Dead' || hStat === 'Unhealthy') return 'dead';
                if (hStat === 'Degraded') return 'degraded';
                if (hStat === 'Healthy') return 'ok';
                return bStat.alive ? 'unverified' : 'dead';
            };

            var statsOf = function (arr, idx) { return (arr && arr[idx]) ? arr[idx] : {}; };

            var rootId = 'AGBERO';
            addNode(rootId, 'AGBERO', 'root');

            if (config.hosts) {
                Object.keys(config.hosts).forEach(function (hostname) {
                    var hostCfg = config.hosts[hostname] || {};
                    var hostStats = (stats && stats[hostname]) ? stats[hostname] : {};

                    addNode(hostname, hostname, 'host', 'ok', { hostname: hostname }, {
                        protocol: hostCfg.tls && hostCfg.tls.mode ? 'https' : 'http',
                        total: hostStats.total_reqs
                    });
                    addLink(rootId, hostname, hostStats.total_reqs || 0);

                    (hostCfg.routes || []).forEach(function (route, rIdx) {
                        var path = route.path || '/';
                        var routeId = hostname + '|' + path;
                        var routeStats = statsOf(hostStats.routes, rIdx);
                        var bkStats = routeStats.backends || [];

                        addNode(routeId, path, 'route', 'ok',
                            { hostname: hostname, routeIdx: rIdx, routeType: 'route' },
                            { protocol: 'http', total: routeStats.total_reqs });
                        addLink(hostname, routeId, routeStats.total_reqs || 0);

                        var servers = (route.backends && route.backends.servers) || [];
                        servers.forEach(function (srv, bIdx) {
                            var beUrl = srv.address;
                            if (!beUrl) return;
                            var beId = routeId + '|' + beUrl;
                            var status = beStatus(bkStats, bIdx);
                            var bStat = bkStats[bIdx] || {};
                            addNode(beId, beUrl.replace(/^https?:\/\//, ''), 'backend', status,
                                { hostname: hostname, routeIdx: rIdx, backendIdx: bIdx, routeType: 'route' },
                                { protocol: 'http', total: bStat.total_reqs, failures: bStat.failures,
                                  latency_us: bStat.latency_us, alive: bStat.alive });
                            addLink(routeId, beId, bStat.total_reqs || 0, status);
                        });

                        if (route.serverless && route.serverless.replay) {
                            route.serverless.replay.forEach(function (rp) {
                                var slId = routeId + '|replay|' + rp.name;
                                var slStats = (routeStats.serverless || []).filter(function (s) {
                                    return s.name === rp.name && s.kind === 'replay';
                                })[0];
                                var status = slStats && slStats.failures > 0 ? 'degraded' : 'ok';
                                addNode(slId, '\u21bb ' + rp.name, 'serverless', status,
                                    { hostname: hostname, routeIdx: rIdx, routeType: 'route' },
                                    { protocol: 'replay', kind: 'replay', total: slStats && slStats.total_reqs,
                                      failures: slStats && slStats.failures });
                                addLink(routeId, slId, (slStats && slStats.total_reqs) || 0, status);
                            });
                        }

                        if (route.serverless && route.serverless.workers) {
                            route.serverless.workers.forEach(function (wk) {
                                var wkId = routeId + '|worker|' + wk.name;
                                var wkStats = (routeStats.serverless || []).filter(function (s) {
                                    return s.name === wk.name && s.kind === 'worker';
                                })[0];
                                var status = wkStats && wkStats.failures > 0 ? 'degraded' : 'ok';
                                addNode(wkId, '\u2699 ' + wk.name, 'serverless', status,
                                    { hostname: hostname, routeIdx: rIdx, routeType: 'route' },
                                    { protocol: 'worker', kind: 'worker', total: wkStats && wkStats.total_reqs,
                                      failures: wkStats && wkStats.failures });
                                addLink(routeId, wkId, (wkStats && wkStats.total_reqs) || 0, status);
                            });
                        }
                    });

                    (hostCfg.proxies || []).forEach(function (proxy, pIdx) {
                        var name = proxy.name || proxy.listen;
                        var isUDP = String(proxy.protocol || '').toLowerCase() === 'udp';
                        var proto = isUDP ? 'UDP' : 'TCP';
                        var proxyId = hostname + '|' + proto.toLowerCase() + '|' + name;
                        var proxyStats = statsOf(hostStats.proxies, pIdx);
                        var bkStats = proxyStats.backends || [];
                        var matcher = isUDP && proxy.matcher ? ':' + proxy.matcher : '';

                        addNode(proxyId, proto + matcher + ':' + name, 'route', 'ok',
                            { hostname: hostname, routeIdx: pIdx, routeType: 'proxy' },
                            { protocol: isUDP ? 'udp' : 'tcp', total: proxyStats.total_reqs,
                              sessions: proxyStats.active_sessions });
                        addLink(hostname, proxyId, proxyStats.total_reqs || 0);

                        (proxy.backends || []).forEach(function (srv, bIdx) {
                            var beUrl = srv.address;
                            if (!beUrl) return;
                            var beId = proxyId + '|' + beUrl;
                            var status = beStatus(bkStats, bIdx);
                            var bStat = bkStats[bIdx] || {};
                            addNode(beId, beUrl, 'backend', status,
                                { hostname: hostname, routeIdx: pIdx, backendIdx: bIdx, routeType: 'proxy' },
                                { protocol: isUDP ? 'udp' : 'tcp', total: bStat.total_reqs,
                                  failures: bStat.failures, latency_us: bStat.latency_us, alive: bStat.alive });
                            addLink(proxyId, beId, bStat.total_reqs || 0, status);
                        });
                    });
                });
            }

            return { nodes: nodes, links: links };
        }
    }

    if (typeof window !== 'undefined') window.RouteGraph = RouteGraph;

})();
