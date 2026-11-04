/**
 * js/graph-layout.js — pure geometry for the topology map.
 *
 * No DOM, no D3, no random numbers: the same nodes+links always produce the
 * same positions. That is what makes statistics refreshes cheap — only the
 * labels change, never the layout.
 *
 *   computeLayout(nodes, links, { orientation, density, ... })
 *     → { positions, edges, bounds, orientation, density }
 *
 * Depth is derived from the link graph (root → host → route/proxy →
 * backend/worker), not from the node type, so an unexpected shape still lays
 * out (unreachable nodes fall back to a type rank).
 *
 * Exposed as both `computeLayout` and `GraphLayout.computeLayout` so the
 * renderer can use it from a classic script and the layout tests can load this
 * file on its own.
 */
(function (global) {
    'use strict';

    // Card sizes per node type, in CSS pixels at density "detailed".
    var CARD = {
        root:       { w: 236, h: 78 },
        host:       { w: 212, h: 68 },
        route:      { w: 196, h: 58 },
        serverless: { w: 186, h: 54 },
        backend:    { w: 178, h: 50 }
    };

    var DENSITY = { compact: 0.84, detailed: 1, inspect: 1.14 };

    // Used only for nodes the link graph does not reach.
    var TYPE_RANK = { root: 0, host: 1, route: 2, serverless: 3, backend: 3 };

    function cardSize(type, density) {
        var base = CARD[type] || CARD.backend;
        var scale = DENSITY[density] || 1;
        return {
            w: Math.round(base.w * (type === 'root' ? 1 : scale)),
            h: Math.round(base.h * scale)
        };
    }

    function idOf(end) {
        return end && typeof end === 'object' ? end.id : end;
    }

    function computeLayout(nodes, links, opts) {
        opts = opts || {};
        var orientation = opts.orientation === 'TB' ? 'TB' : 'LR';
        var density = DENSITY[opts.density] ? opts.density : 'detailed';
        var isTB = orientation === 'TB';
        var margin = opts.margin != null ? opts.margin : 48;
        var gapDepth = opts.gapDepth != null ? opts.gapDepth : (isTB ? 96 : 120);
        var gapSibling = opts.gapSibling != null ? opts.gapSibling : (isTB ? 34 : 22);

        nodes = nodes || [];
        links = links || [];

        // index
        var byId = new Map();
        var order = [];
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            if (!n || !n.id || byId.has(n.id)) continue;
            var size = cardSize(n.type, density);
            // Grow the card to fit the label instead of truncating hostnames into
            // an ellipsis — the widest label in the column sets the column width.
            var labelW = 46 + String(n.label || '').length * 6.6;
            size.w = Math.max(size.w, Math.min(340, Math.round(labelW)));
            byId.set(n.id, { id: n.id, type: n.type || 'backend', w: size.w, h: size.h, index: order.length });
            order.push(n.id);
        }

        // tree (first parent wins; extra parents stay decorative)
        var children = new Map();
        order.forEach(function (id) { children.set(id, []); });
        var parentOf = new Map();
        var keptLinks = [];
        for (var j = 0; j < links.length; j++) {
            var s = idOf(links[j].source);
            var t = idOf(links[j].target);
            if (!byId.has(s) || !byId.has(t) || s === t) continue;
            keptLinks.push({ source: s, target: t, raw: links[j] });
            if (parentOf.has(t)) continue;
            parentOf.set(t, s);
            children.get(s).push(t);
        }

        var roots = order.filter(function (id) { return !parentOf.has(id); });
        roots.sort(function (a, b) {
            var ra = byId.get(a).type === 'root' ? 0 : 1;
            var rb = byId.get(b).type === 'root' ? 0 : 1;
            return ra - rb || byId.get(a).index - byId.get(b).index;
        });

        // depth
        var depth = new Map();
        var queue = roots.slice();
        queue.forEach(function (id) { depth.set(id, 0); });
        while (queue.length) {
            var cur = queue.shift();
            var kids = children.get(cur) || [];
            for (var k = 0; k < kids.length; k++) {
                if (depth.has(kids[k])) continue;
                depth.set(kids[k], depth.get(cur) + 1);
                queue.push(kids[k]);
            }
        }
        order.forEach(function (id) {
            if (!depth.has(id)) depth.set(id, TYPE_RANK[byId.get(id).type] || 0);
        });

        // cross-axis extent, post-order
        var extent = new Map();
        function measure(id) {
            if (extent.has(id)) return extent.get(id);
            var self = byId.get(id);
            var own = isTB ? self.w : self.h;
            var kids = children.get(id) || [];
            if (!kids.length) { extent.set(id, own); return own; }
            var total = 0;
            for (var i = 0; i < kids.length; i++) {
                var kid = byId.get(kids[i]);
                total += Math.max(measure(kids[i]), isTB ? kid.w : kid.h);
                if (i < kids.length - 1) total += gapSibling;
            }
            var value = Math.max(own, total);
            extent.set(id, value);
            return value;
        }
        roots.forEach(measure);
        order.forEach(measure);

        // positions (parents centred over their children)
        var slots = new Map();

        function place(id, crossStart) {
            var self = byId.get(id);
            var own = isTB ? self.w : self.h;
            var myExtent = extent.get(id);
            var kids = children.get(id) || [];
            var cross;

            if (!kids.length) {
                cross = crossStart + (myExtent - own) / 2;
            } else {
                var childTotal = 0;
                for (var i = 0; i < kids.length; i++) {
                    var size = byId.get(kids[i]);
                    childTotal += Math.max(extent.get(kids[i]), isTB ? size.w : size.h);
                    if (i < kids.length - 1) childTotal += gapSibling;
                }
                var run = crossStart + (myExtent - childTotal) / 2;
                var firstCentre = 0, lastCentre = 0;
                for (var c = 0; c < kids.length; c++) {
                    var kidId = kids[c];
                    var kidBox = byId.get(kidId);
                    var kidOwn = isTB ? kidBox.w : kidBox.h;
                    var kidExtent = Math.max(extent.get(kidId), kidOwn);
                    var kidCross = place(kidId, run);
                    var centre = kidCross + kidOwn / 2;
                    if (c === 0) firstCentre = centre;
                    lastCentre = centre;
                    run += kidExtent + gapSibling;
                }
                cross = (firstCentre + lastCentre) / 2 - own / 2;
            }
            slots.set(id, cross);
            return cross;
        }

        var cursor = margin;
        roots.forEach(function (id) {
            place(id, cursor);
            cursor += extent.get(id) + gapSibling;
        });

        // depth columns
        var maxDepth = 0;
        order.forEach(function (id) { maxDepth = Math.max(maxDepth, depth.get(id)); });

        var columnSize = [];
        for (var d = 0; d <= maxDepth; d++) columnSize[d] = 0;
        order.forEach(function (id) {
            var box = byId.get(id);
            var dd = depth.get(id);
            columnSize[dd] = Math.max(columnSize[dd], isTB ? box.h : box.w);
        });

        var columnStart = [];
        var acc = margin;
        for (var c = 0; c <= maxDepth; c++) {
            columnStart[c] = acc;
            acc += columnSize[c] + gapDepth;
        }

        var positions = {};
        order.forEach(function (id) {
            var box = byId.get(id);
            var dd = depth.get(id);
            var main = columnStart[dd] + (columnSize[dd] - (isTB ? box.h : box.w)) / 2;
            var cross = slots.get(id) || margin;
            positions[id] = {
                x: Math.round(isTB ? cross : main),
                y: Math.round(isTB ? main : cross),
                w: box.w,
                h: box.h,
                depth: dd,
                type: box.type
            };
        });

        // bounds
        var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        order.forEach(function (id) {
            var p = positions[id];
            if (p.x < minX) minX = p.x;
            if (p.y < minY) minY = p.y;
            if (p.x + p.w > maxX) maxX = p.x + p.w;
            if (p.y + p.h > maxY) maxY = p.y + p.h;
        });
        if (!order.length) { minX = 0; minY = 0; maxX = 0; maxY = 0; }

        var bounds = { minX: minX, minY: minY, maxX: maxX, maxY: maxY, width: maxX - minX, height: maxY - minY };

        // edges
        var edges = keptLinks.map(function (link, idx) {
            var a = positions[link.source] || { x: 0, y: 0, w: 0, h: 0 };
            var b = positions[link.target] || { x: 0, y: 0, w: 0, h: 0 };
            return { id: link.source + '->' + link.target + ':' + idx, source: link.source, target: link.target, raw: link.raw,
                     geom: edgeGeometry(a, b, isTB) };
        });

        return {
            orientation: orientation,
            density: density,
            positions: positions,
            edges: edges,
            bounds: bounds,
            order: order
        };
    }

    // classic view
    //
    // The original map was a force-directed graph. It is kept as its own mode so
    // the familiar view stays one click away, but implemented here without D3:
    // concentric seeding by depth + a fixed number of iterations makes it
    // deterministic (same config → same picture) and lets `update()` reuse the
    // previous positions instead of re-running the solver for every metrics tick.
    var FORCE_RADIUS = { root: 14, host: 10, route: 7, serverless: 6, backend: 5 };

    function forceRadius(type) { return FORCE_RADIUS[type] || 5; }

    function computeForceLayout(nodes, links, opts) {
        opts = opts || {};
        var prev = opts.previous || null;   // id → {x,y} from the last pass
        // Seeded from the previous pass (a config change, not a first paint): a
        // short relaxation keeps the picture recognisable instead of reshuffling
        // every node.
        var iterations = opts.iterations != null ? opts.iterations : (prev ? 12 : 260);
        var ideal = opts.ideal != null ? opts.ideal : 96;
        var margin = opts.margin != null ? opts.margin : 60;

        nodes = nodes || [];
        links = links || [];

        // index nodes
        var list = [];
        var byId = new Map();
        for (var i = 0; i < nodes.length; i++) {
            var n = nodes[i];
            if (!n || !n.id || byId.has(n.id)) continue;
            var r = forceRadius(n.type);
            var nodeObj = {
                id: n.id,
                type: n.type || 'backend',
                radius: r,
                x: 0, y: 0,
                vx: 0, vy: 0,
                depth: 0
            };
            list.push(nodeObj);
            byId.set(n.id, nodeObj);
        }

        // build tree to compute depth
        var children = new Map();
        var parentOf = new Map();
        list.forEach(function (nd) { children.set(nd.id, []); });
        var adjacency = [];
        for (var j = 0; j < links.length; j++) {
            var src = idOf(links[j].source);
            var tgt = idOf(links[j].target);
            var a = byId.get(src);
            var b = byId.get(tgt);
            if (!a || !b || a === b) continue;
            adjacency.push({ a: a, b: b, raw: links[j] });
            if (!parentOf.has(tgt)) {
                parentOf.set(tgt, src);
                children.get(src).push(tgt);
            }
        }

        // BFS from roots (nodes with no parent) to assign depth
        var roots = list.filter(function (nd) { return !parentOf.has(nd.id); });
        var depth = new Map();
        var queue = roots.slice();
        queue.forEach(function (nd) { depth.set(nd.id, 0); nd.depth = 0; });
        while (queue.length) {
            var cur = queue.shift();
            var kids = children.get(cur.id) || [];
            for (var k = 0; k < kids.length; k++) {
                if (depth.has(kids[k])) continue;
                var d = depth.get(cur.id) + 1;
                depth.set(kids[k], d);
                byId.get(kids[k]).depth = d;
                queue.push(byId.get(kids[k]));
            }
        }
        // Unreachable nodes get depth by type rank
        list.forEach(function (nd) {
            if (!depth.has(nd.id)) {
                nd.depth = TYPE_RANK[nd.type] || 3;
            }
        });

        // seed positions by depth level
        // Group nodes by depth, then place each group in a concentric ring.
        var maxDepth = 0;
        list.forEach(function (nd) { if (nd.depth > maxDepth) maxDepth = nd.depth; });
        var byDepth = [];
        for (var dd = 0; dd <= maxDepth; dd++) byDepth[dd] = [];
        list.forEach(function (nd) { byDepth[nd.depth].push(nd); });

        var goldenAngle = 2.399963229728653;
        list.forEach(function (nd) {
            var p = prev && prev[nd.id];
            if (p) {
                // Use previous position if available (config change, not first paint).
                nd.x = p.x;
                nd.y = p.y;
                return;
            }
            var d = nd.depth;
            var group = byDepth[d];
            var idxInGroup = group.indexOf(nd);
            // Root (depth 0) at center, others in rings that grow with depth.
            if (d === 0) {
                nd.x = 0;
                nd.y = 0;
            } else {
                var ringRadius = 60 + d * 80;
                var angle = idxInGroup * goldenAngle;
                nd.x = Math.cos(angle) * ringRadius;
                nd.y = Math.sin(angle) * ringRadius;
            }
        });

        // Repulsion + spring, cooled linearly. O(n²) is fine: the classic view is
        // for inspection, and past a few hundred nodes the topology view is the
        // better tool.
        for (var step = 0; step < iterations; step++) {
            var cooling = 1 - step / iterations;

            for (var x = 0; x < list.length; x++) {
                for (var y = x + 1; y < list.length; y++) {
                    var n1 = list[x], n2 = list[y];
                    var dx = n2.x - n1.x, dy = n2.y - n1.y;
                    var d2 = dx * dx + dy * dy;
                    if (d2 < 1) { d2 = 1; dx = 0.5 + x * 0.01; dy = 0.5 + y * 0.01; }
                    var dist = Math.sqrt(d2);
                    var minDist = n1.radius + n2.radius + 26;
                    var force = (ideal * ideal) / d2;
                    if (dist < minDist) force += (minDist - dist) * 0.9;
                    var fx = (dx / dist) * force, fy = (dy / dist) * force;
                    n1.vx -= fx; n1.vy -= fy;
                    n2.vx += fx; n2.vy += fy;
                }
            }

            for (var e = 0; e < adjacency.length; e++) {
                var link = adjacency[e];
                var lx = link.b.x - link.a.x, ly = link.b.y - link.a.y;
                var ld = Math.sqrt(lx * lx + ly * ly) || 1;
                var pull = (ld - ideal) * 0.06;
                var px = (lx / ld) * pull, py = (ly / ld) * pull;
                link.a.vx += px; link.a.vy += py;
                link.b.vx -= px; link.b.vy -= py;
            }

            for (var m = 0; m < list.length; m++) {
                var node2 = list[m];
                node2.vx -= node2.x * 0.004;   // gravity toward the origin
                node2.vy -= node2.y * 0.004;
                node2.x += node2.vx * cooling;
                node2.y += node2.vy * cooling;
                node2.vx *= 0.55;
                node2.vy *= 0.55;
            }
        }

        var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        list.forEach(function (node3) {
            minX = Math.min(minX, node3.x - node3.radius);
            minY = Math.min(minY, node3.y - node3.radius);
            maxX = Math.max(maxX, node3.x + node3.radius);
            maxY = Math.max(maxY, node3.y + node3.radius);
        });
        if (!list.length) { minX = minY = 0; maxX = maxY = 0; }

        // Normalise into positive space, leaving room for the labels on the right.
        var shiftX = margin - minX;
        var shiftY = margin - minY;
        var positions = {};
        list.forEach(function (node4) {
            positions[node4.id] = {
                x: Math.round(node4.x + shiftX),
                y: Math.round(node4.y + shiftY),
                w: node4.radius * 2,
                h: node4.radius * 2,
                radius: node4.radius,
                depth: 0,
                type: node4.type
            };
        });

        var bounds = {
            minX: margin, minY: margin,
            maxX: maxX + shiftX + 150,   // label column
            maxY: maxY + shiftY,
            width: (maxX - minX) + 150,
            height: maxY - minY
        };

        var edges = adjacency.map(function (link2, idx2) {
            var A = positions[link2.a.id], B = positions[link2.b.id];
            return {
                id: link2.a.id + '->' + link2.b.id + ':' + idx2,
                source: link2.a.id,
                target: link2.b.id,
                raw: link2.raw,
                geom: forceEdge(A, B)
            };
        });

        return { orientation: 'force', density: 'detailed', positions: positions, edges: edges, bounds: bounds, order: list.map(function (n5) { return n5.id; }) };
    }

    function forceEdge(a, b) {
        if (!a || !b) return { x1: 0, y1: 0, x2: 0, y2: 0, path: '', midX: 0, midY: 0 };
        var ax = a.x + a.radius, ay = a.y + a.radius;
        var bx = b.x + b.radius, by = b.y + b.radius;
        var dx = bx - ax, dy = by - ay;
        var len = Math.sqrt(dx * dx + dy * dy) || 1;
        var trim = (b.radius || 5) + 6;   // stop short of the target circle
        var x2 = bx - (dx / len) * trim;
        var y2 = by - (dy / len) * trim;
        return {
            x1: r(ax), y1: r(ay), x2: r(x2), y2: r(y2),
            path: 'M' + r(ax) + ',' + r(ay) + 'L' + r(x2) + ',' + r(y2),
            midX: r((ax + x2) / 2), midY: r((ay + y2) / 2)
        };
    }

    // Cubic Bézier from the source card border to the target card border. The
    // control points are offset along the primary axis so curves leave and
    // enter horizontally (LR) or vertically (TB).
    function edgeGeometry(a, b, isTB) {
        var sx, sy, tx, ty, c1x, c1y, c2x, c2y;

        if (isTB) {
            sx = a.x + a.w / 2; sy = a.y + a.h;
            tx = b.x + b.w / 2; ty = b.y;
            var dy = Math.max(28, (ty - sy) * 0.45);
            c1x = sx; c1y = sy + dy;
            c2x = tx; c2y = ty - dy;
        } else if (b.x >= a.x + a.w) {
            sx = a.x + a.w; sy = a.y + a.h / 2;
            tx = b.x;       ty = b.y + b.h / 2;
            var dx = Math.max(28, (tx - sx) * 0.45);
            c1x = sx + dx; c1y = sy;
            c2x = tx - dx; c2y = ty;
        } else {
            // Same column or a loop back: leave from the bottom, enter the top.
            sx = a.x + a.w / 2; sy = a.y + a.h;
            tx = b.x + b.w / 2; ty = b.y;
            var droop = Math.max(26, Math.abs(ty - sy) * 0.5);
            c1x = sx; c1y = sy + droop;
            c2x = tx; c2y = ty - droop;
        }

        var path = 'M' + r(sx) + ',' + r(sy) + 'C' + r(c1x) + ',' + r(c1y) + ' ' + r(c2x) + ',' + r(c2y) + ' ' + r(tx) + ',' + r(ty);

        // Midpoint of the curve (t = 0.5) — used for edge labels.
        var mx = (sx + 3 * c1x + 3 * c2x + tx) / 8;
        var my = (sy + 3 * c1y + 3 * c2y + ty) / 8;

        return { x1: r(sx), y1: r(sy), x2: r(tx), y2: r(ty), path: path, midX: r(mx), midY: r(my) };
    }

    function r(n) { return Math.round(n * 100) / 100; }

    var api = {
        computeLayout: computeLayout,
        computeForceLayout: computeForceLayout,
        cardSize: cardSize,
        edgeGeometry: edgeGeometry,
        forceRadius: forceRadius,
        forceEdge: forceEdge,
        CARD: CARD
    };

    global.computeLayout = computeLayout;
    global.computeForceLayout = computeForceLayout;
    global.GraphLayout = api;

})(typeof window !== 'undefined' ? window : globalThis);
