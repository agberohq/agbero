class RouteGraph {
    constructor(containerId) {
        this.containerId = containerId;
        this.container = document.getElementById(containerId);
        this.simulation = null;
        this.svg = null;
        this.data = null;
        this.transform = d3.zoomIdentity;
    }

    render(config, stats) {
        if (!config || !this.container) return;
        this._hostsData = stats || {};           // raw stats kept for tooltip lookups
        this.data = this.processData(config, stats);

        this.container.innerHTML = "";

        const width  = this.container.clientWidth;
        const height = this.container.clientHeight || 600;

        this.svg = d3.select(this.container)
            .append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", [0, 0, width, height]);

        const defs = this.svg.append("defs");

        // One sharp arrowhead per link color
        const arrowConfigs =[
            { id: "arrow-default",   color: "#bbbbbb" },
            { id: "arrow-dead",      color: "#ff3b30" },
            { id: "arrow-degraded",  color: "#ffcc00" },
        ];

        arrowConfigs.forEach(({ id, color }) => {
            defs.append("marker")
                .attr("id", id)
                .attr("viewBox", "0 -4 8 8")
                .attr("refX", 22)
                .attr("refY", 0)
                .attr("markerWidth", 5)
                .attr("markerHeight", 5)
                .attr("orient", "auto")
                .append("path")
                .attr("d", "M0,-4L8,0L0,4Z")
                .attr("fill", color);
        });

        // Glow filter for root node
        const filter = defs.append("filter").attr("id", "glow");
        filter.append("feGaussianBlur").attr("stdDeviation", "3").attr("result", "coloredBlur");
        const feMerge = filter.append("feMerge");
        feMerge.append("feMergeNode").attr("in", "coloredBlur");
        feMerge.append("feMergeNode").attr("in", "SourceGraphic");

        const g = this.svg.append("g");

        // Tooltip element — one per graph instance, attached to container
        let _tooltip = this.container.querySelector('.graph-node-tooltip');
        if (!_tooltip) {
            _tooltip = document.createElement('div');
            _tooltip.className = 'graph-node-tooltip';
            _tooltip.style.display = 'none';
            this.container.appendChild(_tooltip);
        }
        this._tooltip = _tooltip;

        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => {
                this.transform = event.transform;
                g.attr("transform", event.transform);
            });

        this.svg.call(zoom);

        // Force layout — more breathing room
        this.simulation = d3.forceSimulation(this.data.nodes)
            .force("link",    d3.forceLink(this.data.links).id(d => d.id).distance(d => this.getLinkDistance(d)))
            .force("charge",  d3.forceManyBody().strength(-500))
            .force("center",  d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(d => this.getNodeRadius(d.type) + 18).strength(0.8));

        // Links — color and weight by target status
        const link = g.append("g")
            .selectAll("line")
            .data(this.data.links)
            .join("line")
            .attr("stroke",         d => this.getLinkColor(d))
            .attr("stroke-opacity", d => this.getLinkOpacity(d))
            .attr("stroke-width",   d => this.getLinkWidth(d))
            .attr("stroke-dasharray", d => d.target?.status === "dead" ? "4 3" : null)
            .attr("marker-end",     d => this.getLinkArrow(d));

        // Node groups
        const self = this;
        const node = g.append("g")
            .selectAll("g")
            .data(this.data.nodes)
            .join("g")
            .call(d3.drag()
                .on("start", (event, d) => this.dragstarted(event, d))
                .on("drag",  (event, d) => this.dragged(event, d))
                .on("end",   (event, d) => this.dragended(event, d)))
            .on("click", (event, d) => {
                if (event.defaultPrevented) return;
                if (typeof this._onClick === 'function') this._onClick(d);
            })
            .on("contextmenu", (event, d) => {
                event.preventDefault();
                event.stopPropagation();
                if (typeof this._onRightClick === 'function') this._onRightClick(event, d);
            })
            .on("mouseenter", (event, d) => {
                if (d.type === "root") return;
                d3.select(event.currentTarget).select("circle")
                    .transition().duration(150)
                    .attr("r", self.getNodeRadius(d.type) * 1.4);
                // Build tooltip content
                const lines = [];
                const push = (label, val) => { if (val !== null && val !== undefined && val !== '' && val !== '—') lines.push(`<div class="gtt-row"><span class="gtt-label">${label}</span><span class="gtt-val">${val}</span></div>`); };
                // Type badge
                const typeLabel = d.protocol ? `${d.type} · ${d.protocol.toUpperCase()}` : d.type;
                lines.push(`<div class="gtt-title">${d.label}</div><div class="gtt-type">${typeLabel}</div>`);
                // Status
                if (d.status && d.status !== 'ok') {
                    const sc = d.status === 'dead' ? '#ff3b30' : d.status === 'degraded' ? '#ffcc00' : '#aaa';
                    lines.push(`<div class="gtt-row"><span class="gtt-label">Status</span><span class="gtt-val" style="color:${sc};font-weight:500;">${d.status}</span></div>`);
                }
                // Host-level stats from hostsData
                if (d.type === 'host' && d.meta?.hostname) {
                    const hStat = self._hostsData?.[d.meta.hostname] || {};
                    push('Total Reqs', hStat.total_reqs ? hStat.total_reqs.toLocaleString() : null);
                    push('Routes',     (hStat.routes?.length || 0) + (hStat.proxies?.length || 0) || null);
                }
                // Route/proxy node — show path or listen
                if (d.type === 'route' && d.meta?.hostname) {
                    const hStat  = self._hostsData?.[d.meta.hostname] || {};
                    const rIdx   = d.meta.routeIdx;
                    if (d.meta.routeType === 'route') {
                        const r      = hStat.routes?.[rIdx];
                        if (r) {
                            push('Path',      r.path);
                            push('Reqs',      r.total_reqs?.toLocaleString());
                            const bAlive  = (r.backends || []).filter(b => b.alive !== false).length;
                            const bTotal  = (r.backends || []).length;
                            if (bTotal) push('Backends', `${bAlive}/${bTotal} alive`);
                        }
                    } else {
                        const p = hStat.proxies?.[rIdx];
                        if (p) {
                            push('Listen',   p.name);
                            push('Sessions', p.active_sessions > 0 ? p.active_sessions : null);
                        }
                    }
                }
                // Backend node — health + latency
                if (d.type === 'backend' && d.meta?.hostname) {
                    const hStat  = self._hostsData?.[d.meta.hostname] || {};
                    const isProxy = d.meta.routeType === 'proxy';
                    const rArr   = isProxy ? (hStat.proxies || []) : (hStat.routes || []);
                    const r      = rArr[d.meta.routeIdx];
                    const b      = r?.backends?.[d.meta.backendIdx];
                    if (b) {
                        push('Health',   b.health?.status);
                        push('Score',    b.health?.score !== undefined ? b.health.score.toFixed(2) : null);
                        push('Reqs',     b.total_reqs?.toLocaleString());
                        push('Failures', b.failures > 0 ? `<span style="color:#ff3b30">${b.failures}</span>` : null);
                        if (b.latency_us?.p99) push('p99', (b.latency_us.p99 / 1000).toFixed(1) + 'ms');
                        if (b.latency_us?.p50) push('p50', (b.latency_us.p50 / 1000).toFixed(1) + 'ms');
                    }
                }
                if (lines.length === 0) return;
                self._tooltip.innerHTML = lines.join('');
                self._tooltip.style.display = 'block';
                // Position near cursor inside container
                const rect = self.container.getBoundingClientRect();
                let tx = event.clientX - rect.left + 14;
                let ty = event.clientY - rect.top  - 10;
                // Keep inside container
                self._tooltip.style.left = tx + 'px';
                self._tooltip.style.top  = ty + 'px';
            })
            .on("mousemove", (event) => {
                if (!self._tooltip || self._tooltip.style.display === 'none') return;
                const rect = self.container.getBoundingClientRect();
                const ttW  = self._tooltip.offsetWidth  || 180;
                const ttH  = self._tooltip.offsetHeight || 80;
                let tx = event.clientX - rect.left + 14;
                let ty = event.clientY - rect.top  - 10;
                if (tx + ttW > rect.width  - 8) tx = event.clientX - rect.left - ttW - 14;
                if (ty + ttH > rect.height - 8) ty = event.clientY - rect.top  - ttH - 10;
                self._tooltip.style.left = tx + 'px';
                self._tooltip.style.top  = ty + 'px';
            })
            .on("mouseleave", (event, d) => {
                d3.select(event.currentTarget).select("circle")
                    .transition().duration(150)
                    .attr("r", self.getNodeRadius(d.type));
                if (self._tooltip) self._tooltip.style.display = 'none';
            });

        node.style("cursor", d => d.type === "root" ? "default" : "pointer");

        // Status ring (outer pulse for dead nodes)
        node.filter(d => d.status === "dead")
            .append("circle")
            .attr("r", d => this.getNodeRadius(d.type) + 5)
            .attr("fill", "none")
            .attr("stroke", "var(--danger)")
            .attr("stroke-width", 1)
            .attr("stroke-opacity", 0.4);

        // Main circle
        node.append("circle")
            .attr("r",            d => this.getNodeRadius(d.type))
            .attr("fill",         d => this.getNodeFill(d))
            .attr("stroke",       d => this.getNodeRingColor(d))
            .attr("stroke-width", d => this.getNodeRingWidth(d))
            .attr("filter",       d => d.type === "root" ? "url(#glow)" : null);

        // Inner dot for backend nodes — makes small circles legible
        node.filter(d => d.type === "backend")
            .append("circle")
            .attr("r", 2)
            .attr("fill", "#ffffff")
            .attr("fill-opacity", 0.6)
            .style("pointer-events", "none");

        // Labels — with background halo for readability
        const labelGroup = node.append("g").style("pointer-events", "none");

        // Halo
        labelGroup.append("text")
            .attr("x", d => this.getNodeRadius(d.type) + 7)
            .attr("y", 4)
            .text(d => d.label)
            .attr("font-family", "monospace")
            .attr("font-size",   d => this.getLabelSize(d.type))
            .attr("font-weight", d => d.type === "root" ? "700" : "400")
            .attr("stroke",      "var(--bg)")
            .attr("stroke-width", 4)
            .attr("stroke-linejoin", "round")
            .attr("fill", "var(--bg)");

        // Actual text
        labelGroup.append("text")
            .attr("x", d => this.getNodeRadius(d.type) + 7)
            .attr("y", 4)
            .text(d => d.label)
            .attr("font-family", "monospace")
            .attr("font-size",   d => this.getLabelSize(d.type))
            .attr("font-weight", d => d.type === "root" ? "700" : "400")
            .attr("fill",        d => this.getLabelColor(d));

        // Tick
        this.simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node.attr("transform", d => `translate(${d.x},${d.y})`);
        });

        this.zoomObj   = zoom;
        this.mainGroup = g;
    }

    resetZoom() {
        if (this.svg && this.zoomObj) {
            this.svg.transition().duration(750).call(this.zoomObj.transform, d3.zoomIdentity);
        }
    }

    // Visual helpers

    getNodeRadius(type) {
        switch (type) {
            case "root":       return 14;
            case "host":       return 10;
            case "route":      return 7;
            case "serverless": return 6;
            case "backend":    return 5;
            default:           return 5;
        }
    }

    getLabelSize(type) {
        switch (type) {
            case "root":       return "11px";
            case "host":       return "11px";
            case "route":      return "10px";
            case "serverless": return "9px";
            case "backend":    return "9px";
            default:           return "10px";
        }
    }

    getLabelColor(d) {
        if (d.status === "dead")      return "var(--danger)";
        if (d.status === "degraded")  return "var(--warning)";
        return "var(--fg)";
    }

    getNodeFill(d) {
        if (d.status === "dead")      return "var(--danger)";
        if (d.status === "degraded")  return "var(--warning)";
        switch (d.type) {
            case "root":       return "var(--fg)";
            case "host":       return "var(--accent)";
            case "route": {
                // UDP gets a distinct color; TCP/HTTP default green
                if (d.protocol === "udp")    return "#ff9500";   // orange
                if (d.protocol === "tcp")    return "#5ac8fa";   // blue
                return "var(--success)";
            }
            case "serverless": {
                if (d.kind === "worker")  return "#af52de";  // purple
                if (d.kind === "replay")  return "#34c759";  // green
                return "var(--info)";
            }
            case "backend":    return "var(--text-mute)";
            default:           return "#999";
        }
    }

    getNodeRingColor(d) {
        if (d.status === "dead")       return "var(--danger)";
        if (d.status === "degraded")   return "var(--warning)";
        if (d.status === "unverified") return "var(--info)";
        return "var(--bg)";
    }

    getNodeRingWidth(d) {
        if (d.status === "dead")     return 3;
        if (d.status === "degraded") return 2;
        return 2;
    }

    getLinkColor(d) {
        // Use the link's own status (from addLink) rather than target node status
        const status = d.status || d.target?.status;
        if (status === "dead")     return "#ff3b30";
        if (status === "degraded") return "#ffcc00";
        return "#cccccc";
    }

    getLinkOpacity(d) {
        const status = d.status || d.target?.status;
        if (status === "dead")     return 0.9;
        if (status === "degraded") return 0.8;
        return 0.5;
    }

    getLinkWidth(d) {

        const type = d.source?.type || d.source;
        if (type === "root") return 2;
        if (type === "host") return 1.5;
        // Scale weight logarithmically: 0 reqs = 1px, high traffic = up to 4px
        const w = d.weight || 0;
        if (w > 0) {
            const scaled = 1 + Math.min(Math.log10(w + 1) * 1.2, 3);
            return scaled;
        }
        return 1;
    }

    getLinkArrow(d) {
        const status = d.status || d.target?.status;
        if (status === "dead")     return "url(#arrow-dead)";
        if (status === "degraded") return "url(#arrow-degraded)";
        return "url(#arrow-default)";
    }

    getLinkDistance(d) {
        const srcType = d.source?.type || d.source;
        if (srcType === "root")    return 120;
        if (srcType === "host")    return 100;
        if (srcType === "route")   return 90;
        return 80;
    }

    // Data processing (unchanged)

    processData(config, stats) {
        const nodes   = [];
        const links   = [];
        const nodeSet = new Set();

        const addNode = (id, label, type, status = "ok", meta = null, extra = {}) => {
            if (!nodeSet.has(id)) {
                nodes.push({ id, label, type, status, meta, ...extra });
                nodeSet.add(id);
            }
        };

        const addLink = (source, target, weight = 0, status = "ok") => {
            links.push({ source, target, weight, status });
        };

        const beStatus = (backendStats, bIdx) => {
            if (!backendStats[bIdx]) return "unverified";
            const bStat = backendStats[bIdx];
            const hStat = bStat.health?.status || "Unknown";
            if (bStat.alive === false || hStat === "Dead" || hStat === "Unhealthy") return "dead";
            if (hStat === "Degraded") return "degraded";
            if (hStat === "Healthy") return "ok";
            return bStat.alive ? "unverified" : "dead";
        };

        const rootId = "AGBERO";
        addNode(rootId, "AGBERO", "root");

        if (config.hosts) {
            Object.entries(config.hosts).forEach(([hostname, hostCfg]) => {
                const hostStats = (stats && stats[hostname]) ? stats[hostname] : {};

                addNode(hostname, hostname, "host", "ok", { hostname });
                addLink(rootId, hostname);

                // HTTP routes
                if (hostCfg.routes) {
                    hostCfg.routes.forEach((route, rIdx) => {
                        const path       = route.path || "/";
                        const routeId    = `${hostname}|${path}`;
                        const routeStats = hostStats.routes ? hostStats.routes[rIdx] : {};
                        const bkStats    = routeStats?.backends || [];

                        addNode(routeId, path, "route", "ok", { hostname, routeIdx: rIdx, routeType: "route" });
                        addLink(hostname, routeId);

                        // HTTP backends
                        if (route.backends?.servers) {
                            route.backends.servers.forEach((srv, bIdx) => {
                                const beUrl  = srv.address || srv.url;
                                if (!beUrl) return;
                                const beId   = `${routeId}|${beUrl}`;
                                const status = beStatus(bkStats, bIdx);
                                const reqs   = bkStats[bIdx]?.total_reqs || 0;
                                addNode(beId, beUrl.replace(/^https?:\/\//, ""), "backend", status,
                                    { hostname, routeIdx: rIdx, backendIdx: bIdx, routeType: "route" },
                                    { protocol: "http" });
                                addLink(routeId, beId, reqs, status);
                            });
                        }

                        // Serverless — replay nodes
                        if (route.serverless?.replay?.length) {
                            route.serverless.replay.forEach((rp) => {
                                const slId    = `${routeId}|replay|${rp.name}`;
                                const slStats = (routeStats?.serverless || []).find(s => s.name === rp.name && s.kind === "replay");
                                const status  = slStats?.failures > 0 ? "degraded" : "ok";
                                const reqs    = slStats?.total_reqs || 0;
                                addNode(slId, `\u21bb ${rp.name}`, "serverless", status,
                                    { hostname, routeIdx: rIdx, routeType: "route" },
                                    { protocol: "replay", kind: "replay" });
                                addLink(routeId, slId, reqs, status);
                            });
                        }

                        // Serverless — worker nodes
                        if (route.serverless?.workers?.length) {
                            route.serverless.workers.forEach((wk) => {
                                const wkId    = `${routeId}|worker|${wk.name}`;
                                const wkStats = (routeStats?.serverless || []).find(s => s.name === wk.name && s.kind === "worker");
                                const status  = wkStats?.failures > 0 ? "degraded" : "ok";
                                const reqs    = wkStats?.total_reqs || 0;
                                addNode(wkId, `\u2699 ${wk.name}`, "serverless", status,
                                    { hostname, routeIdx: rIdx, routeType: "route" },
                                    { protocol: "worker", kind: "worker" });
                                addLink(routeId, wkId, reqs, status);
                            });
                        }
                    });
                }

                // TCP and UDP proxies
                if (hostCfg.proxies) {
                    hostCfg.proxies.forEach((proxy, pIdx) => {
                        const name       = proxy.name || proxy.listen;
                        const isUDP      = (proxy.protocol || "").toLowerCase() === "udp";
                        const proto      = isUDP ? "UDP" : "TCP";
                        const proxyId    = `${hostname}|${proto.toLowerCase()}|${name}`;
                        const proxyStats = hostStats.proxies ? hostStats.proxies[pIdx] : {};
                        const bkStats    = proxyStats?.backends || [];
                        const matcher    = isUDP && proxy.matcher ? `:${proxy.matcher}` : "";

                        addNode(proxyId, `${proto}${matcher}:${name}`, "route", "ok",
                            { hostname, routeIdx: pIdx, routeType: "proxy" },
                            { protocol: isUDP ? "udp" : "tcp" });
                        addLink(hostname, proxyId);

                        (proxy.backends || []).forEach((srv, bIdx) => {
                            const beUrl  = srv.address;
                            if (!beUrl) return;
                            const beId   = `${proxyId}|${beUrl}`;
                            const status = beStatus(bkStats, bIdx);
                            const reqs   = bkStats[bIdx]?.total_reqs || 0;
                            addNode(beId, beUrl, "backend", status,
                                { hostname, routeIdx: pIdx, backendIdx: bIdx, routeType: "proxy" },
                                { protocol: isUDP ? "udp" : "tcp" });
                            addLink(proxyId, beId, reqs, status);
                        });
                    });
                }
            });
        }

        return { nodes, links };
    }

    // Drag handlers

    dragstarted(event, d) {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }

    dragged(event, d) {
        d.fx = event.x;
        d.fy = event.y;
    }

    dragended(event, d) {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }
}
// Expose on window so the lazy-loader guard (window.RouteGraph) works correctly.
window.RouteGraph = RouteGraph;
