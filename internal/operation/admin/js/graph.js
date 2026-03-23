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
            .on("mouseenter", function(event, d) {
                if (d.type === "root") return;
                d3.select(this).select("circle")
                    .transition().duration(150)
                    .attr("r", self.getNodeRadius(d.type) * 1.4);
            })
            .on("mouseleave", function(event, d) {
                d3.select(this).select("circle")
                    .transition().duration(150)
                    .attr("r", self.getNodeRadius(d.type));
            });

        const self = this;
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

    // ── Visual helpers ────────────────────────────────────────────────────────

    getNodeRadius(type) {
        switch (type) {
            case "root":    return 14;
            case "host":    return 10;
            case "route":   return 7;
            case "backend": return 5;
            default:        return 5;
        }
    }

    getLabelSize(type) {
        switch (type) {
            case "root":    return "11px";
            case "host":    return "11px";
            case "route":   return "10px";
            case "backend": return "9px";
            default:        return "10px";
        }
    }

    getLabelColor(d) {
        if (d.status === "dead")      return "var(--danger)";
        if (d.status === "degraded")  return "var(--warning)";
        if (d.type   === "root")      return "var(--fg)";
        return "var(--fg)";
    }

    getNodeFill(d) {
        if (d.status === "dead") return "var(--danger)";
        switch (d.type) {
            case "root":    return "var(--fg)";
            case "host":    return "var(--accent)";
            case "route":   return "var(--success)";
            case "backend": return "var(--text-mute)";
            default:        return "#999";
        }
    }

    getNodeRingColor(d) {
        if (d.status === "dead")      return "var(--danger)";
        if (d.status === "degraded")  return "var(--warning)";
        if (d.status === "unverified") return "var(--info)";
        return "var(--bg)";
    }

    getNodeRingWidth(d) {
        if (d.status === "dead")     return 3;
        if (d.status === "degraded") return 2;
        return 2;
    }

    getLinkColor(d) {
        const status = d.target?.status;
        if (status === "dead")     return "#ff3b30";
        if (status === "degraded") return "#ffcc00";
        return "#cccccc";
    }

    getLinkOpacity(d) {
        const status = d.target?.status;
        if (status === "dead")     return 0.9;
        if (status === "degraded") return 0.8;
        return 0.7;
    }

    getLinkWidth(d) {
        const type = d.source?.type;
        if (type === "root") return 2;
        if (type === "host") return 1.5;
        return 1;
    }

    getLinkArrow(d) {
        const status = d.target?.status;
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

    // ── Data processing (unchanged) ───────────────────────────────────────────

    processData(config, stats) {
        const nodes  =[];
        const links  =[];
        const nodeSet = new Set();

        const addNode = (id, label, type, status = "ok", meta = null) => {
            if (!nodeSet.has(id)) {
                nodes.push({ id, label, type, status, meta });
                nodeSet.add(id);
            }
        };

        const rootId = "AGBERO";
        addNode(rootId, "AGBERO", "root");

        if (config.hosts) {
            Object.entries(config.hosts).forEach(([hostname, hostCfg]) => {
                const hostStats = stats && stats[hostname] ? stats[hostname] : {};

                addNode(hostname, hostname, "host", "ok", { hostname });
                links.push({ source: rootId, target: hostname });

                if (hostCfg.routes) {
                    hostCfg.routes.forEach((route, rIdx) => {
                        const path    = route.path || "/";
                        const routeId = `${hostname}|${path}`;
                        addNode(routeId, path, "route", "ok", { hostname, routeIdx: rIdx, routeType: "route" });
                        links.push({ source: hostname, target: routeId });

                        const routeStats   = hostStats.routes ? hostStats.routes[rIdx] : {};
                        const backendStats = routeStats.backends ||[];

                        if (route.backends && route.backends.servers) {
                            route.backends.servers.forEach((srv, bIdx) => {
                                const beUrl = srv.address || srv.url;
                                if (!beUrl) return;
                                const beId      = `${routeId}|${beUrl}`;
                                const displayUrl = beUrl.replace(/^https?:\/\//, "");
                                let   status    = "unverified";

                                if (backendStats[bIdx]) {
                                    const bStat = backendStats[bIdx];
                                    const hStat = bStat.health?.status || "Unknown";
                                    if (bStat.alive === false || hStat === "Dead" || hStat === "Unhealthy") {
                                        status = "dead";
                                    } else if (hStat === "Degraded") {
                                        status = "degraded";
                                    } else if (hStat === "Healthy") {
                                        status = "ok";
                                    } else {
                                        status = bStat.alive ? "unverified" : "dead";
                                    }
                                }

                                addNode(beId, displayUrl, "backend", status, { hostname, routeIdx: rIdx, backendIdx: bIdx, routeType: "route" });
                                links.push({ source: routeId, target: beId });
                            });
                        }
                    });
                }

                if (hostCfg.proxies) {
                    hostCfg.proxies.forEach((proxy, pIdx) => {
                        const name    = proxy.name || proxy.listen;
                        const proxyId = `${hostname}|tcp|${name}`;
                        addNode(proxyId, `TCP:${name}`, "route", "ok", { hostname, routeIdx: pIdx, routeType: "proxy" });
                        links.push({ source: hostname, target: proxyId });

                        const proxyStats   = hostStats.proxies ? hostStats.proxies[pIdx] : {};
                        const backendStats = proxyStats.backends ||[];

                        if (proxy.backends) {
                            proxy.backends.forEach((srv, bIdx) => {
                                const beUrl = srv.address;
                                const beId  = `${proxyId}|${beUrl}`;
                                let   status = "unverified";

                                if (backendStats[bIdx]) {
                                    const bStat = backendStats[bIdx];
                                    const hStat = bStat.health?.status || "Unknown";
                                    if (bStat.alive === false || hStat === "Dead" || hStat === "Unhealthy") {
                                        status = "dead";
                                    } else if (hStat === "Degraded") {
                                        status = "degraded";
                                    } else if (hStat === "Healthy") {
                                        status = "ok";
                                    } else {
                                        status = bStat.alive ? "unverified" : "dead";
                                    }
                                }

                                addNode(beId, beUrl, "backend", status, { hostname, routeIdx: pIdx, backendIdx: bIdx, routeType: "proxy" });
                                links.push({ source: proxyId, target: beId });
                            });
                        }
                    });
                }
            });
        }

        return { nodes, links };
    }

    // ── Drag handlers ─────────────────────────────────────────────────────────

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