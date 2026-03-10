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

        // Cleanup existing
        this.container.innerHTML = "";

        const width = this.container.clientWidth;
        const height = this.container.clientHeight || 600;

        this.svg = d3.select(this.container)
            .append("svg")
            .attr("width", "100%")
            .attr("height", "100%")
            .attr("viewBox", [0, 0, width, height]);

        // Define arrowhead marker
        const defs = this.svg.append("defs");

        defs.selectAll("marker")
            .data(["end"])
            .enter().append("marker")
            .attr("id", "arrow")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", 18)
            .attr("refY", 0)
            .attr("markerWidth", 6)
            .attr("markerHeight", 6)
            .attr("orient", "auto")
            .append("path")
            .attr("d", "M0,-5L10,0L0,5")
            .attr("fill", "var(--text-mute)");

        const g = this.svg.append("g");

        // Zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 4])
            .on("zoom", (event) => {
                this.transform = event.transform;
                g.attr("transform", event.transform);
            });

        this.svg.call(zoom);

        // Simulation setup
        this.simulation = d3.forceSimulation(this.data.nodes)
            .force("link", d3.forceLink(this.data.links).id(d => d.id).distance(80))
            .force("charge", d3.forceManyBody().strength(-300))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collide", d3.forceCollide().radius(40).strength(0.5));

        // Draw Links
        const link = g.append("g")
            .selectAll("line")
            .data(this.data.links)
            .join("line")
            .attr("stroke", "var(--border)")
            .attr("stroke-opacity", 0.6)
            .attr("stroke-width", 1.5)
            .attr("marker-end", "url(#arrow)");

        // Draw Nodes
        const node = g.append("g")
            .selectAll("g")
            .data(this.data.nodes)
            .join("g")
            .call(d3.drag()
                .on("start", (event, d) => this.dragstarted(event, d))
                .on("drag", (event, d) => this.dragged(event, d))
                .on("end", (event, d) => this.dragended(event, d)))
            .on("click", (event, d) => {
                if (event.defaultPrevented) return; // Prevent click if dragged

                if (d.type === 'route' && d.meta) {
                    window.app.openRouteDrawer(d.meta.hostname, d.meta.routeIdx, d.meta.routeType);
                } else if (d.type === 'backend' && d.meta) {
                    window.app.openBackendDrawer(d.meta.hostname, d.meta.routeIdx, d.meta.backendIdx, d.meta.routeType);
                } else if (d.type === 'host' && d.meta) {
                    const searchInput = document.getElementById("hostSearch");
                    if (searchInput) {
                        searchInput.value = d.meta.hostname;
                        sessionStorage.setItem("ag_search", d.meta.hostname);
                        window.app.searchTerm = d.meta.hostname;
                        window.app.setPage("hosts");
                    }
                }
            });

        // Style node hover state for clickability
        node.style("cursor", d => d.type === "root" ? "default" : "pointer");

        // Node Circles
        node.append("circle")
            .attr("r", d => this.getNodeRadius(d.type))
            .attr("fill", d => this.getNodeColor(d.type))
            .attr("stroke", d => this.getNodeStroke(d.status))
            .attr("stroke-width", d => d.status === 'dead' ? 3 : 1.5);

        // Node Labels
        node.append("text")
            .attr("x", d => this.getNodeRadius(d.type) + 5)
            .attr("y", 4)
            .text(d => d.label)
            .attr("font-family", "monospace")
            .attr("font-size", "10px")
            .attr("fill", "var(--fg)")
            .style("pointer-events", "none")
            .clone(true).lower()
            .attr("stroke", "var(--bg)")
            .attr("stroke-width", 3);

        // Simulation Tick
        this.simulation.on("tick", () => {
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);

            node
                .attr("transform", d => `translate(${d.x},${d.y})`);
        });

        // Save references for reset
        this.zoomObj = zoom;
        this.mainGroup = g;
    }

    resetZoom() {
        if(this.svg && this.zoomObj) {
            this.svg.transition().duration(750).call(this.zoomObj.transform, d3.zoomIdentity);
        }
    }

    processData(config, stats) {
        const nodes = [];
        const links =[];
        const nodeSet = new Set();

        const addNode = (id, label, type, status = 'ok', meta = null) => {
            if (!nodeSet.has(id)) {
                nodes.push({ id, label, type, status, meta });
                nodeSet.add(id);
            }
        };

        // Root Node
        const rootId = "AGBERO";
        addNode(rootId, "AGBERO", "root");

        if (config.hosts) {
            Object.entries(config.hosts).forEach(([hostname, hostCfg]) => {
                const hostStats = stats && stats[hostname] ? stats[hostname] : {};

                addNode(hostname, hostname, "host", "ok", { hostname: hostname });
                links.push({ source: rootId, target: hostname });

                // HTTP Routes
                if (hostCfg.routes) {
                    hostCfg.routes.forEach((route, rIdx) => {
                        const path = route.path || "/";
                        const routeId = `${hostname}|${path}`;
                        addNode(routeId, path, "route", "ok", { hostname: hostname, routeIdx: rIdx, routeType: "route" });
                        links.push({ source: hostname, target: routeId });

                        const routeStats = hostStats.routes ? hostStats.routes[rIdx] : {};
                        const backendStats = routeStats.backends ||[];

                        if (route.backends && route.backends.servers) {
                            route.backends.servers.forEach((srv, bIdx) => {
                                const beUrl = srv.address || srv.url;
                                if (beUrl) {
                                    const beId = `${routeId}|${beUrl}`;
                                    const displayUrl = beUrl.replace(/^https?:\/\//, '');

                                    let status = 'unverified';
                                    if(backendStats[bIdx]) {
                                        const bStat = backendStats[bIdx];
                                        const hStat = bStat.health?.status || 'Unknown';

                                        if (bStat.alive === false || hStat === 'Dead' || hStat === 'Unhealthy') {
                                            status = 'dead';
                                        } else if (hStat === 'Degraded') {
                                            status = 'degraded';
                                        } else if (hStat === 'Healthy') {
                                            status = 'ok';
                                        } else {
                                            status = bStat.alive ? 'unverified' : 'dead';
                                        }
                                    }

                                    addNode(beId, displayUrl, "backend", status, { hostname: hostname, routeIdx: rIdx, backendIdx: bIdx, routeType: "route" });
                                    links.push({ source: routeId, target: beId });
                                }
                            });
                        }
                    });
                }

                // TCP Proxies
                if (hostCfg.proxies) {
                    hostCfg.proxies.forEach((proxy, pIdx) => {
                        const name = proxy.name || proxy.listen;
                        const proxyId = `${hostname}|tcp|${name}`;
                        addNode(proxyId, `TCP:${name}`, "route", "ok", { hostname: hostname, routeIdx: pIdx, routeType: "proxy" });
                        links.push({ source: hostname, target: proxyId });

                        const proxyStats = hostStats.proxies ? hostStats.proxies[pIdx] : {};
                        const backendStats = proxyStats.backends ||[];

                        if(proxy.backends) {
                            proxy.backends.forEach((srv, bIdx) => {
                                const beUrl = srv.address;
                                const beId = `${proxyId}|${beUrl}`;

                                let status = 'unverified';
                                if(backendStats[bIdx]) {
                                    const bStat = backendStats[bIdx];
                                    const hStat = bStat.health?.status || 'Unknown';

                                    if (bStat.alive === false || hStat === 'Dead' || hStat === 'Unhealthy') {
                                        status = 'dead';
                                    } else if (hStat === 'Degraded') {
                                        status = 'degraded';
                                    } else if (hStat === 'Healthy') {
                                        status = 'ok';
                                    } else {
                                        status = bStat.alive ? 'unverified' : 'dead';
                                    }
                                }

                                addNode(beId, beUrl, "backend", status, { hostname: hostname, routeIdx: pIdx, backendIdx: bIdx, routeType: "proxy" });
                                links.push({ source: proxyId, target: beId });
                            });
                        }
                    });
                }
            });
        }

        return { nodes, links };
    }

    getNodeColor(type) {
        switch (type) {
            case "root": return "var(--fg)";
            case "host": return "var(--accent)";
            case "route": return "var(--success)";
            case "backend": return "var(--text-mute)";
            default: return "#999";
        }
    }

    getNodeStroke(status) {
        switch(status) {
            case "dead": return "var(--danger)";
            case "degraded": return "var(--warning)";
            case "unverified": return "var(--info)";
            default: return "#fff";
        }
    }

    getNodeRadius(type) {
        switch (type) {
            case "root": return 12;
            case "host": return 8;
            case "route": return 6;
            case "backend": return 4;
            default: return 5;
        }
    }

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