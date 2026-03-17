const UI = {
    updateVersionDisplay(version) {
        const el = document.getElementById("versionDisplay");
        if (el) el.innerText = version || "v—";
    },

    updateMetrics(metrics, series) {
        this.updateSystemMetrics(metrics.system);
        this.updateFooterStats(metrics.stats);
        this.updateCertificateCounts(metrics.certificates);
        this.updateLastUpdated(metrics.lastUpdateTime);
        this.renderHealthBar(metrics.stats.total_reqs, metrics.stats.total_errors);
        this.renderGraph(series);
    },

    updateSystemMetrics(system) {
        if (!system) return;

        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerText = value;
        };

        setText("sysCpu", system.cpu_percent !== undefined ? `${system.cpu_percent.toFixed(1)}%` : `${system.num_goroutine || 0} GRs`);
        setText("sysMem", this.formatBytes(system.mem_rss || 0));
        setText("sysCpuCores", system.num_cpu || '—');
        setText("sysGoroutines", system.num_goroutine || '—');
        setText("sysMemAlloc", this.formatBytes(system.mem_alloc || 0));
        setText("sysMemUsed", this.formatBytes(system.mem_used || 0));
        setText("sysMemTotalOs", this.formatBytes(system.mem_total_os || 0));
    },

    updateFooterStats(stats) {
        const setText = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerText = value;
        };

        setText("totalReqsStat", this.fmtNum(stats.total_reqs));
        setText("errorsStat", this.fmtNum(stats.total_errors));
        setText("meanResponseStat", stats.avg_ms ? stats.avg_ms.toFixed(0) + "ms" : "0ms");
        setText("activeBackendsStat", stats.active_backends || 0);
        setText("apdexStat", stats.apdex || "1.0");
        setText("uptimeStat", stats.uptime || "100%");

        // Add RPS display - THIS IS THE KEY FIX
        const rps = stats.rps !== undefined ? stats.rps.toFixed(1) : "0.0";
        setText("rpsStat", rps);

        const errorRate = stats.total_reqs > 0 ? ((stats.total_errors / stats.total_reqs) * 100).toFixed(1) : 0;
        setText("errorRateText", `${errorRate}% errors`);
    },

    updateCertificateCounts(certificates) {
        const activeCerts = certificates.filter(c => c.daysLeft > 0).length;
        const expiringCerts = certificates.filter(c => c.daysLeft > 0 && c.daysLeft < 7).length;

        document.getElementById("activeCertsCount").innerText = activeCerts;
        document.getElementById("expiringCertsCount").innerText = expiringCerts;
    },

    updateHeroCounts(hostCount, routeCount) {
        document.getElementById("heroHostCount").innerText = hostCount;
        document.getElementById("heroRouteCount").innerText = routeCount;
    },

    renderConfigMetrics(metrics) {
        const setMetric = (id, value) => {
            const el = document.getElementById(id);
            if (el) el.innerText = value;
        };

        setMetric('configHttpPort', metrics.httpPort);
        setMetric('configHttpsPort', metrics.httpsPort);
        setMetric('configVersion', metrics.version);
        setMetric('configHostCount', this.fmtNum(metrics.hostCount));
        setMetric('configRouteCount', this.fmtNum(metrics.routeCount));
        setMetric('configTlsCount', this.fmtNum(metrics.tlsCount));
        setMetric('configLogLevel', metrics.logLevel ? metrics.logLevel.toUpperCase() : 'INFO');
    },

    updateLastUpdated(timestamp) {
        if (!timestamp) return;
        const seconds = Math.floor((Date.now() - timestamp) / 1000);
        let text = 'just now';
        if (seconds >= 10) text = seconds < 60 ? `${seconds}s ago` : `${Math.floor(seconds / 60)}m ago`;

        const el = document.getElementById("lastUpdatedText");
        if (el) el.innerText = `Updated ${text}`;
    },

    updateStaleState(isStale) {
        const footer = document.querySelector(".stats-footer");
        if (footer) {
            if (isStale) footer.classList.add("stale");
            else footer.classList.remove("stale");
        }
    },

    renderHealthBar(total, errors) {
        const bar = document.getElementById("globalHealthBar");
        if (!bar || total === 0) return;

        const errPct = (errors / total) * 100;
        const okPct = 100 - errPct;
        bar.innerHTML = `
            <div class="hb-seg hb-ok" style="width: ${okPct}%"></div>
            <div class="hb-seg hb-err" style="width: ${errPct}%"></div>
        `;
    },

    renderGlobalSettings(global) {
        const container = document.getElementById('configGlobalDetails');
        if (!container) return;

        if (!global) {
            container.innerHTML = '<div class="empty-state">No global settings</div>';
            return;
        }

        const trustedProxies = global.security?.trusted_proxies || [];
        const settings = [
            {label: 'Environment', value: global.development ? 'development' : 'production'},
            {label: 'Admin Email', value: global.lets_encrypt?.email || '—'},
            {
                label: 'Max Header Size',
                value: global.general?.max_header_bytes ? this.formatBytes(global.general.max_header_bytes) : '—'
            },
            {label: 'Trusted Proxies', value: trustedProxies.length > 0 ? trustedProxies.join(', ') : 'none'}
        ];

        container.innerHTML = settings.map(setting => `
            <div class="config-detail-item">
                <div class="config-detail-label">${setting.label}</div>
                <div class="config-detail-value">${setting.value}</div>
            </div>
        `).join('');
    },

    renderClusterSettings(cluster) {
        const container = document.getElementById('configClusterDetails');
        if (!container) return;

        if (!cluster || !cluster.members || cluster.members.length === 0) {
            container.innerHTML = '<div class="empty-state">Cluster not active</div>';
            return;
        }

        let html = `
            <div class="config-detail-item">
                <div class="config-detail-label">Status</div>
                <div class="config-detail-value"><span class="badge success">Active</span></div>
            </div>
            <div class="config-detail-item">
                <div class="config-detail-label">Members</div>
                <div class="config-detail-value">${cluster.members.length} nodes</div>
            </div>
        `;

        cluster.members.forEach(member => {
            html += `
            <div class="config-detail-item">
                <div class="config-detail-label">Node</div>
                <div class="config-detail-value">${member}</div>
            </div>`;
        });

        container.innerHTML = html;
    },

    renderClusterPage(config, stats) {
        const grid = document.getElementById('clusterMetricsGrid');
        const table = document.getElementById('clusterNodesTable');
        if (!grid || !table) return;

        if (!stats || !stats.enabled) {
            grid.innerHTML = '<div class="empty-state" style="grid-column: 1 / -1;">Cluster mode is disabled</div>';
            table.innerHTML = '';
            return;
        }

        const members = stats.members || [];
        const metrics = stats.metrics || {};

        grid.innerHTML = `
            <div class="metric-card">
                <div class="metric-content">
                    <div class="metric-label">Active Nodes</div>
                    <div class="metric-value">${members.length}</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-content">
                    <div class="metric-label">Updates Received</div>
                    <div class="metric-value">${this.fmtNum(metrics.updates_received || 0)}</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-content">
                    <div class="metric-label">Total Deletes</div>
                    <div class="metric-value">${this.fmtNum(metrics.deletes || 0)}</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-content">
                    <div class="metric-label">Ignored Updates</div>
                    <div class="metric-value">${this.fmtNum(metrics.updates_ignored || 0)}</div>
                </div>
            </div>
        `;

        if (members.length === 0) {
            table.innerHTML = `<tr><td colspan="2"><div class="empty-state">No active nodes found</div></td></tr>`;
        } else {
            table.innerHTML = members.map(m => `
                <tr>
                    <td class="mono">${m}</td>
                    <td><span class="badge success">Active</span></td>
                </tr>
            `).join("");
        }
    },

    renderRawConfig(config) {
        const el = document.getElementById("configContent");
        if (el) {
            el.innerText = JSON.stringify(config, null, 2);
        }
    },

    renderGraph(series) {
        const el = document.getElementById("responseGraph");
        if (!el) return;

        const h = el.clientHeight || 200;
        const pTop = 15;
        const drawH = h - 30;

        if (!series || series.length === 0) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">⚡ Waiting for metrics...</div>`;
            return;
        }

        const max = Math.max(10, ...series) * 1.1;
        const bars = series.map((val, i) => {
            const barH = Math.max(2, (val / max) * drawH);
            const x = (i / 60) * 100;
            const width = (100 / 60) - 0.3;
            let color = "var(--chart-bar-fill)";
            if (val > 200) color = "var(--warning)";
            if (val > 500) color = "var(--danger)";
            const y = (pTop + drawH) - barH;
            return `<rect x="${x}%" y="${y}" width="${width}%" height="${barH}" fill="${color}" rx="1"></rect>`;
        }).join("");

        el.innerHTML = `<svg width="100%" height="100%">
            <text x="0" y="10" fill="var(--text-mute)" font-size="10" font-family="monospace">${max.toFixed(0)}ms</text>
            <line x1="0" y1="${pTop}" x2="100%" y2="${pTop}" stroke="var(--border)" stroke-dasharray="4 4" stroke-width="1" />
            ${bars}
        </svg>`;
    },

    renderHosts(hostsData, filterTerm, certificates) {
        const container = document.getElementById("hostsContainer");
        if (!container) return;

        const hosts = hostsData.config || {};
        const stats = hostsData.stats || {};

        filterTerm = filterTerm ? filterTerm.toLowerCase() : "";
        let html = "";
        let hostCount = 0, routeCount = 0;

        if (Object.keys(hosts).length === 0) {
            container.innerHTML = `<div class="empty-state">
                <span>🔮 No hosts configured</span>
                <span>Add a host in agbero.hcl and restart</span>
            </div>`;
            return;
        }

        for (const [hostname, cfg] of Object.entries(hosts)) {
            const domainsStr = (cfg.domains || []).join(" ");
            const matchesHost = hostname.toLowerCase().includes(filterTerm) || domainsStr.toLowerCase().includes(filterTerm);

            let hostHtml = "";
            let hostHasMatch = matchesHost;

            hostCount++;
            const rtStats = stats[hostname] || {};

            let tlsMode = cfg.tls?.mode || "";
            let tlsText = "Auto (Secure)";
            let tlsClass = "success";
            let tlsTitle = "Managed by Agbero";

            if (tlsMode === "none") {
                tlsClass = "error";
                tlsText = "No TLS";
            } else if (tlsMode && tlsMode.includes("local")) {
                tlsClass = "warning";
                tlsText = "Local TLS";
            }

            const hostCert = certificates.find(c => c.host === hostname);
            if (hostCert && hostCert.daysLeft !== undefined) {
                tlsTitle = `Expires: ${new Date(hostCert.expiry).toLocaleDateString()} (${hostCert.daysLeft} days)`;
                if (hostCert.daysLeft < 7) {
                    tlsClass = hostCert.daysLeft < 0 ? "error" : "warning";
                    tlsText = hostCert.daysLeft < 0 ? "Expired" : `Expires in ${hostCert.daysLeft}d`;
                }
            }

            hostHtml += `
        <div class="host-row" data-hostname="${hostname}">
            <div class="host-header">
                <div>
                    <div class="host-name">${hostname}
                        <span class="badge ${tlsClass}" title="${tlsTitle}">${tlsText}</span>${rtStats.total_reqs ? `<span class="badge" style="background:var(--hover-bg);color:var(--text-mute);border:1px solid var(--border);">${this.fmtNum(rtStats.total_reqs)} reqs</span>` : ''}
                    </div>
                    ${cfg.domains?.length && cfg.domains.join(", ") !== hostname ? `<div class="host-meta">${cfg.domains.join(", ")}</div>` : ''}
                </div>
                <span class="host-perf-hint">Performance &nearr;</span>
            </div>`;

            if (cfg.routes && Array.isArray(cfg.routes)) {
                cfg.routes.forEach((route, idx) => {
                    routeCount++;
                    const pathMatches = route.path ? route.path.toLowerCase().includes(filterTerm) : false;
                    const routeStats = (rtStats.routes && rtStats.routes[idx]) || {};

                    let backendHtml = "";
                    const configBackends = route.backends?.servers || [];
                    const uptimeBackends = routeStats.backends || [];

                    if (configBackends.length > 0 || uptimeBackends.length > 0) {
                        const displayBackends = uptimeBackends.length > 0 ? uptimeBackends : configBackends;
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            const configBackend = configBackends[bIdx] || {};
                            const url = b.address || b.url || configBackend.address || configBackend.url || '';
                            const weight = configBackend.weight !== undefined ? configBackend.weight : (b.weight || '-');

                            let healthStatus = 'unknown';
                            let dotColor = 'warn';
                            let title = 'No data';
                            const hasStats = uptimeBackends[bIdx] !== undefined;

                            if (hasStats) {
                                const isAlive = b.alive;
                                const hStat = b.health?.status || 'Unknown';

                                if (isAlive === false || hStat === 'Dead' || hStat === 'Unhealthy') {
                                    healthStatus = 'down';
                                    dotColor = 'down';
                                    title = hStat !== 'Unknown' ? hStat : 'Dead';
                                } else if (hStat === 'Degraded') {
                                    healthStatus = 'degraded';
                                    dotColor = 'warn';
                                    title = 'Degraded';
                                } else if (hStat === 'Healthy') {
                                    healthStatus = 'ok';
                                    dotColor = 'ok';
                                    title = 'Healthy';
                                } else {
                                    healthStatus = isAlive ? 'unverified' : 'down';
                                    dotColor = isAlive ? 'info' : 'down';
                                    title = isAlive ? 'Unverified (Active)' : 'Dead';
                                }
                            }

                            if (url && url.toLowerCase().includes(filterTerm)) hostHasMatch = true;

                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;
                            const in_flight = b.in_flight || 0;

                            backendHtml += `
                            <div class="backend-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                                <span class="dot ${dotColor}" title="${title}"></span>
                                <span class="be-url copyable" data-action="copy-url" data-url="${url}">${url} ${in_flight > 0 ? `<span class="badge warn">⚡${in_flight}</span>` : ''}</span>
                                <span class="be-stat">W: ${weight}</span>
                                <span class="be-stat">${p99}</span>
                                <span class="be-stat">${this.fmtNum(reqs)}</span>
                            </div>`;
                        });
                        backendHtml += `</div>`;
                    } else if (route.web && (route.web.root || (route.web.git && route.web.git.enabled === "on" || route.web.git.enabled === true))) {
                        if (route.web.git && (route.web.git.enabled === "on" || route.web.git.enabled === true)) {
                            const gitId = route.web.git.id || "unknown";
                            const gitStat = window.app.gitStats[gitId] || {};
                            const stateClass = gitStat.state === 'healthy' ? 'ok' : (gitStat.state === 'unavailable' ? 'warn' : 'down');
                            backendHtml = `<div class="backend-row"><span class="dot ${stateClass}"></span> <span>🐙 Git: ${gitId}</span></div>`;
                            if (gitId.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                        } else {
                            backendHtml = `<div class="backend-row"><span class="dot ok"></span> <span>📂 ${route.web.root}</span></div>`;
                            if (route.web.root && route.web.root.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                        }
                    }

                    const shouldShowRoute = filterTerm === "" || hostHasMatch || pathMatches;
                    const protocolBadgeClass = (route.protocol || 'http') === 'http' ? 'success' : 'info';
                    const protocolBadge = `<span class="badge ${protocolBadgeClass}">${(route.protocol || 'HTTP').toUpperCase()}</span>`;

                    if (shouldShowRoute) {
                        hostHtml += `
                        <div class="route-block clickable" data-action="open-route" data-host="${hostname}" data-idx="${idx}" data-type="route">
                            <div class="route-header">
                               ${protocolBadge} <span class="route-path">${route.path || '/'}</span>
                                <span class="badge info" style="margin-left:auto; font-size:9px;">DETAILS →</span>
                            </div>
                            ${backendHtml}
                        </div>`;
                    }
                });
            }

            if (cfg.proxies && Array.isArray(cfg.proxies)) {
                cfg.proxies.forEach((proxy, pidx) => {
                    routeCount++;
                    const path = proxy.name ? proxy.name.replace('*default*', '* (TCP)') : (proxy.path || proxy.protocol || "*");
                    const pathMatches = path.toLowerCase().includes(filterTerm);
                    const proxyStats = (rtStats.proxies && rtStats.proxies[pidx]) || {};

                    let backendHtml = "";
                    const configBackends = proxy.backends || [];
                    const uptimeBackends = proxyStats.backends || [];

                    if (configBackends.length > 0 || uptimeBackends.length > 0) {
                        const displayBackends = uptimeBackends.length > 0 ? uptimeBackends : configBackends;
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            const configBackend = configBackends[bIdx] || {};
                            const url = b.address || b.url || configBackend.address || configBackend.url || '';
                            const weight = configBackend.weight !== undefined ? configBackend.weight : (b.weight || '-');

                            let healthStatus = 'unknown';
                            let dotColor = 'warn';
                            let title = 'No data';
                            const hasStats = uptimeBackends[bIdx] !== undefined;

                            if (hasStats) {
                                const isAlive = b.alive;
                                const hStat = b.health?.status || 'Unknown';

                                if (isAlive === false || hStat === 'Dead' || hStat === 'Unhealthy') {
                                    healthStatus = 'down';
                                    dotColor = 'down';
                                    title = hStat !== 'Unknown' ? hStat : 'Dead';
                                } else if (hStat === 'Degraded') {
                                    healthStatus = 'degraded';
                                    dotColor = 'warn';
                                    title = 'Degraded';
                                } else if (hStat === 'Healthy') {
                                    healthStatus = 'ok';
                                    dotColor = 'ok';
                                    title = 'Healthy';
                                } else {
                                    healthStatus = isAlive ? 'unverified' : 'down';
                                    dotColor = isAlive ? 'info' : 'down';
                                    title = isAlive ? 'Unverified (Active)' : 'Dead';
                                }
                            }

                            if (url && url.toLowerCase().includes(filterTerm)) hostHasMatch = true;

                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;
                            const in_flight = b.in_flight || 0;

                            backendHtml += `
                            <div class="backend-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                                <span class="dot ${dotColor}" title="${title}"></span>
                                <span class="be-url copyable" data-action="copy-url" data-url="${url}">${url} ${in_flight > 0 ? `<span class="badge warn">⚡${in_flight}</span>` : ''}</span>
                                <span class="be-stat">W: ${weight}</span>
                                <span class="be-stat">${p99}</span>
                                <span class="be-stat">${this.fmtNum(reqs)}</span>
                            </div>`;
                        });
                        backendHtml += `</div>`;
                    }

                    const shouldShowRoute = filterTerm === "" || hostHasMatch || pathMatches;
                    const protocolBadgeClass = (proxy.protocol || 'tcp') === 'http' ? 'success' : 'info';
                    const protocolBadge = `<span class="badge ${protocolBadgeClass}">${(proxy.protocol || 'TCP').toUpperCase()}</span>`;

                    if (shouldShowRoute) {
                        hostHtml += `
                        <div class="route-block clickable" data-action="open-route" data-host="${hostname}" data-idx="${pidx}" data-type="proxy">
                            <div class="route-header">
                               ${protocolBadge} <span class="route-path">${path}</span>
                                <span class="badge info" style="margin-left:auto; font-size:9px;">DETAILS →</span>
                            </div>
                            ${backendHtml}
                        </div>`;
                    }
                });
            }
            hostHtml += `</div>`;

            if (hostHasMatch || filterTerm === "") {
                html += hostHtml;
            }
        }

        container.innerHTML = html || `<div class="empty-state">
            <span>🔍 No hosts found matching "${filterTerm}"</span>
            <span>Try a different search term</span>
        </div>`;

        container.querySelectorAll(".host-header").forEach(el => {
            el.addEventListener("click", e => {
                if (e.target.closest(".badge")) return;
                const hostname = el.closest(".host-row")?.dataset?.hostname;
                if (hostname && window.app) window.app.openPerformanceModal(hostname);
            });
        });

        document.getElementById("heroHostCount").innerText = hostCount;
        document.getElementById("heroRouteCount").innerText = routeCount;
    },

    renderFirewall(data) {
        const tbody = document.getElementById("firewallTable");
        if (!tbody) return;

        if (!data) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">⚠️ Firewall unavailable</div></td></tr>`;
            return;
        }

        if (data.enabled === false) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">
                <span>🛡️ Firewall disabled</span>
                <span>Enable in agbero.hcl to block IPs</span>
            </div></td></tr>`;
            return;
        }

        const rules = data.rules || [];
        if (rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">
                <span>✅ No blocked IPs</span>
                <span>All traffic is allowed</span>
            </div></td></tr>`;
            return;
        }

        tbody.innerHTML = rules.map(r => {
            const created = r.created_at ? new Date(r.created_at) : new Date();
            const createdStr = !isNaN(created.getTime()) ? created.toLocaleDateString() : 'N/A';

            return `<tr>
                <td class="mono">${r.ip || '0.0.0.0'}</td>
                <td>${r.reason || '-'}</td>
                <td class="hide-mobile">${r.host || '*'} / ${r.path || '*'}</td>
                <td class="hide-mobile">${createdStr}</td>
                <td><button class="btn small error" data-action="unblock-ip" data-ip="${r.ip || ''}">Unblock</button></td>
            </tr>`;
        }).join("");
    },
    
    renderLogs(logs, filter) {
        const container = document.getElementById("logsList");
        if (!container) return;

        if (!logs || logs.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute); text-align:center; padding:40px;">
            <span style="display:block; font-size:24px; margin-bottom:10px;">📭</span>
            No logs yet. Waiting for traffic...
        </div>`;
            return;
        }

        const filtered = logs.filter(l => {
            if (filter === "ALL") return true;
            let lvl = "INFO";
            if (typeof l === 'object' && l !== null) lvl = l.lvl || l.level || "INFO";
            else if (typeof l === 'string') {
                if (l.includes('"lvl":"ERROR"') || l.includes('ERROR')) lvl = "ERROR";
                else if (l.includes('"lvl":"WARN"') || l.includes('WARN')) lvl = "WARN";
            }
            return lvl === filter;
        });

        if (filtered.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute);text-align:center; padding:20px;">No logs for filter: ${filter}</div>`;
            return;
        }

        container.innerHTML = filtered.map(l => {
            let lvl = "INFO", msg = "", ts = "", fields = {};
            let duration = "", method = "", path = "", status = "", remote = "";

            if (typeof l === 'string') {
                try {
                    const parsed = JSON.parse(l);
                    lvl = parsed.lvl || parsed.level || "INFO";
                    msg = parsed.msg || parsed.message || l;
                    ts = parsed.ts || parsed.time || "";
                    fields = parsed.fields || {};
                } catch {
                    msg = l;
                }
            } else if (typeof l === 'object' && l !== null) {
                lvl = l.lvl || l.level || "INFO";
                msg = l.msg || l.message || "";
                ts = l.ts || l.time || "";
                fields = l.fields || {};
            }

            // Format timestamp to show only time if it's ISO
            if (ts) {
                if (ts.includes('T')) {
                    ts = ts.split('T')[1]?.split('.')[0] || ts;
                }
            }

            // Extract fields for display
            if (fields.method) method = fields.method;
            if (fields.path) path = fields.path;
            if (fields.status) status = fields.status;
            if (fields.remote) remote = fields.remote;
            if (fields.duration) {
                const ms = (fields.duration / 1000000).toFixed(2);
                duration = `${ms}ms`;
            }
            if (fields.bytes) {
                const bytes = fields.bytes > 1024 ? `${(fields.bytes / 1024).toFixed(1)}KB` : `${fields.bytes}B`;
            }

            // Build the message with fields
            let fullMsg = msg;
            if (method && path) fullMsg += ` ${method} ${path}`;
            if (status) fullMsg += ` [${status}]`;
            if (duration) fullMsg += ` (${duration})`;
            if (remote) fullMsg += ` from ${remote}`;

            let color = "#aaa";
            if (lvl === "ERROR") color = "var(--danger)";
            if (lvl === "WARN") color = "var(--warning)";

            return `<div class="log-entry">
            <div class="log-ts">${ts}</div>
            <div class="log-lvl" style="color:${color}">${lvl}</div>
            <div class="log-msg" title="${JSON.stringify(fields)}">${fullMsg}</div>
        </div>`;
        }).join("");
    },

    renderDrawer(hostname, cfg_item, itemStats, type, certificates, routeIdx) {
        const path = cfg_item.path || (cfg_item.name ? cfg_item.name.replace('*default*', '* (TCP)') : cfg_item.protocol || "*");
        document.getElementById("drawerRoutePath").innerText = path;
        document.getElementById("drawerHostName").innerText = hostname;

        const content = document.getElementById("drawerBody");
        if (!content) return;
        content.innerHTML = "";

        const isTCPRoute = type === 'proxy' || cfg_item.protocol === 'tcp' || (cfg_item.listen && !cfg_item.listen.includes('http'));
        const protocolType = isTCPRoute ? 'TCP' : 'HTTP';
        const protocolIcon = isTCPRoute ? '🔌' : '🌐';
        const protocolClass = isTCPRoute ? 'info' : 'success';

        if (!isTCPRoute && cfg_item.web) {
            if (cfg_item.web.git && (cfg_item.web.git.enabled === "on" || cfg_item.web.git.enabled === true)) {
                const gitCfg = cfg_item.web.git;
                const gStat = window.app.gitStats[gitCfg.id] || {};
                const state = gStat.state || 'unknown';
                const commit = gStat.commit ? gStat.commit.substring(0, 8) : 'none';
                const whUrl = `${window.location.origin}/.well-known/agbero/webhook/git/${gitCfg.id}`;

                let stateClass = state === 'healthy' ? 'success' : (state === 'unavailable' ? 'warning' : 'error');

                content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">🐙 Git Deployment</div>
                    <div class="handler-card">
                        <span class="handler-icon">📦</span>
                        <div class="handler-info" style="flex:1;">
                            <strong>${gitCfg.id}</strong>
                            <span>Branch: ${gitCfg.branch || 'main'}</span>
                            <div style="margin-top:8px; display:flex; gap:10px; align-items:center;">
                                <span class="badge ${stateClass}">State: ${state}</span>
                                <span class="badge info">Commit: ${commit}</span>
                                <span class="badge">Deploys: ${gStat.deployments || 0}</span>
                            </div>
                        </div>
                    </div>
                    <div class="kv-grid" style="margin-top:10px;">
                        <div class="kv-item" style="grid-column: span 2;">
                            <label>Webhook URL</label>
                            <div style="display:flex; gap:10px; align-items:center;">
                                <span class="mono" style="font-size:10px; padding:6px; background:var(--bg); border:1px solid var(--border); border-radius:4px; flex:1; overflow-x:auto;">${whUrl}</span>
                                <button class="btn small" data-action="copy-url" data-url="${whUrl}">Copy</button>
                            </div>
                        </div>
                    </div>
                </div>`;
            } else if (cfg_item.web.root) {
                let webHtml = `
                <div class="detail-section">
                    <div class="detail-title">📂 Static File Handler</div>
                    <div class="handler-card">
                        <span class="handler-icon">📁</span>
                        <div class="handler-info">
                            <strong>File Server</strong>
                            <span>Root: ${cfg_item.web.root}</span>
                            <span>Listing: ${cfg_item.web.listing ? 'Enabled' : 'Disabled'}</span>
                        </div>
                    </div>
                </div>`;

                if (cfg_item.web.php && cfg_item.web.php.enabled && cfg_item.web.php.enabled === "on") {
                    webHtml += `
                    <div class="detail-section">
                        <div class="detail-title">🐘 PHP Handler</div>
                        <div class="handler-card">
                            <span class="handler-icon">⚙️</span>
                            <div class="handler-info">
                                <strong>FastCGI Proxy</strong>
                                <span>Address: ${cfg_item.web.php.address || '127.0.0.1:9000'}</span>
                                <span>Index: ${cfg_item.web.php.index || 'index.php'}</span>
                            </div>
                        </div>
                    </div>`;
                }
                content.innerHTML += webHtml;
            }
        }

        const configBackends = cfg_item.backends?.servers || cfg_item.backends || [];
        const statBackends = (itemStats && itemStats.backends) || [];
        const displayBackends = configBackends.length > 0 ? configBackends : statBackends;

        if (displayBackends.length > 0) {
            let backendsHtml = "";

            displayBackends.forEach((b, bIdx) => {
                const backendStats = statBackends[bIdx] || {};
                const url = b.address || b.url || backendStats.address || backendStats.url || '';
                const weight = (b.weight !== undefined) ? b.weight : (backendStats.weight || '-');

                let healthStatus = 'unknown';
                let dotColor = 'warn';
                let title = 'No data';
                const hasStats = statBackends[bIdx] !== undefined;

                if (hasStats) {
                    const isAlive = backendStats.alive;
                    const hStat = backendStats.health?.status || 'Unknown';

                    if (isAlive === false || hStat === 'Dead' || hStat === 'Unhealthy') {
                        healthStatus = 'down';
                        dotColor = 'down';
                        title = hStat !== 'Unknown' ? hStat : 'Dead';
                    } else if (hStat === 'Degraded') {
                        healthStatus = 'degraded';
                        dotColor = 'warn';
                        title = 'Degraded';
                    } else if (hStat === 'Healthy') {
                        healthStatus = 'ok';
                        dotColor = 'ok';
                        title = 'Healthy';
                    } else {
                        healthStatus = isAlive ? 'unverified' : 'down';
                        dotColor = isAlive ? 'info' : 'down';
                        title = isAlive ? 'Unverified (Active)' : 'Dead';
                    }
                }

                const p99 = backendStats.latency_us?.p99 ? (backendStats.latency_us.p99 / 1000).toFixed(0) + "ms" : "";
                const in_flight = backendStats.in_flight || 0;
                const failures = backendStats.failures || 0;
                const total_reqs = backendStats.total_reqs || 0;

                backendsHtml += `
                <div class="drawer-row clickable" data-action="open-backend" data-host="${hostname}" data-route-idx="${routeIdx}" data-backend-idx="${bIdx}" data-type="${type}">
                    <div class="row-left">
                        <span class="dot ${dotColor}" title="${title}"></span>
                        <span class="mono">${url}</span>
                        ${in_flight > 0 ? `<span class="badge info">⚡ ${in_flight} in flight</span>` : ''}
                        ${failures > 0 ? `<span class="badge error">⚠️ ${failures} failures</span>` : ''}
                    </div>
                    <div class="row-right">
                        ${p99 ? `<span class="badge info">p99: ${p99}</span>` : ''}
                        <span class="badge ${healthStatus === 'ok' ? 'success' : healthStatus === 'warn' ? 'warning' : 'error'}">W: ${weight}</span>
                        <span class="badge" style="background: var(--text-mute);">${window.app.fmtNum(total_reqs)} reqs</span>
                    </div>
                </div>`;
            });

            const lbStrategy = cfg_item.backends?.strategy || cfg_item.backends?.load_balancing?.strategy || cfg_item.strategy || "round_robin";
            const strategyDisplay = lbStrategy.split('_').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');

            let tcpDetailsHtml = '';
            if (isTCPRoute) {
                if (cfg_item.listen) {
                    tcpDetailsHtml += `<div class="kv-item"><label>Listen</label><div><span class="badge info">${cfg_item.listen}</span></div></div>`;
                }
                if (cfg_item.sni) {
                    tcpDetailsHtml += `<div class="kv-item"><label>SNI</label><div><span class="badge info">${cfg_item.sni}</span></div></div>`;
                }
                if (cfg_item.proxy_protocol) {
                    tcpDetailsHtml += `<div class="kv-item"><label>Proxy Protocol</label><div><span class="badge success">Enabled</span></div></div>`;
                }
                if (cfg_item.max_connections > 0) {
                    tcpDetailsHtml += `<div class="kv-item"><label>Max Connections</label><div><span class="badge info">${cfg_item.max_connections}</span></div></div>`;
                }
            }

            const healthCheck = cfg_item.health_check || cfg_item.backends?.health_check;
            let healthCheckHtml = '<div class="kv-item"><label>Health Check</label><div><span class="badge error">Not Configured</span></div></div>';
            if (healthCheck && healthCheck.enabled && healthCheck.enabled === "on") {
                if (isTCPRoute && healthCheck.send) {
                    healthCheckHtml = `<div class="kv-item"><label>Health Check</label><div><span class="badge success">Send: ${healthCheck.send} | Expect: ${healthCheck.expect || 'connection'}</span></div></div>`;
                } else {
                    const hcPath = healthCheck.path || '/health';
                    const hcInterval = healthCheck.interval ? (healthCheck.interval / 1000000000) + 's' : '30s';
                    const hcTimeout = healthCheck.timeout ? (healthCheck.timeout / 1000000000) + 's' : '5s';
                    healthCheckHtml = `<div class="kv-item"><label>Health Check</label><div><span class="badge success">${hcPath} | ${hcInterval} | ${hcTimeout}</span></div></div>`;
                }
            }

            let cbHtml = '';
            const cb = cfg_item.circuit_breaker || cfg_item.backends?.circuit_breaker;
            if (cb && cb.enabled && cb.enabled === "on") {
                const firstBackendStats = statBackends[0] || {};
                const cbStatus = firstBackendStats.circuit_breaker_state || 'closed';
                const cbClass = cbStatus === 'closed' ? 'success' : (cbStatus === 'open' ? 'error' : 'warning');
                cbHtml = `<div class="kv-item"><label>Circuit Breaker</label><div><span class="badge ${cbClass}">${cbStatus} | ${cb.threshold || 5} fails</span></div></div>`;
            }

            const timeouts = cfg_item.timeouts || {};
            const readTimeout = timeouts.read ? (timeouts.read / 1000000000) + 's' : 'inherit';
            const writeTimeout = timeouts.write ? (timeouts.write / 1000000000) + 's' : 'inherit';
            const idleTimeout = timeouts.idle ? (timeouts.idle / 1000000000) + 's' : 'inherit';

            let upstreamsHtml = `
            <div class="detail-section">
                <div class="detail-title">
                    <span class="badge ${protocolClass}" style="margin-right: 8px;">${protocolIcon} ${protocolType}</span>
                    Upstreams & Load Balancing
                </div>
                ${backendsHtml}
                <div class="kv-grid" style="margin-top:15px;">
                    <div class="kv-item"><label>Strategy</label><div><span class="badge success">${strategyDisplay}</span></div></div>
                    ${tcpDetailsHtml}
                    ${healthCheckHtml}
                    ${cbHtml}
                </div>
                <div class="kv-grid" style="margin-top:10px;">
                    <div class="kv-item"><label>Read Timeout</label><div>${readTimeout}</div></div>
                    <div class="kv-item"><label>Write Timeout</label><div>${writeTimeout}</div></div>
                    <div class="kv-item"><label>Idle Timeout</label><div>${idleTimeout}</div></div>
                </div>
            </div>`;

            content.innerHTML += upstreamsHtml;

            if (!isTCPRoute) {
                let httpFeaturesHtml = '';

                const compression = cfg_item.compression_config || {};
                if (compression.enabled && compression.enabled === "on") {
                    const algo = compression.type || 'gzip';
                    const level = compression.level || 'default';
                    httpFeaturesHtml += `<div class="kv-item"><label>Compression</label><div><span class="badge info">${algo} (lvl ${level})</span></div></div>`;
                }

                const rl = cfg_item.rate_limit;
                if (rl && rl.enabled && rl.enabled === "on") {
                    const keyType = rl.key || 'ip';
                    const rule = rl.rule || {};
                    httpFeaturesHtml += `<div class="kv-item"><label>Rate Limit</label><div><span class="badge warning">${rule.requests || rl.requests || 0} req / ${(rule.window || rl.window || 60) / 1000000000}s (${keyType})</span></div></div>`;
                }

                const wasm = cfg_item.wasm;
                if (wasm && wasm.enabled && wasm.enabled === "on") {
                    const moduleName = wasm.module ? wasm.module.split('/').pop() : 'filter.wasm';
                    const access = wasm.access ? wasm.access.join(', ') : 'none';
                    httpFeaturesHtml += `<div class="kv-item"><label>WASM Filter</label><div><span class="badge info">${moduleName} (${access})</span></div></div>`;
                }

                if (httpFeaturesHtml) {
                    content.innerHTML += `
                    <div class="detail-section">
                        <div class="detail-title">⚙️ HTTP Features</div>
                        <div class="kv-grid">
                            ${httpFeaturesHtml}
                        </div>
                    </div>`;
                }
            }
        }

        const hostCerts = certificates.filter(c => c.host === hostname);
        if (hostCerts.length > 0) {
            let certHtml = '<div class="cert-grid">';
            hostCerts.forEach(cert => {
                let certClass = 'success';
                let certText = `${cert.daysLeft}d`;
                if (cert.daysLeft < 0) {
                    certClass = 'error';
                    certText = 'Expired';
                } else if (cert.daysLeft < 7) {
                    certClass = 'warning';
                    certText = `${cert.daysLeft}d left`;
                }

                certHtml += `
                <div class="cert-card">
                    <div class="cert-domain">${cert.host}</div>
                    <div class="cert-expiry">
                        <span>${cert.issuer || 'Let\'s Encrypt'}</span>
                        <span class="badge ${certClass}">${certText}</span>
                    </div>
                    <div style="font-size:9px; color:var(--text-mute); margin-top:6px;">
                        ${new Date(cert.expiry).toLocaleDateString()}
                    </div>
                </div>`;
            });
            certHtml += '</div>';

            content.innerHTML += `
            <div class="detail-section">
                <div class="detail-title">🔐 TLS Certificates</div>
                ${certHtml}
            </div>`;
        }

        if (!isTCPRoute) {
            let authHtml = '';

            if (cfg_item.basic_auth && cfg_item.basic_auth.enabled === "on") {
                authHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Basic Auth</div>
                    <div class="mw-body">${cfg_item.basic_auth.users ? cfg_item.basic_auth.users.length + ' users' : 'Enabled'}</div>
                    <div class="mw-sub">Realm: ${cfg_item.basic_auth.realm || 'default'}</div>
                </div>`;
            }

            if (cfg_item.jwt_auth && cfg_item.jwt_auth.enabled === "on") {
                authHtml += `
                <div class="mw-card security">
                    <div class="mw-head">JWT Auth</div>
                    <div class="mw-body">${cfg_item.jwt_auth.issuer || 'No issuer'}</div>
                    <div class="mw-sub">Audience: ${cfg_item.jwt_auth.audience || 'any'}</div>
                </div>`;
            }

            if (cfg_item.oauth && cfg_item.oauth.enabled === "on") {
                authHtml += `
                <div class="mw-card security">
                    <div class="mw-head">OAuth</div>
                    <div class="mw-body">${cfg_item.oauth.provider || 'OIDC'}</div>
                    <div class="mw-sub">${cfg_item.oauth.scopes ? cfg_item.oauth.scopes.join(', ') : 'openid'}</div>
                </div>`;
            }

            if (cfg_item.forward_auth && cfg_item.forward_auth.enabled === "on") {
                authHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Forward Auth</div>
                    <div class="mw-body">${cfg_item.forward_auth.name || 'auth service'}</div>
                    <div class="mw-sub">${cfg_item.forward_auth.url || 'No URL'}</div>
                </div>`;
            }

            if (authHtml) {
                content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">🔑 Authentication</div>
                    <div class="mw-grid">
                        ${authHtml}
                    </div>
                </div>`;
            }

            if (cfg_item.headers && cfg_item.headers.enabled === "on") {
                const reqHeaders = cfg_item.headers.request || {};
                const resHeaders = cfg_item.headers.response || {};
                const headerCount = (reqHeaders.set ? Object.keys(reqHeaders.set).length : 0) +
                    (reqHeaders.add ? Object.keys(reqHeaders.add).length : 0) +
                    (reqHeaders.remove ? reqHeaders.remove.length : 0) +
                    (resHeaders.set ? Object.keys(resHeaders.set).length : 0) +
                    (resHeaders.add ? Object.keys(resHeaders.add).length : 0) +
                    (resHeaders.remove ? resHeaders.remove.length : 0);

                if (headerCount > 0) {
                    content.innerHTML += `
                    <div class="detail-section">
                        <div class="detail-title">📋 Header Rules</div>
                        <div class="handler-card">
                            <span class="handler-icon">📝</span>
                            <div class="handler-info">
                                <strong>${headerCount} Header Modifications</strong>
                                <span>Request/Response headers</span>
                            </div>
                        </div>
                    </div>`;
                }
            }
        }

        content.innerHTML += `
        <div class="detail-section">
            <div class="detail-title">📜 Source (read-only)</div>
            <div class="code-box" style="max-height: 200px;">
                <pre>${JSON.stringify(cfg_item, null, 2)}</pre>
            </div>
        </div>`;
    },

    renderBackendDrawer(hostname, cfg_item, bStat, type) {
        const url = cfg_item.address || cfg_item.url || bStat.url || "Unknown";
        document.getElementById("backendDrawerTitle").innerText = "Backend Activity";
        document.getElementById("backendDrawerUrl").innerText = url;

        const content = document.getElementById("backendDrawerBody");
        if (!content) return;

        let healthHtml = "";

        const hasHealthData = bStat.health !== undefined && bStat.health !== null;
        const isAlive = bStat.alive !== undefined ? bStat.alive : true;
        let scoreColor = 'var(--info)';
        let stateText = isAlive ? 'Unverified (Active)' : 'Dead';
        let hScore = 100;
        let consFails = 0;
        let lastSuccessHtml = 'Never';
        let lastFailHtml = 'None';
        let downtimeHtml = '';

        if (hasHealthData) {
            const h = bStat.health;
            hScore = h.score || 100;
            consFails = h.consecutive_failures || 0;

            if (h.status === 'Unknown') {
                scoreColor = 'var(--info)';
                stateText = isAlive ? 'Unverified (Active)' : 'Dead';
            } else {
                scoreColor = hScore > 80 ? 'var(--success)' : (hScore > 50 ? 'var(--warning)' : 'var(--danger)');
                stateText = h.status;
            }

            lastSuccessHtml = h.last_success ? new Date(h.last_success).toLocaleString() : 'Never';
            lastFailHtml = h.last_failure ? new Date(h.last_failure).toLocaleString() : 'None';
            downtimeHtml = h.downtime ? `<div class="kv-item"><label>Downtime</label><div><span class="badge error">${h.downtime}</span></div></div>` : "";
        }

        healthHtml = `
        <div class="detail-section">
            <div class="detail-title">🏥 Predictive Health</div>
            <div class="health-gauge">
                <div class="gauge-circle" style="background: ${scoreColor}">${hScore}</div>
                <div class="gauge-info">
                    <div class="gauge-status">${stateText}</div>
                    <div class="gauge-sub">Consecutive Fails: ${consFails}</div>
                </div>
            </div>
            <div class="kv-grid">
                <div class="kv-item"><label>Last Success</label><div>${lastSuccessHtml}</div></div>
                <div class="kv-item"><label>Last Failure</label><div>${lastFailHtml}</div></div>
                ${downtimeHtml}
            </div>
        </div>`;

        let trafficHtml = "";
        const reqs = bStat.total_reqs || 0;
        const fails = bStat.failures || 0;
        const in_flight = bStat.in_flight || 0;

        let p50 = bStat.latency_us?.p50 ? (bStat.latency_us.p50 / 1000).toFixed(1) + "ms" : "-";
        let p90 = bStat.latency_us?.p90 ? (bStat.latency_us.p90 / 1000).toFixed(1) + "ms" : "-";
        let p99 = bStat.latency_us?.p99 ? (bStat.latency_us.p99 / 1000).toFixed(1) + "ms" : "-";
        let avg = bStat.latency_us?.avg ? (bStat.latency_us.avg / 1000).toFixed(1) + "ms" : "-";

        trafficHtml = `
        <div class="detail-section">
            <div class="detail-title">📊 Traffic & Latency</div>
            <div class="kv-grid" style="margin-bottom: 15px;">
                <div class="kv-item"><label>Total Requests</label><div>${this.fmtNum(reqs)}</div></div>
                <div class="kv-item"><label>Active / In-Flight</label><div><span class="badge info">${in_flight}</span></div></div>
                <div class="kv-item"><label>Total Failures</label><div>${fails > 0 ? `<span class="badge error">${fails}</span>` : '0'}</div></div>
                <div class="kv-item"><label>Configured Weight</label><div>${cfg_item.weight || 1}</div></div>
            </div>
            
            <div class="handler-card" style="padding: 10px 15px; display: grid; grid-template-columns: repeat(4, 1fr); text-align: center; gap: 5px;">
                <div>
                    <div style="font-size:9px; color:var(--text-mute); text-transform:uppercase;">Avg</div>
                    <div style="font-size:12px; font-family:monospace; margin-top:2px; color:var(--fg);">${avg}</div>
                </div>
                <div>
                    <div style="font-size:9px; color:var(--text-mute); text-transform:uppercase;">p50</div>
                    <div style="font-size:12px; font-family:monospace; margin-top:2px; color:var(--fg);">${p50}</div>
                </div>
                <div>
                    <div style="font-size:9px; color:var(--text-mute); text-transform:uppercase;">p90</div>
                    <div style="font-size:12px; font-family:monospace; margin-top:2px; color:var(--warning);">${p90}</div>
                </div>
                <div>
                    <div style="font-size:9px; color:var(--text-mute); text-transform:uppercase;">p99</div>
                    <div style="font-size:12px; font-family:monospace; margin-top:2px; color:var(--danger);">${p99}</div>
                </div>
            </div>
        </div>`;

        let criteriaHtml = "";
        if (cfg_item.criteria && (cfg_item.criteria.source_ips || cfg_item.criteria.headers)) {
            const ips = cfg_item.criteria.source_ips ? cfg_item.criteria.source_ips.join(", ") : "Any";
            const hdrs = cfg_item.criteria.headers ? JSON.stringify(cfg_item.criteria.headers) : "None";
            criteriaHtml = `
            <div class="detail-section">
                <div class="detail-title">🎯 Routing Criteria</div>
                <div class="kv-grid">
                    <div class="kv-item"><label>Source IPs</label><div>${ips}</div></div>
                    <div class="kv-item"><label>Required Headers</label><div>${hdrs}</div></div>
                </div>
            </div>`;
        }

        content.innerHTML = healthHtml + trafficHtml + criteriaHtml + `
        <div class="detail-section">
            <div class="detail-title">📜 Backend Config</div>
            <div class="code-box" style="max-height: 150px;">
                <pre>${JSON.stringify(cfg_item, null, 2)}</pre>
            </div>
        </div>`;
    },

    showSessionWarning(timeLeft) {
        const minutes = Math.floor(timeLeft / 60000);
        const seconds = Math.floor((timeLeft % 60000) / 1000);
        const banner = document.getElementById("sessionWarning");
        const timeSpan = document.getElementById("sessionExpiryTime");
        if (banner && timeSpan) {
            timeSpan.innerText = `${minutes}m ${seconds}s`;
            banner.classList.add("active");
        }
    },

    hideSessionWarning() {
        const banner = document.getElementById("sessionWarning");
        if (banner) banner.classList.remove("active");
    },

    showConfirmDialog(title, msg) {
        document.getElementById("confirmTitle").innerText = title;
        document.getElementById("confirmText").innerText = msg;
    },

    fmtNum(n) {
        if (n === undefined || n === null) return "0";
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "k";
        return n;
    },

    formatBytes(b) {
        if (b === 0 || !b) return "0";
        const k = 1024, s = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(b) / Math.log(k));
        return parseFloat((b / Math.pow(k, i)).toFixed(1)) + s[i];
    }
};


const PerfChart = {
    render(containerId, values, timestamps, opts = {}) {
        const el = document.getElementById(containerId);
        if (!el) return;
        const W = el.clientWidth || 360;
        const H = el.clientHeight || 110;
        const P = {top: 14, right: 8, bottom: 20, left: 36};
        const iW = W - P.left - P.right;
        const iH = H - P.top - P.bottom;

        if (!values || values.length === 0) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">No data</div>`;
            return;
        }

        const unit = opts.unit ?? "";
        const color = opts.color ?? "var(--accent)";
        const isInt = opts.isInt ?? false;
        const warnAt = opts.warnAt ?? null;
        const rawMax = Math.max(...values);
        let yMax = opts.maxY !== undefined ? opts.maxY : (rawMax === 0 ? 1 : rawMax * 1.15);
        const yMin = opts.minY !== undefined ? opts.minY : 0;
        if (yMax <= yMin) yMax = yMin + 1;

        const n = values.length;
        const xS = i => P.left + (i / Math.max(n - 1, 1)) * iW;
        const yS = v => P.top + iH - ((Math.min(v, yMax) - yMin) / (yMax - yMin)) * iH;
        const pts = values.map((v, i) => `${xS(i).toFixed(1)},${yS(v).toFixed(1)}`).join(" ");
        const fX = xS(0).toFixed(1), lX = xS(n - 1).toFixed(1), bY = (P.top + iH).toFixed(1);
        const area = `M${fX},${bY} ` + values.map((v, i) => `L${xS(i).toFixed(1)},${yS(v).toFixed(1)}`).join(" ") + ` L${lX},${bY} Z`;
        const lc = (warnAt !== null && rawMax >= warnAt) ? "var(--danger)" : color;
        const fmt = v => isInt ? Math.round(v) + "" : (v >= 1000 ? (v / 1000).toFixed(1) + "k" : v < 10 ? v.toFixed(1) : v.toFixed(0));
        const ytks = [yMin, (yMin + yMax) / 2, yMax].map(v => ({y: yS(v), l: fmt(v) + unit}));
        const tL = ts => new Date(ts * 1000).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
        const xlbs = [
            {x: xS(0), l: tL(timestamps[0]), a: "start"},
            {x: xS(Math.floor((n - 1) / 2)), l: tL(timestamps[Math.floor((n - 1) / 2)]), a: "middle"},
            {x: xS(n - 1), l: tL(timestamps[n - 1]), a: "end"}
        ];
        const gid = "pg_" + containerId;

        el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
            <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stop-color="${lc}" stop-opacity="0.18"/>
                <stop offset="100%" stop-color="${lc}" stop-opacity="0.01"/>
            </linearGradient></defs>
            ${ytks.map(t => `<line x1="${P.left}" y1="${t.y.toFixed(1)}" x2="${P.left + iW}" y2="${t.y.toFixed(1)}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 3"/>`).join("")}
            <path d="${area}" fill="url(#${gid})"/>
            <polyline points="${pts}" fill="none" stroke="${lc}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
            <circle cx="${xS(n - 1).toFixed(1)}" cy="${yS(values[n - 1]).toFixed(1)}" r="3" fill="${lc}" stroke="var(--bg)" stroke-width="1.5"/>
            ${ytks.map(t => `<text x="${P.left - 4}" y="${(t.y + 3.5).toFixed(1)}" font-size="9" font-family="monospace" fill="var(--text-mute)" text-anchor="end">${t.l}</text>`).join("")}
            ${xlbs.map(xl => `<text x="${xl.x.toFixed(1)}" y="${H - 3}" font-size="9" font-family="monospace" fill="var(--text-mute)" text-anchor="${xl.a}">${xl.l}</text>`).join("")}
        </svg>`;
    }
};

window.PerfChart = PerfChart;