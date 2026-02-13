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
        setText("meanResponseStat", stats.avg_ms.toFixed(0) + "ms");
        setText("activeBackendsStat", stats.active_backends);
        setText("apdexStat", stats.apdex);
        setText("uptimeStat", stats.uptime || "100%");

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
        setMetric('configLogLevel', metrics.logLevel.toUpperCase());
    },

    updateLastUpdated(timestamp) {
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

        const settings = [
            { label: 'Environment', value: global.development ? 'development' : 'production' },
            { label: 'Admin Email', value: global.lets_encrypt?.email || '—' },
            { label: 'Max Header Size', value: global.general?.max_header_bytes ? this.formatBytes(global.general.max_header_bytes) : '—' },
            { label: 'Trusted Proxies', value: global.security?.trusted_proxies?.join(', ') || 'none' }
        ];

        container.innerHTML = settings.map(setting => `
            <div class="config-detail-item">
                <div class="config-detail-label">${setting.label}</div>
                <div class="config-detail-value">${setting.value}</div>
            </div>
        `).join('');
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

        if (series.length === 0) {
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
        const hosts = hostsData.config;
        const stats = hostsData.stats;

        filterTerm = filterTerm.toLowerCase();
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
                tlsClass = "error"; tlsText = "No TLS";
            } else if (tlsMode.includes("local")) {
                tlsClass = "warning"; tlsText = "Local TLS";
            }

            if (cfg.tls?.expiry) {
                const daysLeft = Math.floor((new Date(cfg.tls.expiry) - Date.now()) / 86400000);
                tlsTitle = `Expires: ${cfg.tls.expiry} (${daysLeft} days)`;
                if (daysLeft < 7) {
                    tlsClass = daysLeft < 0 ? "error" : "warning";
                    tlsText = daysLeft < 0 ? "Expired" : `Expires in ${daysLeft}d`;
                }
            }

            hostHtml += `
        <div class="host-row">
            <div class="host-header">
                <div class="host-name">${hostname} 
                    <span class="badge ${tlsClass}" title="${tlsTitle}">${tlsText}</span>
                </div>
                <div class="host-meta">${cfg.domains?.join(", ")} &bull; ${this.fmtNum(rtStats.total_reqs || 0)} Reqs</div>
            </div>`;

            if (cfg.routes) {
                cfg.routes.forEach((route, idx) => {
                    routeCount++;
                    const pathMatches = route.path.toLowerCase().includes(filterTerm);
                    const routeStats = rtStats.routes?.[idx];

                    let backendHtml = "";
                    const configBackends = route.backends?.servers || [];
                    const uptimeBackends = routeStats?.backends || [];

                    if (configBackends.length > 0 || uptimeBackends.length > 0) {
                        const displayBackends = uptimeBackends.length > 0 ? uptimeBackends : configBackends;
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            const configBackend = configBackends[bIdx] || {};
                            const url = b.address || b.url || configBackend.address || configBackend.url;
                            const weight = configBackend.weight !== undefined ? configBackend.weight : (b.weight || '-');

                            const hasStats = uptimeBackends[bIdx] !== undefined;
                            let healthStatus = 'unknown';
                            let dotColor = 'warn';

                            if (hasStats) {
                                if (b.healthy !== undefined) {
                                    healthStatus = b.healthy ? 'ok' : 'down';
                                    dotColor = b.healthy ? 'ok' : 'down';
                                } else if (b.alive !== undefined) {
                                    const isTCPBackend = url && !url.startsWith('http');
                                    if (isTCPBackend) {
                                        healthStatus = b.alive ? 'ok' : 'warn';
                                        dotColor = b.alive ? 'ok' : 'warn';
                                    } else {
                                        healthStatus = b.alive ? 'ok' : 'down';
                                        dotColor = b.alive ? 'ok' : 'down';
                                    }
                                }
                            }

                            if (url && url.toLowerCase().includes(filterTerm)) hostHasMatch = true;

                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;
                            const in_flight = b.in_flight || 0;

                            backendHtml += `
                            <div class="backend-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                                <span class="dot ${dotColor}" title="${hasStats ? (healthStatus === 'ok' ? 'Healthy' : healthStatus === 'warn' ? 'Idle' : 'Unhealthy') : 'No data'}"></span>
                                <span class="be-url" onclick="event.stopPropagation(); app.copyToClipboard('${url}')">${url} ${in_flight > 0 ? `<span class="badge warn">⚡${in_flight}</span>` : ''}</span>
                                <span class="be-stat">W: ${weight}</span>
                                <span class="be-stat">${p99}</span>
                                <span class="be-stat">${this.fmtNum(reqs)}</span>
                            </div>`;
                        });
                        backendHtml += `</div>`;
                    } else if (route.web && route.web.root) {
                        backendHtml = `<div class="backend-row"><span class="dot ok"></span> <span>📂 ${route.web.root}</span></div>`;
                        if (route.web.root.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                    }

                    const shouldShowRoute = filterTerm === "" || hostHasMatch || pathMatches || route.protocol === 'tcp';
                    const protocolBadgeClass = (route.protocol || 'http') === 'http' ? 'success' : 'info';
                    const protocolBadge = `<span class="badge ${protocolBadgeClass}">${(route.protocol || 'HTTP').toUpperCase()}</span>`;

                    if (shouldShowRoute) {
                        hostHtml += `
                        <div class="route-block" onclick="app.openRouteDrawer('${hostname}', ${idx})">
                            <div class="route-header">
                               ${protocolBadge} <span class="route-path">${route.path}</span>
                                <span class="badge info" style="margin-left:auto; font-size:9px;">DETAILS →</span>
                            </div>
                            ${backendHtml}
                        </div>`;
                    }
                });
            }

            if (cfg.proxies) {
                cfg.proxies.forEach((proxy, pidx) => {
                    routeCount++;
                    const path = proxy.name ? proxy.name.replace('*default*', '* (TCP)') : proxy.path || proxy.protocol || "*";
                    const pathMatches = path.toLowerCase().includes(filterTerm);
                    const proxyStats = rtStats.proxies?.[pidx];

                    let backendHtml = "";
                    const configBackends = proxy.backends?.servers || [];
                    const uptimeBackends = proxyStats?.backends || [];

                    if (configBackends.length > 0 || uptimeBackends.length > 0) {
                        const displayBackends = uptimeBackends.length > 0 ? uptimeBackends : configBackends;
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            const configBackend = configBackends[bIdx] || {};
                            const url = b.address || b.url || configBackend.address || configBackend.url;
                            const weight = configBackend.weight !== undefined ? configBackend.weight : (b.weight || '-');

                            const hasStats = uptimeBackends[bIdx] !== undefined;
                            let healthStatus = 'unknown';
                            let dotColor = 'warn';

                            if (hasStats) {
                                if (b.healthy !== undefined) {
                                    healthStatus = b.healthy ? 'ok' : 'down';
                                    dotColor = b.healthy ? 'ok' : 'down';
                                } else if (b.alive !== undefined) {
                                    const isTCPBackend = url && !url.startsWith('http');
                                    if (isTCPBackend) {
                                        healthStatus = b.alive ? 'ok' : 'warn';
                                        dotColor = b.alive ? 'ok' : 'warn';
                                    } else {
                                        healthStatus = b.alive ? 'ok' : 'down';
                                        dotColor = b.alive ? 'ok' : 'down';
                                    }
                                }
                            }

                            if (url && url.toLowerCase().includes(filterTerm)) hostHasMatch = true;

                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;
                            const in_flight = b.in_flight || 0;

                            backendHtml += `
                            <div class="backend-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                                <span class="dot ${dotColor}" title="${hasStats ? (healthStatus === 'ok' ? 'Healthy' : healthStatus === 'warn' ? 'Idle' : 'Unhealthy') : 'No data'}"></span>
                                <span class="be-url" onclick="event.stopPropagation(); app.copyToClipboard('${url}')">${url} ${in_flight > 0 ? `<span class="badge warn">⚡${in_flight}</span>` : ''}</span>
                                <span class="be-stat">W: ${weight}</span>
                                <span class="be-stat">${p99}</span>
                                <span class="be-stat">${this.fmtNum(reqs)}</span>
                            </div>`;
                        });
                        backendHtml += `</div>`;
                    } else if (proxy.web && proxy.web.root) {
                        backendHtml = `<div class="backend-row"><span class="dot ok"></span> <span>📂 ${proxy.web.root}</span></div>`;
                        if (proxy.web.root.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                    }

                    const shouldShowRoute = filterTerm === "" || hostHasMatch || pathMatches || proxy.protocol === 'tcp';
                    const protocolBadgeClass = (proxy.protocol || 'tcp') === 'http' ? 'success' : 'info';
                    const protocolBadge = `<span class="badge ${protocolBadgeClass}">${(proxy.protocol || 'TCP').toUpperCase()}</span>`;

                    if (shouldShowRoute) {
                        hostHtml += `
                        <div class="route-block" onclick="app.openRouteDrawer('${hostname}', ${pidx}, 'proxy')">
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

        const rules = data.rules || data || [];
        if (Array.isArray(rules) && rules.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">
                <span>✅ No blocked IPs</span>
                <span>All traffic is allowed</span>
            </div></td></tr>`;
            return;
        }

        if (Array.isArray(rules)) {
            tbody.innerHTML = rules.map(r => `
                <tr>
                    <td class="mono">${r.ip}</td>
                    <td>${r.reason || '-'}</td>
                    <td class="hide-mobile">${r.host || '*'} / ${r.path || '*'}</td>
                    <td class="hide-mobile">${new Date(r.created_at).toLocaleDateString()}</td>
                    <td><button class="btn small error" onclick="app.confirmDeleteFw('${r.ip}')">Unblock</button></td>
                </tr>`).join("");
        }
    },

    renderLogs(logs, filter) {
        const container = document.getElementById("logsList");
        if (!container) return;

        if (logs.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute); text-align:center; padding:40px;">
                <span style="display:block; font-size:24px; margin-bottom:10px;">📭</span>
                No logs yet. Waiting for traffic...
            </div>`;
            return;
        }

        const filtered = logs.filter(l => {
            if (filter === "ALL") return true;
            let lvl = "INFO";
            if (typeof l === 'object') lvl = l.lvl || "INFO";
            else if (typeof l === 'string' && l.includes("ERR")) lvl = "ERROR";
            return lvl === filter;
        });

        if (filtered.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute);text-align:center; padding:20px;">No logs for filter: ${filter}</div>`;
            return;
        }

        container.innerHTML = filtered.map(l => {
            let lvl = "INFO", msg = "", ts = "";
            if (typeof l === 'string') {
                try { l = JSON.parse(l); } catch { msg = l; }
            }
            if (typeof l === 'object') {
                lvl = l.lvl || "INFO";
                msg = l.msg || "";
                ts = l.ts ? l.ts.split('T')[1].split('.')[0] : "";
                if (l.fields) msg += ` [${l.fields.method || ''} ${l.fields.path || ''}]`;
            }
            let c = "#aaa";
            if (lvl === "ERROR") c = "var(--danger)";
            if (lvl === "WARN") c = "var(--warning)";
            return `<div class="log-entry"><div class="log-ts">${ts}</div><div class="log-lvl" style="color:${c}">${lvl}</div><div class="log-msg">${msg}</div></div>`;
        }).join("");
    },

    renderDrawer(hostname, cfg_item, itemStats, type, certificates) {
        const path = cfg_item.path || (cfg_item.name ? cfg_item.name.replace('*default*', '* (TCP)') : cfg_item.protocol || "*");
        document.getElementById("drawerRoutePath").innerText = path;
        document.getElementById("drawerHostName").innerText = hostname;

        const content = document.getElementById("drawerBody");
        content.innerHTML = "";

        // Handler section
        if (cfg_item.web && cfg_item.web.root) {
            content.innerHTML += `
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
        }

        if (cfg_item.web && cfg_item.web.php && cfg_item.web.php.enabled) {
            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">🐘 PHP Handler</div>
                    <div class="handler-card">
                        <span class="handler-icon">⚙️</span>
                        <div class="handler-info">
                            <strong>FastCGI Proxy</strong>
                            <span>Address: ${cfg_item.web.php.address}</span>
                            <span>Index: ${cfg_item.web.php.index || 'index.php'}</span>
                        </div>
                    </div>
                </div>`;
        }

        const configBackends = cfg_item.backends?.servers || [];
        const statBackends = itemStats.backends || [];
        const displayBackends = configBackends.length > 0 ? configBackends : statBackends;

        if (displayBackends.length > 0) {
            let backendsHtml = "";

            displayBackends.forEach((b, i) => {
                const s = statBackends[i] || {};
                const url = b.address || b.url || s.url || s.address;
                const weight = (b.weight !== undefined) ? b.weight : (s.weight || '-');

                const hasStats = statBackends[i] !== undefined;
                let healthStatus = 'unknown';
                let dotColor = 'warn';

                if (hasStats) {
                    if (s.healthy !== undefined) {
                        healthStatus = s.healthy ? 'ok' : 'down';
                        dotColor = s.healthy ? 'ok' : 'down';
                    }
                    else if (s.alive !== undefined) {
                        const isTCPBackend = url && !url.startsWith('http');
                        if (isTCPBackend) {
                            healthStatus = s.alive ? 'ok' : 'warn';
                            dotColor = s.alive ? 'ok' : 'warn';
                        } else {
                            healthStatus = s.alive ? 'ok' : 'down';
                            dotColor = s.alive ? 'ok' : 'down';
                        }
                    }
                }

                const p99 = s.latency_us?.p99 ? (s.latency_us.p99 / 1000).toFixed(0) + "ms" : "";
                const in_flight = s.in_flight || 0;
                const failures = s.failures || 0;
                const total_reqs = s.total_reqs || 0;

                backendsHtml += `
                    <div class="drawer-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                        <div class="row-left">
                            <span class="dot ${dotColor}" title="${hasStats ? (healthStatus === 'ok' ? 'Healthy' : healthStatus === 'warn' ? 'Idle/Healthy' : 'Unhealthy') : 'No health data yet'}"></span>
                            <span class="mono">${url}</span>
                            ${in_flight > 0 ? `<span class="badge info">⚡ ${in_flight} in flight</span>` : ''}
                            ${failures > 0 ? `<span class="badge error">⚠️ ${failures} failures</span>` : ''}
                        </div>
                        <div class="row-right">
                            ${p99 ? `<span class="badge info">p99: ${p99}</span>` : ''}
                            <span class="badge ${healthStatus === 'ok' ? 'success' : healthStatus === 'warn' ? 'warning' : 'error'}">W: ${weight}</span>
                            <span class="badge" style="background: var(--text-mute);">${this.fmtNum(total_reqs)} reqs</span>
                        </div>
                    </div>`;
            });

            const lbStrategy = cfg_item.backends?.lb_strategy || cfg_item.backends?.load_balancing?.strategy || "round_robin";
            let strategyDisplay = "Round Robin";
            if (lbStrategy === "least_conn") strategyDisplay = "Least Connections";
            else if (lbStrategy === "ip_hash") strategyDisplay = "IP Hash";
            else if (lbStrategy === "uri_hash") strategyDisplay = "URI Hash";

            const healthCheck = cfg_item.health_check || cfg_item.backends?.health_check;
            let healthCheckHtml = '<div class="kv-item"><label>Health Check</label><div><span class="badge error">Not Configured</span></div></div>';
            if (healthCheck) {
                const hcPath = healthCheck.path || '/health';
                const hcInterval = healthCheck.interval ? (healthCheck.interval/1000000000)+'s' : '30s';
                const hcTimeout = healthCheck.timeout ? (healthCheck.timeout/1000000000)+'s' : '5s';
                healthCheckHtml = `
                    <div class="kv-item"><label>Health Check</label><div><span class="badge success">${hcPath} | ${hcInterval} | ${hcTimeout}</span></div></div>
                `;
            }

            let cbHtml = '';
            const cb = cfg_item.circuit_breaker || cfg_item.backends?.circuit_breaker;
            if (cb && cb.enabled) {
                const cbStatus = s.circuit_breaker_state || 'closed';
                const cbClass = cbStatus === 'closed' ? 'success' : (cbStatus === 'open' ? 'error' : 'warning');
                cbHtml = `
                    <div class="kv-item"><label>Circuit Breaker</label><div><span class="badge ${cbClass}">${cbStatus} | ${cb.failure_threshold || 5} fails</span></div></div>
                `;
            }

            const timeouts = cfg_item.timeouts || {};
            const readTimeout = timeouts.read ? (timeouts.read/1000000000)+'s' : 'inherit';
            const writeTimeout = timeouts.write ? (timeouts.write/1000000000)+'s' : 'inherit';
            const idleTimeout = timeouts.idle ? (timeouts.idle/1000000000)+'s' : 'inherit';

            let compressionHtml = '';
            const compression = cfg_item.compression_config || {};
            if (compression.enabled) {
                const algo = compression.type || 'gzip';
                const level = compression.level || 'default';
                compressionHtml = `
                    <div class="kv-item"><label>Compression</label><div><span class="badge info">${algo} (lvl ${level})</span></div></div>
                `;
            }

            let rateLimitHtml = '';
            const rl = cfg_item.rate_limit;
            if (rl) {
                const keyType = rl.key || 'ip';
                rateLimitHtml = `
                    <div class="kv-item"><label>Rate Limit</label><div><span class="badge warning">${rl.requests || 0} req / ${rl.window_seconds || 60}s (${keyType})</span></div></div>
                `;
            }

            let wasmHtml = '';
            const wasm = cfg_item.wasm;
            if (wasm && wasm.enabled !== false) {
                const moduleName = wasm.path ? wasm.path.split('/').pop() : 'filter.wasm';
                wasmHtml = `
                    <div class="kv-item"><label>WASM Filter</label><div><span class="badge info">${moduleName}</span></div></div>
                `;
            }

            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">📡 Upstreams & Load Balancing</div>
                    ${backendsHtml}
                    <div class="kv-grid" style="margin-top:15px;">
                        <div class="kv-item"><label>Strategy</label><div><span class="badge success">${strategyDisplay}</span></div></div>
                        ${healthCheckHtml}
                        ${cbHtml}
                        ${compressionHtml}
                        ${rateLimitHtml}
                        ${wasmHtml}
                    </div>
                    <div class="kv-grid" style="margin-top:10px;">
                        <div class="kv-item"><label>Read Timeout</label><div>${readTimeout}</div></div>
                        <div class="kv-item"><label>Write Timeout</label><div>${writeTimeout}</div></div>
                        <div class="kv-item"><label>Idle Timeout</label><div>${idleTimeout}</div></div>
                    </div>
                </div>`;
        }

        // Certificate section
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
                            <span>${cert.issuer}</span>
                            <span class="badge ${certClass}">${certText}</span>
                        </div>
                        <div style="font-size:9px; color:var(--text-mute); margin-top:6px;">
                            ${new Date(cert.expiry).toLocaleDateString()}
                        </div>
                    </div>
                `;
            });
            certHtml += '</div>';

            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">🔐 TLS Certificates</div>
                    ${certHtml}
                </div>`;
        }

        let mwHtml = "";
        const mw = cfg_item.middleware || {};

        if (mw.ip_allowlist && mw.ip_allowlist.length > 0) {
            mwHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Access Control</div>
                    <div class="mw-body">${mw.ip_allowlist.length} IPs Allowed</div>
                    <div class="mw-sub">${mw.ip_allowlist.join(", ")}</div>
                </div>`;
        }

        if (mw.basic_auth) {
            mwHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Authentication</div>
                    <div class="mw-body">Basic Auth</div>
                    <div class="mw-sub">${Object.keys(mw.basic_auth).length} Users</div>
                </div>`;
        }

        if (mw.webauthn) {
            mwHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Authentication</div>
                    <div class="mw-body">Passkeys</div>
                    <div class="mw-sub">WebAuthn</div>
                </div>`;
        }

        if (mw.rate_limit) {
            mwHtml += `
                <div class="mw-card traffic">
                    <div class="mw-head">Rate Limiter</div>
                    <div class="mw-body">${mw.rate_limit.requests} req / ${mw.rate_limit.window_seconds}s</div>
                    <div class="mw-sub">${mw.rate_limit.key || 'ip'}</div>
                </div>`;
        }

        if (mw.circuit_breaker) {
            mwHtml += `
                <div class="mw-card traffic">
                    <div class="mw-head">Circuit Breaker</div>
                    <div class="mw-body">Enabled</div>
                    <div class="mw-sub">Threshold: ${mw.circuit_breaker.failure_threshold || 5}</div>
                </div>`;
        }

        if (mw.compress) {
            mwHtml += `
                <div class="mw-card transform">
                    <div class="mw-head">Optimization</div>
                    <div class="mw-body">Compression</div>
                    <div class="mw-sub">${mw.compress.type || 'gzip'}</div>
                </div>`;
        }

        if (mw.headers) {
            const count = Object.keys(mw.headers).length;
            mwHtml += `
                <div class="mw-card transform">
                    <div class="mw-head">Header Mod</div>
                    <div class="mw-body">${count} Rules</div>
                    <div class="mw-sub">Request/Response</div>
                </div>`;
        }

        if (mwHtml) {
            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">⚡ Active Middleware</div>
                    <div class="mw-grid">
                        ${mwHtml}
                    </div>
                </div>`;
        }

        content.innerHTML += `
            <div class="detail-section">
                <div class="detail-title">📜 Source (read-only)</div>
                <div class="code-box" style="max-height: 200px;">
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