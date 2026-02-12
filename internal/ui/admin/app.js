// app.js
class AgberoApp {
    constructor() {
        this.apiBase = window.location.origin;
        this.token = sessionStorage.getItem("ag_tok");
        this.basic = sessionStorage.getItem("ag_bas");

        // State
        this.page = "dashboard";
        this.metricsSeries = [];
        this.lastReqTotal = 0;
        this.lastReqTime = Date.now();

        // Data Caches
        this.hostsData = { config: {}, stats: {} };
        this.logs = [];

        // Settings
        this.logsPaused = false;
        this.logFilter = "ALL"; // ALL, INFO, WARN, ERROR

        // Timers
        this.timers = { metrics: null, config: null, logs: null };

        this.init();
    }

    init() {
        this.loadTheme();
        this.bindEvents();
        this.updateAuthButton();

        if (this.token || this.basic) {
            this.startLoop();
            this.fetchHostsData(); // Initial Load
        } else {
            this.openModal("loginModal");
        }
    }

    // ================== THEME ==================
    loadTheme() {
        const t = localStorage.getItem("theme") || "light";
        document.documentElement.setAttribute("data-theme", t);
    }

    toggleTheme() {
        const cur = document.documentElement.getAttribute("data-theme");
        const next = cur === "light" ? "dark" : "light";
        document.documentElement.setAttribute("data-theme", next);
        localStorage.setItem("theme", next);
    }

    // ================== EVENTS ==================
    bindEvents() {
        // Navigation
        document.querySelectorAll(".nav-link").forEach(l => {
            l.addEventListener("click", e => {
                if (e.target.id === 'loginBtn') return;
                e.preventDefault();
                this.setPage(e.target.dataset.page);
            });
        });

        document.getElementById("themeToggle").addEventListener("click", () => this.toggleTheme());
        document.getElementById("loginBtn").addEventListener("click", () => this.handleAuthClick());
        document.getElementById("refreshHostsBtn").addEventListener("click", () => this.fetchHostsData());

        // Host Search
        document.getElementById("hostSearch").addEventListener("input", (e) => this.renderHosts(e.target.value));

        // Forms
        document.getElementById("loginForm").addEventListener("submit", e => this.doLogin(e));
        document.getElementById("addRuleBtn").addEventListener("click", () => this.openModal("ruleModal"));
        document.getElementById("ruleForm").addEventListener("submit", e => this.addFirewallRule(e));

        // Logs Controls
        document.getElementById("logsPauseBtn").addEventListener("click", () => {
            this.logsPaused = !this.logsPaused;
            document.getElementById("logsPauseBtn").innerText = this.logsPaused ? "Resume" : "Pause";
        });
        document.getElementById("logsClearBtn").addEventListener("click", () => {
            this.logs = [];
            this.renderLogs();
        });

        // Log Filters
        document.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", (e) => {
                document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
                e.target.classList.add("active");
                this.logFilter = e.target.dataset.level;
                this.renderLogs();
            });
        });

        // Modals
        document.querySelectorAll(".close-modal").forEach(b => {
            b.addEventListener("click", () => this.closeModals());
        });

        document.getElementById("confirmCancel").addEventListener("click", () => this.closeModals());
        document.getElementById("confirmOk").addEventListener("click", async () => {
            if (this._confirmFn) await this._confirmFn();
            this.closeModals();
        });

        // Drawer
        document.getElementById("drawerCloseBtn").addEventListener("click", () => this.closeDrawer());
        document.getElementById("drawerBackdrop").addEventListener("click", () => this.closeDrawer());

        // Escape key to close drawer
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") this.closeDrawer();
        });
    }

    setPage(p) {
        this.page = p;
        document.querySelectorAll(".nav-link").forEach(n => n.classList.remove("active"));
        document.querySelector(`.nav-link[data-page="${p}"]`)?.classList.add("active");

        document.querySelectorAll(".page").forEach(div => div.classList.remove("active"));
        document.getElementById(p + "Page").classList.add("active");

        if (this.token || this.basic) {
            this.refreshCurrentPage();
        }
    }

    // ================== LOOP & AUTH ==================
    startLoop() {
        this.stopLoop();
        this.timers.metrics = setInterval(() => this.fetchMetrics(), 2000);
        this.timers.config = setInterval(() => {
            if (this.page === 'hosts') this.fetchHostsData();
        }, 10000);
        this.timers.logs = setInterval(() => {
            if (this.page === 'logs' && !this.logsPaused) this.fetchLogs();
        }, 2000);
    }

    stopLoop() {
        if (this.timers.metrics) clearInterval(this.timers.metrics);
        if (this.timers.config) clearInterval(this.timers.config);
        if (this.timers.logs) clearInterval(this.timers.logs);
        this.timers = { metrics: null, config: null, logs: null };
    }

    async refreshCurrentPage() {
        if (this.page === 'hosts') await this.fetchHostsData();
        if (this.page === 'firewall') await this.fetchFirewall();
        if (this.page === 'config') await this.fetchConfig();
        if (this.page === 'logs') await this.fetchLogs();
    }

    async api(path, method = "GET", body = null) {
        const headers = {};
        if (this.token) headers["Authorization"] = "Bearer " + this.token;
        else if (this.basic) headers["Authorization"] = "Basic " + this.basic;

        const opts = {method, headers};
        if (body) {
            headers["Content-Type"] = "application/json";
            opts.body = JSON.stringify(body);
        }

        try {
            const res = await fetch(this.apiBase + path, opts);
            if (res.status === 401) { this.handleSessionExpired(); return null; }
            if (res.status === 204) return true;
            return await res.json();
        } catch (e) {
            console.error("API Error", e);
            return null;
        }
    }

    handleAuthClick() {
        if (this.token || this.basic) {
            sessionStorage.clear();
            this.token = null; this.basic = null;
            this.stopLoop();
            this.updateAuthButton();
            window.location.reload();
        } else {
            this.openModal("loginModal");
        }
    }

    handleSessionExpired() {
        this.stopLoop();
        sessionStorage.clear();
        this.token = null; this.basic = null;
        this.updateAuthButton();
        this.openModal("loginModal");
    }

    async doLogin(e) {
        e.preventDefault();
        const u = document.getElementById("username").value;
        const p = document.getElementById("password").value;

        // Try JWT
        const jwt = await this.api("/login", "POST", {username: u, password: p});
        if (jwt && jwt.token) {
            this.token = jwt.token;
            sessionStorage.setItem("ag_tok", this.token);
            this.finishLoginSuccess();
            return;
        }

        // Try Basic Fallback
        const tempBasic = btoa(u + ":" + p);
        this.basic = tempBasic;
        const check = await this.api("/health");
        if (check) {
            sessionStorage.setItem("ag_bas", this.basic);
            this.finishLoginSuccess();
        } else {
            this.basic = null;
            alert("Login Failed");
        }
    }

    finishLoginSuccess() {
        this.closeModals();
        this.updateAuthButton();
        this.startLoop();
        this.fetchHostsData();
    }

    updateAuthButton() {
        const btn = document.getElementById("loginBtn");
        btn.innerText = (this.token || this.basic) ? "Logout" : "Login";
    }

    // ================== METRICS ==================
    async fetchMetrics() {
        const data = await this.api("/uptime");
        if (!data) return;

        const stats = this.parseMetricsJSON(data);

        // Text Updates
        document.getElementById("totalReqsStat").innerText = this.fmtNum(stats.total_reqs);
        document.getElementById("errorsStat").innerText = this.fmtNum(stats.total_errors);
        document.getElementById("meanResponseStat").innerText = stats.avg_ms.toFixed(0) + "ms";
        document.getElementById("activeBackendsStat").innerText = stats.active_backends;
        document.getElementById("apdexStat").innerText = stats.apdex;
        document.getElementById("sysCpu").innerText = stats.sys_cpu;
        document.getElementById("sysMem").innerText = stats.sys_mem;

        // RPS
        const now = Date.now();
        const timeDiff = (now - this.lastReqTime) / 1000;
        let rps = 0;
        if (this.lastReqTotal > 0 && timeDiff > 0 && stats.total_reqs >= this.lastReqTotal) {
            rps = (stats.total_reqs - this.lastReqTotal) / timeDiff;
        }
        this.lastReqTotal = stats.total_reqs;
        this.lastReqTime = now;
        document.getElementById("rpsStat").innerText = rps.toFixed(1);

        // Update Charts & Health Bar
        this.metricsSeries.push(stats.avg_ms);
        if (this.metricsSeries.length > 60) this.metricsSeries.shift();
        this.renderGraph();
        this.renderHealthBar(stats.total_reqs, stats.total_errors);
    }

    renderHealthBar(total, errors) {
        const bar = document.getElementById("globalHealthBar");
        if (total === 0) return;

        const errPct = (errors / total) * 100;
        const okPct = 100 - errPct;

        bar.innerHTML = `
            <div class="hb-seg hb-ok" style="width: ${okPct}%"></div>
            <div class="hb-seg hb-err" style="width: ${errPct}%"></div>
        `;
    }

    parseMetricsJSON(obj) {
        let total_reqs = 0, total_errors = 0, active_backends = 0;
        let sumLat = 0, countLat = 0;

        if (obj.hosts) {
            Object.values(obj.hosts).forEach(h => {
                if (h.routes) h.routes.forEach(r => {
                    if (r.backends) r.backends.forEach(b => {
                        total_reqs += (b.total_reqs || 0);
                        total_errors += (b.failures || 0);
                        if (b.alive) active_backends++;
                        if (b.latency_us && b.latency_us.count > 0) {
                            sumLat += b.latency_us.sum_us;
                            countLat += b.latency_us.count;
                        }
                    });
                });
            });
        }

        const avg_ms = countLat > 0 ? (sumLat / countLat / 1000) : 0;
        const apdex = avg_ms < 200 ? 1.0 : (avg_ms < 1000 ? 0.8 : 0.5);

        let sys_cpu = "—", sys_mem = "—";
        if (obj.system) {
            sys_cpu = (obj.system.num_goroutine || 0) + " GRs";
            sys_mem = this.formatBytes(obj.system.mem_rss || 0);
        }

        return {
            total_reqs, total_errors, active_backends, avg_ms,
            apdex: apdex.toFixed(2), sys_cpu, sys_mem
        };
    }

    renderGraph() {
        const el = document.getElementById("responseGraph");
        if (this.page !== "dashboard") return;
        const h = el.clientHeight || 200;
        const pTop = 15;
        const drawH = h - 30;

        if (this.metricsSeries.length === 0) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">Waiting for data...</div>`;
            return;
        }

        const max = Math.max(10, ...this.metricsSeries) * 1.1;
        const bars = this.metricsSeries.map((val, i) => {
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
    }

    // ================== HOSTS ==================
    async fetchHostsData() {
        // Fetch raw data
        const [config, stats] = await Promise.all([this.api("/config"), this.api("/uptime")]);
        if (!config || !config.hosts) return;

        // Save to instance for filtering
        this.hostsData.config = config.hosts;
        this.hostsData.stats = stats?.hosts || {};

        // Render with current search term
        const searchTerm = document.getElementById("hostSearch").value;
        this.renderHosts(searchTerm);
    }

    renderHosts(filterTerm = "") {
        const container = document.getElementById("hostsContainer");
        const hosts = this.hostsData.config;
        const stats = this.hostsData.stats;

        filterTerm = filterTerm.toLowerCase();
        let html = "";
        let hostCount = 0, routeCount = 0;

        for (const [hostname, cfg] of Object.entries(hosts)) {
            // Basic filtering on Hostname or Domains
            const domainsStr = (cfg.domains || []).join(" ");
            const matchesHost = hostname.toLowerCase().includes(filterTerm) || domainsStr.toLowerCase().includes(filterTerm);

            let hostHtml = "";
            let hostHasMatch = matchesHost;

            hostCount++;
            const rtStats = stats[hostname] || {};

            // TLS Info
            let tlsMode = cfg.tls?.mode || "";
            let tlsText = "Auto (Secure)";
            let tlsClass = "tls";
            let tlsTitle = "Managed by Agbero";

            if (tlsMode === "none") {
                tlsClass = "sec"; tlsText = "No TLS";
            } else if (tlsMode.includes("local")) {
                tlsClass = "local"; tlsText = "Local TLS";
            }

            if (cfg.tls?.expiry) {
                const daysLeft = Math.floor((new Date(cfg.tls.expiry) - Date.now()) / 86400000);
                tlsTitle = `Expires: ${cfg.tls.expiry} (${daysLeft} days)`;
                if (daysLeft < 7) { tlsClass = "sec"; tlsText += " (Expiring)"; }
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

                    // --- FIX START ---
                    // 1. Get Static Config (Source of Truth for Weight/Address)
                    const configBackends = route.backends?.servers || [];
                    // 2. Get Runtime Stats (Source of Truth for Reqs/Latency)
                    const statBackends = routeStats?.backends || [];

                    // Use config as base, fallback to stats if config is empty (dynamic backends)
                    const displayBackends = configBackends.length > 0 ? configBackends : statBackends;

                    if (displayBackends.length > 0) {
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            // Find matching stats object by index
                            const bStats = statBackends[bIdx] || {};

                            // Prefer Config address, fallback to Stats url
                            const url = b.address || b.url || bStats.url || bStats.address;

                            // Prefer Config weight
                            const weight = (b.weight !== undefined) ? b.weight : (bStats.weight || '-');

                            if (pathMatches || matchesHost || (url && url.toLowerCase().includes(filterTerm))) {
                                hostHasMatch = true;
                            }

                            // Use Stats for liveness (default true if stats missing)
                            const alive = bStats.alive !== false;
                            const p99 = bStats.latency_us?.p99 ? (bStats.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = bStats.total_reqs || 0;

                            backendHtml += `
                                <div class="backend-row ${alive ? '' : 'down'}">
                                    <span class="be-actions" onclick="event.stopPropagation(); app.toggleBackend('${hostname}', ${idx}, '${url}', ${alive})">
                                        <span class="dot ${alive ? 'ok' : 'down'}" title="Toggle Backend"></span>
                                    </span>
                                    <span class="be-url">${url}</span>
                                    <span class="be-stat">W: ${weight}</span>
                                    <span class="be-stat">${p99}</span>
                                    <span class="be-stat">${this.fmtNum(reqs)}</span>
                                </div>`;
                        });
                        backendHtml += `</div>`;
                    }
                    // --- FIX END ---
                    else if (route.web && route.web.root) {
                        backendHtml = `<div class="backend-row"><span class="dot ok"></span> <span>📂 ${route.web.root}</span></div>`;
                        if (route.web.root.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                    }

                    if (filterTerm === "" || hostHasMatch || pathMatches) {
                        hostHtml += `
                            <div class="route-block" onclick="app.openRouteDrawer('${hostname}', ${idx})">
                                <div class="route-header">
                                    <span class="route-path">${route.path}</span>
                                    <span class="badge" style="margin-left:auto; font-size:9px;">DETAILS &rarr;</span>
                                </div>
                                ${backendHtml}
                            </div>`;
                    }
                });
            }
            hostHtml += `</div>`;

            if (hostHasMatch) {
                html += hostHtml;
            }
        }

        container.innerHTML = html || `<div style="text-align:center;color:var(--text-mute);margin-top:40px;">No hosts found matching "${filterTerm}"</div>`;
        document.getElementById("heroHostCount").innerText = hostCount;
        document.getElementById("heroRouteCount").innerText = routeCount;
    }

    async toggleBackend(host, routeIdx, backendUrl, currentStatus) {
        const action = currentStatus ? "disable" : "enable";
        this.confirm("Confirm Action", `Are you sure you want to ${action} ${backendUrl}?`, async () => {
            // Simulated API Call
            // await this.api(`/config/backend/toggle`, "POST", { host, routeIdx, url: backendUrl, active: !currentStatus });
            alert("Backend toggle signal sent (Simulated). In a real setup, this endpoint would update cluster state.");
            this.fetchHostsData(); // Refresh UI
        });
    }

    // ================== DRAWER (Route Details) ==================
    openRouteDrawer(hostname, routeIdx) {
        const route = this.hostsData.config[hostname].routes[routeIdx];

        // Fetch Live Stats for this specific route to show Real-time status in drawer
        const routeStats = this.hostsData.stats[hostname]?.routes?.[routeIdx] || {};

        document.getElementById("drawerRoutePath").innerText = route.path;
        document.getElementById("drawerHostName").innerText = hostname;

        const content = document.getElementById("drawerBody");
        content.innerHTML = ""; // Clear previous

        // ================= SECTION 1: THE HANDLER (Backend/PHP/Static) =================

        // CASE A: Static File Server
        if (route.web && route.web.root) {
            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">📂 Static File Handler</div>
                    <div class="handler-card">
                        <span class="handler-icon">📁</span>
                        <div class="handler-info">
                            <strong>File Server</strong>
                            <span>Root: ${route.web.root}</span>
                            <span>Listing: ${route.web.listing ? 'Enabled' : 'Disabled'}</span>
                        </div>
                    </div>
                </div>`;
        }

        // CASE B: PHP Handler
        if (route.web && route.web.php && route.web.php.enabled) {
            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">🐘 PHP Handler</div>
                    <div class="handler-card">
                        <span class="handler-icon">⚙️</span>
                        <div class="handler-info">
                            <strong>FastCGI Proxy</strong>
                            <span>Address: ${route.web.php.address}</span>
                            <span>Index: ${route.web.php.index || 'index.php'}</span>
                        </div>
                    </div>
                </div>`;
        }

        // CASE C: Load Balancer (Backends)
        const configBackends = route.backends?.servers || [];
        const statBackends = routeStats.backends || [];

        // Merge Config + Stats for the Drawer list
        const displayBackends = configBackends.length > 0 ? configBackends : statBackends;

        if (displayBackends.length > 0) {
            let backendsHtml = "";

            displayBackends.forEach((b, i) => {
                const s = statBackends[i] || {};

                // Data Merging
                const url = b.address || b.url || s.url || s.address;
                const weight = (b.weight !== undefined) ? b.weight : (s.weight || '-');
                const alive = s.alive !== false; // Default to true if no stats
                const p99 = s.latency_us?.p99 ? (s.latency_us.p99 / 1000).toFixed(0) + "ms" : "";

                backendsHtml += `
                    <div class="drawer-row ${alive ? '' : 'down'}">
                        <div class="row-left">
                            <span class="dot ${alive ? 'ok' : 'down'}" title="${alive ? 'Healthy' : 'Unhealthy'}"></span>
                            <span class="mono">${url}</span>
                        </div>
                        <div class="row-right">
                            ${p99 ? `<span class="badge" style="border:none;background:var(--panel-bg)">${p99}</span>` : ''}
                            <span class="badge ${alive ? 'tls' : 'sec'}">W: ${weight}</span>
                        </div>
                    </div>`;
            });

            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">📡 Upstreams & Load Balancing</div>
                    ${backendsHtml}
                    <div class="kv-grid" style="margin-top:15px;">
                        <div class="kv-item"><label>Strategy</label><div>${route.backends?.load_balancing?.strategy || 'Round Robin'}</div></div>
                        <div class="kv-item"><label>Health Check</label><div>${route.backends?.health_check ? 'Enabled' : 'Disabled'}</div></div>
                    </div>
                </div>`;
        }

        // ================= SECTION 2: MIDDLEWARE GRID =================
        let mwHtml = "";
        const mw = route.middleware || {};

        // Security Group
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
                    <div class="mw-sub">${Object.keys(mw.basic_auth).length} Users Configured</div>
                </div>`;
        }

        if (mw.webauthn) {
            mwHtml += `
                <div class="mw-card security">
                    <div class="mw-head">Authentication</div>
                    <div class="mw-body">Passkeys (WebAuthn)</div>
                    <div class="mw-sub">Relying Party Configured</div>
                </div>`;
        }

        // Traffic Group
        if (mw.rate_limit) {
            mwHtml += `
                <div class="mw-card traffic">
                    <div class="mw-head">Rate Limiter</div>
                    <div class="mw-body">${mw.rate_limit.requests} req / ${mw.rate_limit.window_seconds}s</div>
                    <div class="mw-sub">Local Strategy</div>
                </div>`;
        }

        if (mw.circuit_breaker) {
            mwHtml += `
                <div class="mw-card traffic">
                    <div class="mw-head">Circuit Breaker</div>
                    <div class="mw-body">Enabled</div>
                    <div class="mw-sub">Protecting Upstreams</div>
                </div>`;
        }

        // Transform Group
        if (mw.compress) {
            mwHtml += `
                <div class="mw-card transform">
                    <div class="mw-head">Optimization</div>
                    <div class="mw-body">Compression</div>
                    <div class="mw-sub">Gzip / Brotli</div>
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

        // Render Middleware Section if any exist
        if (mwHtml) {
            content.innerHTML += `
                <div class="detail-section">
                    <div class="detail-title">⚡ Active Middleware</div>
                    <div class="mw-grid">
                        ${mwHtml}
                    </div>
                </div>`;
        }

        // ================= SECTION 3: RAW CONFIG =================
        content.innerHTML += `
            <div class="detail-section">
                <div class="detail-title">📜 Raw Config</div>
                <div class="code-box" style="max-height: 200px;">
                    <pre>${JSON.stringify(route, null, 2)}</pre>
                </div>
            </div>`;

        // Open Drawer
        document.getElementById("drawerBackdrop").classList.add("active");
        document.getElementById("routeDrawer").classList.add("active");
    }

    closeDrawer() {
        document.getElementById("drawerBackdrop").classList.remove("active");
        document.getElementById("routeDrawer").classList.remove("active");
    }

    // ================== FIREWALL & UTILS ==================
    async fetchFirewall() {
        const res = await this.api("/firewall");
        const tbody = document.getElementById("firewallTable");
        tbody.innerHTML = "";

        if (res && res.enabled === false) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-mute);">Firewall Disabled</td></tr>`;
            return;
        }
        const rules = res.rules || res || [];
        if (Array.isArray(rules)) {
            tbody.innerHTML = rules.map(r => `
                <tr>
                    <td class="mono">${r.ip}</td>
                    <td>${r.reason || '-'}</td>
                    <td>${r.host || '*'} / ${r.path || '*'}</td>
                    <td>${new Date(r.created_at).toLocaleDateString()}</td>
                    <td><button class="btn small" onclick="app.deleteFw('${r.ip}')">Unblock</button></td>
                </tr>`).join("");
        }
    }

    async addFirewallRule(e) {
        e.preventDefault();
        const body = {
            ip: document.getElementById("fwIp").value,
            reason: document.getElementById("fwReason").value,
            path: document.getElementById("fwPath").value,
            duration_sec: parseInt(document.getElementById("fwDuration").value)
        };
        await this.api("/firewall", "POST", body);
        this.closeModals();
        this.fetchFirewall();
    }

    async deleteFw(ip) {
        await this.api(`/firewall?ip=${encodeURIComponent(ip)}`, "DELETE");
        this.fetchFirewall();
    }

    async fetchConfig() {
        const data = await this.api("/config");
        document.getElementById("configContent").innerText = JSON.stringify(data, null, 2);
    }

    // ================== LOGS ==================
    async fetchLogs() {
        const n = document.getElementById("logsTailSelect").value;
        const data = await this.api(`/logs?lines=${n}`);
        if (data && Array.isArray(data)) {
            this.logs = data.reverse();
            this.renderLogs();
        }
    }

    renderLogs() {
        const container = document.getElementById("logsList");

        // Filter Logs
        const filtered = this.logs.filter(l => {
            if (this.logFilter === "ALL") return true;
            let lvl = "INFO";
            if (typeof l === 'object') lvl = l.lvl || "INFO";
            else if (typeof l === 'string' && l.includes("ERR")) lvl = "ERROR";
            return lvl === this.logFilter;
        });

        if (filtered.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute);text-align:center;">No logs for filter: ${this.logFilter}</div>`;
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
    }

    // ================== HELPERS ==================
    fmtNum(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "k";
        return n;
    }

    formatBytes(b) {
        if (b === 0) return "0";
        const k = 1024, s = ["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(b) / Math.log(k));
        return parseFloat((b / Math.pow(k, i)).toFixed(1)) + s[i];
    }

    openModal(id) { document.getElementById(id).classList.add("active"); }
    closeModals() { document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active")); }

    confirm(t, msg, fn) {
        this._confirmFn = fn;
        document.getElementById("confirmTitle").innerText = t;
        document.getElementById("confirmText").innerText = msg;
        this.openModal("confirmModal");
    }
}

window.app = new AgberoApp();