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
        this.lastUpdateTime = Date.now();
        this.staleTimer = null;
        this.searchTerm = sessionStorage.getItem("ag_search") || "";
        this.sessionExpiry = null;
        this.sessionWarningShown = false;
        this.version = null;

        // Data Caches
        this.hostsData = { config: {}, stats: {} };
        this.logs = [];
        this.certificates = [];

        // Settings
        this.logsPaused = false;
        this.logFilter = "ALL";

        // Timers
        this.timers = { metrics: null, config: null, logs: null };

        this.init();
    }

    init() {
        this.loadTheme();
        this.bindEvents();
        this.updateAuthButton();
        this.fetchVersion();

        if (this.token || this.basic) {
            this.startLoop();
            this.fetchHostsData();
            this.parseJWTExpiry();
        } else {
            this.openModal("loginModal");
        }

        if (this.searchTerm) {
            const searchInput = document.getElementById("hostSearch");
            if (searchInput) {
                searchInput.value = this.searchTerm;
            }
        }

        this.startStaleDetection();
    }

    // ================== VERSION DISCOVERY ==================
    async fetchVersion() {
        try {
            const res = await fetch(this.apiBase + "/health", { method: "HEAD" });
            const serverHeader = res.headers.get("Server");
            if (serverHeader && serverHeader.includes("agbero/")) {
                this.version = serverHeader.split("agbero/")[1].split(" ")[0];
            } else {
                const config = await this.api("/config");
                if (config && config.global && config.global.version) {
                    this.version = "v" + config.global.version;
                } else {
                    this.version = "dev";
                }
            }
        } catch (e) {
            this.version = "—";
        }
        document.getElementById("versionDisplay").innerText = this.version || "v—";
    }

    // ================== SESSION MANAGEMENT ==================
    parseJWTExpiry() {
        if (!this.token) return;
        try {
            const parts = this.token.split('.');
            if (parts.length === 3) {
                const payload = JSON.parse(atob(parts[1]));
                if (payload.exp) {
                    this.sessionExpiry = payload.exp * 1000;
                    this.startSessionWarning();
                }
            }
        } catch (e) {}
    }

    startSessionWarning() {
        if (!this.sessionExpiry) return;
        const checkExpiry = () => {
            const now = Date.now();
            const timeLeft = this.sessionExpiry - now;
            if (timeLeft <= 0) {
                this.handleSessionExpired();
                return;
            }
            if (timeLeft < 300000 && !this.sessionWarningShown) {
                this.sessionWarningShown = true;
                this.showSessionWarning(timeLeft);
            }
        };
        setInterval(checkExpiry, 10000);
        checkExpiry();
    }

    showSessionWarning(timeLeft) {
        const minutes = Math.floor(timeLeft / 60000);
        const seconds = Math.floor((timeLeft % 60000) / 1000);
        const banner = document.getElementById("sessionWarning");
        const timeSpan = document.getElementById("sessionExpiryTime");
        if (banner && timeSpan) {
            timeSpan.innerText = `${minutes}m ${seconds}s`;
            banner.classList.add("active");
        }
    }

    // ================== CERTIFICATE MANAGEMENT ==================
    parseCertificates() {
        const certs = [];
        const hosts = this.hostsData.config || {};

        for (const [hostname, cfg] of Object.entries(hosts)) {
            if (cfg.tls && cfg.tls.expiry) {
                const expiry = new Date(cfg.tls.expiry);
                const daysLeft = Math.floor((expiry - Date.now()) / 86400000);
                certs.push({
                    host: hostname,
                    expiry: expiry,
                    daysLeft: daysLeft,
                    mode: cfg.tls.mode || "auto",
                    issuer: cfg.tls.issuer || "Let's Encrypt"
                });
            }
        }

        this.certificates = certs;

        const activeCerts = certs.filter(c => c.daysLeft > 0).length;
        const expiringCerts = certs.filter(c => c.daysLeft > 0 && c.daysLeft < 7).length;

        document.getElementById("activeCertsCount").innerText = activeCerts;
        document.getElementById("expiringCertsCount").innerText = expiringCerts;
    }

    // ================== STALE DETECTION ==================
    startStaleDetection() {
        this.staleTimer = setInterval(() => {
            const staleTime = Date.now() - this.lastUpdateTime;
            const footer = document.querySelector(".stats-footer");
            if (staleTime > 10000) {
                footer?.classList.add("stale");
            } else {
                footer?.classList.remove("stale");
            }
        }, 1000);
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

        const searchInput = document.getElementById("hostSearch");
        searchInput.addEventListener("input", (e) => {
            const term = e.target.value;
            sessionStorage.setItem("ag_search", term);
            this.searchTerm = term;
            this.renderHosts(term);
        });

        document.getElementById("loginForm").addEventListener("submit", e => this.doLogin(e));
        document.getElementById("addRuleBtn").addEventListener("click", () => this.openModal("ruleModal"));
        document.getElementById("ruleForm").addEventListener("submit", e => this.addFirewallRule(e));

        document.getElementById("logsPauseBtn").addEventListener("click", () => {
            this.logsPaused = !this.logsPaused;
            document.getElementById("logsPauseBtn").innerText = this.logsPaused ? "Resume" : "Pause";
        });
        document.getElementById("logsClearBtn").addEventListener("click", () => {
            this.logs = [];
            this.renderLogs();
        });

        document.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", (e) => {
                document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
                e.target.classList.add("active");
                this.logFilter = e.target.dataset.level;
                this.renderLogs();
            });
        });

        document.querySelectorAll(".close-modal").forEach(b => {
            b.addEventListener("click", () => this.closeModals());
        });

        document.getElementById("confirmCancel").addEventListener("click", () => this.closeModals());
        document.getElementById("confirmOk").addEventListener("click", async () => {
            if (this._confirmFn) await this._confirmFn();
            this.closeModals();
        });

        document.getElementById("drawerCloseBtn").addEventListener("click", () => this.closeDrawer());
        document.getElementById("drawerBackdrop").addEventListener("click", () => this.closeDrawer());
        document.getElementById("drawerBackToHosts").addEventListener("click", () => {
            this.closeDrawer();
            this.setPage("hosts");
        });

        const hostNameEl = document.getElementById("drawerHostName");
        if (hostNameEl) {
            hostNameEl.addEventListener("click", () => {
                const hostname = hostNameEl.innerText;
                this.closeDrawer();
                this.setPage("hosts");
                const searchInput = document.getElementById("hostSearch");
                searchInput.value = hostname;
                sessionStorage.setItem("ag_search", hostname);
                this.searchTerm = hostname;
                this.renderHosts(hostname);
            });
        }

        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") this.closeDrawer();
        });

        document.getElementById("refreshSessionBtn").addEventListener("click", () => {
            this.renewSession();
        });

        this.initTouchEvents();
    }

    initTouchEvents() {
        const drawer = document.getElementById("routeDrawer");
        let touchStartX = 0;
        drawer.addEventListener("touchstart", (e) => {
            touchStartX = e.touches[0].clientX;
        }, false);
        drawer.addEventListener("touchmove", (e) => {
            if (!drawer.classList.contains("active")) return;
            const touchX = e.touches[0].clientX;
            const diff = touchX - touchStartX;
            if (diff > 50) {
                this.closeDrawer();
            }
        }, false);
    }

    async renewSession() {
        document.getElementById("sessionWarning").classList.remove("active");
        this.sessionWarningShown = false;
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

        const opts = { method, headers };
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
        document.getElementById("sessionWarning")?.classList.remove("active");
    }

    async doLogin(e) {
        e.preventDefault();
        const u = document.getElementById("username").value;
        const p = document.getElementById("password").value;

        const jwt = await this.api("/login", "POST", { username: u, password: p });
        if (jwt && jwt.token) {
            this.token = jwt.token;
            sessionStorage.setItem("ag_tok", this.token);
            this.finishLoginSuccess();
            this.parseJWTExpiry();
            return;
        }

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
        this.fetchVersion();
    }

    updateAuthButton() {
        const btn = document.getElementById("loginBtn");
        btn.innerText = (this.token || this.basic) ? "Logout" : "Login";
    }

    // ================== METRICS ==================
    async fetchMetrics() {
        const data = await this.api("/uptime");
        if (!data) return;

        this.lastUpdateTime = Date.now();
        document.querySelector(".stats-footer")?.classList.remove("stale");

        const stats = this.parseMetricsJSON(data);

        // Update last updated text
        document.getElementById("lastUpdatedText").innerText = `Updated ${this.timeAgo(this.lastUpdateTime)}`;

        // ===== SYSTEM STATS BAR - COMPLETE SYSTEM METRICS =====
        if (data.system) {
            // CPU Usage
            const cpuEl = document.getElementById("sysCpu");
            if (data.system.cpu_percent !== undefined) {
                cpuEl.innerText = `${data.system.cpu_percent.toFixed(1)}%`;
            } else {
                cpuEl.innerText = `${data.system.num_goroutine || 0} GRs`;
            }

            // Memory RSS
            const memEl = document.getElementById("sysMem");
            memEl.innerText = this.formatBytes(data.system.mem_rss || 0);

            // ADDITIONAL SYSTEM METRICS
            const cpuCoresEl = document.getElementById("sysCpuCores");
            if (cpuCoresEl) cpuCoresEl.innerText = data.system.num_cpu || '—';

            const goroutinesEl = document.getElementById("sysGoroutines");
            if (goroutinesEl) goroutinesEl.innerText = data.system.num_goroutine || '—';

            const memAllocEl = document.getElementById("sysMemAlloc");
            if (memAllocEl) memAllocEl.innerText = this.formatBytes(data.system.mem_alloc || 0);

            const memTotalEl = document.getElementById("sysMemTotal");
            if (memTotalEl) memTotalEl.innerText = this.formatBytes(data.system.mem_total || 0);

            const memSysEl = document.getElementById("sysMemSys");
            if (memSysEl) memSysEl.innerText = this.formatBytes(data.system.mem_sys || 0);

            const memUsedEl = document.getElementById("sysMemUsed");
            if (memUsedEl) memUsedEl.innerText = this.formatBytes(data.system.mem_used || 0);

            const memTotalOsEl = document.getElementById("sysMemTotalOs");
            if (memTotalOsEl) memTotalOsEl.innerText = this.formatBytes(data.system.mem_total_os || 0);
        }

        // Certificate counts - refresh from parsed certificates
        const activeCerts = this.certificates.filter(c => c.daysLeft > 0).length;
        const expiringCerts = this.certificates.filter(c => c.daysLeft > 0 && c.daysLeft < 7).length;
        document.getElementById("activeCertsCount").innerText = activeCerts;
        document.getElementById("expiringCertsCount").innerText = expiringCerts;

        // Footer stats
        document.getElementById("totalReqsStat").innerText = this.fmtNum(stats.total_reqs);
        document.getElementById("errorsStat").innerText = this.fmtNum(stats.total_errors);
        document.getElementById("meanResponseStat").innerText = stats.avg_ms.toFixed(0) + "ms";
        document.getElementById("activeBackendsStat").innerText = stats.active_backends;
        document.getElementById("apdexStat").innerText = stats.apdex;
        document.getElementById("uptimeStat").innerText = stats.uptime || "100%";

        // Error rate
        const errorRate = stats.total_reqs > 0 ? ((stats.total_errors / stats.total_reqs) * 100).toFixed(1) : 0;
        document.getElementById("errorRateText").innerText = `${errorRate}% errors`;

        // RPS calculation
        const now = Date.now();
        const timeDiff = (now - this.lastReqTime) / 1000;
        let rps = 0;
        if (this.lastReqTotal > 0 && timeDiff > 0 && stats.total_reqs >= this.lastReqTotal) {
            rps = (stats.total_reqs - this.lastReqTotal) / timeDiff;
        }
        this.lastReqTotal = stats.total_reqs;
        this.lastReqTime = now;
        document.getElementById("rpsStat").innerText = rps.toFixed(1);

        // Update metrics series for graph (using p99 latency)
        this.metricsSeries.push(stats.p99_ms || 0);
        if (this.metricsSeries.length > 60) this.metricsSeries.shift();
        this.renderGraph();
        this.renderHealthBar(stats.total_reqs, stats.total_errors);
    }

    parseMetricsJSON(obj) {
        let total_reqs = 0, total_errors = 0, active_backends = 0;
        let sumLat = 0, countLat = 0;
        let total_p99 = 0, hosts_with_p99 = 0;
        let uptime = "100%";

        if (obj.hosts) {
            Object.values(obj.hosts).forEach(h => {
                if (h.routes) h.routes.forEach(r => {
                    if (r.backends) r.backends.forEach(b => {
                        total_reqs += (b.total_reqs || 0);
                        total_errors += (b.failures || 0);

                        // FIXED: Only count HTTP backends as "active" for dashboard stats
                        const isHTTP = b.url && b.url.startsWith('http');
                        if (isHTTP) {
                            const healthy = b.healthy !== undefined ? b.healthy : (b.alive === true);
                            if (healthy) active_backends++;
                        }

                        // Latency metrics - apply to all backend types
                        if (b.latency_us && b.latency_us.count > 0) {
                            sumLat += b.latency_us.sum_us;
                            countLat += b.latency_us.count;

                            if (b.latency_us.p99 > 0) {
                                total_p99 += b.latency_us.p99;
                                hosts_with_p99++;
                            }
                        }
                    });
                });

                if (h.avg_p99_us > 0) {
                    total_p99 += h.avg_p99_us;
                    hosts_with_p99++;
                }
            });
        }

        const avg_ms = countLat > 0 ? (sumLat / countLat / 1000) : 0;
        const p99_ms = hosts_with_p99 > 0 ? (total_p99 / hosts_with_p99 / 1000) : 0;

        // Apdex based on average latency
        const apdex = avg_ms < 200 ? 1.0 : (avg_ms < 1000 ? 0.8 : 0.5);

        return {
            total_reqs,
            total_errors,
            active_backends,
            avg_ms,
            p99_ms,
            apdex: apdex.toFixed(2),
            uptime
        };
    }

    timeAgo(timestamp) {
        const seconds = Math.floor((Date.now() - timestamp) / 1000);
        if (seconds < 10) return 'just now';
        if (seconds < 60) return `${seconds}s ago`;
        return `${Math.floor(seconds / 60)}m ago`;
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

    renderGraph() {
        const el = document.getElementById("responseGraph");
        if (this.page !== "dashboard" || !el) return;

        const h = el.clientHeight || 200;
        const pTop = 15;
        const drawH = h - 30;

        if (this.metricsSeries.length === 0) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">⚡ Waiting for metrics...</div>`;
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
        const [config, stats] = await Promise.all([this.api("/config"), this.api("/uptime")]);
        if (!config || !config.hosts) return;

        this.hostsData.config = config.hosts;
        this.hostsData.stats = stats?.hosts || {};

        this.parseCertificates();

        const searchTerm = this.searchTerm;
        this.renderHosts(searchTerm);
    }

    // ================== RENDER HOSTS - COMPLETELY FIXED ==================
    renderHosts(filterTerm = "") {
        const container = document.getElementById("hostsContainer");
        const hosts = this.hostsData.config;
        const stats = this.hostsData.stats;

        filterTerm = filterTerm.toLowerCase();
        let html = "";
        let hostCount = 0, routeCount = 0;

        if (Object.keys(hosts).length === 0) {
            container.innerHTML = `<div class="empty-state">
            <span>🔮 No hosts configured</span>
            <span>Add a host in agbero.hcl and restart</span>
        </div>`;
            document.getElementById("heroHostCount").innerText = "0";
            document.getElementById("heroRouteCount").innerText = "0";
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
                    const hasAnyBackends = configBackends.length > 0 || uptimeBackends.length > 0;

                    if (hasAnyBackends) {
                        const displayBackends = uptimeBackends.length > 0 ? uptimeBackends : configBackends;
                        backendHtml = `<div class="backend-list">`;

                        displayBackends.forEach((b, bIdx) => {
                            const configBackend = configBackends[bIdx] || {};
                            const url = b.address || b.url || configBackend.address || configBackend.url;
                            const weight = configBackend.weight !== undefined ? configBackend.weight : (b.weight || '-');

                            const hasStats = uptimeBackends[bIdx] !== undefined;
                            let healthStatus = 'unknown';
                            let dotColor = 'warn';
                            let healthy = false;

                            if (hasStats) {
                                if (b.healthy !== undefined) {
                                    healthy = b.healthy;
                                    healthStatus = healthy ? 'ok' : 'down';
                                    dotColor = healthy ? 'ok' : 'down';
                                } else if (b.alive !== undefined) {
                                    const isTCPBackend = url && !url.startsWith('http');
                                    if (isTCPBackend) {
                                        healthy = true;
                                        healthStatus = b.alive ? 'ok' : 'warn';
                                        dotColor = b.alive ? 'ok' : 'warn';
                                    } else {
                                        healthy = b.alive === true;
                                        healthStatus = healthy ? 'ok' : 'down';
                                        dotColor = healthy ? 'ok' : 'down';
                                    }
                                }
                            }

                            if (url && url.toLowerCase().includes(filterTerm)) {
                                hostHasMatch = true;
                            }

                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;
                            const in_flight = b.in_flight || 0;

                            backendHtml += `
                            <div class="backend-row ${hasStats && healthStatus === 'down' ? 'down' : ''}">
                                <span class="dot ${dotColor}" title="${hasStats ? (healthStatus === 'ok' ? 'Healthy' : healthStatus === 'warn' ? 'Idle' : 'Unhealthy') : 'No data'}"></span>
                                <span class="be-url" onclick="event.stopPropagation(); app.copyToClipboard('${url}')">${url}</span>
                                <span class="be-stat">W: ${weight}</span>
                                <span class="be-stat">${p99}</span>
                                <span class="be-stat">${this.fmtNum(reqs)}</span>
                                <span class="be-badge">${in_flight > 0 ? `<span class="badge info">⚡${in_flight}</span>` : ''}</span>
                            </div>`;
                        });
                        backendHtml += `</div>`;
                    } else if (route.web && route.web.root) {
                        backendHtml = `<div class="backend-row"><span class="dot ok"></span> <span>📂 ${route.web.root}</span></div>`;
                        if (route.web.root.toLowerCase().includes(filterTerm)) hostHasMatch = true;
                    }

                    const shouldShowRoute = filterTerm === "" || hostHasMatch || pathMatches || route.protocol === 'tcp';

                    if (shouldShowRoute) {
                        hostHtml += `
                        <div class="route-block" onclick="app.openRouteDrawer('${hostname}', ${idx})">
                            <div class="route-header">
                                <span class="route-path">${route.path}</span>
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
    }

    copyToClipboard(text) {
        navigator.clipboard?.writeText(text).then(() => {}).catch(() => {});
    }

    // ================== DRAWER - FIXED HEALTH DETECTION ==================
    openRouteDrawer(hostname, routeIdx) {
        const route = this.hostsData.config[hostname].routes[routeIdx];
        const routeStats = this.hostsData.stats[hostname]?.routes?.[routeIdx] || {};

        document.getElementById("drawerRoutePath").innerText = route.path;
        document.getElementById("drawerHostName").innerText = hostname;

        const content = document.getElementById("drawerBody");
        content.innerHTML = "";

        // Handler section
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

        const configBackends = route.backends?.servers || [];
        const statBackends = routeStats.backends || [];
        const displayBackends = configBackends.length > 0 ? configBackends : statBackends;

        if (displayBackends.length > 0) {
            let backendsHtml = "";

            displayBackends.forEach((b, i) => {
                const s = statBackends[i] || {};
                const url = b.address || b.url || s.url || s.address;
                const weight = (b.weight !== undefined) ? b.weight : (s.weight || '-');

                // Proper health detection for drawer (same logic as renderHosts)
                const hasStats = statBackends[i] !== undefined;
                let healthStatus = 'unknown';
                let dotColor = 'warn';
                let healthy = false;

                if (hasStats) {
                    if (s.healthy !== undefined) {
                        healthy = s.healthy;
                        healthStatus = healthy ? 'ok' : 'down';
                        dotColor = healthy ? 'ok' : 'down';
                    }
                    else if (s.alive !== undefined) {
                        const isTCPBackend = url && !url.startsWith('http');
                        if (isTCPBackend) {
                            healthy = true;
                            healthStatus = s.alive ? 'ok' : 'warn';
                            dotColor = s.alive ? 'ok' : 'warn';
                        } else {
                            healthy = s.alive === true;
                            healthStatus = healthy ? 'ok' : 'down';
                            dotColor = healthy ? 'ok' : 'down';
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

            const lbStrategy = route.backends?.lb_strategy || route.backends?.load_balancing?.strategy || "round_robin";
            let strategyDisplay = "Round Robin";
            if (lbStrategy === "least_conn") strategyDisplay = "Least Connections";
            else if (lbStrategy === "ip_hash") strategyDisplay = "IP Hash";
            else if (lbStrategy === "uri_hash") strategyDisplay = "URI Hash";

            const healthCheck = route.health_check || route.backends?.health_check;
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
            const cb = route.circuit_breaker || route.backends?.circuit_breaker;
            if (cb && cb.enabled) {
                const cbStatus = s.circuit_breaker_state || 'closed';
                const cbClass = cbStatus === 'closed' ? 'success' : (cbStatus === 'open' ? 'error' : 'warning');
                cbHtml = `
                    <div class="kv-item"><label>Circuit Breaker</label><div><span class="badge ${cbClass}">${cbStatus} | ${cb.failure_threshold || 5} fails</span></div></div>
                `;
            }

            const timeouts = route.timeouts || {};
            const readTimeout = timeouts.read ? (timeouts.read/1000000000)+'s' : 'inherit';
            const writeTimeout = timeouts.write ? (timeouts.write/1000000000)+'s' : 'inherit';
            const idleTimeout = timeouts.idle ? (timeouts.idle/1000000000)+'s' : 'inherit';

            let compressionHtml = '';
            const compression = route.compression_config || {};
            if (compression.enabled) {
                const algo = compression.type || 'gzip';
                const level = compression.level || 'default';
                compressionHtml = `
                    <div class="kv-item"><label>Compression</label><div><span class="badge info">${algo} (lvl ${level})</span></div></div>
                `;
            }

            let rateLimitHtml = '';
            const rl = route.rate_limit;
            if (rl) {
                const keyType = rl.key || 'ip';
                rateLimitHtml = `
                    <div class="kv-item"><label>Rate Limit</label><div><span class="badge warning">${rl.requests || 0} req / ${rl.window_seconds || 60}s (${keyType})</span></div></div>
                `;
            }

            let wasmHtml = '';
            const wasm = route.wasm;
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
        const hostCerts = this.certificates.filter(c => c.host === hostname);
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
        const mw = route.middleware || {};

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
                    <pre>${JSON.stringify(route, null, 2)}</pre>
                </div>
            </div>`;

        document.getElementById("drawerBackdrop").classList.add("active");
        document.getElementById("routeDrawer").classList.add("active");
    }

    closeDrawer() {
        document.getElementById("drawerBackdrop").classList.remove("active");
        document.getElementById("routeDrawer").classList.remove("active");
    }

    // ================== FIREWALL ==================
    async fetchFirewall() {
        const res = await this.api("/firewall");
        const tbody = document.getElementById("firewallTable");
        tbody.innerHTML = "";

        if (!res) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">⚠️ Firewall unavailable</div></td></tr>`;
            return;
        }

        if (res.enabled === false) {
            tbody.innerHTML = `<tr><td colspan="5" style="padding:20px;"><div class="empty-state">
                <span>🛡️ Firewall disabled</span>
                <span>Enable in agbero.hcl to block IPs</span>
            </div></td></tr>`;
            return;
        }

        const rules = res.rules || res || [];
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
    }

    confirmDeleteFw(ip) {
        this.confirm("Unblock IP", `Remove ${ip} from firewall?`, async () => {
            await this.deleteFw(ip);
        });
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

        if (this.logs.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute); text-align:center; padding:40px;">
                <span style="display:block; font-size:24px; margin-bottom:10px;">📭</span>
                No logs yet. Waiting for traffic...
            </div>`;
            return;
        }

        const filtered = this.logs.filter(l => {
            if (this.logFilter === "ALL") return true;
            let lvl = "INFO";
            if (typeof l === 'object') lvl = l.lvl || "INFO";
            else if (typeof l === 'string' && l.includes("ERR")) lvl = "ERROR";
            return lvl === this.logFilter;
        });

        if (filtered.length === 0) {
            container.innerHTML = `<div style="color:var(--text-mute);text-align:center; padding:20px;">No logs for filter: ${this.logFilter}</div>`;
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