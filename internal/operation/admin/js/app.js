class AgberoApp {
    constructor() {
        this.apiBase = window.location.origin;
        this.token = sessionStorage.getItem("ag_tok");
        this.basic = sessionStorage.getItem("ag_bas");

        this.page = "dashboard";
        this.metricsHistory = {
            all: [],
            http:[],
            tcp:[]
        };
        this.activeChart = 'all';
        this.lastReqTotal = 0;
        this.lastReqTime = Date.now();
        this.lastUpdateTime = Date.now();
        this.staleTimer = null;
        this.searchTerm = sessionStorage.getItem("ag_search") || "";
        this.sessionExpiry = null;
        this.sessionWarningShown = false;
        this.version = null;
        this.build = null;

        this.hostsData = { config: {}, stats: {} };
        this.gitStats = {};
        this.logs =[];
        this.certificates =[];

        this.logsPaused = false;
        this.mapPaused = false;
        this.logFilter = "ALL";
        this.isOnline = true;

        this.timers = { metrics: null, config: null, logs: null };
        this.page = sessionStorage.getItem("ag_page") || "dashboard";
        this.lastConfig = null;
        this.lastStatsData = null; // Store stats for cluster page
        this._confirmFn = null;

        this.routeGraph = new RouteGraph("graphContainer");
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
            this.setOnlineState(true);

            if (res.status === 401) {
                this.handleSessionExpired();
                return null;
            }
            if (res.status === 204) return true;
            if (res.status === 404) return null;
            const text = await res.text();
            try {
                return text ? JSON.parse(text) : null;
            } catch {
                return text;
            }
        } catch (e) {
            this.setOnlineState(false);
            return null;
        }
    }

    setOnlineState(online) {
        if (this.isOnline === online) return;
        this.isOnline = online;

        const banner = document.getElementById("offlineBanner");
        if (banner) {
            if (online) {
                banner.classList.remove("active");
            } else {
                banner.classList.add("active");
            }
        }

        if (this.token || this.basic) {
            this.startLoop();
        }
    }

    async fetchVersion() {
        try {
            const config = await this.api("/config");
            if (config && config.global && config.global.version) {
                this.version = "v" + config.global.version;
                this.build = "b" + config.global.build;
            } else {
                this.version = "dev";
                this.build = "dev";
            }
        } catch (e) {
            this.version = "—";
            this.build = "—";
        }
        UI.updateVersionDisplay(this.version);
    }

    async fetchMetrics() {
        const data = await this.api("/uptime");
        if (!data) return;

        this.lastUpdateTime = Date.now();
        this.lastStatsData = data;
        this.gitStats = data.git || {};

        const stats = this.parseMetricsJSON(data);
        const metrics = {
            stats,
            system: data.system || {},
            certificates: this.certificates,
            lastReqTotal: this.lastReqTotal,
            lastReqTime: this.lastReqTime,
            lastUpdateTime: this.lastUpdateTime
        };

        const global = data.global || {};
        this.metricsHistory.all.push(global.avg_p99_ms || 0);
        this.metricsHistory.http.push(global.http_p99_ms || 0);
        this.metricsHistory.tcp.push(global.tcp_p99_ms || 0);

        ['all', 'http', 'tcp'].forEach(k => {
            if (this.metricsHistory[k].length > 60) this.metricsHistory[k].shift();
        });

        UI.updateMetrics(metrics, this.metricsHistory[this.activeChart]);

        // Refresh Cluster page if active
        if (this.page === 'cluster') {
            UI.renderClusterPage(this.lastConfig?.cluster, data.cluster);
        }
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

                        const isHTTP = b.url && b.url.startsWith('http');
                        if (isHTTP) {
                            const hStat = b.health?.status || 'Unknown';
                            if (hStat === 'Healthy' || hStat === 'Degraded' || (hStat === 'Unknown' && b.alive)) {
                                active_backends++;
                            }
                        }

                        if (b.latency_us && b.latency_us.count > 0) {
                            sumLat += b.latency_us.sum_us || 0;
                            countLat += b.latency_us.count || 0;
                        }
                    });
                });

                if (h.proxies) h.proxies.forEach(p => {
                    if (p.backends) p.backends.forEach(b => {
                        total_reqs += (b.total_reqs || 0);
                        total_errors += (b.failures || 0);

                        const isHTTP = b.url && b.url.startsWith('http');
                        if (isHTTP) {
                            const hStat = b.health?.status || 'Unknown';
                            if (hStat === 'Healthy' || hStat === 'Degraded' || (hStat === 'Unknown' && b.alive)) {
                                active_backends++;
                            }
                        }

                        if (b.latency_us && b.latency_us.count > 0) {
                            sumLat += b.latency_us.sum_us || 0;
                            countLat += b.latency_us.count || 0;
                        }
                    });
                });
            });
        }

        const avg_ms = countLat > 0 ? (sumLat / countLat / 1000) : 0;
        const apdex = avg_ms < 200 ? 1.0 : (avg_ms < 1000 ? 0.8 : 0.5);

        return {
            total_reqs,
            total_errors,
            active_backends,
            avg_ms,
            apdex: apdex.toFixed(2),
            uptime: "100%"
        };
    }

    async fetchHostsData() {
        const[config, stats] = await Promise.all([this.api("/config"), this.api("/uptime")]);
        if (!config || !config.hosts) return;

        this.hostsData.config = config.hosts;
        this.hostsData.stats = stats?.hosts || {};
        this.gitStats = stats?.git || {};
        this.lastConfig = config;
        this.lastStatsData = stats;

        this.parseCertificates();
        UI.renderHosts(this.hostsData, this.searchTerm, this.certificates);
        UI.updateHeroCounts(Object.keys(this.hostsData.config).length, this.getRouteCount());

        if (this.page === 'map' && !this.mapPaused) {
            this.routeGraph.render(this.lastConfig, this.hostsData.stats);
        }
        if (this.page === 'cluster') {
            UI.renderClusterPage(config.cluster, stats?.cluster);
        }
    }

    getRouteCount(config = this.hostsData.config) {
        let count = 0;
        if (!config) return 0;
        Object.values(config).forEach(host => {
            if (host.routes) count += host.routes.length;
            if (host.proxies) count += host.proxies.length;
        });
        return count;
    }

    parseCertificates() {
        const certs =[];
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
    }

    async fetchFirewall() {
        const res = await this.api("/firewall");
        UI.renderFirewall(res);
    }

    async deleteFw(ip) {
        if (!ip) return;
        await this.api(`/firewall?ip=${encodeURIComponent(ip)}`, "DELETE");
        this.fetchFirewall();
    }

    async confirmDeleteFw(ip) {
        this.confirm("Unblock IP", `Are you sure you want to unblock ${ip}?`, () => this.deleteFw(ip));
    }

    async addFirewallRule(e) {
        e.preventDefault();
        const body = {
            ip: document.getElementById("fwIp").value,
            reason: document.getElementById("fwReason").value,
            path: document.getElementById("fwPath").value,
            duration_sec: parseInt(document.getElementById("fwDuration").value) || 0
        };
        await this.api("/firewall", "POST", body);
        Modal.closeAll();
        this.fetchFirewall();
    }

    async addClusterRoute(e) {
        e.preventDefault();
        const host = document.getElementById("crHost").value;
        const path = document.getElementById("crPath").value;
        const target = document.getElementById("crTarget").value;
        const ttl = parseInt(document.getElementById("crTTL").value) || 0;

        const body = {
            host: host,
            ttl_seconds: ttl,
            route: {
                path: path,
                backends: {
                    servers: [{ address: target }]
                }
            }
        };

        const res = await this.api("/api/v1/routes", "POST", body);
        if (res && res.error) {
            alert("Error: " + res.error);
        } else {
            Modal.closeAll();
            this.fetchHostsData();
        }
    }

    async fetchConfig() {
        const data = await this.api("/config");
        this.lastConfig = data;

        if (data) {
            const bindHttp = data.global?.bind?.http;
            const bindHttps = data.global?.bind?.https;

            const metrics = {
                httpPort: bindHttp && bindHttp[0] ? bindHttp[0].replace(':', '') : '80',
                httpsPort: bindHttps && bindHttps[0] ? bindHttps[0].replace(':', '') : '443',
                version: "v" + (data.global?.version || '?'),
                build: data.global?.build || 'dev',
                logLevel: data.global?.logging?.level || 'info',
                hostCount: Object.keys(data.hosts || {}).length,
                routeCount: this.getRouteCount(data.hosts),
                tlsCount: this.getTLSConfigCount(data)
            };

            UI.renderConfigMetrics(metrics);
            UI.renderGlobalSettings(data.global);
            UI.renderClusterSettings(data.cluster);
            UI.renderRawConfig(data);
            this.updateConfigTitle(metrics.version, metrics.build);
        }
    }

    getTLSConfigCount(config) {
        let count = 0;
        if (!config.hosts) return 0;

        Object.values(config.hosts).forEach(host => {
            if (host.tls && host.tls.mode && host.tls.mode !== 'none') count++;
        });
        return count;
    }

    async fetchLogs() {
        const select = document.getElementById("logsTailSelect");
        if (!select) return;

        const n = select.value;
        const data = await this.api(`/logs?lines=${n}`);
        if (data && Array.isArray(data)) {
            this.logs = data.reverse();
            UI.renderLogs(this.logs, this.logFilter);
        }
    }

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
                UI.showSessionWarning(timeLeft);
            }
        };
        setInterval(checkExpiry, 10000);
        checkExpiry();
    }

    renewSession() {
        UI.hideSessionWarning();
        this.sessionWarningShown = false;
    }

    handleSessionExpired() {
        this.stopLoop();
        sessionStorage.clear();
        this.token = null;
        this.basic = null;
        this.updateAuthButton();
        Modal.open("loginModal");
        UI.hideSessionWarning();
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
        const check = await this.api("/uptime");
        if (check) {
            sessionStorage.setItem("ag_bas", this.basic);
            this.finishLoginSuccess();
        } else {
            this.basic = null;
            alert("Login Failed");
        }
    }

    finishLoginSuccess() {
        Modal.closeAll();
        this.updateAuthButton();
        this.startLoop();
        this.fetchHostsData();
        this.fetchVersion();

        const savedPage = sessionStorage.getItem("ag_page");
        if (savedPage && savedPage !== "dashboard") {
            this.setPage(savedPage);
        }
    }

    handleAuthClick() {
        if (this.token || this.basic) {
            sessionStorage.clear();
            this.token = null;
            this.basic = null;
            this.stopLoop();
            this.updateAuthButton();
            window.location.reload();
        } else {
            Modal.open("loginModal");
        }
    }

    updateAuthButton() {
        const btn = document.getElementById("loginBtn");
        if (btn) btn.innerText = (this.token || this.basic) ? "Logout" : "Login";
    }

    updateConfigTitle(version, build) {
        const titleEl = document.querySelector('#configPage .config-header h2');
        if (titleEl) {
            titleEl.innerHTML = `Configuration Overview <span style="font-size: 14px; color: var(--text-mute); margin-left: 10px;">${version} (${build})</span>`;
        }
    }

    startLoop() {
        this.stopLoop();
        const interval = this.isOnline ? 2000 : 10000;

        this.timers.metrics = setInterval(() => this.fetchMetrics(), interval);
        this.timers.config = setInterval(() => {
            if (this.page === 'hosts' || this.page === 'map' || this.page === 'cluster') this.fetchHostsData();
        }, this.isOnline ? 10000 : 30000);
        this.timers.logs = setInterval(() => {
            if (this.page === 'logs' && !this.logsPaused) this.fetchLogs();
        }, interval);
    }

    stopLoop() {
        if (this.timers.metrics) clearInterval(this.timers.metrics);
        if (this.timers.config) clearInterval(this.timers.config);
        if (this.timers.logs) clearInterval(this.timers.logs);
        this.timers = { metrics: null, config: null, logs: null };
    }

    setPage(p) {
        this.page = p;
        sessionStorage.setItem("ag_page", p);

        document.querySelectorAll(".nav-link").forEach(n => n.classList.remove("active"));
        const link = document.querySelector(`.nav-link[data-page="${p}"]`);
        if (link) link.classList.add("active");

        document.querySelectorAll(".page").forEach(div => div.classList.remove("active"));
        const page = document.getElementById(p + "Page");
        if (page) page.classList.add("active");

        if (this.token || this.basic) {
            this.refreshCurrentPage();
        }
    }

    async refreshCurrentPage() {
        if (this.page === 'hosts') await this.fetchHostsData();
        if (this.page === 'firewall') await this.fetchFirewall();
        if (this.page === 'config') await this.fetchConfig();
        if (this.page === 'logs') await this.fetchLogs();
        if (this.page === 'map') await this.fetchHostsData();
        if (this.page === 'cluster') {
            await this.fetchConfig();
            await this.fetchMetrics();
        }
    }

    fmtNum(n) {
        if (n === undefined || n === null) return "0";
        if (n >= 1000000) return (n / 1000000).toFixed(1) + "M";
        if (n >= 1000) return (n / 1000).toFixed(1) + "k";
        return n;
    }

    formatBytes(b) {
        if (b === 0 || !b) return "0";
        const k = 1024, s =["B", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(b) / Math.log(k));
        return parseFloat((b / Math.pow(k, i)).toFixed(1)) + s[i];
    }

    copyToClipboard(text) {
        if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                const btn = event.target;
                if(btn && btn.innerText) {
                    const oldText = btn.innerText;
                    btn.innerText = "Copied!";
                    setTimeout(() => btn.innerText = oldText, 2000);
                }
            }).catch(() => {});
        }
    }

    confirm(title, msg, fn) {
        this._confirmFn = fn;
        UI.showConfirmDialog(title, msg);
        Modal.open("confirmModal");
    }

    openRouteDrawer(hostname, idx, type = 'route') {
        let cfg_item;
        let itemStats = {};

        if (!this.hostsData.config || !this.hostsData.config[hostname]) return;

        if (type === 'proxy') {
            const proxies = this.hostsData.config[hostname].proxies;
            if (proxies && proxies[idx]) {
                cfg_item = proxies[idx];
                itemStats = (this.hostsData.stats[hostname]?.proxies && this.hostsData.stats[hostname].proxies[idx]) || {};
            }
        } else {
            const routes = this.hostsData.config[hostname].routes;
            if (routes && routes[idx]) {
                cfg_item = routes[idx];
                itemStats = (this.hostsData.stats[hostname]?.routes && this.hostsData.stats[hostname].routes[idx]) || {};
            }
        }

        if (cfg_item) {
            UI.renderDrawer(hostname, cfg_item, itemStats, type, this.certificates, idx);
            Drawer.open("routeDrawer");
        }
    }

    openBackendDrawer(hostname, routeIdx, backendIdx, type) {
        let cfg_item;
        let bStat = {};

        if (type === 'proxy') {
            cfg_item = this.hostsData.config[hostname]?.proxies?.[routeIdx]?.backends?.[backendIdx];
            bStat = (this.hostsData.stats[hostname]?.proxies?.[routeIdx]?.backends && this.hostsData.stats[hostname].proxies[routeIdx].backends[backendIdx]) || {};
        } else {
            cfg_item = this.hostsData.config[hostname]?.routes?.[routeIdx]?.backends?.servers?.[backendIdx];
            bStat = (this.hostsData.stats[hostname]?.routes?.[routeIdx]?.backends && this.hostsData.stats[hostname].routes[routeIdx].backends[backendIdx]) || {};
        }

        if (cfg_item || bStat.url) {
            UI.renderBackendDrawer(hostname, cfg_item || {}, bStat, type);
            Drawer.open("backendDrawer");
        }
    }

    closeDrawer(id) {
        Drawer.close(id);
    }

    setChartType(type) {
        this.activeChart = type;
        document.querySelectorAll('.chart-tab').forEach(t => t.classList.remove('active'));
        const tab = document.querySelector(`.chart-tab[data-type="${type}"]`);
        if (tab) tab.classList.add('active');
        UI.renderGraph(this.metricsHistory[type]);
    }

    init() {
        this.loadTheme();
        this.updateAuthButton();
        this.fetchVersion();

        if (this.token || this.basic) {
            this.startLoop();
            this.fetchHostsData();
            this.parseJWTExpiry();
        } else {
            Modal.open("loginModal");
        }

        if (this.searchTerm) {
            const searchInput = document.getElementById("hostSearch");
            if (searchInput) {
                searchInput.value = this.searchTerm;
            }
        }

        this.startStaleDetection();
        EventHandler.bindAll(this);

        document.querySelectorAll('.chart-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                const type = e.target.dataset.type;
                this.setChartType(type);
            });
        });
    }

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

    startStaleDetection() {
        this.staleTimer = setInterval(() => {
            const staleTime = Date.now() - this.lastUpdateTime;
            UI.updateStaleState(staleTime > 10000);
        }, 1000);
    }
}