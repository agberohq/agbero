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
        this.logs = [];
        this.logsPaused = false;
        this.timers = {};

        this.init();
    }

    init() {
        this.loadTheme();
        this.bindEvents();
        this.updateAuthButton();
        this.startLoop();
        this.fetchHostsData();
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
        document.querySelectorAll(".close-modal").forEach(b => {
            b.addEventListener("click", () => document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active")));
        });
        // Confirm Modal
        document.getElementById("confirmCancel").addEventListener("click", () => this.closeModals());
        document.getElementById("confirmOk").addEventListener("click", async () => {
            if (this._confirmFn) await this._confirmFn();
            this.closeModals();
        });
    }

    setPage(p) {
        this.page = p;
        document.querySelectorAll(".nav-link").forEach(n => n.classList.remove("active"));
        document.querySelector(`.nav-link[data-page="${p}"]`)?.classList.add("active");
        document.querySelectorAll(".page").forEach(div => div.classList.remove("active"));
        document.getElementById(p + "Page").classList.add("active");
        this.refreshCurrentPage();
    }

    startLoop() {
        this.timers.metrics = setInterval(() => this.fetchMetrics(), 2000);
        this.timers.config = setInterval(() => {
            if (this.page === 'hosts') this.fetchHostsData();
        }, 10000);
        this.timers.logs = setInterval(() => {
            if (this.page === 'logs' && !this.logsPaused) this.fetchLogs();
        }, 2000);
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
            if (res.status === 401) {
                this.logout();
                return null;
            }
            if (res.status === 204) return true;
            return await res.json();
        } catch (e) {
            return null;
        }
    }

    // ================== METRICS ==================
    async fetchMetrics() {
        const data = await this.api("/uptime");
        if (!data) return;

        // 1. Calculate aggregated stats
        const stats = this.parseMetricsJSON(data);

        // 2. Update Footer Stats
        document.getElementById("totalReqsStat").innerText = this.fmtNum(stats.total_reqs);
        document.getElementById("errorsStat").innerText = this.fmtNum(stats.total_errors);
        document.getElementById("meanResponseStat").innerText = stats.avg_ms.toFixed(0) + "ms";
        document.getElementById("activeBackendsStat").innerText = stats.active_backends;
        document.getElementById("apdexStat").innerText = stats.apdex;

        // 3. Update Hero System Stats
        document.getElementById("sysCpu").innerText = stats.sys_cpu;
        document.getElementById("sysMem").innerText = stats.sys_mem;

        // 4. Calculate RPS
        const now = Date.now();
        const timeDiff = (now - this.lastReqTime) / 1000;
        let rps = 0;
        if (this.lastReqTotal > 0 && timeDiff > 0 && stats.total_reqs >= this.lastReqTotal) {
            rps = (stats.total_reqs - this.lastReqTotal) / timeDiff;
        }
        this.lastReqTotal = stats.total_reqs;
        this.lastReqTime = now;
        document.getElementById("rpsStat").innerText = rps.toFixed(1);

        // 5. Update Graph
        this.metricsSeries.push(stats.avg_ms);
        if (this.metricsSeries.length > 60) this.metricsSeries.shift();
        this.renderGraph();
    }

    parseMetricsJSON(obj) {
        let total_reqs = 0, total_errors = 0, active_backends = 0;
        let sumLat = 0, countLat = 0;

        // Host Stats
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

        // System Stats (from Go runtime)
        let sys_cpu = "—";
        let sys_mem = "—";

        if (obj.system) {
            // obj.system matches the Go struct: { num_goroutine, mem_rss, ... }
            sys_cpu = (obj.system.num_goroutine || 0) + " GRs";
            sys_mem = this.formatBytes(obj.system.mem_rss || 0);
        }

        return {
            total_reqs, total_errors, active_backends, avg_ms,
            apdex: apdex.toFixed(2),
            sys_cpu, sys_mem
        };
    }

    renderGraph() {
        const el = document.getElementById("responseGraph");
        if(this.page !== "dashboard") return;

        // Dimensions
        const rect = el.getBoundingClientRect();
        const w = rect.width;
        const h = rect.height;

        // Padding for labels
        const pTop = 15;
        const pBottom = 15;
        const drawH = h - pTop - pBottom;

        if (this.metricsSeries.length === 0) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">Waiting for data...</div>`;
            return;
        }

        const max = Math.max(10, ...this.metricsSeries) * 1.1;

        // 1. Generate Bars
        const bars = this.metricsSeries.map((val, i) => {
            const barH = Math.max(2, (val / max) * drawH);
            const x = (i / 60) * 100;
            const width = (100 / 60) - 0.3;

            let color = "var(--accent)"; // Default color
            if(val > 200) color = "var(--warning)";
            if(val > 500) color = "var(--danger)";

            // y pos accounting for padding
            const y = (pTop + drawH) - barH;

            return `<rect x="${x}%" y="${y}" width="${width}%" height="${barH}" fill="${color}" rx="1"></rect>`;
        }).join("");

        // 2. Y-Axis Label (Top Left - Max Value)
        const yLabel = `<text x="0" y="10" fill="var(--text-mute)" font-size="10" font-family="monospace" font-weight="500">${max.toFixed(0)}ms</text>`;

        // 3. X-Axis Labels (Bottom - Time)
        const xLabels = `
            <text x="0" y="${h}" fill="var(--text-mute)" font-size="10" font-family="monospace">-2m</text>
            <text x="50%" y="${h}" fill="var(--text-mute)" font-size="10" font-family="monospace" text-anchor="middle">-1m</text>
            <text x="100%" y="${h}" fill="var(--text-mute)" font-size="10" font-family="monospace" text-anchor="end">now</text>
        `;

        // 4. Reference Line (Dashed line at top value)
        const grid = `<line x1="0" y1="${pTop}" x2="100%" y2="${pTop}" stroke="var(--border)" stroke-dasharray="4 4" stroke-width="1" />`;

        el.innerHTML = `<svg width="100%" height="100%">${grid}${yLabel}${xLabels}${bars}</svg>`;
    }

    // ================== HOSTS ==================
    async fetchHostsData() {
        const [config, stats] = await Promise.all([this.api("/config"), this.api("/uptime")]);
        if (!config || !config.hosts) return;

        const container = document.getElementById("hostsContainer");
        let html = "";
        let hostCount = 0, routeCount = 0;

        for (const [hostname, cfg] of Object.entries(config.hosts)) {
            hostCount++;
            const rtStats = stats?.hosts?.[hostname] || {};

            // TLS Badge
            let tlsMode = cfg.tls?.mode || "";
            let badges = "";
            let tlsClass = "tls";
            let tlsText = "Auto (Secure)"; // Default

            if (tlsMode === "none") {
                tlsClass = "sec";
                tlsText = "No TLS";
            } else if (tlsMode === "lets_encrypt" || tlsMode === "letsencrypt") {
                tlsText = "Let's Encrypt";
            } else if (tlsMode === "local" || tlsMode === "local_auto") {
                tlsClass = "local";
                tlsText = "Local TLS";
            } else if (tlsMode === "") {
                if (hostname.endsWith(".localhost")) {
                    tlsClass = "local";
                    tlsText = "Auto (mkcert)";
                }
            }
            badges += `<span class="badge ${tlsClass}">${tlsText}</span> `;

            html += `
            <div class="host-row">
                <div class="host-header">
                    <div class="host-name">${hostname} ${badges}</div>
                    <div class="host-meta">${cfg.domains?.join(", ")}</div>
                </div>`;

            if (cfg.routes) {
                cfg.routes.forEach((route, idx) => {
                    routeCount++;
                    const routeStats = rtStats.routes?.[idx];

                    let routeBadges = "";
                    if (route.allowed_ips) routeBadges += `<span class="badge sec">IP Limit</span> `;
                    if (route.basic_auth) routeBadges += `<span class="badge auth">Auth</span> `;
                    if (route.web && route.web.root) routeBadges += `<span class="badge">Static</span> `;

                    let backendHtml = "";
                    const backendList = routeStats?.backends || (route.backends?.servers || []);

                    if (backendList.length > 0) {
                        backendHtml = `<div class="backend-list">`;
                        backendList.forEach(b => {
                            const url = b.url || b.address;
                            const alive = b.alive !== false;
                            const p99 = b.latency_us?.p99 ? (b.latency_us.p99 / 1000).toFixed(0) + "ms" : "-";
                            const reqs = b.total_reqs || 0;

                            backendHtml += `
                                <div class="backend-row ${alive ? '' : 'down'}">
                                    <span class="dot ${alive ? 'ok pulse' : 'down'}"></span>
                                    <span class="be-url">${url}</span>
                                    <span class="be-stat">W: ${b.weight || '-'}</span>
                                    <span class="be-stat">${p99}</span>
                                    <span class="be-stat">${this.fmtNum(reqs)}</span>
                                </div>`;
                        });
                        backendHtml += `</div>`;
                    } else if (route.web && route.web.root) {
                        backendHtml = `<div class="backend-row"><span class="dot ok pulse"></span> <span>📂 ${route.web.root}</span></div>`;
                    }

                    html += `
                        <div class="route-block">
                            <div class="route-header">
                                <span class="route-path">${route.path}</span>
                                <div class="route-badges">${routeBadges}</div>
                            </div>
                            ${backendHtml}
                        </div>`;
                });
            }
            html += `</div>`;
        }

        container.innerHTML = html;
        document.getElementById("heroHostCount").innerText = hostCount;
        document.getElementById("heroRouteCount").innerText = routeCount;
    }

    // ================== UTILS & OTHER PAGES ==================
    async fetchFirewall() { /* ... same as before ... */
        const res = await this.api("/firewall");
        const tbody = document.getElementById("firewallTable");
        tbody.innerHTML = "";

        // Handle Disabled state
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
                </tr>
            `).join("");
        }
    }

    async addFirewallRule(e) { /* ... same ... */
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

    async fetchLogs() {
        const n = document.getElementById("logsTailSelect").value;
        const data = await this.api(`/logs?lines=${n}`);
        if (data && Array.isArray(data)) {
            this.logs = data.reverse();
            this.renderLogs();
        }
    }

    renderLogs() { /* ... same ... */
        document.getElementById("logsList").innerHTML = this.logs.map(l => {
            let lvl = "INFO", msg = "", ts = "";
            if (typeof l === 'string') {
                try {
                    l = JSON.parse(l);
                } catch {
                    msg = l;
                }
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

    handleAuthClick() {
        if (this.token || this.basic) this.logout(); else this.openModal("loginModal");
    }

    async doLogin(e) { /* ... same ... */
        e.preventDefault();
        const u = document.getElementById("username").value, p = document.getElementById("password").value;
        const jwt = await this.api("/login", "POST", {username: u, password: p});
        if (jwt && jwt.token) {
            this.token = jwt.token;
            sessionStorage.setItem("ag_tok", this.token);
            this.closeModals();
            this.updateAuthButton();
            return;
        }
        this.basic = btoa(u + ":" + p);
        const check = await this.api("/config");
        if (check) {
            sessionStorage.setItem("ag_bas", this.basic);
            this.closeModals();
            this.updateAuthButton();
        } else {
            this.basic = null;
            alert("Login Failed");
        }
    }

    logout() {
        this.token = null;
        this.basic = null;
        sessionStorage.clear();
        this.updateAuthButton();
        window.location.reload();
    }

    updateAuthButton() {
        document.getElementById("loginBtn").innerText = (this.token || this.basic) ? "Logout" : "Login";
    }

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

    openModal(id) {
        document.getElementById(id).classList.add("active");
    }

    closeModals() {
        document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    }

    confirm(t, msg, fn) {
        this._confirmFn = fn;
        document.getElementById("confirmTitle").innerText = t;
        document.getElementById("confirmText").innerText = msg;
        this.openModal("confirmModal");
    }
}

window.app = new AgberoApp();