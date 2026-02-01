class AgberoAdmin {
    constructor() {
        this.baseUrl = window.location.origin;

        this.token = sessionStorage.getItem("agbero_token") || null;
        this.basicAuth = sessionStorage.getItem("agbero_basic") || null;
        this.isAuthenticated = !!(this.token || this.basicAuth);

        this.currentPage = "dashboard";

        // Polling intervals
        this.metricsPollMs = 2500;
        this.healthPollMs = 5000;
        this.logsPollMs = 2000;

        this.metricsTimer = null;
        this.healthTimer = null;

        // Metrics rolling series
        this.metricsSeriesMax = 180;
        this.metricsSeries = []; // [{t,p50_ms,p90_ms,p99_ms,mean_ms,max_ms,errors}]

        // Uptime tracking
        this.lastStatusAtMs = Date.now();
        this.wasUp = null;
        this.upMs = 0;
        this.downMs = 0;

        // Apdex threshold (ms)
        this.apdexTms = 200;

        // Logs
        this.logsTailDefault = 200;
        this.logsMaxInMemory = 1000;
        this.logs = []; // newest at end
        this.logsTimer = null;
        this.logsEventSource = null;
        this.logsPaused = false;

        // Graph
        this._resizeObs = null;

        this.init();
    }

    init() {
        this.cacheEls();
        this.bindEvents();
        this.updateAuthUI();
        this.setupResizeObserver();
        this.loadInitialData();
    }

    cacheEls() {
        this.el = {
            header: document.querySelector(".top-header"),

            // Nav / actions
            refreshBtn: document.getElementById("refreshBtn"),
            loginBtn: document.getElementById("loginBtn"),
            addRuleBtn: document.getElementById("addRuleBtn"),
            reloadConfigBtn: document.getElementById("reloadConfigBtn"),
            addHostBtn: document.getElementById("addHostBtn"),

            // Dashboard
            timeRange: document.getElementById("timeRange"),
            responseGraph: document.getElementById("responseGraph"),
            meanResponse: document.getElementById("meanResponse"),

            uptimeStat: document.getElementById("uptimeStat"),
            downtimeStat: document.getElementById("downtimeStat"),
            apdexStat: document.getElementById("apdexStat"),
            meanResponseStat: document.getElementById("meanResponseStat"),
            headerSizeStat: document.getElementById("headerSizeStat"),
            bodySizeStat: document.getElementById("bodySizeStat"),
            errorsStat: document.getElementById("errorsStat"),

            metricsRaw: document.getElementById("metricsRaw"),

            // Hosts/Config/Firewall
            hostsList: document.getElementById("hostsList"),
            firewallTable: document.getElementById("firewallTable"),
            configContent: document.getElementById("configContent"),

            // Logs (optional – only if you add logs page)
            logsList: document.getElementById("logsList"),
            logsStatus: document.getElementById("logsStatus"),
            logsPauseBtn: document.getElementById("logsPauseBtn"),
            logsClearBtn: document.getElementById("logsClearBtn"),
            logsTailSelect: document.getElementById("logsTailSelect"),

            // Modals
            loginModal: document.getElementById("loginModal"),
            ruleModal: document.getElementById("ruleModal"),
            confirmModal: document.getElementById("confirmModal"),

            // Forms
            loginForm: document.getElementById("loginForm"),
            ruleForm: document.getElementById("ruleForm"),

            // Confirm modal bits
            confirmTitle: document.getElementById("confirmTitle"),
            confirmText: document.getElementById("confirmText"),
            confirmCancel: document.getElementById("confirmCancel"),
            confirmOk: document.getElementById("confirmOk"),
        };
    }

    bindEvents() {
        // Navigation
        document.querySelectorAll(".nav-link").forEach((link) => {
            link.addEventListener("click", (e) => this.switchPage(e));
        });

        // Buttons
        this.el.refreshBtn?.addEventListener("click", () => this.refreshData());
        this.el.loginBtn?.addEventListener("click", () => this.toggleLogin());

        this.el.addRuleBtn?.addEventListener("click", () => {
            if (!this.requireAuthForAction()) return;
            this.showModal("ruleModal");
        });

        this.el.reloadConfigBtn?.addEventListener("click", () => {
            this.showMessage("Reload endpoint is not implemented on server", "error");
        });

        this.el.addHostBtn?.addEventListener("click", () => {
            this.showMessage("Add host is not implemented in UI yet", "error");
        });

        // Modals
        document.querySelectorAll(".close-modal").forEach((btn) => {
            btn.addEventListener("click", () => this.closeModals());
        });

        document.querySelectorAll(".modal-overlay").forEach((modal) => {
            modal.addEventListener("click", (e) => {
                if (e.target === modal) this.closeModals();
            });
        });

        // Forms
        this.el.loginForm?.addEventListener("submit", (e) => this.handleLogin(e));
        this.el.ruleForm?.addEventListener("submit", (e) => this.handleAddRule(e));

        // Time range impacts series length (client-only)
        this.el.timeRange?.addEventListener("change", () => {
            this.applyTimeRangePreset();
            this.renderTimeSeries();
        });

        // Firewall table: event delegation
        this.el.firewallTable?.addEventListener("click", (e) => {
            const btn = e.target.closest('button[data-action="delete-rule"]');
            if (!btn) return;

            if (!this.requireAuthForAction()) return;

            const ip = btn.getAttribute("data-ip");
            if (!ip) return;

            this.confirm({
                title: "Remove firewall rule",
                text: `Remove rule for ${ip}?`,
                okText: "Remove",
                danger: true,
                onOk: () => this.deleteRule(ip),
            });
        });

        // Logs controls (optional)
        this.el.logsPauseBtn?.addEventListener("click", () => {
            this.logsPaused = !this.logsPaused;
            this.updateLogsStatus();
            this.el.logsPauseBtn.textContent = this.logsPaused ? "Resume" : "Pause";
        });

        this.el.logsClearBtn?.addEventListener("click", () => {
            this.logs = [];
            this.renderLogs();
        });

        this.el.logsTailSelect?.addEventListener("change", async () => {
            await this.loadLogsTail(true);
        });

        // Confirm modal actions
        this.el.confirmCancel?.addEventListener("click", () => this.closeModals());
        this.el.confirmOk?.addEventListener("click", async () => {
            if (typeof this._confirmOk === "function") {
                const fn = this._confirmOk;
                this._confirmOk = null;
                await fn();
            }
            this.closeModals();
        });

        // Pause polling when tab hidden
        document.addEventListener("visibilitychange", () => {
            if (document.hidden) {
                this.stopDashboardPolling();
                this.stopLogsFollow();
            } else {
                if (this.currentPage === "dashboard") this.startDashboardPolling(true);
                if (this.currentPage === "logs") this.startLogsFollow(true);
            }
        });
    }

    setupResizeObserver() {
        const target = this.el.responseGraph;
        if (!target || typeof ResizeObserver === "undefined") return;

        this._resizeObs = new ResizeObserver(() => {
            if (this.currentPage === "dashboard") this.renderTimeSeries();
        });
        this._resizeObs.observe(target);
    }

    switchPage(e) {
        e.preventDefault();
        const page = e.currentTarget.dataset.page;
        this.currentPage = page;

        document.querySelectorAll(".nav-link").forEach((link) => link.classList.remove("active"));
        e.currentTarget.classList.add("active");

        document.querySelectorAll(".page").forEach((pageEl) => pageEl.classList.remove("active"));
        document.getElementById(`${page}Page`)?.classList.add("active");

        // Start/stop pollers for pages
        if (page === "dashboard") this.startDashboardPolling(true);
        else this.stopDashboardPolling();

        if (page === "logs") this.startLogsFollow(true);
        else this.stopLogsFollow();

        this.refreshData();
    }

    // ================================
    // Networking
    // ================================

    async fetchWithAuth(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { ...(options.headers || {}) };

        const hasBody = options.body !== undefined && options.body !== null;
        if (hasBody && !(options.body instanceof FormData)) {
            headers["Content-Type"] = headers["Content-Type"] || "application/json";
        }

        if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
        else if (this.basicAuth) headers["Authorization"] = `Basic ${this.basicAuth}`;

        let response;
        try {
            response = await fetch(url, {
                ...options,
                headers,
                credentials: "same-origin",
            });
        } catch {
            if (!options.silent) this.showMessage("Network error", "error");
            return { ok: false, status: 0, data: null, text: "", headers: null };
        }

        const ct = (response.headers.get("content-type") || "").toLowerCase();
        const wwwAuth = (response.headers.get("www-authenticate") || "").toLowerCase();

        if (response.status === 401) {
            // Clear auth locally
            this.token = null;
            this.basicAuth = null;
            sessionStorage.removeItem("agbero_token");
            sessionStorage.removeItem("agbero_basic");
            this.isAuthenticated = false;
            this.updateAuthUI();

            if (!options.silent) {
                const hint = wwwAuth.includes("basic") ? "Basic auth required" : "Login required";
                this.showMessage(hint, "error");
                this.showModal("loginModal");
            }
            return { ok: false, status: 401, data: null, text: "", headers: response.headers };
        }

        if (response.status === 204) {
            return { ok: true, status: 204, data: null, text: "", headers: response.headers };
        }

        let text = "";
        let data = null;

        try {
            if (ct.includes("application/json")) data = await response.json();
            else text = await response.text();
        } catch {
            // ignore parse errors
        }

        if (!response.ok) {
            if (!options.silent) {
                const msg = text?.trim() ? text.trim() : `HTTP ${response.status}`;
                this.showMessage(msg, "error");
            }
            return { ok: false, status: response.status, data, text, headers: response.headers };
        }

        return { ok: true, status: response.status, data, text, headers: response.headers };
    }

    async loadInitialData() {
        const health = await this.fetchWithAuth("/health", { method: "GET", silent: true });
        if (health.ok) {
            this.updateConnectionStatus(true);
            this.recordUpDown(true);
        } else {
            this.updateConnectionStatus(false);
            this.recordUpDown(false);
            this.showMessage("Cannot connect to server", "error");
            return;
        }

        if (this.currentPage === "dashboard") this.startDashboardPolling(true);
        if (this.currentPage === "logs") this.startLogsFollow(true);

        await this.refreshData();
    }

    // ================================
    // Auth
    // ================================

    toggleLogin() {
        if (this.isAuthenticated) {
            this.confirm({
                title: "Logout",
                text: "Logout of admin session?",
                okText: "Logout",
                danger: false,
                onOk: () => this.handleLogout(false),
            });
        } else {
            this.showModal("loginModal");
        }
    }

    handleLogout(from401) {
        this.token = null;
        this.basicAuth = null;
        this.isAuthenticated = false;
        sessionStorage.removeItem("agbero_token");
        sessionStorage.removeItem("agbero_basic");
        this.updateAuthUI();

        if (!from401) this.showMessage("Logged out", "success");
    }

    setLoading(formEl, loading, labelText, resetText) {
        if (!formEl) return;
        const btn = formEl.querySelector('button[type="submit"]');
        const inputs = formEl.querySelectorAll("input, select, button");
        inputs.forEach((i) => (i.disabled = !!loading));
        if (btn) btn.textContent = loading ? labelText || "Working…" : resetText || "Login";
    }

    async handleLogin(e) {
        e.preventDefault();

        const username = document.getElementById("username")?.value?.trim();
        const password = document.getElementById("password")?.value;

        if (!username || !password) {
            this.showMessage("Username and password required", "error");
            return;
        }

        this.setLoading(this.el.loginForm, true, "Signing in…", "Login");

        // Try JWT login first (your server requires jwt_auth.secret configured for /login)
        const jwtRes = await this.fetchWithAuth("/login", {
            method: "POST",
            body: JSON.stringify({ username, password }),
            silent: true,
        });

        if (jwtRes.ok && jwtRes.data && jwtRes.data.token) {
            this.token = jwtRes.data.token;
            this.basicAuth = null;

            sessionStorage.setItem("agbero_token", this.token);
            sessionStorage.removeItem("agbero_basic");

            this.isAuthenticated = true;
            this.updateAuthUI();
            this.closeModals();
            this.showMessage("Login successful", "success");
            this.setLoading(this.el.loginForm, false, null, "Login");

            await this.refreshData();
            return;
        }

        // Fallback: BasicAuth-only mode (older/alt server configs)
        // If server says "jwt_auth.secret is required", then /login is not usable, so use Basic.
        const looksLikeBasicOnly =
            jwtRes.status === 403 && (jwtRes.text || "").toLowerCase().includes("jwt_auth.secret");

        if (looksLikeBasicOnly) {
            const b64 = btoa(`${username}:${password}`);
            this.basicAuth = b64;
            this.token = null;

            sessionStorage.setItem("agbero_basic", b64);
            sessionStorage.removeItem("agbero_token");

            // Probe a protected endpoint
            const probe = await this.fetchWithAuth("/config", { method: "GET", silent: true });
            if (!probe.ok) {
                this.basicAuth = null;
                sessionStorage.removeItem("agbero_basic");
                this.isAuthenticated = false;
                this.updateAuthUI();
                this.showMessage("Invalid credentials", "error");
                this.setLoading(this.el.loginForm, false, null, "Login");
                return;
            }

            this.isAuthenticated = true;
            this.updateAuthUI();
            this.closeModals();
            this.showMessage("Login successful", "success");
            this.setLoading(this.el.loginForm, false, null, "Login");

            await this.refreshData();
            return;
        }

        this.setLoading(this.el.loginForm, false, null, "Login");
        this.showMessage("Invalid credentials", "error");
    }

    updateAuthUI() {
        const loginBtn = this.el.loginBtn;
        if (!loginBtn) return;

        const dot = loginBtn.querySelector(".status-dot");
        if (this.isAuthenticated) {
            dot?.classList.add("on");
            loginBtn.title = "Logout";
        } else {
            dot?.classList.remove("on");
            loginBtn.title = "Admin Login";
        }
    }

    requireAuthForAction() {
        if (!this.token && !this.basicAuth) {
            this.showMessage("Login required", "error");
            this.showModal("loginModal");
            return false;
        }
        return true;
    }

    // ================================
    // UI states
    // ================================

    updateConnectionStatus(connected) {
        if (!this.el.header) return;
        this.el.header.dataset.connected = connected ? "1" : "0";
    }

    showModal(modalId) {
        document.getElementById(modalId)?.classList.add("active");
    }

    closeModals() {
        document.querySelectorAll(".modal-overlay").forEach((modal) => modal.classList.remove("active"));
        document.querySelectorAll("form").forEach((form) => form.reset());
        this._confirmOk = null;
    }

    confirm({ title, text, okText = "OK", danger = false, onOk }) {
        this.el.confirmTitle.textContent = title || "Confirm";
        this.el.confirmText.textContent = text || "";
        this.el.confirmOk.textContent = okText;

        if (danger) this.el.confirmOk.classList.add("danger");
        else this.el.confirmOk.classList.remove("danger");

        this._confirmOk = onOk;
        this.showModal("confirmModal");
    }

    showMessage(text, type) {
        const existing = document.querySelector(".message");
        if (existing) existing.remove();

        const message = document.createElement("div");
        message.className = `message message-${type}`;
        message.textContent = text;

        document.body.appendChild(message);

        setTimeout(() => {
            message.classList.add("hide");
            setTimeout(() => message.remove(), 250);
        }, 2500);
    }

    // ================================
    // Main refresh dispatcher
    // ================================

    async refreshData() {
        switch (this.currentPage) {
            case "dashboard":
                await this.loadDashboardData();
                break;
            case "hosts":
                await this.loadHosts();
                break;
            case "firewall":
                await this.loadFirewallRules();
                break;
            case "config":
                await this.loadConfig();
                break;
            case "logs":
                await this.loadLogsTail(false);
                break;
            default:
                break;
        }
    }

    // ================================
    // Dashboard polling + uptime tracking
    // ================================

    applyTimeRangePreset() {
        const v = this.el.timeRange?.value || "24h";
        const map = {
            "1h": 60,
            "6h": 120,
            "24h": 180,
            "7d": 240,
        };
        this.metricsSeriesMax = map[v] || 180;

        if (this.metricsSeries.length > this.metricsSeriesMax) {
            this.metricsSeries = this.metricsSeries.slice(-this.metricsSeriesMax);
        }
    }

    startDashboardPolling(forceImmediate) {
        this.applyTimeRangePreset();

        if (!this.metricsTimer) {
            const tickMetrics = async () => {
                if (this.currentPage !== "dashboard" || document.hidden) return;

                const res = await this.fetchWithAuth("/metrics", { method: "GET", silent: true });
                if (!res.ok) return;

                if (res.data && typeof res.data === "object") {
                    const parsed = this.parseMetricsJSON(res.data);
                    if (!parsed) return;

                    this.updateDashboardUI(parsed.stats);

                    const t = this.extractTimestampMs(res.data.timestamp) || Date.now();
                    this.pushMetricsPoint({
                        t,
                        p50_ms: parsed.percentiles?.p50_ms ?? null,
                        p90_ms: parsed.percentiles?.p90_ms ?? null,
                        p99_ms: parsed.percentiles?.p99_ms ?? null,
                        max_ms: parsed.percentiles?.max_ms ?? null,
                        mean_ms: this.safeNum(parsed.stats.mean_response),
                        errors: this.safeNum(parsed.stats.errors),
                    });

                    this.renderTimeSeries();
                    this.showRawMetrics(null);
                } else if (res.text) {
                    this.showRawMetrics(res.text);
                }
            };

            if (forceImmediate) tickMetrics();
            this.metricsTimer = setInterval(tickMetrics, this.metricsPollMs);
        }

        if (!this.healthTimer) {
            const tickHealth = async () => {
                if (this.currentPage !== "dashboard" || document.hidden) return;

                const health = await this.fetchWithAuth("/health", { method: "GET", silent: true });
                this.updateConnectionStatus(health.ok);
                this.recordUpDown(health.ok);
                this.updateUptimeUI();
            };

            if (forceImmediate) tickHealth();
            this.healthTimer = setInterval(tickHealth, this.healthPollMs);
        }
    }

    stopDashboardPolling() {
        if (this.metricsTimer) {
            clearInterval(this.metricsTimer);
            this.metricsTimer = null;
        }
        if (this.healthTimer) {
            clearInterval(this.healthTimer);
            this.healthTimer = null;
        }
    }

    recordUpDown(isUp) {
        const now = Date.now();
        const elapsed = Math.max(0, now - this.lastStatusAtMs);

        if (this.wasUp === null) {
            this.wasUp = isUp;
            this.lastStatusAtMs = now;
            return;
        }

        if (this.wasUp) this.upMs += elapsed;
        else this.downMs += elapsed;

        this.wasUp = isUp;
        this.lastStatusAtMs = now;
    }

    updateUptimeUI() {
        const total = this.upMs + this.downMs;
        const pct = total > 0 ? (this.upMs / total) * 100 : 0;

        if (this.el.uptimeStat) this.el.uptimeStat.textContent = total > 0 ? `${pct.toFixed(2)}%` : "—";
        if (this.el.downtimeStat) this.el.downtimeStat.textContent = this.formatDuration(this.downMs);
    }

    // ================================
    // Dashboard (/metrics)
    // ================================

    async loadDashboardData() {
        // Keep series, just refresh now
        this.renderTimeSeries();

        const res = await this.fetchWithAuth("/metrics", { method: "GET", silent: false });
        if (!res.ok) return;

        if (res.data && typeof res.data === "object") {
            const parsed = this.parseMetricsJSON(res.data);
            if (!parsed) {
                this.showRawMetrics(JSON.stringify(res.data, null, 2));
                this.showMessage("Metrics JSON format is unknown to UI", "error");
                return;
            }

            this.updateDashboardUI(parsed.stats);

            const t = this.extractTimestampMs(res.data.timestamp) || Date.now();
            this.pushMetricsPoint({
                t,
                p50_ms: parsed.percentiles?.p50_ms ?? null,
                p90_ms: parsed.percentiles?.p90_ms ?? null,
                p99_ms: parsed.percentiles?.p99_ms ?? null,
                max_ms: parsed.percentiles?.max_ms ?? null,
                mean_ms: this.safeNum(parsed.stats.mean_response),
                errors: this.safeNum(parsed.stats.errors),
            });

            this.renderTimeSeries();
            this.showRawMetrics(null);
            return;
        }

        if (res.text) {
            this.showRawMetrics(res.text);
            this.showMessage("Metrics are text; UI expects JSON to render chart", "error");
            return;
        }

        this.showMessage("No metrics returned", "error");
    }

    parseMetricsJSON(obj) {
        // Supports your new metrics shape:
        // {
        //   timestamp: "...",
        //   hosts: {
        //     "admin.localhost": {
        //       routes:[{ backends:[{ latency_us:{p50,p90,p99,max,count,sum_us,avg_us}, failures, total_reqs, alive }]}],
        //       total_reqs, avg_p99_us
        //     }
        //   }
        // }
        if (obj && obj.hosts && typeof obj.hosts === "object") {
            let totalCount = 0;
            let totalSumUs = 0;
            let totalFailures = 0;

            // Use "worst" percentiles across all alive backends (actionable)
            let p50Us = null,
                p90Us = null,
                p99Us = null,
                maxUs = null;

            for (const host of Object.values(obj.hosts)) {
                const routes = Array.isArray(host.routes) ? host.routes : [];
                for (const r of routes) {
                    const backends = Array.isArray(r.backends) ? r.backends : [];
                    for (const b of backends) {
                        if (!b) continue;
                        if (b.alive === false) continue;

                        const lat = b.latency_us || {};
                        const count = Number(lat.count) || 0;
                        const sumUs = Number(lat.sum_us) || 0;

                        if (count > 0 && sumUs > 0) {
                            totalCount += count;
                            totalSumUs += sumUs;
                        } else if (Number.isFinite(Number(lat.avg_us)) && (Number(b.total_reqs) || 0) > 0) {
                            const c = Number(b.total_reqs) || 0;
                            totalCount += c;
                            totalSumUs += (Number(lat.avg_us) || 0) * c;
                        }

                        totalFailures += Number(b.failures) || 0;

                        if (Number.isFinite(Number(lat.p50))) p50Us = p50Us == null ? Number(lat.p50) : Math.max(p50Us, Number(lat.p50));
                        if (Number.isFinite(Number(lat.p90))) p90Us = p90Us == null ? Number(lat.p90) : Math.max(p90Us, Number(lat.p90));
                        if (Number.isFinite(Number(lat.p99))) p99Us = p99Us == null ? Number(lat.p99) : Math.max(p99Us, Number(lat.p99));
                        if (Number.isFinite(Number(lat.max))) maxUs = maxUs == null ? Number(lat.max) : Math.max(maxUs, Number(lat.max));
                    }
                }
            }

            const avgUs = totalCount > 0 ? totalSumUs / totalCount : null;
            const avgMs = avgUs != null ? avgUs / 1000 : null;

            const apdex = this.computeApdex(avgMs, this.apdexTms);

            const stats = {
                uptime: "—", // filled by /health poller
                downtime: "—",
                apdex: apdex == null ? "—" : apdex.toFixed(2),
                mean_response: avgMs != null ? avgMs.toFixed(2) : "—",
                header_size: "—",
                body_size: "—",
                errors: totalFailures,
            };

            return {
                stats: this.normalizeStats(stats),
                percentiles: {
                    p50_ms: this.usToMs(p50Us),
                    p90_ms: this.usToMs(p90Us),
                    p99_ms: this.usToMs(p99Us),
                    max_ms: this.usToMs(maxUs),
                },
            };
        }

        return null;
    }

    normalizeStats(stats) {
        const mean = stats.mean_response_ms ?? stats.mean_response;
        const meanStr = mean === "—" || mean === undefined || mean === null ? "—" : `${mean}`.replace(/ms$/i, "");

        return {
            uptime: stats.uptime ?? "—",
            downtime: stats.downtime ?? "—",
            apdex: stats.apdex ?? "—",
            mean_response: meanStr === "—" ? "—" : `${meanStr}`,
            header_size: stats.header_size ?? "—",
            body_size: stats.body_size ?? "—",
            errors: stats.errors ?? "—",
        };
    }

    computeApdex(meanMs, T) {
        const m = Number(meanMs);
        if (!Number.isFinite(m)) return null;
        if (m <= T) return 1.0;
        if (m <= 4 * T) return 0.5;
        return 0.0;
    }

    updateDashboardUI(data) {
        // Uptime/downtime are updated by the health poller.
        if (this.el.apdexStat) this.el.apdexStat.textContent = `${data.apdex}`;

        const mean = data.mean_response === "—" ? "—" : `${data.mean_response}ms`;
        if (this.el.meanResponseStat) this.el.meanResponseStat.textContent = mean;
        if (this.el.meanResponse) this.el.meanResponse.textContent = mean;

        if (this.el.headerSizeStat) this.el.headerSizeStat.textContent = `${data.header_size}`;
        if (this.el.bodySizeStat) this.el.bodySizeStat.textContent = `${data.body_size}`;
        if (this.el.errorsStat) this.el.errorsStat.textContent = `${data.errors}`;
    }

    // ================================
    // Time-series graph (SVG lines)
    // ================================

    clearGraph() {
        if (!this.el.responseGraph) return;
        this.el.responseGraph.innerHTML = "";
    }

    pushMetricsPoint(p) {
        const last = this.metricsSeries[this.metricsSeries.length - 1];
        if (last && last.t === p.t) this.metricsSeries[this.metricsSeries.length - 1] = p;
        else this.metricsSeries.push(p);

        if (this.metricsSeries.length > this.metricsSeriesMax) {
            this.metricsSeries = this.metricsSeries.slice(-this.metricsSeriesMax);
        }
    }

    renderTimeSeries() {
        if (!this.el.responseGraph) return;
        this.clearGraph();

        const points = this.metricsSeries.slice(-this.metricsSeriesMax);
        if (!points.length) return;

        const rect = this.el.responseGraph.getBoundingClientRect();
        const w = Math.max(420, Math.floor(rect.width || 520));
        const h = Math.max(76, Math.floor(rect.height || 76));

        // Use p99 range for scaling (ignore extreme max spikes)
        const vals = [];
        for (const p of points) {
            if (Number.isFinite(p.p50_ms)) vals.push(p.p50_ms);
            if (Number.isFinite(p.p90_ms)) vals.push(p.p90_ms);
            if (Number.isFinite(p.p99_ms)) vals.push(p.p99_ms);
        }
        if (!vals.length) {
            for (const p of points) {
                if (Number.isFinite(p.mean_ms)) vals.push(p.mean_ms);
            }
        }

        let yMax = Math.max(1, ...vals);
        yMax = yMax * 1.15;

        const nonZero = vals.filter((v) => Number.isFinite(v));
        const vMin = nonZero.length ? Math.min(...nonZero) : 0;
        const vMax = nonZero.length ? Math.max(...nonZero) : 1;
        const span = Math.max(0.0001, vMax - vMin);
        const minVisibleSpan = Math.max(0.6, vMax * 0.25);
        if (span < minVisibleSpan) {
            yMax = Math.max(vMax + minVisibleSpan, yMax);
        }

        const yMin = 0;

        const padTop = 6;
        const padBottom = 12;
        const padLeft = 2;
        const padRight = 2;

        const innerW = w - padLeft - padRight;
        const innerH = h - padTop - padBottom;

        const xFor = (i) => {
            if (points.length === 1) return padLeft + innerW;
            return padLeft + (i / (points.length - 1)) * innerW;
        };

        const yFor = (v) => {
            const n = Number(v);
            if (!Number.isFinite(n)) return null;
            const clamped = Math.max(yMin, Math.min(yMax, n));
            const frac = (clamped - yMin) / (yMax - yMin);
            return padTop + (1 - frac) * innerH;
        };

        const makePath = (key) => {
            let d = "";
            for (let i = 0; i < points.length; i++) {
                const y = yFor(points[i][key]);
                if (y == null) continue;
                const x = xFor(i);
                d += d ? ` L ${x.toFixed(1)} ${y.toFixed(1)}` : `M ${x.toFixed(1)} ${y.toFixed(1)}`;
            }
            return d || null;
        };

        const p50Path = makePath("p50_ms");
        const p90Path = makePath("p90_ms");
        const p99Path = makePath("p99_ms");

        const svgNS = "http://www.w3.org/2000/svg";
        const svg = document.createElementNS(svgNS, "svg");
        svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
        svg.setAttribute("width", "100%");
        svg.setAttribute("height", "100%");

        // baseline
        const baseline = document.createElementNS(svgNS, "line");
        baseline.setAttribute("x1", "0");
        baseline.setAttribute("x2", String(w));
        baseline.setAttribute("y1", String(padTop + innerH));
        baseline.setAttribute("y2", String(padTop + innerH));
        baseline.setAttribute("stroke", "var(--border)");
        baseline.setAttribute("stroke-width", "1");
        svg.appendChild(baseline);

        const addLine = (d, colorVar, width, dash) => {
            if (!d) return;
            const path = document.createElementNS(svgNS, "path");
            path.setAttribute("d", d);
            path.setAttribute("fill", "none");
            path.setAttribute("stroke", `var(${colorVar})`);
            path.setAttribute("stroke-width", String(width));
            path.setAttribute("stroke-linecap", "round");
            path.setAttribute("stroke-linejoin", "round");
            if (dash) path.setAttribute("stroke-dasharray", dash);
            svg.appendChild(path);
        };

        // Minimal apex-like lines
        addLine(p50Path, "--fast", 1.7, null);
        addLine(p90Path, "--mid", 1.7, "3 2");
        addLine(p99Path, "--slow", 2.2, null);

        // Range label top-right (tiny)
        const label = document.createElementNS(svgNS, "text");
        label.setAttribute("x", String(w - 6));
        label.setAttribute("y", "12");
        label.setAttribute("text-anchor", "end");
        label.setAttribute("font-size", "11");
        label.setAttribute("fill", "var(--text-tertiary)");
        label.textContent = `0–${this.formatMsShort(yMax)}`;
        svg.appendChild(label);

        // Title tooltip (latest)
        const last = points[points.length - 1];
        const title = document.createElementNS(svgNS, "title");
        title.textContent = `p50 ${this.fmtMs(last.p50_ms)} | p90 ${this.fmtMs(last.p90_ms)} | p99 ${this.fmtMs(
            last.p99_ms
        )} | mean ${this.fmtMs(last.mean_ms)}`;
        svg.appendChild(title);

        this.el.responseGraph.appendChild(svg);
    }

    // ================================
    // Raw metrics panel
    // ================================

    showRawMetrics(text) {
        if (!this.el.metricsRaw) return;
        const panel = this.el.metricsRaw.closest(".raw-metrics");
        if (!text) {
            this.el.metricsRaw.textContent = "";
            panel?.classList.add("hidden");
            return;
        }
        this.el.metricsRaw.textContent = text;
        panel?.classList.remove("hidden");
    }

    // ================================
    // Hosts (derived from /config)
    // ================================

    async loadHosts() {
        if (!this.el.hostsList) return;
        this.el.hostsList.innerHTML = "";

        const res = await this.fetchWithAuth("/config", { method: "GET" });
        if (!res.ok || !res.data) return;

        const cfg = res.data;
        const hostsObj = cfg.hosts || cfg.Hosts || {};
        const hosts = [];

        for (const [name, h] of Object.entries(hostsObj)) {
            const domains = h.domains || h.Domains || [];
            const routesArr = h.routes || h.Routes || [];
            hosts.push({
                name,
                domains,
                routes: Array.isArray(routesArr) ? routesArr : [],
                status: "active",
            });
        }

        this.renderHostsList(hosts);
    }

    renderHostsList(hosts) {
        const container = this.el.hostsList;
        if (!container) return;

        container.innerHTML = hosts
            .map((host) => {
                const routes = Array.isArray(host.routes) ? host.routes : [];

                const routeHtml = routes
                    .map((r) => {
                        const path = r.path || r.Path || "—";

                        const web = r.web || r.Web || null;
                        const webRoot = web?.Root || web?.root || "";
                        const webListing = (web?.Listing ?? web?.listing) ? "listing" : "";

                        const backendsCfg = r.backends || r.Backends || null;
                        const servers = backendsCfg?.Servers || backendsCfg?.servers || null;
                        const lb = backendsCfg?.LBStrategy || backendsCfg?.lbStrategy || "";

                        const serversArr = Array.isArray(servers) ? servers : [];
                        const hasServers = serversArr.length > 0;

                        const serverHtml = hasServers
                            ? serversArr
                                .map((s) => {
                                    const addr = s.Address || s.address || "";
                                    const type = this.backendType(addr);
                                    const weight = Number(s.Weight ?? s.weight ?? 0);
                                    const conditions = s.Conditions || s.conditions || null;
                                    const condText = conditions ? this.compactConditions(conditions) : "";
                                    return `
                      <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--text-tertiary);margin-top:6px;">
                        <span style="color:var(--text-secondary);font-weight:600">${this.escapeHtml(type)}</span>
                        <span>${this.escapeHtml(addr)}</span>
                        ${weight ? `<span>weight: ${weight}</span>` : ""}
                        ${condText ? `<span style="color:var(--text-secondary);">${this.escapeHtml(condText)}</span>` : ""}
                      </div>
                    `;
                                })
                                .join("")
                            : "";

                        const modeBits = [];
                        if (web) modeBits.push(`web${webListing ? ` (${webListing})` : ""}${webRoot ? `: ${webRoot}` : ""}`);
                        if (hasServers) modeBits.push(`proxy${lb ? ` (${lb})` : ""}`);
                        if (!web && !hasServers) modeBits.push("no backends");

                        return `
              <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
                <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;">
                  <div style="font-size:12px;color:var(--text-secondary);font-weight:600;">Route ${this.escapeHtml(path)}</div>
                  <div style="font-size:12px;color:var(--text-tertiary);">${this.escapeHtml(modeBits.join(" • "))}</div>
                </div>
                ${serverHtml || ""}
              </div>
            `;
                    })
                    .join("");

                return `
          <div class="host-card">
            <div class="host-header">
              <div class="host-name">${this.escapeHtml(host.name)}</div>
              <div class="host-status">${this.escapeHtml(host.status)}</div>
            </div>
            <div class="host-domains">${(host.domains || []).map((d) => this.escapeHtml(d)).join(", ")}</div>
            <div class="host-stats">
              <span>${routes.length} routes</span>
              <span>Active</span>
            </div>
            ${routeHtml}
          </div>
        `;
            })
            .join("");
    }

    backendType(url) {
        const u = String(url || "").toLowerCase();
        if (u.startsWith("http://") || u.startsWith("https://")) return "http";
        if (u.startsWith("tcp://")) return "tcp";
        if (u.startsWith("udp://")) return "udp";
        return "backend";
    }

    compactConditions(conditions) {
        try {
            const s = JSON.stringify(conditions);
            if (s.length <= 160) return `if ${s}`;
            return `if ${s.slice(0, 160)}…`;
        } catch {
            return "if (conditions)";
        }
    }

    // ================================
    // Firewall
    // ================================

    async loadFirewallRules() {
        if (!this.el.firewallTable) return;
        this.el.firewallTable.innerHTML = "";

        const res = await this.fetchWithAuth("/firewall", { method: "GET" });
        if (!res.ok) return;

        if (!Array.isArray(res.data)) {
            this.showMessage("Firewall API returned unexpected data", "error");
            return;
        }

        this.renderFirewallTable(res.data);
        this.updateFirewallCount(res.data.length);
    }

    renderFirewallTable(rules) {
        const container = this.el.firewallTable;
        if (!container) return;

        container.innerHTML = rules
            .map(
                (rule) => `
        <div class="table-row">
          <div class="table-col ip-address">${this.escapeHtml(rule.ip || rule.IP || "")}</div>
          <div class="table-col">${this.escapeHtml(rule.reason || rule.Reason || "")}</div>
          <div class="table-col">${this.formatDate(rule.added || rule.Added || rule.created_at || rule.CreatedAt)}</div>
          <div class="table-col">
            <button class="action-btn danger"
                    data-action="delete-rule"
                    data-ip="${this.escapeAttr(rule.ip || rule.IP || "")}">
              Remove
            </button>
          </div>
        </div>
      `
            )
            .join("");
    }

    updateFirewallCount(n) {
        const page = document.getElementById("firewallPage");
        const h2 = page?.querySelector(".page-header h2");
        if (!h2) return;

        h2.querySelectorAll("[data-fw-count]").forEach((x) => x.remove());

        const badge = document.createElement("span");
        badge.setAttribute("data-fw-count", "1");
        badge.textContent = ` ${n}`;
        badge.style.marginLeft = "8px";
        badge.style.fontSize = "12px";
        badge.style.color = "var(--text-tertiary)";
        badge.style.fontWeight = "600";
        h2.appendChild(badge);
    }

    async handleAddRule(e) {
        e.preventDefault();
        if (!this.requireAuthForAction()) return;

        const ip = document.getElementById("ipAddress")?.value?.trim();
        const reason = document.getElementById("reason")?.value?.trim();
        const duration = document.getElementById("duration")?.value;

        // Optional (only if you add inputs in the modal)
        const host = document.getElementById("fwHost")?.value?.trim() || "";
        const path = document.getElementById("fwPath")?.value?.trim() || "";

        if (!ip) return this.showMessage("IP required", "error");
        if (!reason) return this.showMessage("Reason required", "error");

        const durationSec = parseInt(duration, 10);
        if (Number.isNaN(durationSec)) return this.showMessage("Invalid duration", "error");

        const payload = { ip, reason, host, path, duration_sec: durationSec };

        const res = await this.fetchWithAuth("/firewall", {
            method: "POST",
            body: JSON.stringify(payload),
        });

        if (!res.ok) return;

        this.closeModals();
        this.showMessage("Rule added", "success");
        await this.loadFirewallRules();
    }

    async deleteRule(ip) {
        const res = await this.fetchWithAuth(`/firewall?ip=${encodeURIComponent(ip)}`, {
            method: "DELETE",
        });

        if (!res.ok) return;

        this.showMessage("Rule removed", "success");
        await this.loadFirewallRules();
    }

    // ================================
    // Config
    // ================================

    async loadConfig() {
        const res = await this.fetchWithAuth("/config", { method: "GET" });
        if (!res.ok) return;

        const container = this.el.configContent;
        if (!container) return;

        if (res.data && typeof res.data === "object") container.textContent = JSON.stringify(res.data, null, 2);
        else if (res.text) container.textContent = res.text;
        else container.textContent = "{}";
    }

    // ================================
    // Logs (tail + follow on ONE endpoint /logs)
    // ================================

    async loadLogsTail(forceScrollToBottom) {
        // Logs page might not exist yet in HTML - fail safely
        if (!this.el.logsList) return;

        const tail = this.getLogsTailCount();
        const res = await this.fetchWithAuth(`/logs?tail=${encodeURIComponent(tail)}`, {
            method: "GET",
            silent: true,
        });

        if (!res.ok) {
            this.setLogsStatus(`tail failed (HTTP ${res.status || "—"})`);
            return;
        }

        if (!Array.isArray(res.data)) {
            // if server returns something else, show raw
            this.setLogsStatus("tail returned non-array");
            return;
        }

        // Replace logs with tail snapshot (keeps simple)
        // We keep them ordered oldest -> newest as server returns (your readLastLines returns newest first currently).
        // Your readLastLines appends lines while scanning backwards -> it returns newest-first.
        // So we reverse to display oldest-first.
        const normalized = res.data.slice().reverse();
        this.logs = normalized.slice(-this.logsMaxInMemory);

        this.renderLogs(forceScrollToBottom);
        this.setLogsStatus(`tail ${tail}`);
    }

    startLogsFollow(forceImmediate) {
        // If logs page not present, do nothing
        if (!document.getElementById("logsPage")) return;

        // Ensure tail loaded first (auth safe)
        if (forceImmediate) this.loadLogsTail(true);

        // Try SSE follow (works only if /logs is public OR uses cookie-based auth)
        this.tryStartLogsSSE();

        // Always keep a polling fallback (auth safe)
        if (!this.logsTimer) {
            const tick = async () => {
                if (this.currentPage !== "logs" || document.hidden) return;
                if (this.logsPaused) return;

                // If SSE is running, don't poll.
                if (this.logsEventSource) return;

                // Poll tail
                await this.loadLogsTail(false);
            };

            this.logsTimer = setInterval(tick, this.logsPollMs);
        }

        this.updateLogsStatus();
    }

    stopLogsFollow() {
        if (this.logsTimer) {
            clearInterval(this.logsTimer);
            this.logsTimer = null;
        }
        this.stopLogsSSE();
    }

    tryStartLogsSSE() {
        // If already running, keep it
        if (this.logsEventSource) return;

        // EventSource cannot send Authorization headers.
        // So we only try SSE in cases where it might work:
        // - server has no auth, or
        // - auth is cookie-based (future), or
        // - /logs is left public (not recommended but possible)
        //
        // If it fails, we just keep polling.

        const url = `${this.baseUrl}/logs?follow=1`;

        try {
            const es = new EventSource(url, { withCredentials: true });

            let opened = false;

            es.addEventListener("open", () => {
                opened = true;
                this.logsEventSource = es;
                this.setLogsStatus("live");
            });

            es.addEventListener("error", () => {
                // If it never opened, it's likely blocked by auth
                if (!opened) {
                    es.close();
                    if (this.logsEventSource === es) this.logsEventSource = null;
                    this.setLogsStatus("polling");
                    return;
                }
                // If it was open but errored, fallback to polling
                es.close();
                if (this.logsEventSource === es) this.logsEventSource = null;
                this.setLogsStatus("polling");
            });

            // Server can send "log" events or default "message"
            const onLog = (ev) => {
                if (this.logsPaused) return;

                let entry = null;
                try {
                    entry = JSON.parse(ev.data);
                } catch {
                    entry = { raw: ev.data };
                }

                this.appendLogEntry(entry);
            };

            es.addEventListener("log", onLog);
            es.addEventListener("message", onLog);

            // Optional: ready/ping
            es.addEventListener("ready", () => this.setLogsStatus("live"));
            es.addEventListener("ping", () => { /* keep-alive */ });

            // Tentatively show "connecting..."
            this.setLogsStatus("connecting…");
        } catch {
            this.setLogsStatus("polling");
        }
    }

    stopLogsSSE() {
        if (this.logsEventSource) {
            this.logsEventSource.close();
            this.logsEventSource = null;
        }
    }

    appendLogEntry(entry) {
        // Keep only last N
        this.logs.push(entry);
        if (this.logs.length > this.logsMaxInMemory) {
            this.logs = this.logs.slice(-this.logsMaxInMemory);
        }

        // If user is scrolled near bottom, auto scroll
        const list = this.el.logsList;
        const shouldStick =
            list &&
            (list.scrollHeight - (list.scrollTop + list.clientHeight) < 80);

        this.renderLogs(shouldStick);
    }

    renderLogs(scrollToBottom) {
        const list = this.el.logsList;
        if (!list) return;

        // minimal rendering: newest last
        list.innerHTML = this.logs
            .map((l) => this.renderLogRow(l))
            .join("");

        if (scrollToBottom) {
            list.scrollTop = list.scrollHeight;
        }
    }

    renderLogRow(entry) {
        const e = entry || {};
        const ts = e.ts || e.time || e.timestamp || e.TS || e.Time || "";
        const level = (e.level || e.lvl || e.Level || "info").toString().toLowerCase();
        const msg = e.msg || e.message || e.Message || e.Msg || e.event || e.Event || e.raw || "";

        const host = e.host || e.Host || "";
        const path = e.path || e.Path || "";
        const ip = e.ip || e.IP || "";

        const tag = (s) => (s ? `<span style="color:var(--text-tertiary)">${this.escapeHtml(s)}</span>` : "");

        const lvlColor =
            level === "error" || level === "fatal"
                ? "var(--danger)"
                : level === "warn" || level === "warning"
                    ? "color-mix(in srgb, var(--danger) 55%, var(--text-tertiary) 45%)"
                    : "var(--text-tertiary)";

        const timeStr = ts ? this.escapeHtml(ts) : "";

        return `
      <div style="padding:10px 0;border-bottom:1px solid var(--border);font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;font-size:12px;line-height:1.5;">
        <div style="display:flex;gap:10px;flex-wrap:wrap;">
          ${timeStr ? `<span style="color:var(--text-tertiary)">${timeStr}</span>` : ""}
          <span style="color:${lvlColor};font-weight:650">${this.escapeHtml(level)}</span>
          <span style="color:var(--text-secondary)">${this.escapeHtml(String(msg))}</span>
        </div>
        <div style="margin-top:4px;display:flex;gap:12px;flex-wrap:wrap;">
          ${tag(host)}
          ${tag(path)}
          ${tag(ip)}
        </div>
      </div>
    `;
    }

    getLogsTailCount() {
        const v = this.el.logsTailSelect?.value;
        const n = parseInt(v, 10);
        if (Number.isFinite(n) && n > 0) return Math.min(n, 1000);
        return this.logsTailDefault;
    }

    setLogsStatus(text) {
        if (!this.el.logsStatus) return;
        this.el.logsStatus.textContent = text || "";
    }

    updateLogsStatus() {
        if (!this.el.logsStatus) return;
        if (this.logsPaused) {
            this.setLogsStatus("paused");
            return;
        }
        if (this.logsEventSource) {
            this.setLogsStatus("live");
            return;
        }
        this.setLogsStatus("polling");
    }

    // ================================
    // Utilities
    // ================================

    extractTimestampMs(ts) {
        if (!ts) return null;
        const d = new Date(ts);
        const n = d.getTime();
        return Number.isFinite(n) ? n : null;
    }

    usToMs(us) {
        const n = Number(us);
        if (!Number.isFinite(n)) return null;
        return n / 1000;
    }

    safeNum(v) {
        const n = Number(v);
        return Number.isFinite(n) ? n : null;
    }

    fmtMs(v) {
        const n = Number(v);
        if (!Number.isFinite(n)) return "—";
        return `${n.toFixed(2)}ms`;
    }

    formatMsShort(ms) {
        const n = Number(ms);
        if (!Number.isFinite(n)) return "—";
        if (n < 1) return `${(n * 1000).toFixed(0)}µs`;
        if (n < 10) return `${n.toFixed(2)}ms`;
        if (n < 100) return `${n.toFixed(1)}ms`;
        return `${n.toFixed(0)}ms`;
    }

    formatDuration(ms) {
        const n = Math.max(0, Math.floor(ms || 0));
        if (n === 0) return "0s";
        const s = Math.floor(n / 1000);
        const m = Math.floor(s / 60);
        const h = Math.floor(m / 60);

        if (h > 0) return `${h}h ${m % 60}m`;
        if (m > 0) return `${m}m ${s % 60}s`;
        return `${s}s`;
    }

    formatDate(ts) {
        if (!ts) return "—";
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return "—";
        return d.toLocaleDateString("en-US", {
            month: "short",
            day: "numeric",
            hour: "2-digit",
            minute: "2-digit",
        });
    }

    escapeHtml(s) {
        const str = String(s ?? "");
        return str
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;")
            .replaceAll("'", "&#39;");
    }

    escapeAttr(s) {
        return this.escapeHtml(s).replaceAll("`", "&#96;");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    window.admin = new AgberoAdmin();
});
