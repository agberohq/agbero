// app.js
// ====== PRODUCTION (JWT OR BASIC AUTH) ======
// Fixes requested:
// 1) Graph was too flat -> now:
//    - Uses container width (responsive) instead of fixed 520px
//    - Auto-scales Y using p99 only (ignores max spikes) + padding
//    - If the range is tiny, it zooms in (adds a minimum visible span)
//    - Adds a subtle "range label" (e.g. 0–3.2ms) without clutter
//    - Re-renders on resize (ResizeObserver)
// 2) Uptime / Downtime / Apdex were missing -> now computed client-side:
//    - Polls /health alongside /metrics
//    - Tracks up/down time since the page was opened
//    - Uptime shown as percentage, downtime shown as a duration
//    - Apdex calculated from mean latency using threshold T=200ms (tuneable)
//      (satisfied if <=T, tolerating if <=4T, else frustrated)
// 3) Keeps minimal look (Apex-like, no heavy axes)

class AgberoAdmin {
    constructor() {
        this.baseUrl = window.location.origin;

        this.token = sessionStorage.getItem('agbero_token') || null;
        this.basicAuth = sessionStorage.getItem('agbero_basic') || null;
        this.isAuthenticated = !!(this.token || this.basicAuth);

        this.currentPage = 'dashboard';

        // Polling
        this.metricsTimer = null;
        this.healthTimer = null;
        this.metricsPollMs = 2500;
        this.healthPollMs = 5000;

        // Rolling series
        this.metricsSeriesMax = 120;
        this.metricsSeries = []; // [{t, p50_ms,p90_ms,p99_ms,mean_ms,max_ms,errors}]

        // Uptime tracking (client-side)
        this.sessionStartMs = Date.now();
        this.lastStatusAtMs = Date.now();
        this.wasUp = null;      // unknown until first probe
        this.upMs = 0;
        this.downMs = 0;

        // Apdex threshold (tune)
        this.apdexTms = 200; // 200ms target

        // Resize handling for graph
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
            header: document.querySelector('.top-header'),

            refreshBtn: document.getElementById('refreshBtn'),
            loginBtn: document.getElementById('loginBtn'),
            addRuleBtn: document.getElementById('addRuleBtn'),
            reloadConfigBtn: document.getElementById('reloadConfigBtn'),
            addHostBtn: document.getElementById('addHostBtn'),

            timeRange: document.getElementById('timeRange'),
            responseGraph: document.getElementById('responseGraph'),
            meanResponse: document.getElementById('meanResponse'),

            uptimeStat: document.getElementById('uptimeStat'),
            downtimeStat: document.getElementById('downtimeStat'),
            apdexStat: document.getElementById('apdexStat'),
            meanResponseStat: document.getElementById('meanResponseStat'),
            headerSizeStat: document.getElementById('headerSizeStat'),
            bodySizeStat: document.getElementById('bodySizeStat'),
            errorsStat: document.getElementById('errorsStat'),

            metricsRaw: document.getElementById('metricsRaw'),

            hostsList: document.getElementById('hostsList'),
            firewallTable: document.getElementById('firewallTable'),
            configContent: document.getElementById('configContent'),

            loginModal: document.getElementById('loginModal'),
            ruleModal: document.getElementById('ruleModal'),
            confirmModal: document.getElementById('confirmModal'),

            loginForm: document.getElementById('loginForm'),
            ruleForm: document.getElementById('ruleForm'),

            confirmTitle: document.getElementById('confirmTitle'),
            confirmText: document.getElementById('confirmText'),
            confirmCancel: document.getElementById('confirmCancel'),
            confirmOk: document.getElementById('confirmOk')
        };
    }

    bindEvents() {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => this.switchPage(e));
        });

        this.el.refreshBtn?.addEventListener('click', () => this.refreshData());
        this.el.loginBtn?.addEventListener('click', () => this.toggleLogin());

        this.el.addRuleBtn?.addEventListener('click', () => {
            if (!this.requireAuthForAction()) return;
            this.showModal('ruleModal');
        });

        this.el.reloadConfigBtn?.addEventListener('click', () => {
            this.showMessage('Reload endpoint is not implemented on server', 'error');
        });

        this.el.addHostBtn?.addEventListener('click', () => {
            this.showMessage('Add host is not implemented in UI yet', 'error');
        });

        document.querySelectorAll('.close-modal').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeModals();
            });
        });

        this.el.loginForm?.addEventListener('submit', (e) => this.handleLogin(e));
        this.el.ruleForm?.addEventListener('submit', (e) => this.handleAddRule(e));

        this.el.timeRange?.addEventListener('change', () => {
            this.applyTimeRangePreset();
            this.renderTimeSeries();
        });

        this.el.firewallTable?.addEventListener('click', (e) => {
            const btn = e.target.closest('button[data-action="delete-rule"]');
            if (!btn) return;

            if (!this.requireAuthForAction()) return;

            const ip = btn.getAttribute('data-ip');
            if (!ip) return;

            this.confirm({
                title: 'Remove firewall rule',
                text: `Remove rule for ${ip}?`,
                okText: 'Remove',
                danger: true,
                onOk: () => this.deleteRule(ip)
            });
        });

        this.el.confirmCancel?.addEventListener('click', () => this.closeModals());
        this.el.confirmOk?.addEventListener('click', async () => {
            if (typeof this._confirmOk === 'function') {
                const fn = this._confirmOk;
                this._confirmOk = null;
                await fn();
            }
            this.closeModals();
        });

        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                this.stopDashboardPolling();
            } else if (this.currentPage === 'dashboard') {
                this.startDashboardPolling(true);
            }
        });
    }

    setupResizeObserver() {
        const target = this.el.responseGraph;
        if (!target || typeof ResizeObserver === 'undefined') return;

        this._resizeObs = new ResizeObserver(() => {
            if (this.currentPage === 'dashboard') this.renderTimeSeries();
        });
        this._resizeObs.observe(target);
    }

    switchPage(e) {
        e.preventDefault();
        const page = e.currentTarget.dataset.page;
        this.currentPage = page;

        document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
        e.currentTarget.classList.add('active');

        document.querySelectorAll('.page').forEach(pageEl => pageEl.classList.remove('active'));
        document.getElementById(`${page}Page`)?.classList.add('active');

        if (page === 'dashboard') this.startDashboardPolling(true);
        else this.stopDashboardPolling();

        this.refreshData();
    }

    // ============ Networking ============

    async fetchWithAuth(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = { ...(options.headers || {}) };

        const hasBody = options.body !== undefined && options.body !== null;
        if (hasBody && !(options.body instanceof FormData)) {
            headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        }

        if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
        else if (this.basicAuth) headers['Authorization'] = `Basic ${this.basicAuth}`;

        let response;
        try {
            response = await fetch(url, {
                ...options,
                headers,
                credentials: 'same-origin'
            });
        } catch {
            if (!options.silent) this.showMessage('Network error', 'error');
            return { ok: false, status: 0, data: null, text: '', headers: null };
        }

        const ct = (response.headers.get('content-type') || '').toLowerCase();
        const wwwAuth = (response.headers.get('www-authenticate') || '').toLowerCase();

        if (response.status === 401) {
            this.token = null;
            this.basicAuth = null;
            sessionStorage.removeItem('agbero_token');
            sessionStorage.removeItem('agbero_basic');
            this.isAuthenticated = false;
            this.updateAuthUI();

            if (!options.silent) {
                const hint = wwwAuth.includes('basic') ? 'Basic auth required' : 'Login required';
                this.showMessage(hint, 'error');
                this.showModal('loginModal');
            }
            return { ok: false, status: 401, data: null, text: '', headers: response.headers };
        }

        if (response.status === 204) {
            return { ok: true, status: 204, data: null, text: '', headers: response.headers };
        }

        let text = '';
        let data = null;

        try {
            if (ct.includes('application/json')) data = await response.json();
            else text = await response.text();
        } catch {
            // ignore parse errors
        }

        if (!response.ok) {
            if (!options.silent) {
                const msg = text?.trim() ? text.trim() : `HTTP ${response.status}`;
                this.showMessage(msg, 'error');
            }
            return { ok: false, status: response.status, data, text, headers: response.headers };
        }

        return { ok: true, status: response.status, data, text, headers: response.headers };
    }

    async loadInitialData() {
        const health = await this.fetchWithAuth('/health', { method: 'GET', silent: true });
        if (health.ok) {
            this.updateConnectionStatus(true);
            this.recordUpDown(true);
        } else {
            this.updateConnectionStatus(false);
            this.recordUpDown(false);
            this.showMessage('Cannot connect to server', 'error');
            return;
        }

        if (this.currentPage === 'dashboard') this.startDashboardPolling(true);

        await this.refreshData();
    }

    // ============ Auth ============

    toggleLogin() {
        if (this.isAuthenticated) {
            this.confirm({
                title: 'Logout',
                text: 'Logout of admin session?',
                okText: 'Logout',
                danger: false,
                onOk: () => this.handleLogout(false)
            });
        } else {
            this.showModal('loginModal');
        }
    }

    handleLogout(from401) {
        this.token = null;
        this.basicAuth = null;
        this.isAuthenticated = false;
        sessionStorage.removeItem('agbero_token');
        sessionStorage.removeItem('agbero_basic');
        this.updateAuthUI();
        if (!from401) this.showMessage('Logged out', 'success');
    }

    setLoading(formEl, loading, labelText, resetText) {
        if (!formEl) return;
        const btn = formEl.querySelector('button[type="submit"]');
        const inputs = formEl.querySelectorAll('input, select, button');
        inputs.forEach(i => (i.disabled = !!loading));
        if (btn) btn.textContent = loading ? (labelText || 'Working…') : (resetText || 'Login');
    }

    async handleLogin(e) {
        e.preventDefault();

        const username = document.getElementById('username')?.value?.trim();
        const password = document.getElementById('password')?.value;

        if (!username || !password) {
            this.showMessage('Username and password required', 'error');
            return;
        }

        this.setLoading(this.el.loginForm, true, 'Signing in…', 'Login');

        const jwtRes = await this.fetchWithAuth('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password }),
            silent: true
        });

        if (jwtRes.ok && jwtRes.data && jwtRes.data.token) {
            this.token = jwtRes.data.token;
            this.basicAuth = null;
            sessionStorage.setItem('agbero_token', this.token);
            sessionStorage.removeItem('agbero_basic');

            this.isAuthenticated = true;
            this.updateAuthUI();
            this.closeModals();
            this.showMessage('Login successful', 'success');
            this.setLoading(this.el.loginForm, false, null, 'Login');
            await this.refreshData();
            return;
        }

        const looksLikeBasicOnly =
            jwtRes.status === 403 &&
            (jwtRes.text || '').toLowerCase().includes('jwt_auth.secret');

        if (looksLikeBasicOnly) {
            const b64 = btoa(`${username}:${password}`);
            this.basicAuth = b64;
            this.token = null;
            sessionStorage.setItem('agbero_basic', b64);
            sessionStorage.removeItem('agbero_token');

            const probe = await this.fetchWithAuth('/config', { method: 'GET', silent: true });
            if (!probe.ok) {
                this.basicAuth = null;
                sessionStorage.removeItem('agbero_basic');
                this.isAuthenticated = false;
                this.updateAuthUI();
                this.showMessage('Invalid credentials', 'error');
                this.setLoading(this.el.loginForm, false, null, 'Login');
                return;
            }

            this.isAuthenticated = true;
            this.updateAuthUI();
            this.closeModals();
            this.showMessage('Login successful', 'success');
            this.setLoading(this.el.loginForm, false, null, 'Login');
            await this.refreshData();
            return;
        }

        this.setLoading(this.el.loginForm, false, null, 'Login');
        this.showMessage('Invalid credentials', 'error');
    }

    updateAuthUI() {
        const loginBtn = this.el.loginBtn;
        if (!loginBtn) return;

        const dot = loginBtn.querySelector('.status-dot');
        if (this.isAuthenticated) {
            dot?.classList.add('on');
            loginBtn.title = 'Logout';
        } else {
            dot?.classList.remove('on');
            loginBtn.title = 'Admin Login';
        }
    }

    requireAuthForAction() {
        if (!this.token && !this.basicAuth) {
            this.showMessage('Login required', 'error');
            this.showModal('loginModal');
            return false;
        }
        return true;
    }

    // ============ UI states ============

    updateConnectionStatus(connected) {
        if (!this.el.header) return;
        this.el.header.dataset.connected = connected ? '1' : '0';
    }

    showModal(modalId) {
        document.getElementById(modalId)?.classList.add('active');
    }

    closeModals() {
        document.querySelectorAll('.modal-overlay').forEach(modal => modal.classList.remove('active'));
        document.querySelectorAll('form').forEach(form => form.reset());
        this._confirmOk = null;
    }

    confirm({ title, text, okText = 'OK', danger = false, onOk }) {
        this.el.confirmTitle.textContent = title || 'Confirm';
        this.el.confirmText.textContent = text || '';
        this.el.confirmOk.textContent = okText;

        if (danger) this.el.confirmOk.classList.add('danger');
        else this.el.confirmOk.classList.remove('danger');

        this._confirmOk = onOk;
        this.showModal('confirmModal');
    }

    showMessage(text, type) {
        const existing = document.querySelector('.message');
        if (existing) existing.remove();

        const message = document.createElement('div');
        message.className = `message message-${type}`;
        message.textContent = text;

        document.body.appendChild(message);

        setTimeout(() => {
            message.classList.add('hide');
            setTimeout(() => message.remove(), 250);
        }, 2500);
    }

    // ============ Main refresh dispatcher ============

    async refreshData() {
        switch (this.currentPage) {
            case 'dashboard':
                await this.loadDashboardData();
                break;
            case 'hosts':
                await this.loadHosts();
                break;
            case 'firewall':
                await this.loadFirewallRules();
                break;
            case 'config':
                await this.loadConfig();
                break;
            default:
                break;
        }
    }

    // ============ Dashboard polling ============

    applyTimeRangePreset() {
        // Client-only window sizing (still lightweight)
        const v = this.el.timeRange?.value || '24h';
        const map = {
            '1h': 60,
            '6h': 120,
            '24h': 180,
            '7d': 240
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
                if (this.currentPage !== 'dashboard' || document.hidden) return;

                const res = await this.fetchWithAuth('/metrics', { method: 'GET', silent: true });
                if (!res.ok) return;

                if (res.data && typeof res.data === 'object') {
                    const parsed = this.parseMetricsJSON(res.data);
                    if (!parsed) return;

                    this.updateDashboardUI(parsed.stats);

                    if (parsed.percentiles) {
                        const t = this.extractTimestampMs(res.data.timestamp) || Date.now();
                        this.pushMetricsPoint({
                            t,
                            p50_ms: parsed.percentiles.p50_ms,
                            p90_ms: parsed.percentiles.p90_ms,
                            p99_ms: parsed.percentiles.p99_ms,
                            max_ms: parsed.percentiles.max_ms,
                            mean_ms: this.safeNum(parsed.stats.mean_response),
                            errors: this.safeNum(parsed.stats.errors)
                        });
                        this.renderTimeSeries();
                        this.showRawMetrics(null);
                    } else {
                        // show raw JSON if server changes shape unexpectedly
                        this.showRawMetrics(JSON.stringify(res.data, null, 2));
                    }
                } else if (res.text) {
                    this.showRawMetrics(res.text);
                }
            };

            if (forceImmediate) tickMetrics();
            this.metricsTimer = setInterval(tickMetrics, this.metricsPollMs);
        }

        if (!this.healthTimer) {
            const tickHealth = async () => {
                if (this.currentPage !== 'dashboard' || document.hidden) return;
                const health = await this.fetchWithAuth('/health', { method: 'GET', silent: true });
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

    // Track uptime/downtime based on health probes
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

        if (this.el.uptimeStat) this.el.uptimeStat.textContent = total > 0 ? `${pct.toFixed(2)}%` : '—';
        if (this.el.downtimeStat) this.el.downtimeStat.textContent = this.formatDuration(this.downMs);
    }

    // ============ Dashboard (manual refresh) ============

    async loadDashboardData() {
        // keep series; just refresh current stats + immediate render
        this.renderTimeSeries();

        const res = await this.fetchWithAuth('/metrics', { method: 'GET', silent: false });
        if (!res.ok) return;

        if (res.data && typeof res.data === 'object') {
            const parsed = this.parseMetricsJSON(res.data);
            if (!parsed) {
                this.showRawMetrics(JSON.stringify(res.data, null, 2));
                this.showMessage('Metrics JSON format is unknown to UI', 'error');
                return;
            }

            this.updateDashboardUI(parsed.stats);

            if (parsed.percentiles) {
                const t = this.extractTimestampMs(res.data.timestamp) || Date.now();
                this.pushMetricsPoint({
                    t,
                    p50_ms: parsed.percentiles.p50_ms,
                    p90_ms: parsed.percentiles.p90_ms,
                    p99_ms: parsed.percentiles.p99_ms,
                    max_ms: parsed.percentiles.max_ms,
                    mean_ms: this.safeNum(parsed.stats.mean_response),
                    errors: this.safeNum(parsed.stats.errors)
                });
                this.renderTimeSeries();
                this.showRawMetrics(null);
            } else {
                this.showRawMetrics(JSON.stringify(res.data, null, 2));
            }

            return;
        }

        if (res.text) {
            this.showRawMetrics(res.text);
            this.showMessage('Metrics are text; UI expects JSON to render chart', 'error');
        }
    }

    // ============ Metrics parsing (includes your /metrics shape) ============

    parseMetricsJSON(obj) {
        // Your shape:
        // { timestamp, hosts: { host: { routes:[{backends:[{latency_us:{p50,p90,p99,max,count,sum_us,avg_us}}]}], total_reqs, avg_p99_us } } }
        if (obj && obj.hosts && typeof obj.hosts === 'object') {
            let totalCount = 0;
            let totalSumUs = 0;
            let totalFailures = 0;

            // Use "worst" (max) across backends for percentiles (more actionable)
            let p50Us = null, p90Us = null, p99Us = null, maxUs = null;

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

                        if (Number.isFinite(Number(lat.p50))) p50Us = (p50Us == null) ? Number(lat.p50) : Math.max(p50Us, Number(lat.p50));
                        if (Number.isFinite(Number(lat.p90))) p90Us = (p90Us == null) ? Number(lat.p90) : Math.max(p90Us, Number(lat.p90));
                        if (Number.isFinite(Number(lat.p99))) p99Us = (p99Us == null) ? Number(lat.p99) : Math.max(p99Us, Number(lat.p99));
                        if (Number.isFinite(Number(lat.max))) maxUs = (maxUs == null) ? Number(lat.max) : Math.max(maxUs, Number(lat.max));
                    }
                }
            }

            const avgUs = totalCount > 0 ? (totalSumUs / totalCount) : null;
            const avgMs = avgUs != null ? (avgUs / 1000) : null;

            // Apdex from mean (minimal; if you later expose satisfied/tolerating counts, use that)
            const apdex = this.computeApdex(avgMs, this.apdexTms);

            const stats = {
                uptime: '—',           // filled by /health polling
                downtime: '—',         // filled by /health polling
                apdex: apdex == null ? '—' : apdex.toFixed(2),
                mean_response: avgMs != null ? avgMs.toFixed(2) : '—',
                header_size: '—',
                body_size: '—',
                errors: totalFailures
            };

            return {
                stats: this.normalizeStats(stats),
                percentiles: {
                    p50_ms: this.usToMs(p50Us),
                    p90_ms: this.usToMs(p90Us),
                    p99_ms: this.usToMs(p99Us),
                    max_ms: this.usToMs(maxUs)
                }
            };
        }

        return null;
    }

    normalizeStats(stats) {
        const mean = stats.mean_response_ms ?? stats.mean_response;
        const meanStr =
            mean === '—' || mean === undefined || mean === null
                ? '—'
                : `${mean}`.replace(/ms$/i, '');

        return {
            uptime: stats.uptime ?? '—',
            downtime: stats.downtime ?? '—',
            apdex: stats.apdex ?? '—',
            mean_response: meanStr === '—' ? '—' : `${meanStr}`,
            header_size: stats.header_size ?? '—',
            body_size: stats.body_size ?? '—',
            errors: stats.errors ?? '—'
        };
    }

    computeApdex(meanMs, T) {
        const m = Number(meanMs);
        if (!Number.isFinite(m)) return null;

        // Minimal approximation:
        // satisfied if mean <= T
        // tolerating if mean <= 4T
        // frustrated otherwise
        if (m <= T) return 1.0;
        if (m <= 4 * T) return 0.5;
        return 0.0;
    }

    updateDashboardUI(data) {
        // Uptime/downtime are maintained by health polling (but keep safe fallback)
        // Only set if still blank
        if (this.el.apdexStat) this.el.apdexStat.textContent = `${data.apdex}`;
        const mean = data.mean_response === '—' ? '—' : `${data.mean_response}ms`;
        if (this.el.meanResponseStat) this.el.meanResponseStat.textContent = mean;
        if (this.el.meanResponse) this.el.meanResponse.textContent = mean;

        if (this.el.headerSizeStat) this.el.headerSizeStat.textContent = `${data.header_size}`;
        if (this.el.bodySizeStat) this.el.bodySizeStat.textContent = `${data.body_size}`;
        if (this.el.errorsStat) this.el.errorsStat.textContent = `${data.errors}`;
    }

    // ============ Graph rendering (FIXED scaling + responsive width) ============

    clearGraph() {
        if (!this.el.responseGraph) return;
        this.el.responseGraph.innerHTML = '';
    }

    pushMetricsPoint(p) {
        const last = this.metricsSeries[this.metricsSeries.length - 1];
        if (last && last.t === p.t) this.metricsSeries[this.metricsSeries.length - 1] = p;
        else this.metricsSeries.push(p);

        if (this.metricsSeries.length > this.metricsSeriesMax) {
            this.metricsSeries = this.metricsSeries.slice(-this.metricsSeriesMax);
        }
    }

    extractTimestampMs(ts) {
        if (!ts) return null;
        const d = new Date(ts);
        const n = d.getTime();
        return Number.isFinite(n) ? n : null;
    }

    renderTimeSeries() {
        if (!this.el.responseGraph) return;
        this.clearGraph();

        const points = this.metricsSeries.slice(-this.metricsSeriesMax);
        if (!points.length) return;

        // Get container size
        const rect = this.el.responseGraph.getBoundingClientRect();
        const w = Math.max(240, Math.floor(rect.width || 520));
        const h = Math.max(60, Math.floor(rect.height || 76));

        // Use p99 for scaling (ignore max spikes so the lines are visible)
        const vals = [];
        for (const p of points) {
            if (Number.isFinite(p.p50_ms)) vals.push(p.p50_ms);
            if (Number.isFinite(p.p90_ms)) vals.push(p.p90_ms);
            if (Number.isFinite(p.p99_ms)) vals.push(p.p99_ms);
        }

        // Fallback: if all percentiles missing, use mean
        if (!vals.length) {
            for (const p of points) {
                if (Number.isFinite(p.mean_ms)) vals.push(p.mean_ms);
            }
        }

        const yMinRaw = 0;
        let yMaxRaw = Math.max(1, ...vals);

        // Add padding (15%)
        yMaxRaw = yMaxRaw * 1.15;

        // If range is tiny, zoom in by enforcing a minimum span
        // (so 0.90ms vs 0.94ms becomes visible)
        const nonZero = vals.filter(v => Number.isFinite(v));
        const vMin = nonZero.length ? Math.min(...nonZero) : 0;
        const vMax = nonZero.length ? Math.max(...nonZero) : 1;
        const span = Math.max(0.0001, vMax - vMin);

        const minVisibleSpan = Math.max(0.6, vMax * 0.25); // e.g. at 1ms -> 0.6ms span minimum
        if (span < minVisibleSpan) {
            // center around vMax (still anchored at 0 baseline, but with tighter top)
            yMaxRaw = Math.max(vMax + minVisibleSpan, yMaxRaw);
        }

        const yMin = yMinRaw;
        const yMax = Math.max(1, yMaxRaw);

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
            let d = '';
            for (let i = 0; i < points.length; i++) {
                const y = yFor(points[i][key]);
                if (y == null) continue;
                const x = xFor(i);
                d += d ? ` L ${x.toFixed(1)} ${y.toFixed(1)}` : `M ${x.toFixed(1)} ${y.toFixed(1)}`;
            }
            return d || null;
        };

        const p50Path = makePath('p50_ms');
        const p90Path = makePath('p90_ms');
        const p99Path = makePath('p99_ms');

        const svgNS = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
        svg.setAttribute('width', '100%');
        svg.setAttribute('height', '100%');

        // baseline
        const baseline = document.createElementNS(svgNS, 'line');
        baseline.setAttribute('x1', '0');
        baseline.setAttribute('x2', String(w));
        baseline.setAttribute('y1', String(padTop + innerH));
        baseline.setAttribute('y2', String(padTop + innerH));
        baseline.setAttribute('stroke', 'var(--border)');
        baseline.setAttribute('stroke-width', '1');
        svg.appendChild(baseline);

        const addLine = (d, colorVar, width, dash) => {
            if (!d) return;
            const path = document.createElementNS(svgNS, 'path');
            path.setAttribute('d', d);
            path.setAttribute('fill', 'none');
            path.setAttribute('stroke', `var(${colorVar})`);
            path.setAttribute('stroke-width', String(width));
            path.setAttribute('stroke-linecap', 'round');
            path.setAttribute('stroke-linejoin', 'round');
            if (dash) path.setAttribute('stroke-dasharray', dash);
            svg.appendChild(path);
        };

        addLine(p50Path, '--fast', 1.7, null);
        addLine(p90Path, '--mid',  1.7, '3 2');
        addLine(p99Path, '--slow', 2.2, null);

        // Range label (top-right) - minimal, no axis clutter
        const label = document.createElementNS(svgNS, 'text');
        label.setAttribute('x', String(w - 6));
        label.setAttribute('y', String(12));
        label.setAttribute('text-anchor', 'end');
        label.setAttribute('font-size', '11');
        label.setAttribute('fill', 'var(--text-tertiary)');
        label.textContent = `0–${this.formatMsShort(yMax)}`;
        svg.appendChild(label);

        // Tooltip title (latest values)
        const last = points[points.length - 1];
        const title = document.createElementNS(svgNS, 'title');
        title.textContent =
            `p50 ${this.fmtMs(last.p50_ms)} | p90 ${this.fmtMs(last.p90_ms)} | p99 ${this.fmtMs(last.p99_ms)} | mean ${this.fmtMs(last.mean_ms)}`;
        svg.appendChild(title);

        this.el.responseGraph.appendChild(svg);
    }

    // ============ Raw metrics panel ============

    showRawMetrics(text) {
        if (!this.el.metricsRaw) return;
        const panel = this.el.metricsRaw.closest('.raw-metrics');
        if (!text) {
            this.el.metricsRaw.textContent = '';
            panel?.classList.add('hidden');
            return;
        }
        this.el.metricsRaw.textContent = text;
        panel?.classList.remove('hidden');
    }

    // ============ Hosts (unchanged from prior improved version) ============

    async loadHosts() {
        this.el.hostsList.innerHTML = '';

        const res = await this.fetchWithAuth('/config', { method: 'GET' });
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
                status: 'active'
            });
        }

        this.renderHostsList(hosts);
    }

    renderHostsList(hosts) {
        const container = this.el.hostsList;
        if (!container) return;

        container.innerHTML = hosts.map(host => {
            const routes = Array.isArray(host.routes) ? host.routes : [];

            const routeHtml = routes.map(r => {
                const path = r.path || r.Path || '—';

                const web = r.web || r.Web || null;
                const webRoot = web?.Root || web?.root || '';
                const webListing = (web?.Listing ?? web?.listing) ? 'listing' : '';

                const backendsCfg = r.backends || r.Backends || null;
                const servers = backendsCfg?.Servers || backendsCfg?.servers || null;
                const lb = backendsCfg?.LBStrategy || backendsCfg?.lbStrategy || '';

                const serversArr = Array.isArray(servers) ? servers : [];
                const hasServers = serversArr.length > 0;

                const serverHtml = hasServers
                    ? serversArr.map(s => {
                        const addr = s.Address || s.address || '';
                        const type = this.backendType(addr);
                        const weight = Number(s.Weight ?? s.weight ?? 0);
                        const conditions = s.Conditions || s.conditions || null;
                        const condText = conditions ? this.compactConditions(conditions) : '';
                        return `
                          <div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--text-tertiary);margin-top:6px;">
                            <span style="color:var(--text-secondary);font-weight:600">${this.escapeHtml(type)}</span>
                            <span>${this.escapeHtml(addr)}</span>
                            ${weight ? `<span>weight: ${weight}</span>` : ''}
                            ${condText ? `<span style="color:var(--text-secondary);">${this.escapeHtml(condText)}</span>` : ''}
                          </div>
                        `;
                    }).join('')
                    : '';

                const modeBits = [];
                if (web) modeBits.push(`web${webListing ? ` (${webListing})` : ''}${webRoot ? `: ${webRoot}` : ''}`);
                if (hasServers) modeBits.push(`proxy${lb ? ` (${lb})` : ''}`);
                if (!web && !hasServers) modeBits.push('no backends');

                return `
                  <div style="margin-top:10px;padding-top:10px;border-top:1px solid var(--border);">
                    <div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;">
                      <div style="font-size:12px;color:var(--text-secondary);font-weight:600;">Route ${this.escapeHtml(path)}</div>
                      <div style="font-size:12px;color:var(--text-tertiary);">${this.escapeHtml(modeBits.join(' • '))}</div>
                    </div>
                    ${serverHtml || ''}
                  </div>
                `;
            }).join('');

            return `
                <div class="host-card">
                    <div class="host-header">
                        <div class="host-name">${this.escapeHtml(host.name)}</div>
                        <div class="host-status">${this.escapeHtml(host.status)}</div>
                    </div>
                    <div class="host-domains">${(host.domains || []).map(d => this.escapeHtml(d)).join(', ')}</div>
                    <div class="host-stats">
                        <span>${routes.length} routes</span>
                        <span>Active</span>
                    </div>
                    ${routeHtml}
                </div>
            `;
        }).join('');
    }

    backendType(url) {
        const u = String(url || '').toLowerCase();
        if (u.startsWith('http://') || u.startsWith('https://')) return 'http';
        if (u.startsWith('tcp://')) return 'tcp';
        if (u.startsWith('udp://')) return 'udp';
        return 'backend';
    }

    compactConditions(conditions) {
        try {
            const s = JSON.stringify(conditions);
            if (s.length <= 140) return `if ${s}`;
            return `if ${s.slice(0, 140)}…`;
        } catch {
            return 'if (conditions)';
        }
    }

    // ============ Firewall (same as prior improved) ============

    async loadFirewallRules() {
        this.el.firewallTable.innerHTML = '';

        const res = await this.fetchWithAuth('/firewall', { method: 'GET' });
        if (!res.ok) return;

        if (!Array.isArray(res.data)) {
            this.showMessage('Firewall API returned unexpected data', 'error');
            return;
        }

        this.renderFirewallTable(res.data);
        this.updateFirewallCount(res.data.length);
    }

    renderFirewallTable(rules) {
        const container = this.el.firewallTable;
        if (!container) return;

        container.innerHTML = rules.map(rule => `
            <div class="table-row">
                <div class="table-col ip-address">${this.escapeHtml(rule.ip || rule.IP || '')}</div>
                <div class="table-col">${this.escapeHtml(rule.reason || rule.Reason || '')}</div>
                <div class="table-col">${this.formatDate(rule.added || rule.Added || rule.created_at || rule.CreatedAt)}</div>
                <div class="table-col">
                    <button class="action-btn danger"
                            data-action="delete-rule"
                            data-ip="${this.escapeAttr(rule.ip || rule.IP || '')}">
                        Remove
                    </button>
                </div>
            </div>
        `).join('');
    }

    updateFirewallCount(n) {
        const page = document.getElementById('firewallPage');
        const h2 = page?.querySelector('.page-header h2');
        if (!h2) return;

        h2.querySelectorAll('[data-fw-count]').forEach(x => x.remove());

        const badge = document.createElement('span');
        badge.setAttribute('data-fw-count', '1');
        badge.textContent = ` ${n}`;
        badge.style.marginLeft = '8px';
        badge.style.fontSize = '12px';
        badge.style.color = 'var(--text-tertiary)';
        badge.style.fontWeight = '600';

        h2.appendChild(badge);
    }

    async handleAddRule(e) {
        e.preventDefault();
        if (!this.requireAuthForAction()) return;

        const ip = document.getElementById('ipAddress')?.value?.trim();
        const reason = document.getElementById('reason')?.value?.trim();
        const duration = document.getElementById('duration')?.value;

        if (!ip) return this.showMessage('IP required', 'error');
        if (!reason) return this.showMessage('Reason required', 'error');

        const durationSec = parseInt(duration, 10);
        if (Number.isNaN(durationSec)) return this.showMessage('Invalid duration', 'error');

        const payloads = [
            { ip, reason, duration_sec: durationSec },
            { ip, reason, ttl_sec: durationSec },
            { ip, reason, duration: durationSec },
            { ip, reason, ttl: durationSec }
        ];

        let res = null;
        for (const body of payloads) {
            res = await this.fetchWithAuth('/firewall', {
                method: 'POST',
                body: JSON.stringify(body),
                silent: true
            });
            if (res.ok) break;
            if (![400, 422].includes(res.status)) break;
        }

        if (!res?.ok) {
            const msg = res?.text?.trim()
                ? res.text.trim()
                : `Failed to add rule (HTTP ${res?.status || '—'})`;
            this.showMessage(msg, 'error');
            return;
        }

        this.closeModals();
        this.showMessage('Rule added', 'success');
        await this.loadFirewallRules();
    }

    async deleteRule(ip) {
        const res = await this.fetchWithAuth(`/firewall?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' });
        if (!res.ok) return;
        this.showMessage('Rule removed', 'success');
        await this.loadFirewallRules();
    }

    // ============ Config ============

    async loadConfig() {
        const res = await this.fetchWithAuth('/config', { method: 'GET' });
        if (!res.ok) return;

        const container = this.el.configContent;
        if (!container) return;

        if (res.data && typeof res.data === 'object') container.textContent = JSON.stringify(res.data, null, 2);
        else if (res.text) container.textContent = res.text;
        else container.textContent = '{}';
    }

    // ============ Utils ============

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
        if (!Number.isFinite(n)) return '—';
        return `${n.toFixed(2)}ms`;
    }

    formatMsShort(ms) {
        const n = Number(ms);
        if (!Number.isFinite(n)) return '—';
        if (n < 1) return `${(n * 1000).toFixed(0)}µs`;
        if (n < 10) return `${n.toFixed(2)}ms`;
        if (n < 100) return `${n.toFixed(1)}ms`;
        return `${n.toFixed(0)}ms`;
    }

    formatDuration(ms) {
        const n = Math.max(0, Math.floor(ms || 0));
        if (n === 0) return '0s';
        const s = Math.floor(n / 1000);
        const m = Math.floor(s / 60);
        const h = Math.floor(m / 60);

        if (h > 0) return `${h}h ${m % 60}m`;
        if (m > 0) return `${m}m ${s % 60}s`;
        return `${s}s`;
    }

    formatDate(ts) {
        if (!ts) return '—';
        const d = new Date(ts);
        if (Number.isNaN(d.getTime())) return '—';
        return d.toLocaleDateString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        });
    }

    escapeHtml(s) {
        const str = String(s ?? '');
        return str
            .replaceAll('&', '&amp;')
            .replaceAll('<', '&lt;')
            .replaceAll('>', '&gt;')
            .replaceAll('"', '&quot;')
            .replaceAll("'", '&#39;');
    }

    escapeAttr(s) {
        return this.escapeHtml(s).replaceAll('`', '&#96;');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.admin = new AgberoAdmin();
});
