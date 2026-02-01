// app.js
// ====== PRODUCTION (NO DEMO DATA) ======

class AgberoAdmin {
    constructor() {
        this.baseUrl = window.location.origin;

        // Token is optional: if server has no auth configured, endpoints will work without it.
        // If auth is configured, endpoints return 401 and we prompt for login.
        this.token = sessionStorage.getItem('agbero_token') || null;
        this.isAuthenticated = !!this.token;

        this.currentPage = 'dashboard';

        this.init();
    }

    init() {
        this.cacheEls();
        this.bindEvents();
        this.updateAuthUI();
        this.loadInitialData();
    }

    cacheEls() {
        this.el = {
            header: document.querySelector('.top-header'),

            // Nav / actions
            refreshBtn: document.getElementById('refreshBtn'),
            loginBtn: document.getElementById('loginBtn'),
            addRuleBtn: document.getElementById('addRuleBtn'),
            reloadConfigBtn: document.getElementById('reloadConfigBtn'),
            addHostBtn: document.getElementById('addHostBtn'),

            // Dashboard
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

            // Hosts/Config/Firewall
            hostsList: document.getElementById('hostsList'),
            firewallTable: document.getElementById('firewallTable'),
            configContent: document.getElementById('configContent'),

            // Modals
            loginModal: document.getElementById('loginModal'),
            ruleModal: document.getElementById('ruleModal'),
            confirmModal: document.getElementById('confirmModal'),

            // Forms
            loginForm: document.getElementById('loginForm'),
            ruleForm: document.getElementById('ruleForm'),

            // Confirm modal bits
            confirmTitle: document.getElementById('confirmTitle'),
            confirmText: document.getElementById('confirmText'),
            confirmCancel: document.getElementById('confirmCancel'),
            confirmOk: document.getElementById('confirmOk')
        };
    }

    bindEvents() {
        // Navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => this.switchPage(e));
        });

        // Buttons
        this.el.refreshBtn?.addEventListener('click', () => this.refreshData());
        this.el.loginBtn?.addEventListener('click', () => this.toggleLogin());

        this.el.addRuleBtn?.addEventListener('click', () => {
            if (!this.requireAuthForAction()) return;
            this.showModal('ruleModal');
        });

        this.el.reloadConfigBtn?.addEventListener('click', () => {
            // NOTE: Your server snippet does not show a /reload endpoint, so this stays disabled.
            this.showMessage('Reload endpoint is not implemented on server', 'error');
        });

        this.el.addHostBtn?.addEventListener('click', () => {
            this.showMessage('Add host is not implemented in UI yet', 'error');
        });

        // Modals
        document.querySelectorAll('.close-modal').forEach(btn => {
            btn.addEventListener('click', () => this.closeModals());
        });

        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closeModals();
            });
        });

        // Forms
        this.el.loginForm?.addEventListener('submit', (e) => this.handleLogin(e));
        this.el.ruleForm?.addEventListener('submit', (e) => this.handleAddRule(e));

        // Time range (only impacts how you ask backend; today backend has no range param)
        this.el.timeRange?.addEventListener('change', () => this.loadDashboardData());

        // Firewall table: event delegation
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

        // Confirm modal actions
        this.el.confirmCancel?.addEventListener('click', () => this.closeModals());
        this.el.confirmOk?.addEventListener('click', async () => {
            if (typeof this._confirmOk === 'function') {
                const fn = this._confirmOk;
                this._confirmOk = null;
                await fn();
            }
            this.closeModals();
        });
    }

    switchPage(e) {
        e.preventDefault();
        const page = e.currentTarget.dataset.page;
        this.currentPage = page;

        document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
        e.currentTarget.classList.add('active');

        document.querySelectorAll('.page').forEach(pageEl => pageEl.classList.remove('active'));
        document.getElementById(`${page}Page`)?.classList.add('active');

        // Load page data
        this.refreshData();
    }

    // ============ Networking ============

    async fetchWithAuth(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const headers = {
            ...options.headers
        };

        // Only set JSON content-type if we are sending JSON
        const hasBody = options.body !== undefined && options.body !== null;
        if (hasBody && !(options.body instanceof FormData)) {
            headers['Content-Type'] = headers['Content-Type'] || 'application/json';
        }

        // Optional token
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        let response;
        try {
            response = await fetch(url, {
                ...options,
                headers,
                credentials: 'same-origin'
            });
        } catch (err) {
            if (!options.silent) this.showMessage('Network error', 'error');
            return { ok: false, status: 0, data: null, text: '' };
        }

        // If auth is enabled, we must prompt for login upon 401
        if (response.status === 401) {
            this.handleLogout(true);
            if (!options.silent) {
                this.showMessage('Login required', 'error');
                this.showModal('loginModal');
            }
            return { ok: false, status: 401, data: null, text: '' };
        }

        // 204 no-content
        if (response.status === 204) {
            return { ok: true, status: 204, data: null, text: '' };
        }

        const contentType = (response.headers.get('content-type') || '').toLowerCase();
        let text = '';
        let data = null;

        try {
            if (contentType.includes('application/json')) {
                data = await response.json();
            } else {
                text = await response.text();
            }
        } catch {
            // ignore parse errors
        }

        if (!response.ok) {
            if (!options.silent) this.showMessage(`HTTP ${response.status}`, 'error');
            return { ok: false, status: response.status, data, text };
        }

        return { ok: true, status: response.status, data, text };
    }

    async loadInitialData() {
        // Health is public in your server
        const health = await this.fetchWithAuth('/health', { method: 'GET', silent: true });
        if (health.ok) {
            this.updateConnectionStatus(true);
        } else {
            this.updateConnectionStatus(false);
            this.showMessage('Cannot connect to server', 'error');
            return;
        }

        // Load current page data; if protected, it will 401 and show login.
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
        this.isAuthenticated = false;
        sessionStorage.removeItem('agbero_token');
        this.updateAuthUI();

        if (!from401) {
            this.showMessage('Logged out', 'success');
        }
    }

    setLoading(formEl, loading, labelText) {
        if (!formEl) return;
        const btn = formEl.querySelector('button[type="submit"]');
        const inputs = formEl.querySelectorAll('input, select, button');
        inputs.forEach(i => i.disabled = !!loading);
        if (btn) btn.textContent = loading ? (labelText || 'Working…') : 'Login';
    }

    async handleLogin(e) {
        e.preventDefault();

        const username = document.getElementById('username')?.value?.trim();
        const password = document.getElementById('password')?.value;

        if (!username || !password) {
            this.showMessage('Username and password required', 'error');
            return;
        }

        this.setLoading(this.el.loginForm, true, 'Signing in…');

        const res = await this.fetchWithAuth('/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        this.setLoading(this.el.loginForm, false);

        if (!res.ok || !res.data || !res.data.token) {
            this.showMessage('Invalid credentials', 'error');
            return;
        }

        this.token = res.data.token;
        this.isAuthenticated = true;
        sessionStorage.setItem('agbero_token', this.token);

        this.updateAuthUI();
        this.closeModals();
        this.showMessage('Login successful', 'success');

        await this.refreshData();
    }

    updateAuthUI() {
        const loginBtn = this.el.loginBtn;
        if (!loginBtn) return;

        const dot = loginBtn.querySelector('.status-dot');
        if (this.isAuthenticated) {
            if (dot) dot.classList.add('on');
            loginBtn.title = 'Logout';
        } else {
            if (dot) dot.classList.remove('on');
            loginBtn.title = 'Admin Login';
        }
    }

    requireAuthForAction() {
        // For actions that mutate state (firewall POST/DELETE), require login if we have no token.
        // If server is configured with no auth, token is optional, but POST still works.
        // In production, you typically want auth enabled—so we treat "no token" as "require login".
        if (!this.token) {
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

    // ============ Dashboard (/metrics) ============

    async loadDashboardData() {
        // Clear UI while loading (no fake numbers)
        this.updateDashboardUI({
            uptime: '—',
            downtime: '—',
            apdex: '—',
            mean_response: '—',
            header_size: '—',
            body_size: '—',
            errors: '—'
        });
        this.clearGraph();
        this.showRawMetrics(null);

        const res = await this.fetchWithAuth('/metrics', { method: 'GET', silent: false });
        if (!res.ok) return;

        // If JSON: attempt to render histogram and stats
        if (res.data && typeof res.data === 'object') {
            const parsed = this.parseMetricsJSON(res.data);
            if (!parsed) {
                // Show raw JSON for now, better than wrong numbers
                this.showRawMetrics(JSON.stringify(res.data, null, 2));
                this.showMessage('Metrics JSON format is unknown to UI', 'error');
                return;
            }

            this.updateDashboardUI(parsed.stats);
            if (parsed.histogram) {
                this.renderHistogram(parsed.histogram);
            } else {
                this.clearGraph();
            }
            return;
        }

        // Otherwise text (likely Prometheus)
        if (res.text) {
            // Do NOT guess dashboard stats from Prometheus text unless you define exact metric names.
            // We show the raw metrics text safely.
            this.showRawMetrics(res.text);
            this.showMessage('Metrics are text; UI needs a JSON summary to render dashboard stats', 'error');
            return;
        }

        this.showMessage('No metrics returned', 'error');
    }

    // Parse whatever your /metrics returns when it is JSON.
    // This avoids guessing. You can adjust mapping once you confirm the JSON structure.
    //
    // Expected supported shapes (examples):
    // A) { stats:{...}, histogram_ms:{edges:[...], counts:[...]} }
    // B) { uptime:..., apdex:..., mean_response_ms:..., latency_histogram_ms:{...} }
    parseMetricsJSON(obj) {
        // Shape A
        if (obj.stats && obj.histogram_ms && obj.histogram_ms.edges && obj.histogram_ms.counts) {
            return {
                stats: this.normalizeStats(obj.stats),
                histogram: {
                    edges: obj.histogram_ms.edges,
                    counts: obj.histogram_ms.counts
                }
            };
        }

        // Shape B
        const hasCore =
            obj.uptime !== undefined ||
            obj.apdex !== undefined ||
            obj.mean_response_ms !== undefined ||
            obj.errors !== undefined;

        if (hasCore) {
            const stats = {
                uptime: obj.uptime ?? '—',
                downtime: obj.downtime ?? '—',
                apdex: obj.apdex ?? '—',
                mean_response: (obj.mean_response_ms ?? obj.mean_response ?? '—'),
                header_size: obj.header_size ?? '—',
                body_size: obj.body_size ?? '—',
                errors: obj.errors ?? '—'
            };

            let histogram = null;
            const h = obj.latency_histogram_ms || obj.histogram_ms || obj.histogram;
            if (h && Array.isArray(h.edges) && Array.isArray(h.counts)) {
                histogram = { edges: h.edges, counts: h.counts };
            }

            return { stats: this.normalizeStats(stats), histogram };
        }

        return null;
    }

    normalizeStats(stats) {
        // Keep values as strings for display safety
        const mean = stats.mean_response_ms ?? stats.mean_response;
        const meanStr = (mean === '—' || mean === undefined || mean === null) ? '—' : `${mean}`.replace(/ms$/i, '');

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

    updateDashboardUI(data) {
        this.el.uptimeStat.textContent = `${data.uptime}${typeof data.uptime === 'number' ? '%' : ''}`.replace('%%', '%');
        this.el.downtimeStat.textContent = `${data.downtime}`;
        this.el.apdexStat.textContent = `${data.apdex}`;
        this.el.meanResponseStat.textContent = data.mean_response === '—' ? '—' : `${data.mean_response}ms`;
        this.el.meanResponse.textContent = data.mean_response === '—' ? '—' : `${data.mean_response}ms`;
        this.el.headerSizeStat.textContent = `${data.header_size}`;
        this.el.bodySizeStat.textContent = `${data.body_size}`;
        this.el.errorsStat.textContent = `${data.errors}`;
    }

    clearGraph() {
        if (!this.el.responseGraph) return;
        this.el.responseGraph.innerHTML = '';
    }

    // Histogram rendering expects:
    // { edges: [0,200,400,...], counts: [10,22,...] } where counts length = edges length - 1
    renderHistogram(hist) {
        if (!this.el.responseGraph) return;
        this.clearGraph();

        const edges = hist.edges;
        const counts = hist.counts;

        if (!Array.isArray(edges) || !Array.isArray(counts) || edges.length < 2) {
            this.showMessage('Histogram format invalid', 'error');
            return;
        }

        const max = Math.max(1, ...counts.map(n => Number(n) || 0));
        const bucketCount = counts.length;

        for (let i = 0; i < bucketCount; i++) {
            const c = Number(counts[i]) || 0;
            const height = Math.round((c / max) * 100);

            const bar = document.createElement('div');
            bar.className = `bar ${this.bucketClass(edges[i], edges[i + 1])}`;
            bar.style.height = `${height}%`;
            bar.title = `${edges[i]}–${edges[i + 1]}ms : ${c}`;

            this.el.responseGraph.appendChild(bar);
        }
    }

    bucketClass(lo, hi) {
        // Apex-like: fast / ok / slow based on latency thresholds
        // Tune these to match your SLO later
        if (hi <= 400) return 'bar-fast';
        if (hi <= 900) return 'bar-mid';
        return 'bar-slow';
    }

    showRawMetrics(text) {
        if (!this.el.metricsRaw) return;
        if (!text) {
            this.el.metricsRaw.textContent = '';
            this.el.metricsRaw.parentElement?.classList.add('hidden');
            return;
        }
        this.el.metricsRaw.textContent = text;
        this.el.metricsRaw.parentElement?.classList.remove('hidden');
    }

    // ============ Hosts (derived from /config) ============

    async loadHosts() {
        this.el.hostsList.innerHTML = '';

        const res = await this.fetchWithAuth('/config', { method: 'GET' });
        if (!res.ok || !res.data) return;

        const cfg = res.data;
        const hostsObj = cfg.hosts || cfg.Hosts || {};
        const hosts = [];

        for (const [name, h] of Object.entries(hostsObj)) {
            const domains = h.domains || h.Domains || [];
            const routes = Array.isArray(h.routes) ? h.routes.length : (h.routes ?? h.Routes?.length ?? 0);

            hosts.push({
                name,
                domains,
                routes,
                status: 'active'
            });
        }

        this.renderHostsList(hosts);
    }

    renderHostsList(hosts) {
        const container = this.el.hostsList;
        if (!container) return;

        container.innerHTML = hosts.map(host => `
            <div class="host-card">
                <div class="host-header">
                    <div class="host-name">${this.escapeHtml(host.name)}</div>
                    <div class="host-status">${this.escapeHtml(host.status)}</div>
                </div>
                <div class="host-domains">${(host.domains || []).map(d => this.escapeHtml(d)).join(', ')}</div>
                <div class="host-stats">
                    <span>${Number(host.routes) || 0} routes</span>
                    <span>Active</span>
                </div>
            </div>
        `).join('');
    }

    // ============ Firewall ============

    async loadFirewallRules() {
        this.el.firewallTable.innerHTML = '';

        const res = await this.fetchWithAuth('/firewall', { method: 'GET' });
        if (!res.ok) return;

        // Your API returns JSON array on GET
        if (!Array.isArray(res.data)) {
            this.showMessage('Firewall API returned unexpected data', 'error');
            return;
        }

        this.renderFirewallTable(res.data);
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

    async handleAddRule(e) {
        e.preventDefault();

        if (!this.requireAuthForAction()) return;

        const ip = document.getElementById('ipAddress')?.value?.trim();
        const reason = document.getElementById('reason')?.value?.trim();
        const duration = document.getElementById('duration')?.value;

        if (!ip) {
            this.showMessage('IP required', 'error');
            return;
        }
        if (!reason) {
            this.showMessage('Reason required', 'error');
            return;
        }

        const durationSec = parseInt(duration, 10);
        if (Number.isNaN(durationSec)) {
            this.showMessage('Invalid duration', 'error');
            return;
        }

        const res = await this.fetchWithAuth('/firewall', {
            method: 'POST',
            body: JSON.stringify({ ip, reason, duration_sec: durationSec })
        });

        if (!res.ok) return;

        this.closeModals();
        this.showMessage('Rule added', 'success');
        await this.loadFirewallRules();
    }

    async deleteRule(ip) {
        const res = await this.fetchWithAuth(`/firewall?ip=${encodeURIComponent(ip)}`, {
            method: 'DELETE'
        });

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

        if (res.data && typeof res.data === 'object') {
            container.textContent = JSON.stringify(res.data, null, 2);
        } else if (res.text) {
            container.textContent = res.text;
        } else {
            container.textContent = '{}';
        }
    }

    // ============ Utils ============

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
