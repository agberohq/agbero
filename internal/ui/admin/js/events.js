const EventHandler = {
    bindAll(app) {
        // ================== NAVIGATION ==================
        document.querySelectorAll(".nav-link").forEach(l => {
            l.addEventListener("click", e => {
                if (e.target.id === 'loginBtn') return;
                e.preventDefault();
                app.setPage(e.target.dataset.page);
            });
        });

        // ================== THEME ==================
        document.getElementById("themeToggle")?.addEventListener("click", () => app.toggleTheme());

        // ================== AUTH ==================
        document.getElementById("loginBtn")?.addEventListener("click", () => app.handleAuthClick());

        // ================== HOSTS PAGE ==================
        document.getElementById("refreshHostsBtn")?.addEventListener("click", () => app.fetchHostsData());

        const searchInput = document.getElementById("hostSearch");
        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                const term = e.target.value;
                sessionStorage.setItem("ag_search", term);
                app.searchTerm = term;
                UI.renderHosts(app.hostsData, term, app.certificates);
            });
        }

        // ================== LOGIN MODAL ==================
        document.getElementById("loginForm")?.addEventListener("submit", e => app.doLogin(e));

        // ================== FIREWALL PAGE ==================
        document.getElementById("addRuleBtn")?.addEventListener("click", () => Modal.open("ruleModal"));
        document.getElementById("ruleForm")?.addEventListener("submit", e => app.addFirewallRule(e));

        // ================== LOGS PAGE ==================
        document.getElementById("logsPauseBtn")?.addEventListener("click", () => {
            app.logsPaused = !app.logsPaused;
            document.getElementById("logsPauseBtn").innerText = app.logsPaused ? "Resume" : "Pause";
        });

        document.getElementById("logsClearBtn")?.addEventListener("click", () => {
            app.logs = [];
            UI.renderLogs(app.logs, app.logFilter);
        });

        document.getElementById("logsTailSelect")?.addEventListener("change", () => app.fetchLogs());

        document.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", (e) => {
                document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
                e.target.classList.add("active");
                app.logFilter = e.target.dataset.level;
                UI.renderLogs(app.logs, app.logFilter);
            });
        });

        // ================== CONFIG PAGE ==================
        // Refresh button
        const configRefreshBtn = document.querySelector('.config-refresh');
        if (configRefreshBtn) {
            configRefreshBtn.addEventListener('click', (e) => {
                e.preventDefault();
                app.fetchConfig();
            });
        }

        // Copy config button
        const copyConfigBtn = document.querySelector('.config-copy');
        if (copyConfigBtn) {
            copyConfigBtn.addEventListener('click', (e) => {
                e.preventDefault();
                if (app.lastConfig) {
                    app.copyToClipboard(JSON.stringify(app.lastConfig, null, 2));
                }
            });
        }

        // Expand/collapse config button
        const expandBtn = document.querySelector('.config-expand');
        if (expandBtn) {
            expandBtn.addEventListener('click', (e) => {
                e.preventDefault();
                document.getElementById('configContent').classList.toggle('expanded');
                e.target.innerText = document.getElementById('configContent').classList.contains('expanded') ? '↕️ Collapse' : '↕️ Expand';
            });
        }

        // ================== MODAL CONTROLS ==================
        document.querySelectorAll(".close-modal").forEach(b => {
            b.addEventListener("click", () => Modal.closeAll());
        });

        // ================== CONFIRM MODAL ==================
        document.getElementById("confirmCancel")?.addEventListener("click", () => Modal.closeAll());
        document.getElementById("confirmOk")?.addEventListener("click", async () => {
            if (app._confirmFn) await app._confirmFn();
            Modal.closeAll();
        });

        // ================== DRAWER CONTROLS ==================
        document.getElementById("drawerCloseBtn")?.addEventListener("click", () => app.closeDrawer());
        document.getElementById("drawerBackdrop")?.addEventListener("click", () => app.closeDrawer());
        document.getElementById("drawerBackToHosts")?.addEventListener("click", () => {
            app.closeDrawer();
            app.setPage("hosts");
        });

        // Clickable hostname in drawer
        const hostNameEl = document.getElementById("drawerHostName");
        if (hostNameEl) {
            hostNameEl.addEventListener("click", () => {
                const hostname = hostNameEl.innerText;
                app.closeDrawer();
                app.setPage("hosts");
                const searchInput = document.getElementById("hostSearch");
                if (searchInput) {
                    searchInput.value = hostname;
                    sessionStorage.setItem("ag_search", hostname);
                    app.searchTerm = hostname;
                    UI.renderHosts(app.hostsData, hostname, app.certificates);
                }
            });
        }

        // ================== SESSION MANAGEMENT ==================
        document.getElementById("refreshSessionBtn")?.addEventListener("click", () => {
            app.renewSession();
        });

        // ================== KEYBOARD SHORTCUTS ==================
        document.addEventListener("keydown", (e) => {
            if (e.key === "Escape") app.closeDrawer();
        });

        // ================== TOUCH EVENTS FOR DRAWER ==================
        this.initTouchEvents(app);
    },

    initTouchEvents(app) {
        const drawer = document.getElementById("routeDrawer");
        if (!drawer) return;

        let touchStartX = 0;
        drawer.addEventListener("touchstart", (e) => {
            touchStartX = e.touches[0].clientX;
        }, false);

        drawer.addEventListener("touchmove", (e) => {
            if (!drawer.classList.contains("active")) return;
            const touchX = e.touches[0].clientX;
            const diff = touchX - touchStartX;
            if (diff > 50) {
                app.closeDrawer();
            }
        }, false);
    }
};

// ================== MODAL CONTROLS ==================
const Modal = {
    open(id) {
        document.getElementById(id)?.classList.add("active");
    },
    closeAll() {
        document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    }
};

// ================== DRAWER CONTROLS ==================
const Drawer = {
    open() {
        document.getElementById("drawerBackdrop")?.classList.add("active");
        document.getElementById("routeDrawer")?.classList.add("active");
    },
    close() {
        document.getElementById("drawerBackdrop")?.classList.remove("active");
        document.getElementById("routeDrawer")?.classList.remove("active");
    }
};