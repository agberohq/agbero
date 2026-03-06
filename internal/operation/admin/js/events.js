const EventHandler = {
    bindAll(app) {
        if (!app) return;

        // ================== NAVIGATION ==================
        document.querySelectorAll(".nav-link").forEach(l => {
            l.addEventListener("click", e => {
                if (e.target.id === 'loginBtn') return;
                e.preventDefault();
                const page = e.target.dataset.page;
                if (page) app.setPage(page);
            });
        });

        // ================== THEME ==================
        const themeToggle = document.getElementById("themeToggle");
        if (themeToggle) themeToggle.addEventListener("click", () => app.toggleTheme());

        // ================== AUTH ==================
        const loginBtn = document.getElementById("loginBtn");
        if (loginBtn) loginBtn.addEventListener("click", (e) => {
            e.preventDefault();
            app.handleAuthClick();
        });

        // ================== HOSTS PAGE ==================
        const refreshHostsBtn = document.getElementById("refreshHostsBtn");
        if (refreshHostsBtn) refreshHostsBtn.addEventListener("click", () => app.fetchHostsData());

        const searchInput = document.getElementById("hostSearch");
        if (searchInput) {
            searchInput.addEventListener("input", (e) => {
                const term = e.target.value;
                sessionStorage.setItem("ag_search", term);
                app.searchTerm = term;
                UI.renderHosts(app.hostsData, term, app.certificates);
            });
        }

        // ================== MAP PAGE ==================
        const mapPauseBtn = document.getElementById("mapPauseBtn");
        if (mapPauseBtn) {
            mapPauseBtn.addEventListener("click", () => {
                app.mapPaused = !app.mapPaused;
                mapPauseBtn.innerText = app.mapPaused ? "Resume Updates" : "Pause Updates";
                if(!app.mapPaused) app.fetchHostsData();
            });
        }

        const resetZoomBtn = document.getElementById("resetZoomBtn");
        if (resetZoomBtn) {
            resetZoomBtn.addEventListener("click", () => {
                if (app.routeGraph) app.routeGraph.resetZoom();
            });
        }

        // ================== LOGIN MODAL ==================
        const loginForm = document.getElementById("loginForm");
        if (loginForm) loginForm.addEventListener("submit", e => app.doLogin(e));

        // ================== FIREWALL PAGE ==================
        const addRuleBtn = document.getElementById("addRuleBtn");
        if (addRuleBtn) addRuleBtn.addEventListener("click", () => Modal.open("ruleModal"));

        const ruleForm = document.getElementById("ruleForm");
        if (ruleForm) ruleForm.addEventListener("submit", e => app.addFirewallRule(e));

        // ================== LOGS PAGE ==================
        const logsPauseBtn = document.getElementById("logsPauseBtn");
        if (logsPauseBtn) {
            logsPauseBtn.addEventListener("click", () => {
                app.logsPaused = !app.logsPaused;
                logsPauseBtn.innerText = app.logsPaused ? "Resume" : "Pause";
            });
        }

        const logsClearBtn = document.getElementById("logsClearBtn");
        if (logsClearBtn) {
            logsClearBtn.addEventListener("click", () => {
                app.logs = [];
                UI.renderLogs(app.logs, app.logFilter);
            });
        }

        const logsTailSelect = document.getElementById("logsTailSelect");
        if (logsTailSelect) {
            logsTailSelect.addEventListener("change", () => app.fetchLogs());
        }

        document.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", (e) => {
                document.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
                e.target.classList.add("active");
                app.logFilter = e.target.dataset.level;
                UI.renderLogs(app.logs, app.logFilter);
            });
        });

        // ================== CONFIG PAGE ==================
        const configRefreshBtn = document.querySelector('.config-refresh');
        if (configRefreshBtn) {
            configRefreshBtn.addEventListener('click', (e) => {
                e.preventDefault();
                app.fetchConfig();
            });
        }

        const copyConfigBtn = document.querySelector('.config-copy');
        if (copyConfigBtn) {
            copyConfigBtn.addEventListener('click', (e) => {
                e.preventDefault();
                if (app.lastConfig) {
                    app.copyToClipboard(JSON.stringify(app.lastConfig, null, 2));
                }
            });
        }

        const expandBtn = document.querySelector('.config-expand');
        if (expandBtn) {
            expandBtn.addEventListener('click', (e) => {
                e.preventDefault();
                const configContent = document.getElementById('configContent');
                if (configContent) {
                    configContent.classList.toggle('expanded');
                    e.target.innerText = configContent.classList.contains('expanded') ? '↕️ Collapse' : '↕️ Expand';
                }
            });
        }

        // ================== MODAL CONTROLS ==================
        document.querySelectorAll(".close-modal").forEach(b => {
            b.addEventListener("click", () => Modal.closeAll());
        });

        // ================== CONFIRM MODAL ==================
        const confirmCancel = document.getElementById("confirmCancel");
        if (confirmCancel) confirmCancel.addEventListener("click", () => Modal.closeAll());

        const confirmOk = document.getElementById("confirmOk");
        if (confirmOk) {
            confirmOk.addEventListener("click", async () => {
                if (app._confirmFn) await app._confirmFn();
                Modal.closeAll();
            });
        }

        // ================== DRAWER CONTROLS ==================
        const drawerCloseBtn = document.getElementById("drawerCloseBtn");
        if (drawerCloseBtn) drawerCloseBtn.addEventListener("click", () => app.closeDrawer());

        const drawerBackdrop = document.getElementById("drawerBackdrop");
        if (drawerBackdrop) drawerBackdrop.addEventListener("click", () => app.closeDrawer());

        const drawerBackToHosts = document.getElementById("drawerBackToHosts");
        if (drawerBackToHosts) {
            drawerBackToHosts.addEventListener("click", () => {
                app.closeDrawer();
                app.setPage("hosts");
            });
        }

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
        const refreshSessionBtn = document.getElementById("refreshSessionBtn");
        if (refreshSessionBtn) {
            refreshSessionBtn.addEventListener("click", () => {
                app.renewSession();
            });
        }

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