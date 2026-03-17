const EventHandler = {
    bindAll(app) {
        if (!app) return;

        // ================== GLOBAL EVENT DELEGATION ==================
        document.body.addEventListener('click', (e) => {
            const openRouteBtn = e.target.closest('[data-action="open-route"]');
            if (openRouteBtn) {
                app.openRouteDrawer(openRouteBtn.dataset.host, parseInt(openRouteBtn.dataset.idx), openRouteBtn.dataset.type);
                return;
            }

            const openBackendBtn = e.target.closest('[data-action="open-backend"]');
            if (openBackendBtn) {
                app.openBackendDrawer(openBackendBtn.dataset.host, parseInt(openBackendBtn.dataset.routeIdx), parseInt(openBackendBtn.dataset.backendIdx), openBackendBtn.dataset.type);
                return;
            }

            const copyableBtn = e.target.closest('[data-action="copy-url"]');
            if (copyableBtn) {
                e.stopPropagation();
                app.copyToClipboard(copyableBtn.dataset.url);
                return;
            }

            const unblockBtn = e.target.closest('[data-action="unblock-ip"]');
            if (unblockBtn) {
                app.confirmDeleteFw(unblockBtn.dataset.ip);
                return;
            }
        });

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
            let searchTimeout = null;
            searchInput.addEventListener("input", (e) => {
                clearTimeout(searchTimeout);
                const term = e.target.value;
                sessionStorage.setItem("ag_search", term);
                app.searchTerm = term;

                searchTimeout = setTimeout(() => {
                    UI.renderHosts(app.hostsData, term, app.certificates);
                }, 300);
            });
        }

        // ================== CLUSTER PAGE ==================
        const addClusterRouteBtn = document.getElementById("addClusterRouteBtn");
        if (addClusterRouteBtn) {
            addClusterRouteBtn.addEventListener("click", () => Modal.open("clusterRouteModal"));
        }

        const clusterRouteForm = document.getElementById("clusterRouteForm");
        if (clusterRouteForm) {
            clusterRouteForm.addEventListener("submit", (e) => app.addClusterRoute(e));
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

        const logsExportBtn = document.getElementById("logsExportBtn");
        if (logsExportBtn) {
            logsExportBtn.addEventListener("click", () => app.exportLogs());
        }

        const logsClearBtn = document.getElementById("logsClearBtn");
        if (logsClearBtn) {
            logsClearBtn.addEventListener("click", () => {
                app.logs =[];
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

        // ================== PERFORMANCE MODAL ==================
        const perfRange = document.getElementById("perfRangeSelect");
        if (perfRange) {
            perfRange.addEventListener("change", async () => {
                if (app._perfHost) {
                    ["perfChartReqs", "perfChartP99", "perfChartErrors", "perfChartBE"].forEach(id => {
                        document.getElementById(id).innerHTML = `<div class="perf-skeleton"></div>`;
                    });
                    await app._loadPerfData(app._perfHost, perfRange.value);
                }
            });
        }

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
        document.querySelectorAll(".drawer-close").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const target = e.currentTarget.getAttribute("data-target");
                app.closeDrawer(target);
            });
        });

        document.querySelectorAll(".drawer-back-link").forEach(btn => {
            btn.addEventListener("click", (e) => {
                const target = e.currentTarget.getAttribute("data-target");
                app.closeDrawer(target);
                if (target === "routeDrawer") {
                    app.setPage("hosts");
                }
            });
        });

        const drawerBackdrop = document.getElementById("drawerBackdrop");
        if (drawerBackdrop) drawerBackdrop.addEventListener("click", () => app.closeDrawer());

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

            hostNameEl.addEventListener("dblclick", (e) => {
                e.stopPropagation();
                const hostname = hostNameEl.innerText;
                app.openPerformanceModal(hostname);
            });

            hostNameEl.title = "Click to filter · Double-click for performance history";
        }

        const drawerPerfBtn = document.getElementById("drawerPerfBtn");
        if (drawerPerfBtn) {
            drawerPerfBtn.addEventListener("click", () => {
                const hostname = document.getElementById("drawerHostName")?.innerText;
                if (hostname) app.openPerformanceModal(hostname);
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
            if (e.target.matches('input, textarea, select')) return;

            if (e.key === "Escape") {
                app.closeDrawer();
                return;
            }

            if (e.ctrlKey || e.metaKey) {
                const num = parseInt(e.key);
                if (num >= 1 && num <= 7) {
                    e.preventDefault();
                    const pages = ['dashboard', 'hosts', 'cluster', 'map', 'firewall', 'logs', 'config'];
                    app.setPage(pages[num - 1]);
                    return;
                }
            }

            if (e.key === 'r' && !e.ctrlKey && !e.metaKey) {
                e.preventDefault();
                app.refreshCurrentPage();
                const activePage = document.querySelector('.page.active');
                if (activePage) {
                    activePage.style.opacity = '0.7';
                    setTimeout(() => activePage.style.opacity = '1', 200);
                }
                return;
            }

            if (e.key === '/' && app.page === 'hosts') {
                e.preventDefault();
                document.getElementById('hostSearch')?.focus();
                return;
            }

            if (e.key === '?' || (e.key === '/' && e.shiftKey)) {
                e.preventDefault();
                const shortcuts = [
                    'Ctrl+1-7: Navigate pages',
                    'r: Refresh current page',
                    'Esc: Close drawers',
                    '/: Focus search (hosts page)'
                ].join('\n');

                const toast = document.createElement('div');
                toast.style.cssText = `
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: var(--fg);
                    color: var(--bg);
                    padding: 16px 24px;
                    border-radius: 8px;
                    font-size: 12px;
                    font-family: monospace;
                    white-space: pre-line;
                    z-index: 2000;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
                    animation: slideIn 0.2s ease;
                `;
                toast.textContent = shortcuts;
                document.body.appendChild(toast);
                setTimeout(() => toast.remove(), 4000);
            }
        });

        this.initTouchEvents(app);
    },

    initTouchEvents(app) {
        ["routeDrawer", "backendDrawer"].forEach(id => {
            const drawer = document.getElementById(id);
            if (!drawer) return;

            let touchStartX = 0;
            drawer.addEventListener("touchstart", (e) => {
                touchStartX = e.touches[0].clientX;
            }, {passive: true});

            drawer.addEventListener("touchmove", (e) => {
                if (!drawer.classList.contains("active")) return;
                const touchX = e.touches[0].clientX;
                const diff = touchX - touchStartX;
                if (diff > 50) {
                    app.closeDrawer(id);
                }
            }, {passive: true});
        });
    }
};

const Drawer = {
    open(id) {
        const backdrop = document.getElementById("drawerBackdrop");
        const drawer = document.getElementById(id || "routeDrawer");
        if (backdrop) backdrop.classList.add("active");
        if (drawer) drawer.classList.add("active");
    },
    close(id) {
        if (id) {
            const drawer = document.getElementById(id);
            if (drawer) drawer.classList.remove("active");
            if (id === "routeDrawer") {
                const backdrop = document.getElementById("drawerBackdrop");
                if (backdrop) backdrop.classList.remove("active");
                const beDrawer = document.getElementById("backendDrawer");
                if (beDrawer) beDrawer.classList.remove("active");
            }
        } else {
            const beDrawer = document.getElementById("backendDrawer");
            if (beDrawer && beDrawer.classList.contains("active")) {
                beDrawer.classList.remove("active");
                return;
            }
            const rDrawer = document.getElementById("routeDrawer");
            if (rDrawer) rDrawer.classList.remove("active");
            const backdrop = document.getElementById("drawerBackdrop");
            if (backdrop) backdrop.classList.remove("active");
        }
    }
};

const Modal = {
    open(id) {
        const modal = document.getElementById(id);
        if (modal) modal.classList.add("active");
    },
    closeAll() {
        document.querySelectorAll(".modal-overlay").forEach(m => m.classList.remove("active"));
    }
};