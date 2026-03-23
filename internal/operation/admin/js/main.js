import { Router, Out, layout, engine, auth, modal, emit, listen, keys } from '../lib/oja.full.esm.js';
import { store, isLoggedIn, clearCredentials, getHost, getCreds, setCredentials } from './store.js';
import { startMetricsPolling } from './metrics.js';
import { fetchConfig, fetchUptime, parseCertificates } from './api.js';
import './drawer-listeners.js';

const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN    = 403;

async function performInitialChecks() {
    try {
        const host    = getHost();
        const baseUrl = host || window.location.origin;
        const creds   = getCreds();
        const headers = {};
        if (creds?.token) headers['Authorization'] = `${creds.type === 'basic' ? 'Basic' : 'Bearer'} ${creds.token}`;
        await fetch(baseUrl + '/healthz', { cache: 'no-store' });
        const res = await fetch(baseUrl + '/uptime', { cache: 'no-store', headers });
        if (res.status === HTTP_UNAUTHORIZED || res.status === HTTP_FORBIDDEN) {
            // 401/403 = auth failure, server IS reachable — never show offline banner
            store.set('sys.isOffline', false);
            clearCredentials();
            return false;
        }
        store.set('sys.isOffline', false);
        return res.ok;
    } catch {
        store.set('sys.isOffline', true);
        return false;
    }
}

let _stopPolling = null;

let _configPollTimer = null;

function startPollingIfNeeded() {
    if (window._isPolling) return;
    window._isPolling = true;
    _stopPolling = startMetricsPolling(store);

    // Config poll: every 30s — picks up weight changes, new routes, backend edits
    // without requiring a manual refresh. Metrics poll is every 2s but only covers
    // live stats; /config only changes when the operator edits configuration.
    if (_configPollTimer) clearInterval(_configPollTimer);
    _configPollTimer = setInterval(loadConfigData, 30_000);
}

// loadConfigData - fetches /config + /uptime and populates all config-related store keys
// Called at boot and on the config page refresh button
export async function loadConfigData() {
    const [config, uptime] = await Promise.all([
        fetchConfig(getCreds()),
        fetchUptime(getCreds()),
    ]);

    if (!config || config.__offline || config.__unauthorized) return;

    store.set('lastConfig',  config);
    store.set('sys.version', 'v' + (config.global?.version ?? '—'));

    const certs    = parseCertificates(config.hosts);
    const active   = certs.filter(c => c.daysLeft > 0).length;
    const expiring = certs.filter(c => c.daysLeft > 0 && c.daysLeft < 7).length;
    store.set('certificates',  certs);
    store.set('certs.active',   active);
    store.set('certs.expiring', expiring);

    if (uptime && !uptime.__offline) {
        store.set('lastUptime', uptime);
        store.set('gitStats', uptime.git || {});
    }
}

async function bootstrapApp() {
    engine.formatters.loginText = val => val ? 'Logout' : 'Login';
    engine.formatters.fmtNum    = val => Number(val || 0).toLocaleString();
    engine.useStore(store);
    engine.enableAutoBind();

    await layout.apply('#shell', 'layouts/shell.html');

    // layout.onUnmount must be called immediately after layout.apply() — still in context
    layout.onUnmount(() => {
        if (_stopPolling) { _stopPolling(); _stopPolling = null; }
        window._isPolling = false;
    });

    engine.bindToggle('#offlineBanner', 'sys.isOffline', { activeClass: 'active' });

    const router   = new Router({ mode: 'hash', outlet: '#app' });
    window._router = router;

    // ── Keyboard shortcuts (full set matching old admin) ──────────────────
    keys({
        'ctrl+1': () => router.navigate('/'),
        'ctrl+2': () => router.navigate('/hosts'),
        'ctrl+3': () => router.navigate('/cluster'),
        'ctrl+4': () => router.navigate('/map'),
        'ctrl+5': () => router.navigate('/firewall'),
        'ctrl+6': () => router.navigate('/logs'),
        'ctrl+7': () => router.navigate('/config'),
        'escape': () => {
            // Close drawers in order: backend first, then route
            const be = document.getElementById('backendDrawer');
            if (be?.classList.contains('active')) { be.classList.remove('active'); return; }
            const rd = document.getElementById('routeDrawer');
            if (rd?.classList.contains('active')) {
                rd.classList.remove('active');
                document.getElementById('drawerBackdrop')?.classList.remove('active');
            }
        },
        'r': () => {
            const path = router.current();
            if (path) router.refresh();
        },
        '/': () => document.getElementById('hostSearch')?.focus(),
        '?': () => {
            const shortcuts = 'Ctrl+1-7: Navigate  ·  r: Refresh  ·  /: Search  ·  Esc: Close';
            const t = Object.assign(document.createElement('div'), {
                textContent: shortcuts,
                style: 'position:fixed;top:20px;right:20px;background:var(--fg);color:var(--bg);padding:12px 20px;border-radius:8px;font-size:12px;font-family:monospace;z-index:2000;box-shadow:0 4px 12px rgba(0,0,0,.2)',
            });
            document.body.appendChild(t);
            setTimeout(() => t.remove(), 4000);
        },
    });

    // ── Auth level and session hooks ──────────────────────────────────────
    auth.level('protected', () => auth.session.isActive() || isLoggedIn());

    auth.session.OnStart(async () => {
        store.set('auth.isLoggedIn', true);
        modal.closeAll();
        startPollingIfNeeded();
        await loadConfigData();
        const dest = store.get('auth.intendedPath') || '/';
        store.clear('auth.intendedPath');
        router.navigate(dest);
    });

    auth.session.OnExpiry(async () => {
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
        modal.open('loginModal');
    });

    // ── Route guard ───────────────────────────────────────────────────────
    const appGroup = router.Group('/');
    appGroup.Use(async (ctx, next) => {
        if (!auth.guard('protected')) {
            store.set('auth.intendedPath', ctx.path);
            modal.open('loginModal');
            return;
        }
        await next();
    });

    appGroup.Get('/',         Out.component('pages/dashboard.html'));
    appGroup.Get('/hosts',    Out.component('pages/hosts.html'));
    appGroup.Get('/cluster',  Out.component('pages/cluster.html'));
    appGroup.Get('/map',      Out.component('pages/map.html'));
    appGroup.Get('/firewall', Out.component('pages/firewall.html'));
    appGroup.Get('/logs',     Out.component('pages/logs.html'));
    appGroup.Get('/config',   Out.component('pages/config.html'));
    router.NotFound(Out.html('<div class="page active"><div class="empty-state">Page Not Found</div></div>'));

    // ── Boot sequence ─────────────────────────────────────────────────────
    const serverOk = await performInitialChecks();

    if (isLoggedIn()) {
        startPollingIfNeeded();
        loadConfigData(); // non-blocking — populates store for all pages
    } else {
        // No credentials — show login immediately (matches old app.init() behaviour)
        modal.open('loginModal');
    }

    router.start('/');
}

bootstrapApp();