import { Router, Out, layout, engine, auth, modal, emit, listen, keys,
    notify, formatBytes, formatPercent, query, make } from '../lib/oja.full.esm.js';
import { store, isLoggedIn, clearCredentials, getCreds, setCredentials } from './store.js';
import { startMetricsPolling } from './metrics.js';
import { fetchConfig, fetchUptime, parseCertificates } from './api.js';
import './drawer-listeners.js';

// eslint-disable-next-line no-unused-vars
const LOG = () => {}; // stripped — was console.log
const ERR = (...a) => console.error('[agbero]', ...a);

// Module-level router — accessible by onLoginSuccess and event handlers.
let router = null;

function fmtNum(val) {
    const n = Number(val || 0);
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
    return String(n);
}

let _stopPolling     = null;
let _configPollTimer = null;

function startPollingIfNeeded() {
    if (window._isPolling) { LOG('polling already active'); return; }
    LOG('starting metrics polling');
    window._isPolling = true;
    _stopPolling = startMetricsPolling(store);
    if (_configPollTimer) clearInterval(_configPollTimer);
    _configPollTimer = setInterval(loadConfigData, 30_000);
}

export async function loadConfigData() {
    LOG('loadConfigData: fetching /config + /uptime');
    const [config, uptime] = await Promise.all([fetchConfig(), fetchUptime()]);
    LOG('loadConfigData: config=', !!config, 'uptime=', !!uptime);
    if (!config) { LOG('loadConfigData: no config — skipping'); return; }
    store.set('lastConfig',  config);
    store.set('sys.version', 'v' + (config.global?.version ?? '—'));
    const certs = parseCertificates(config.hosts);
    store.set('certificates',  certs);
    store.set('certs.active',   certs.filter(c => c.daysLeft > 0).length);
    store.set('certs.expiring', certs.filter(c => c.daysLeft > 0 && c.daysLeft < 7).length);
    if (uptime) {
        store.set('lastUptime', uptime);
        store.set('gitStats', uptime.git || {});
    }
    LOG('loadConfigData: done, hosts=', Object.keys(config.hosts || {}).length);
}

// Owned by main.js. Called after session is fully established.
export async function onLoginSuccess() {
    LOG('onLoginSuccess: start');
    store.set('auth.isLoggedIn', true);
    modal.closeAll();
    startPollingIfNeeded();
    await loadConfigData();
    const dest = store.get('auth.intendedPath') || '/';
    store.clear('auth.intendedPath');
    LOG('onLoginSuccess: navigating to', dest);
    router.navigate(dest);
}

async function bootstrapApp() {
    LOG('bootstrapApp: start, isLoggedIn=', isLoggedIn());

    engine.formatters.formatBytes   = formatBytes;
    engine.formatters.formatPercent = formatPercent;
    engine.formatters.fmtNum        = fmtNum;
    engine.formatters.loginText     = val => val ? 'Logout' : 'Login';
    engine.useStore(store);
    engine.enableAutoBind();

    // Router (module-level, hoisted)
    router = new Router({ mode: 'hash', outlet: '#app' });

    // Shell event listeners
    // shell.html emits these — main.js owns the responses.
    // Registered before layout.apply so they are live on first user interaction.
    listen('auth:login:success', async ({ type, token }) => {
        LOG('auth:login:success — type=', type);
        setCredentials(type, token);
        try {
            const isJwt = token && token.split('.').length === 3;
            await auth.session.start(token, null, isJwt ? {} : { expires: null });
            LOG('auth.session.start done, isActive=', auth.session.isActive());
        } catch (err) {
            ERR('auth.session.start error:', err);
        }
        await onLoginSuccess();
    });

    listen('config:reload', () => {
        LOG('config:reload');
        loadConfigData();
    });

    // Cleanup emitted from shell.html's layout.onUnmount (must live in layout script, not here)
    listen('app:layout-unmount', () => {
        if (_stopPolling) { _stopPolling(); _stopPolling = null; }
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
    });

    // Any page component can navigate without importing the router directly.
    //   emit('app:navigate', { path: '/hosts' });
    listen('app:navigate', ({ path }) => {
        if (path) router.navigate(path);
    });

    LOG('bootstrapApp: router + listeners registered');

    LOG('bootstrapApp: applying shell layout');
    await layout.apply('#shell', 'layouts/shell.html');
    LOG('bootstrapApp: layout applied — #loginModal exists=',
        !!document.getElementById('loginModal'));

    listen('api:offline', () => {
        LOG('api:offline');
        store.set('sys.isOffline', true);
        notify.banner('⚠️ Connection lost. Attempting to reconnect…', { type: 'warn' });
    });
    listen('api:online', () => {
        LOG('api:online');
        store.set('sys.isOffline', false);
        notify.dismissBanner();
    });
    listen('api:unauthorized', () => {
        LOG('api:unauthorized — clearing session');
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
        emit('auth:expired');
    });

    engine.bindToggle('#offlineBanner', 'sys.isOffline', { activeClass: 'active' });

    keys({
        // Ctrl+1-9,0: navigate pages
        'ctrl+1': () => router.navigate('/'),
        'ctrl+2': () => router.navigate('/hosts'),
        'ctrl+3': () => router.navigate('/cluster'),
        'ctrl+4': () => router.navigate('/map'),
        'ctrl+5': () => router.navigate('/firewall'),
        'ctrl+6': () => router.navigate('/logs'),
        'ctrl+7': () => router.navigate('/config'),
        'ctrl+8': () => router.navigate('/keeper'),
        'ctrl+9': () => router.navigate('/profile'),
        'ctrl+0': () => router.navigate('/certs'),
        // Ctrl+K: command palette — quick nav by name
        'ctrl+k': () => emit('app:command-palette'),
        'escape': () => {
            // Close command palette first if open
            const cp = query('#commandPalette');
            if (cp?.style.display !== 'none' && cp) { emit('app:command-palette-close'); return; }
            const be = query('#backendDrawer');
            if (be?.classList.contains('active')) { modal.closeById('backendDrawer'); return; }
            const rd = query('#routeDrawer');
            if (rd?.classList.contains('active')) { modal.closeById('routeDrawer'); return; }
        },
        'r': () => { const path = router.current(); if (path) router.refresh(); },
        '/': () => query('#hostSearch')?.focus(),
    }, { preventDefault: true });

    auth.level('protected', () => {
        const active = auth.session.isActive();
        const li     = isLoggedIn();
        LOG('auth.guard: isActive=', active, 'isLoggedIn=', li);
        return active || li;
    });

    auth.session.OnExpiry(async () => {
        LOG('auth session expired');
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
        modal.open('loginModal');
    });

    const appGroup = router.Group('/');
    appGroup.Use(async (ctx, next) => {
        const ok = auth.guard('protected');
        LOG('route guard: path=', ctx.path, '| ok=', ok);
        if (!ok) {
            store.set('auth.intendedPath', ctx.path);
            LOG('route guard: opening loginModal');
            modal.open('loginModal');
            return;
        }
        LOG('route guard: authed — rendering', ctx.path);
        await next();
    });

    appGroup.Get('/',         Out.component('pages/dashboard.html'));
    appGroup.Get('/hosts',    Out.component('pages/hosts.html'));
    appGroup.Get('/cluster',  Out.component('pages/cluster.html'));
    appGroup.Get('/map',      Out.component('pages/map.html'));
    appGroup.Get('/firewall', Out.component('pages/firewall.html'));
    appGroup.Get('/logs',     Out.component('pages/logs.html'));
    appGroup.Get('/config',   Out.component('pages/config.html'));
    appGroup.Get('/keeper',   Out.component('pages/keeper.html'));
    appGroup.Get('/profile',  Out.component('pages/profile.html'));
    appGroup.Get('/certs',    Out.component('pages/certs.html'));
    router.NotFound(Out.html('<div class="page active"><div class="empty-state">Page Not Found</div></div>'));

    if (isLoggedIn()) {
        LOG('boot: token in localStorage — restoring session');
        const { token, type } = getCreds();
        LOG('boot: type=', type, 'token length=', token?.length);
        try {
            // auth.session.start() only sets isActive()=true for JWTs (tokens with exp claim).
            // For opaque/Basic tokens there is no exp — pass { expires: null } so isActive()
            // returns true (no-expiry sentinel) while the token is present in storage.
            const isJwt = token && token.split('.').length === 3;
            await auth.session.start(token, null, isJwt ? {} : { expires: null });
            LOG('boot: session restored, isActive=', auth.session.isActive());
        } catch (err) {
            ERR('boot: session restore failed — clearing stale token:', err.message);
            clearCredentials();
        }
        startPollingIfNeeded();
        loadConfigData();
    } else {
        LOG('boot: no token — route guard will open loginModal');
    }

    LOG('bootstrapApp: calling router.start');
    await router.start('/');
    LOG('bootstrapApp: complete');
}

bootstrapApp().catch(err => ERR('bootstrapApp fatal:', err));
