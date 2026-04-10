import { Router, Out, layout, engine, auth, modal, emit, listen, keys,
    notify, query, make } from '../lib/oja.full.esm.js';
import { store, isLoggedIn, clearCredentials, getCreds, setCredentials } from './store.js';
import { startMetricsPolling } from './metrics.js';
import { fetchConfig, fetchUptime, fetchCerts, parseCertificates } from './api.js';
import { fmtNum, formatBytes, formatPercent } from './utils.js';
import './drawer-listeners.js';
import { initPerfListeners } from './perf.js';
import { initCommandPalette } from './command-palette.js';
import { initSessionGuard } from './session-guard.js';

const ERR = (...a) => console.error('[agbero]', ...a);

let router = null;

// Module-level router — accessible by onLoginSuccess and event handlers.
let _stopPolling     = null;
let _configPollTimer = null;

function startPollingIfNeeded() {
    if (window._isPolling) return;
    window._isPolling = true;
    _stopPolling = startMetricsPolling(store);
    if (_configPollTimer) clearInterval(_configPollTimer);
    _configPollTimer = setInterval(loadConfigData, 30_000);
}

export async function loadConfigData() {
    const [config, uptime, certs] = await Promise.all([
        fetchConfig(),
        fetchUptime(),
        fetchCerts(),
    ]);
    if (!config) return;
    store.set('lastConfig', config);
    store.set('sys.version', 'v' + (config.global?.version ?? '—'));

    const parsedCerts = parseCertificates(certs);
    store.set('certificates',  parsedCerts);
    store.set('certs.active',   parsedCerts.filter(c => c.days_left > 0).length);
    store.set('certs.expiring', parsedCerts.filter(c => c.days_left > 0 && c.days_left < 7).length);

    if (uptime) {
        store.set('lastUptime', uptime);
        store.set('gitStats', uptime.git || {});
    }
}

export async function onLoginSuccess() {
    store.set('auth.isLoggedIn', true);
    modal.closeAll();
    startPollingIfNeeded();
    await loadConfigData();
    const dest = store.get('auth.intendedPath') || '/';
    store.clear('auth.intendedPath');
    router.navigate(dest);
}

async function bootstrapApp() {
    engine.formatters.formatBytes   = formatBytes;
    engine.formatters.formatPercent = formatPercent;
    engine.formatters.fmtNum        = fmtNum;
    engine.formatters.loginText     = val => val ? 'Logout' : 'Login';
    engine.useStore(store);
    engine.enableAutoBind();

    router = new Router({ mode: 'hash', outlet: '#app' });

    listen('auth:login:success', async ({ type, token }) => {
        setCredentials(type, token);
        try {
            const isJwt = token && token.split('.').length === 3;
            await auth.session.start(token, null, isJwt ? {} : { expires: null });
        } catch (err) {
            ERR('auth.session.start error:', err);
        }
        await onLoginSuccess();
    });

    listen('config:reload', () => loadConfigData());

    listen('app:layout-unmount', () => {
        if (_stopPolling) { _stopPolling(); _stopPolling = null; }
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
    });

    listen('app:navigate', ({ path }) => {
        if (path) router.navigate(path);
    });

    // Init extracted modules (S-01, S-02, S-03)
    initPerfListeners();
    initCommandPalette();
    initSessionGuard();

    await layout.apply('#shell', 'layouts/shell.html');

    listen('api:offline', () => {
        store.set('sys.isOffline', true);
        notify.banner('⚠️ Connection lost. Attempting to reconnect…', { type: 'warn' });
    });
    listen('api:online', () => {
        store.set('sys.isOffline', false);
        notify.dismissBanner();
    });
    listen('api:unauthorized', () => {
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
        emit('auth:icon:update', { loggedIn: false });
        emit('auth:expired');
    });

    engine.bindToggle('#offlineBanner', 'sys.isOffline', { activeClass: 'active' });

    keys({
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
        'ctrl+k': () => emit('app:command-palette'),
        'escape': () => {
            const cp = query('#commandPaletteModal');
            if (cp?.classList.contains('active')) { emit('app:command-palette-close'); return; }
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
        return active || li;
    });

    auth.session.OnExpiry(async () => {
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = false;
        if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
        modal.open('loginModal');
    });

    const appGroup = router.Group('/');
    appGroup.Use(async (ctx, next) => {
        const ok = auth.guard('protected');
        if (!ok) {
            store.set('auth.intendedPath', ctx.path);
            modal.open('loginModal');
            return;
        }
        await next();
    });

    appGroup.Get('/',          Out.component('pages/dashboard.html'));
    appGroup.Get('/hosts',     Out.component('pages/hosts.html'));
    appGroup.Get('/cluster',   Out.component('pages/cluster.html'));
    appGroup.Get('/map',       Out.component('pages/map.html'));
    appGroup.Get('/firewall',  Out.component('pages/firewall.html'));
    appGroup.Get('/logs',      Out.component('pages/logs.html'));
    appGroup.Get('/config',    Out.component('pages/config.html'));
    appGroup.Get('/keeper',    Out.component('pages/keeper.html'));
    appGroup.Get('/profile',   Out.component('pages/profile.html'));
    appGroup.Get('/certs',     Out.component('pages/certs.html'));
    appGroup.Get('/add-host',  Out.component('pages/add-host.html'));
    router.NotFound(Out.html('<div class="page active"><div class="empty-state">Page Not Found</div></div>'));

    if (isLoggedIn()) {
        const { token, type } = getCreds();
        try {
            const isJwt = token && token.split('.').length === 3;
            await auth.session.start(token, null, isJwt ? {} : { expires: null });
        } catch (err) {
            ERR('boot: session restore failed — clearing stale token:', err.message);
            clearCredentials();
        }
        startPollingIfNeeded();
        loadConfigData();
    }

    await router.start('/');
}

bootstrapApp().catch(err => ERR('bootstrapApp fatal:', err));
