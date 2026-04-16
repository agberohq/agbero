/**
 * js/main.js — Application bootstrap.
 */
import { Router, Out, layout, engine, auth, modal, emit, listen, keys,
    notify, query, make, hotkeys, Queue, Store, logger, progress,
    chart, countdown, clickmenu, pagination, Search, tabs, ui,
    clipboard, wizard, collapse } from '../lib/oja.full.esm.js';
import { store, getHost, setHost } from './store.js';
import { startMetricsPolling } from './metrics.js';
import {
    fetchConfig, fetchUptime, fetchCerts, parseCertificates,
    getApi, apiSetToken, apiClearToken, reinitApi,
    fetchStatus, logout,
    fetchFirewall, addFirewallRule, deleteFirewallRule,
    addHost, addHostHCL, deleteHost, updateHost, updateHostHCL, getHostHCL, checkHostExists,
    fetchLogs, uploadCert, deleteCert,
    keeperStatus, keeperUnlock, keeperLock, keeperList, keeperGet,
    keeperSet, keeperSetFile, keeperDelete,
    setupTOTP, fetchTelemetry, broadcastClusterRoute,
    parseCertificates as _parseCertificates,
} from './api.js';
import {
    fmtNum, formatBytes, formatPercent, isOn, initials, parseDuration,
    debounce, validateKeeperKey, composeKeeperRef, splitKeeperKey, decodeKeeperValue,
} from './utils.js';
import './drawer-listeners.js';
import { initPerfListeners } from './perf.js';
import { initLogin, updateNodeDisplay, _loginReset, checkServerStatus } from './login.js';
import { formatHCL, highlightHCL, HCL_CSS } from './hcl.js';
import { buildHostConfig } from './host-builder.js';

const ERR = (...a) => {
    console.error('[agbero]', ...a);
    try { logger.error('main', String(a[0]), { detail: a.slice(1) }); } catch {}
};

let router = null;

let _isPolling   = false;
let _stopPolling = null;
let _configPollTimer = null;

function startPollingIfNeeded() {
    if (_isPolling) return;
    _isPolling = true;
    _stopPolling = startMetricsPolling(store);
    if (_configPollTimer) clearInterval(_configPollTimer);
    _configPollTimer = setInterval(loadConfigData, 30_000);
}

function stopPolling() {
    if (_stopPolling) { _stopPolling(); _stopPolling = null; }
    _isPolling = false;
    if (_configPollTimer) { clearInterval(_configPollTimer); _configPollTimer = null; }
}

export async function loadConfigData() {
    const [config, uptime, certs] = await Promise.all([fetchConfig(), fetchUptime(), fetchCerts()]);
    if (!config) return;
    store.set('lastConfig', config);
    store.set('sys.version', 'v' + (config.global?.version ?? '—'));
    const parsedCerts = parseCertificates(certs);
    store.set('certificates',   parsedCerts);
    store.set('certs.active',   parsedCerts.filter(c => c.days_left > 0).length);
    store.set('certs.expiring', parsedCerts.filter(c => c.days_left > 0 && c.days_left < 7).length);
    if (uptime) { store.set('lastUptime', uptime); store.set('gitStats', uptime.git || {}); }
}

let writeQueue = null;

function _initWriteQueue() {
    try {
        writeQueue = new Queue({
            api:     getApi(),
            store:   new Store('ag-write-queue', { prefer: 'local' }),
            retries: 3,
        });
        writeQueue.start();
        writeQueue.on('queued',   () => notify.info('Operation queued — will retry when online'));
        writeQueue.on('replayed', () => notify.success('Offline operation synced'));
        writeQueue.on('failed',   ({ error }) => logger.warn('queue', 'Write replay failed', { error: error?.message }));
    } catch (e) { ERR('Queue init failed:', e.message); }
}

async function _onLoginSuccess() {
    store.set('auth.isLoggedIn', true);
    modal.closeAll();
    startPollingIfNeeded();
    await loadConfigData();
    const dest = auth.session.intendedPath() || '/';
    auth.session.clearIntendedPath();
    router.navigate(dest);
}

async function bootstrapApp() {
    logger.info('main', 'bootstrapApp start');

    engine.formatters.formatBytes   = formatBytes;
    engine.formatters.formatPercent = formatPercent;
    engine.formatters.fmtNum        = fmtNum;
    engine.formatters.loginText     = val => val ? 'Logout' : 'Login';
    engine.useStore(store);
    engine.enableAutoBind();

    router = new Router({ mode: 'hash', outlet: '#app' });
    _initWriteQueue();

    // App services — provided to all pages via inject('app')
    const appServices = {
        store,
        api: {
            fetchUptime, fetchConfig, fetchCerts, fetchFirewall, fetchLogs, fetchStatus,
            addHost, addHostHCL, deleteHost, updateHost, updateHostHCL, getHostHCL, checkHostExists,
            uploadCert, deleteCert, addFirewallRule, deleteFirewallRule,
            broadcastClusterRoute,
            keeperStatus, keeperUnlock, keeperLock, keeperList,
            keeperGet, keeperSet, keeperSetFile, keeperDelete,
            setupTOTP, fetchTelemetry, logout,
            parseCertificates: _parseCertificates,
        },
        utils: {
            fmtNum, formatBytes, formatPercent, isOn, initials,
            parseDuration, debounce, validateKeeperKey, composeKeeperRef,
            splitKeeperKey, decodeKeeperValue,
        },
        hcl:         { formatHCL, highlightHCL, HCL_CSS },
        hostBuilder: { buildHostConfig },
        writeQueue,
        logger,
        progress:    (channel) => progress(channel),
        oja:         { modal, emit, listen, notify, auth, query, make,
                       chart, countdown, clickmenu, pagination, Search, tabs, ui,
                       clipboard, wizard, collapse, hotkeys, Out },
    };

    auth.session.OnStart(async (token) => {
        apiSetToken(token);
        await _onLoginSuccess();
        _loginReset();
    });

    auth.session.OnExpiry(() => {
        store.set('auth.isLoggedIn', false);
        apiClearToken(); stopPolling();
        notify.warn('Session expired — please sign in again.');
        modal.open('loginModal');
        logger.warn('auth', 'Session expired');
    });

    auth.session.OnRenew((newToken) => { apiSetToken(newToken); logger.info('auth', 'Session renewed'); });

    listen('config:reload', () => loadConfigData());
    listen('app:navigate',  ({ path }) => { if (path) router.navigate(path); });

    initPerfListeners();

    hotkeys.register([
        { label: 'Dashboard',    action: () => router.navigate('/'),         keys: 'Ctrl+1', icon: '🏠' },
        { label: 'Hosts',        action: () => router.navigate('/hosts'),    keys: 'Ctrl+2', icon: '🖥'  },
        { label: 'Cluster',      action: () => router.navigate('/cluster'),  keys: 'Ctrl+3', icon: '🔗' },
        { label: 'Map',          action: () => router.navigate('/map'),      keys: 'Ctrl+4', icon: '🗺' },
        { label: 'Firewall',     action: () => router.navigate('/firewall'), keys: 'Ctrl+5', icon: '🛡' },
        { label: 'Logs',         action: () => router.navigate('/logs'),     keys: 'Ctrl+6', icon: '📄' },
        { label: 'Config',       action: () => router.navigate('/config'),   keys: 'Ctrl+7', icon: '⚙️'  },
        { label: 'Keeper',       action: () => router.navigate('/keeper'),   keys: 'Ctrl+8', icon: '🔐' },
        { label: 'Profile',      action: () => router.navigate('/profile'),  keys: 'Ctrl+9', icon: '👤' },
        { label: 'Certificates', action: () => router.navigate('/certs'),    keys: 'Ctrl+0', icon: '📜' },
        { label: 'Add Host',     action: () => router.navigate('/add-host'),              icon: '➕' },
    ]);

    // Mount shell layout — shell.js receives appServices via data.app
    // and calls scope.provide('app', data.app) so pages can inject('app')
    await layout.apply('#shell', {
        html: '/layouts/shell.html',
        js:   '/layouts/shell.js',
        data: { app: appServices },
    });

    listen('api:offline',      () => { store.set('sys.isOffline', true);  notify.banner('⚠️ Connection lost. Attempting to reconnect…', { type: 'warn' }); });
    listen('api:online',       () => { store.set('sys.isOffline', false); notify.dismissBanner(); });
    listen('api:unauthorized', () => {
        store.set('auth.isLoggedIn', false);
        apiClearToken(); stopPolling();
        emit('auth:icon:update', { loggedIn: false });
        emit('auth:expired');
    });

    engine.bindToggle('#offlineBanner', 'sys.isOffline', { activeClass: 'active' });

    keys({
        'escape': () => {
            const be = query('#backendDrawer');
            if (be?.classList.contains('active')) { modal.closeById('backendDrawer'); return; }
            const rd = query('#routeDrawer');
            if (rd?.classList.contains('active')) { modal.closeById('routeDrawer'); return; }
        },
        'r':      () => { const path = router.current(); if (path) router.refresh(); },
        '/':      () => query('#hostSearch')?.focus(),
        'ctrl+?': () => modal.open('shortcutsModal'),
    }, { preventDefault: true });

    auth.level('protected', () => auth.session.isActive());

    const appGroup = router.Group('/');
    appGroup.Use(async (ctx, next) => {
        if (!auth.guard('protected')) {
            try { auth.session._metaStore?.set?.('intendedPath', ctx.path); } catch {}
            modal.open('loginModal');
            return;
        }
        await next();
    });

    appGroup.Get('/',         Out.page('/pages/dashboard.html', '/pages/dashboard.js'));
    appGroup.Get('/hosts',    Out.page('/pages/hosts/index.html', '/pages/hosts/index.js'));
    appGroup.Get('/cluster',  Out.page('/pages/cluster.html', '/pages/cluster.js'));
    appGroup.Get('/map',      Out.page('/pages/map.html', '/pages/map.js'));
    appGroup.Get('/firewall', Out.page('/pages/firewall.html', '/pages/firewall.js'));
    appGroup.Get('/logs',     Out.page('/pages/logs.html', '/pages/logs.js'));
    appGroup.Get('/config',   Out.page('/pages/config.html', '/pages/config.js'));
    appGroup.Get('/keeper',   Out.page('/pages/keeper.html', '/pages/keeper.js'));
    appGroup.Get('/profile',  Out.page('/pages/profile.html', '/pages/profile.js'));
    appGroup.Get('/certs',    Out.page('/pages/certs.html', '/pages/certs.js'));
    appGroup.Get('/add-host', Out.page('/pages/add-host/index.html', '/pages/add-host/index.js'));

    router.NotFound(Out.html('<div class="page active"><div class="empty-state">Page Not Found</div></div>'));

    const token = auth.session.tokenSync();
    if (token) {
        apiSetToken(token);
        startPollingIfNeeded();
        loadConfigData();
        logger.info('main', 'Session restored from encrypted storage');
    }

    await router.start('/');
    logger.info('main', 'Router started');
}

bootstrapApp().catch(err => ERR('bootstrapApp fatal:', err.message));
