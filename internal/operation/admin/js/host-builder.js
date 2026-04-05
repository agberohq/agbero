/**
 * js/host-builder.js
 *
 * Pure function: buildHostConfig(wizardData) → alaye Host JSON
 *
 * Accepts either:
 *   - new wizard format: wizardData.routes = [{ path, engine, engineData, extras, authData }]
 *   - legacy flat format: wizardData.domain, wizardData.host_type, etc.
 *
 * No DOM, no imports, no side effects — unit-testable.
 */

export function buildHostConfig(data) {
    const domain  = (data.domain || '').trim().toLowerCase();
    const tlsMode = data.tls_mode || 'auto';

    // TLS block
    // Local/dev domains don't get a TLS block — agbero infers HTTP-only
    const isLocalDomain = (d) => {
        const h = (d||'').trim().toLowerCase();
        return !h || /^\d+\.\d+\.\d+\.\d+$/.test(h) ||
            ['localhost','.localhost','.local','.internal','.test','.example'].some(s => h === s.replace('.','') || h.endsWith(s));
    };
    let tls = null;
    if (!isLocalDomain(domain) && tlsMode && tlsMode !== '') {
        tls = { mode: tlsMode };
        if (tlsMode === 'local') {
            tls.local = {
                enabled:   'on',
                cert_file: (data.tls_cert || '').trim(),
                key_file:  (data.tls_key  || '').trim(),
            };
        }
    }

    // Routes
    // New wizard format passes routes as an array of route objects
    const routesInput = data.routes;
    let routes;

    if (Array.isArray(routesInput) && routesInput.length > 0) {
        routes = routesInput.map(r => buildRouteFromWizardRoute(r, data.host_type));
    } else {
        // Legacy flat format
        routes = [buildLegacyRoute(data)];
    }

    // Host root
    const host = { domains: [domain], routes };
    if (tls) host.tls = tls;

    if (data.bind && data.bind.trim()) {
        host.bind = [data.bind.trim().replace(/^:/, '')];
    }

    return host;
}

function buildRouteFromWizardRoute(r, hostType) {
    const route = {
        enabled: 'on',
        path:    (r.path || '/').trim() || '/',
    };

    const ed = r.engineData || {};
    const engine = r.engine || hostType || 'proxy';

    if (engine === 'web') {
        route.web = buildWebBlock(ed);
    } else if (engine === 'proxy') {
        route.backends = buildBackendBlock(ed);
    } else if (engine === 'serverless') {
        route.serverless = buildServerlessBlock(ed);
    }

    applyExtras(route, r.extras || {});
    applyAuth(route, r.authData || {});

    return route;
}

function buildWebBlock(data) {
    const web = { enabled: 'on' };

    if (data.web_static_on) {
        const root = (data.web_root || '').trim();
        if (root) web.root = root;
    }

    if (data.web_spa)     web.spa      = true;
    if (data.web_listing) web.listing  = true;
    if (data.web_nocache) web.no_cache = true;

    if (data.php_enabled) {
        web.php = { enabled: 'on' };
        if (data.php_address?.trim()) web.php.address = data.php_address.trim();
    }

    if (data.git_enabled) {
        web.git = {
            enabled: 'on',
            id:      (data.git_id     || '').trim() || slugify(data.domain || 'site'),
            url:     (data.git_url    || '').trim(),
            branch:  (data.git_branch || 'main').trim(),
        };
        if (data.git_secret?.trim())   web.git.secret   = data.git_secret.trim();
        if (data.git_interval?.trim()) web.git.interval  = data.git_interval.trim();

        const authType = (data.git_auth_type || '').trim();
        if (authType) {
            web.git.auth = { type: authType };
            if (authType === 'basic') {
                web.git.auth.username = (data.git_auth_user || '').trim();
                web.git.auth.password = (data.git_auth_pass || '').trim();
            } else if (authType === 'ssh-key') {
                web.git.auth.ssh_key = (data.git_ssh_key || '').trim();
            }
        }
    }

    // Index files (comma-separated string from wizard)
    if (data.web_index) {
        const idx = data.web_index.split(',').map(s => s.trim()).filter(Boolean);
        if (idx.length) web.index = idx;
    }

    // Markdown
    if (data.markdown_enabled) {
        web.markdown = { enabled: 'on' };
        if (data.markdown_view === 'browse') web.markdown.view = 'browse';
        if (data.markdown_toc)       web.markdown.toc       = 'on';
        if (data.markdown_unsafe)    web.markdown.unsafe    = 'on';
        if (data.markdown_highlight) web.markdown.highlight = { enabled: 'on' };
    }

    return web;
}

function buildBackendBlock(data) {
    const strategy = data.lb_strategy || 'round_robin';
    let servers = [];
    try {
        const raw = data.backends_list;
        if (typeof raw === 'string') servers = JSON.parse(raw);
        else if (Array.isArray(raw)) servers = raw;
    } catch { servers = []; }

    if (!servers.length && data.backend_url?.trim()) {
        servers = [{ address: data.backend_url.trim(), weight: 1 }];
    }

    servers = servers
        .filter(s => s?.address?.trim())
        .map(s => ({ address: s.address.trim(), weight: Number(s.weight) || 1 }));

    return { enabled: 'on', strategy, servers };
}

function buildServerlessBlock(data) {
    const block = { enabled: 'on' };

    let rests = [];
    try {
        const raw = data.serverless_rests;
        rests = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []);
    } catch { rests = []; }

    const builtRests = rests
        .filter(r => r.name?.trim() && r.url?.trim())
        .map(r => {
            const entry = {
                name:    r.name.trim(),
                enabled: 'on',
                url:     r.url.trim(),
                method:  (r.method || 'GET').toUpperCase(),
            };
            if (r.timeout?.trim()) entry.timeout = r.timeout.trim();
            const auth = (r.auth_header || '').trim();
            if (auth) entry.headers = { 'Authorization': auth };
            return entry;
        });

    if (builtRests.length) block.rests = builtRests;

    let workers = [];
    try {
        const raw = data.serverless_workers;
        workers = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []);
    } catch { workers = []; }

    const builtWorkers = workers
        .filter(w => w.name?.trim() && w.command?.trim())
        .map(w => {
            const cmdRaw = w.command.trim();
            const command = cmdRaw.startsWith('[')
                ? (() => { try { return JSON.parse(cmdRaw); } catch { return cmdRaw.split(/\s+/); } })()
                : cmdRaw.split(/\s+/);
            const entry = { name: w.name.trim(), command };
            if (w.background)       entry.background = true;
            if (w.run_once)         entry.run_once   = true;
            if (w.schedule?.trim()) entry.schedule   = w.schedule.trim();
            if (w.timeout?.trim())  entry.timeout    = w.timeout.trim();
            return entry;
        });

    if (builtWorkers.length) block.workers = builtWorkers;

    return block;
}

function applyExtras(route, data) {
    if (data.cache_enabled) {
        route.cache = {
            enabled: 'on',
            driver:  data.cache_driver || 'memory',
            ttl:     data.cache_ttl    || '5m',
        };
    }

    if (data.cors_enabled) {
        const origins = (data.cors_origins || '*')
            .split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
        route.cors = {
            enabled:         'on',
            allowed_origins: origins,
            allowed_methods: ['GET','POST','PUT','DELETE','OPTIONS'],
            allowed_headers: ['*'],
        };
    }

    if (data.rate_enabled) {
        route.rate_limit = {
            enabled: 'on',
            rule: {
                enabled:  'on',
                requests: Number(data.rate_requests) || 100,
                window:   data.rate_window || '1m',
                burst:    Number(data.rate_burst) || 10,
                key:      data.rate_key || 'ip',
            },
        };
    }

    if (data.gzip_enabled) {
        route.compression_config = { enabled: 'on', type: 'gzip', level: 5 };
    }

    if (data.firewall_enabled) {
        route.firewall = { status: 'on', rules: [] };
    }
}

function applyAuth(route, data) {
    if (data.basic_enabled) {
        const users = (data.basic_users || '').split(/\n+/).map(s => s.trim()).filter(Boolean);
        route.basic_auth = { enabled: 'on', users };
    }

    if (data.jwt_enabled) {
        route.jwt_auth = {
            enabled: 'on',
            secret:  (data.jwt_secret || '').trim(),
            issuer:  (data.jwt_issuer || '').trim(),
        };
    }

    if (data.forward_enabled && data.forward_url?.trim()) {
        route.forward_auth = {
            enabled: 'on',
            url:     data.forward_url.trim(),
        };
    }
}

function buildLegacyRoute(data) {
    const route = {
        enabled: 'on',
        path:    (data.route_path || '/').trim() || '/',
    };
    const hostType = data.host_type || 'proxy';

    if (hostType === 'web') {
        route.web = buildWebBlock(data);
    } else if (hostType === 'proxy') {
        route.backends = buildBackendBlock(data);
    } else if (hostType === 'serverless') {
        route.serverless = buildServerlessBlock(data);
    }

    applyExtras(route, data);
    applyAuth(route, data);
    return route;
}

function slugify(str) {
    return str.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'site';
}
