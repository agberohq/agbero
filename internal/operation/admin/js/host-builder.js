/**
 * js/host-builder.js — buildHostConfig(wizardData) → alaye Host JSON
 * Faithful mapping to alaye struct JSON tags (read from alaye/*.go).
 */

export function buildHostConfig(data) {
    const domain  = (data.domain || '').trim().toLowerCase();
    const tlsMode = data.tls_mode || '';

    // TLS block
    // Local/dev domains: omit TLS block entirely — server inherits global (HTTP)
    // Valid modes: "letsencrypt", "local", "none", "custom_ca", "auto"
    // If user picks "auto" we send "letsencrypt" (server default when mode is empty is also letsencrypt)
    const isLocalDomain = (d) => {
        const h = (d||'').trim().toLowerCase();
        return !h || /^\d+\.\d+\.\d+\.\d+$/.test(h) ||
            ['localhost','.localhost','.local','.internal','.test','.example']
                .some(s => h === s.replace('.','') || h.endsWith(s));
    };

    let tls = null;
    if (!isLocalDomain(domain)) {
        // Only emit TLS block when user explicitly chose a mode
        if (tlsMode && tlsMode !== '') {
            const resolvedMode = tlsMode === 'auto' ? 'letsencrypt' : tlsMode;
            tls = { mode: resolvedMode };
            if (tlsMode === 'local') {
                tls.local = {
                    enabled:   'on',
                    cert_file: (data.tls_cert || '').trim(),
                    key_file:  (data.tls_key  || '').trim(),
                };
            }
        }
        // If no mode chosen → omit TLS block; server defaults to letsencrypt
    }

    // Routes
    const routesInput = data.routes;
    let routes;
    if (Array.isArray(routesInput) && routesInput.length > 0) {
        routes = routesInput.map(r => buildRouteFromWizardRoute(r, data.host_type));
    } else {
        routes = [buildLegacyRoute(data)];
    }

    const host = { domains: [domain], routes };
    if (tls) host.tls = tls;
    return host;
}

// Route builder

function buildRouteFromWizardRoute(r, hostType) {
    const route = {
        enabled: 'on',
        path:    (r.path || '/').trim() || '/',
    };

    const ed = r.engineData || {};
    // Per-route engine determined by hostType (all routes share the host type)
    const engine = hostType || 'proxy';

    if (engine === 'web') {
        route.web = buildWebBlock(ed);
    } else if (engine === 'proxy') {
        // alaye Route.Backends → json:"backends", hcl:"backend,block"
        const be = buildBackendBlock(ed);
        if (be) route.backends = be;
    } else if (engine === 'serverless') {
        route.serverless = buildServerlessBlock(ed);
    }

    applyExtras(route, r.extras || {});
    applyAuth(route, r.authData || {});

    return route;
}

// Web block — alaye.Web
// Web.Root = WebRoot (string-like), Web.Index = []string, Web.Listing = bool,
// Web.SPA = bool, Web.NoCache = bool, Web.PHP = PHP{}, Web.Git = Git{},
// Web.Markdown = Markdown{}

function buildWebBlock(data) {
    const web = { enabled: 'on' };

    if (data.web_static_on) {
        const root = (data.web_root || '').trim();
        if (root) web.root = root;
    }

    if (data.web_spa)     web.spa      = true;
    if (data.web_listing) web.listing  = true;
    if (data.web_nocache) web.no_cache = true;

    // Index files — Web.Index = []string (no path separators)
    if (data.web_index) {
        const idx = data.web_index.split(',').map(s => s.trim()).filter(Boolean);
        if (idx.length) web.index = idx;
    } else if (data.web_static_on) {
        // Default index files when static files enabled
        web.index = ['index.html', 'index.htm', 'index.php', 'index.md', 'README.md'];
    }

    // PHP — alaye.PHP{ Enabled, Address }
    if (data.php_enabled) {
        web.php = { enabled: 'on' };
        if (data.php_address?.trim()) web.php.address = data.php_address.trim();
    }

    // Git — alaye.Git{ Enabled, ID, URL, Branch, Secret, Interval, WorkDir, Auth }
    if (data.git_enabled) {
        web.git = {
            enabled: 'on',
            url:     (data.git_url    || '').trim(),
            branch:  (data.git_branch || 'main').trim(),
        };
        if (data.git_id?.trim())       web.git.id       = data.git_id.trim();
        if (data.git_secret?.trim())   web.git.secret   = data.git_secret.trim();
        if (data.git_interval?.trim()) web.git.interval = data.git_interval.trim();

        const authType = (data.git_auth_type || '').trim();
        if (authType && authType !== '') {
            web.git.auth = { type: authType };
            if (authType === 'basic') {
                web.git.auth.username = (data.git_auth_user || '').trim();
                web.git.auth.password = (data.git_auth_pass || '').trim();
            } else if (authType === 'ssh-key') {
                web.git.auth.ssh_key = (data.git_ssh_key || '').trim();
            }
            // ssh-agent needs no extra fields
        }
    }

    // Markdown — alaye.Markdown{ Enabled, UnsafeHTML(json:"unsafe"), TableOfContents(json:"toc"),
    //             SyntaxHighlight Highlight{Enabled}(json:"highlight"), View }
    if (data.markdown_enabled) {
        web.markdown = { enabled: 'on' };
        if (data.markdown_view === 'browse') web.markdown.view = 'browse';
        if (data.markdown_toc)       web.markdown.toc       = 'on';
        if (data.markdown_unsafe)    web.markdown.unsafe    = 'on';
        if (data.markdown_highlight) web.markdown.highlight = { enabled: 'on' };
    }

    return web;
}

// Backend block — alaye.Backend{ Enabled, Strategy, Servers []Server }
// JSON key on Route is "backends" (field name Backend, json tag "backends")

function buildBackendBlock(data) {
    const strategy = data.lb_strategy || 'round_robin';
    let servers = [];
    try {
        const raw = data.backends_list;
        if (typeof raw === 'string') servers = JSON.parse(raw);
        else if (Array.isArray(raw)) servers = raw;
    } catch { servers = []; }

    servers = servers
        .filter(s => s?.address?.trim())
        .map(s => ({ address: s.address.trim(), weight: Number(s.weight) || 1 }));

    if (!servers.length) return null; // omit empty backend block
    return { enabled: 'on', strategy, servers };
}

// Serverless block — alaye.Serverless{ Enabled, RESTs []REST, Workers []Work }
// REST json:"rests", Work json:"workers"
// REST.Headers = map[string]string  (NOT a single auth header — multiple headers)
// Work.Command = []string

function buildServerlessBlock(data) {
    const block = { enabled: 'on' };

    // REST proxies
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
            // headers: map[string]string — built from key-value pairs array
            const headers = {};
            if (Array.isArray(r.headers)) {
                r.headers.forEach(h => {
                    const k = (h.key || '').trim(), v = (h.value || '').trim();
                    if (k) headers[k] = v;
                });
            } else if (r.auth_header?.trim()) {
                // Legacy single auth_header: try to parse "Key: Value"
                const [k, ...rest] = r.auth_header.split(':');
                if (k && rest.length) headers[k.trim()] = rest.join(':').trim();
            }
            if (Object.keys(headers).length) entry.headers = headers;
            return entry;
        });

    if (builtRests.length) block.rests = builtRests;

    // Workers — alaye.Work{ Name, Engine, Command []string, Env, Background, Restart, RunOnce, Schedule, Timeout }
    let workers = [];
    try {
        const raw = data.serverless_workers;
        workers = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []);
    } catch { workers = []; }

    const builtWorkers = workers
        .filter(w => w.name?.trim() && w.command?.trim())
        .map(w => {
            const cmdRaw = w.command.trim();
            // command is []string
            const command = cmdRaw.startsWith('[')
                ? (() => { try { return JSON.parse(cmdRaw); } catch { return cmdRaw.split(/\s+/); } })()
                : cmdRaw.split(/\s+/);
            const entry = { name: w.name.trim(), command };
            if (w.background)       entry.background = true;
            if (w.run_once)         entry.run_once   = true;
            if (w.restart?.trim())  entry.restart    = w.restart.trim();
            if (w.schedule?.trim()) entry.schedule   = w.schedule.trim();
            if (w.timeout?.trim())  entry.timeout    = w.timeout.trim();
            return entry;
        });

    if (builtWorkers.length) block.workers = builtWorkers;

    return block;
}

// Extras — applied directly onto route object

function applyExtras(route, data) {
    // Cache — alaye.Cache{ Enabled, Driver, TTL Duration, Methods []string }
    if (data.cache_enabled) {
        route.cache = {
            enabled: 'on',
            driver:  data.cache_driver || 'memory',
            ttl:     data.cache_ttl    || '5m',
        };
    }

    // CORS — alaye.CORS{ Enabled, AllowedOrigins []string, AllowedMethods, AllowedHeaders, ... }
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

    // Rate limit — alaye.RouteRate{ Enabled, Rule RateRule{ Requests, Window, Burst, Key } }
    if (data.rate_enabled) {
        route.rate_limit = {
            enabled: 'on',
            rule: {
                enabled:  'on',
                requests: Number(data.rate_requests) || 100,
                window:   data.rate_window || '1m',
                burst:    Number(data.rate_burst)    || 10,
                key:      data.rate_key   || 'ip',
            },
        };
    }

    // Compression — alaye.Compression json:"compression" (renamed from compression_config)
    if (data.gzip_enabled) {
        route.compression = { enabled: 'on', type: 'gzip', level: 5 };
    }

    // Firewall — alaye.FirewallRoute{ Status Enabled json:"enabled", ... }
    // json field is "enabled" not "status"
    if (data.firewall_enabled) {
        route.firewall = { enabled: 'on' };
    }

    // Health check — alaye.HealthCheck{ Enabled, Path, Interval, Timeout, Threshold }
    if (data.health_enabled) {
        route.health_check = {
            enabled:  'on',
            path:     (data.health_path     || '/health').trim(),
            interval: (data.health_interval || '10s').trim(),
            timeout:  (data.health_timeout  || '5s').trim(),
        };
    }

    // Circuit breaker — alaye.CircuitBreaker{ Enabled, Threshold int, Duration Duration }
    if (data.cb_enabled) {
        route.circuit_breaker = {
            enabled:   'on',
            threshold: Number(data.cb_threshold) || 5,
            duration:  (data.cb_duration || '30s').trim(),
        };
    }
}

// Auth

function applyAuth(route, data) {
    // BasicAuth — alaye.BasicAuth{ Enabled, Users []string, Realm }
    if (data.basic_enabled) {
        const users = (data.basic_users || '').split(/\n+/).map(s => s.trim()).filter(Boolean);
        if (users.length) route.basic_auth = { enabled: 'on', users };
    }

    // JWTAuth — alaye.JWTAuth{ Enabled, Secret Value, Issuer, Audience }
    if (data.jwt_enabled) {
        route.jwt_auth = { enabled: 'on', secret: (data.jwt_secret || '').trim() };
        if (data.jwt_issuer?.trim()) route.jwt_auth.issuer = data.jwt_issuer.trim();
    }

    // ForwardAuth — alaye.ForwardAuth{ Enabled, Name(label), URL, OnFailure, Timeout, AllowPrivate }
    if (data.forward_enabled && data.forward_url?.trim()) {
        route.forward_auth = {
            enabled:    'on',
            url:        data.forward_url.trim(),
            on_failure: 'deny',
            timeout:    '10s',
        };
    }
}

// Legacy flat format

function buildLegacyRoute(data) {
    const route = { enabled: 'on', path: (data.route_path || '/').trim() || '/' };
    const hostType = data.host_type || 'proxy';
    if (hostType === 'web') {
        route.web = buildWebBlock(data);
    } else if (hostType === 'proxy') {
        const be = buildBackendBlock(data);
        if (be) route.backends = be;
    } else if (hostType === 'serverless') {
        route.serverless = buildServerlessBlock(data);
    }
    applyExtras(route, data);
    applyAuth(route, data);
    return route;
}
