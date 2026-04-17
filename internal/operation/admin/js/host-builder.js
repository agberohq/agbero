/**
 * js/host-builder.js — buildHostConfig(wizardData) → alaye Host JSON
 *
 * Faithful mapping to alaye struct JSON tags (read from alaye/*.go).
 * See plan.md Appendix C for the full field mapping table.
 *
 * CHANGELOG (Phase 3):
 *   - TLS: custom_ca mode, letsencrypt email/staging, mTLS (client_auth + client_cas)
 *   - Host-level: protected, not_found_page, bind, compression, limits.max_header_bytes
 *   - TCP proxy: buildTcpProxy() from draft._tcp
 *   - Backend: backend.keys (consistent_hash / sticky)
 *   - Git: work_dir, sub_dir, ssh_key_passphrase
 *   - Markdown: extensions, template, highlight.theme
 *   - Web: nonce block
 *   - Extras: allowed_ips, strip_prefixes, rewrites, timeouts, cors.allow_credentials
 *   - Rate limit: ignore_global, use_policy, burst, key, custom key
 *   - Health check: threshold, accelerated_probing, synthetic_when_idle
 *   - Auth: OAuth (o_auth block)
 *   - Headers: per-route request/response header manipulation
 */

export function buildHostConfig(data) {
    const domain  = (data.domain || '').trim().toLowerCase();
    const tlsMode = data.tls_mode || '';

    const isLocalDomain = (d) => {
        const h = (d || '').trim().toLowerCase();
        if (!h) return true;
        if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return true;
        const exact = ['localhost'];
        const suffixes = ['.localhost', '.local', '.internal', '.test', '.example'];
        return exact.includes(h) || suffixes.some(s => h === s.slice(1) || h.endsWith(s));
    };

    let tls = null;
    if (!isLocalDomain(domain) && tlsMode && tlsMode !== '') {
        const resolvedMode = tlsMode === 'auto' ? 'letsencrypt' : tlsMode;
        tls = { mode: resolvedMode };
        if (tlsMode === 'local') {
            tls.local = {
                enabled:   'on',
                cert_file: (data.tls_cert || '').trim(),
                key_file:  (data.tls_key  || '').trim(),
            };
        }
        if (resolvedMode === 'letsencrypt') {
            tls.letsencrypt = { enabled: 'on', email: (data.tls_le_email || '').trim() };
            if (data.tls_le_staging === 'on') tls.letsencrypt.staging = 'on';
        }
        if (tlsMode === 'custom_ca') {
            tls.custom_ca = { enabled: 'on', root: (data.tls_ca_root || '').trim() };
        }
        if (data.tls_client_auth?.trim()) tls.client_auth = data.tls_client_auth.trim();
        if (Array.isArray(data.tls_client_cas) && data.tls_client_cas.length)
            tls.client_cas = data.tls_client_cas.filter(Boolean);
    }

    const host = { domains: [domain] };
    if (tls) host.tls = tls;

    const prot = data.host_protected;
    if (prot && prot !== 'unknown') host.protected = prot;
    if ((data.host_not_found_page || '').trim()) host.not_found_page = data.host_not_found_page.trim();
    if (Array.isArray(data.host_bind) && data.host_bind.length) host.bind = data.host_bind.filter(Boolean);
    if (data.host_compression === true) host.compression = true;
    if (data.host_max_header_bytes > 0) host.limits = { max_header_bytes: Number(data.host_max_header_bytes) };

    const routesInput = data.routes;
    if (Array.isArray(routesInput) && routesInput.length > 0) {
        host.routes = routesInput.map(r => buildRoute(r, data.host_type));
    } else if (data.host_type !== 'tcp') {
        host.routes = [buildLegacyRoute(data)];
    }

    if (data.host_type === 'tcp' && data._tcp) {
        host.proxies = [buildTcpProxy(data._tcp)];
    }

    return host;
}

function buildTcpProxy(tcp) {
    const proxy = { name: (tcp.name || '').trim(), enabled: 'on', listen: (tcp.listen || '').trim() };
    if (tcp.sni?.trim())             proxy.sni             = tcp.sni.trim();
    if (tcp.strategy?.trim())        proxy.strategy        = tcp.strategy.trim();
    if (tcp.max_connections > 0)     proxy.max_connections = Number(tcp.max_connections);
    if (tcp.proxy_protocol === true) proxy.proxy_protocol  = true;
    // UDP-specific fields
    if (tcp.protocol?.trim())        proxy.protocol        = tcp.protocol.trim();
    if (tcp.matcher?.trim())         proxy.matcher         = tcp.matcher.trim();
    if (tcp.session_ttl?.trim())     proxy.session_ttl     = tcp.session_ttl.trim();
    if (tcp.max_sessions > 0)        proxy.max_sessions    = Number(tcp.max_sessions);

    // backends is a flat array of Server objects — NOT wrapped in {server: ...}
    const servers = (tcp.backends || [])
        .filter(b => b?.address?.trim())
        .map(b => ({ address: b.address.trim(), weight: Number(b.weight) || 1 }));
    if (servers.length) proxy.backends = servers;

    const hcEnabled = tcp.hc_interval?.trim() || tcp.hc_send?.trim() || tcp.hc_expect?.trim();
    if (hcEnabled) {
        proxy.health_check = { enabled: 'on' };
        if (tcp.hc_interval?.trim()) proxy.health_check.interval = tcp.hc_interval.trim();
        if (tcp.hc_timeout?.trim())  proxy.health_check.timeout  = tcp.hc_timeout.trim();
        if (tcp.hc_send?.trim())     proxy.health_check.send     = tcp.hc_send.trim();
        if (tcp.hc_expect?.trim())   proxy.health_check.expect   = tcp.hc_expect.trim();
    }
    return proxy;
}

function buildRoute(r, hostType) {
    const route  = { enabled: 'on', path: (r.path || '/').trim() || '/' };
    const ed     = r.engineData || {};
    const engine = hostType || 'proxy';
    if      (engine === 'web')        route.web        = buildWebBlock(ed);
    else if (engine === 'proxy')      { const be = buildBackendBlock(ed); if (be) route.backends = be; }
    else if (engine === 'serverless') route.serverless = buildServerlessBlock(ed);
    applyExtras (route, r.extras   || {});
    applyAuth   (route, r.authData || {});
    applyHeaders(route, r.headers  || {});
    return route;
}

function buildWebBlock(data) {
    const web = { enabled: 'on' };
    if (data.web_static_on) { const root = (data.web_root || '').trim(); if (root) web.root = root; }
    if (data.web_spa)     web.spa      = 'on';
    if (data.web_listing) web.listing  = 'on';
    if (data.web_nocache) web.no_cache = 'on';
    if (data.web_index) {
        const idx = data.web_index.split(',').map(s => s.trim()).filter(Boolean);
        if (idx.length) web.index = idx;
    } else if (data.web_static_on) {
        web.index = ['index.html', 'index.htm', 'index.php', 'index.md', 'README.md'];
    }
    if (data.php_enabled) {
        const phpAddr = (data.php_address || '').trim();
        if (!phpAddr) throw new Error('PHP is enabled but no FastCGI address is set (e.g. 127.0.0.1:9000).');
        web.php = { enabled: 'on', address: phpAddr };
    }
    if (data.git_enabled) {
        web.git = { enabled: 'on', url: (data.git_url || '').trim(), branch: (data.git_branch || 'main').trim() };
        if (data.git_id?.trim())                web.git.id                = data.git_id.trim();
        if (data.git_secret?.trim())            web.git.secret            = data.git_secret.trim();
        if (data.git_interval?.trim())          web.git.interval          = data.git_interval.trim();
        if (data.git_work_dir?.trim())          web.git.work_dir          = data.git_work_dir.trim();
        if (data.git_sub_dir?.trim())           web.git.sub_dir           = data.git_sub_dir.trim();
        const authType = (data.git_auth_type || '').trim();
        if (authType) {
            web.git.auth = { type: authType };
            if (authType === 'basic') {
                web.git.auth.username = (data.git_auth_user || '').trim();
                web.git.auth.password = (data.git_auth_pass || '').trim();
            } else if (authType === 'ssh-key') {
                web.git.auth.ssh_key            = (data.git_ssh_key            || '').trim();
                web.git.auth.ssh_key_passphrase = (data.git_ssh_key_passphrase || '').trim();
            }
        }
    }
    if (data.markdown_enabled) {
        web.markdown = { enabled: 'on' };
        if (data.markdown_view === 'browse') web.markdown.view = 'browse';
        if (data.markdown_toc)    web.markdown.toc    = 'on';
        if (data.markdown_unsafe) web.markdown.unsafe = 'on';
        if (data.markdown_highlight) {
            web.markdown.highlight = { enabled: 'on' };
            const theme = (data.markdown_highlight_theme || '').trim();
            if (theme) web.markdown.highlight.theme = theme;
        }
        if (data.markdown_extensions?.trim())
            web.markdown.extensions = data.markdown_extensions.split(',').map(s => s.trim()).filter(Boolean);
        if (data.markdown_template?.trim()) web.markdown.template = data.markdown_template.trim();
    }
    if (data.nonce_enabled) {
        const endpoints = (data.nonce_endpoints || '').split(',').map(s => s.trim()).filter(Boolean);
        if (endpoints.length) web.nonce = { enabled: 'on', endpoints };
    }
    return web;
}

function buildBackendBlock(data) {
    const strategy = data.lb_strategy || 'round_robin';
    let servers = [];
    try { const raw = data.backends_list; servers = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []); } catch { servers = []; }
    servers = servers.filter(s => s?.address?.trim()).map(s => ({ address: s.address.trim(), weight: Number(s.weight) || 1 }));
    if (!servers.length) return null;
    const block = { enabled: 'on', strategy, servers };
    const keysRaw = (data.backend_keys || '').trim();
    if (keysRaw) block.keys = keysRaw.split(',').map(s => s.trim()).filter(Boolean);
    return block;
}

function buildServerlessBlock(data) {
    const block = { enabled: 'on' };

    // Git block for serverless (code source for workers)
    if (data.serverless_git_enabled) {
        block.git = { enabled: 'on', url: (data.serverless_git_url || '').trim(), id: (data.serverless_git_id || '').trim() };
        if (data.serverless_git_branch?.trim()) block.git.branch   = data.serverless_git_branch.trim();
        if (data.serverless_git_interval?.trim()) block.git.interval = data.serverless_git_interval.trim();
    }

    // Replay proxies — JSON key is "replay" (not "rests")
    let replays = [];
    try {
        const raw = data.serverless_rests;  // internal draft key keeps "rests" for backwards compat
        replays = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []);
    } catch { replays = []; }
    const builtReplay = replays.filter(r => r.name?.trim()).map(r => {
        const entry = { name: r.name.trim(), enabled: 'on' };
        if (r.url?.trim()) {
            entry.url = r.url.trim();
        } else if ((r.allowed_domains || []).length) {
            // Relay mode
            entry.allowed_domains = r.allowed_domains.filter(Boolean);
        }
        if ((r.methods || []).length) entry.methods = r.methods;
        if (r.timeout?.trim())        entry.timeout = r.timeout.trim();
        if (r.referer_mode)           entry.referer_mode = r.referer_mode;
        if (r.referer_value?.trim())  entry.referer_value = r.referer_value.trim();
        if (r.forward_query)          entry.forward_query = 'on';
        if (r.strip_headers)          entry.strip_headers = 'on';
        const headers = {};
        (r.headers || []).forEach(h => { const k = (h.key || '').trim(), v = (h.value || '').trim(); if (k) headers[k] = v; });
        if (Object.keys(headers).length) entry.headers = headers;
        return entry;
    });
    if (builtReplay.length) block.replay = builtReplay;

    // Workers
    let workers = [];
    try {
        const raw = data.serverless_workers;
        workers = typeof raw === 'string' ? JSON.parse(raw) : (Array.isArray(raw) ? raw : []);
    } catch { workers = []; }
    const builtWorkers = workers.filter(w => w.name?.trim() && w.command?.trim()).map(w => {
        const cmdRaw = w.command.trim();
        const command = cmdRaw.startsWith('[')
            ? (() => { try { return JSON.parse(cmdRaw); } catch { return cmdRaw.split(/\s+/); } })()
            : cmdRaw.split(/\s+/);
        const entry = { name: w.name.trim(), command };
        if (w.landlock !== false)    entry.landlock  = 'on';
        if (w.background)       entry.background = true;
        if (w.run_once)         entry.run_once   = true;
        if (w.restart?.trim())  entry.restart    = w.restart.trim();
        if (w.schedule?.trim()) entry.schedule   = w.schedule.trim();
        if (w.timeout?.trim())  entry.timeout    = w.timeout.trim();
        if (w.engine?.trim())   entry.engine     = w.engine.trim();
        return entry;
    });
    if (builtWorkers.length) block.workers = builtWorkers;

    return block;
}

function applyExtras(route, data) {
    if (data.cache_enabled) {
        route.cache = { enabled: 'on', driver: data.cache_driver || 'memory', ttl: data.cache_ttl || '5m' };
    }
    if (data.cors_enabled) {
        const origins = (data.cors_origins || '*').split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
        route.cors = { enabled: 'on', allowed_origins: origins, allowed_methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowed_headers: ['*'] };
        if (data.cors_credentials) route.cors.allow_credentials = true;
    }
    if (data.rate_enabled) {
        route.rate_limit = { enabled: 'on' };
        if (data.rate_ignore_global)      route.rate_limit.ignore_global = true;
        if (data.rate_use_policy?.trim()) route.rate_limit.use_policy   = data.rate_use_policy.trim();
        const rateKey = ((data.rate_key === 'custom' ? data.rate_key_custom : data.rate_key) || '').trim() || 'ip';
        route.rate_limit.rule = { enabled: 'on', requests: Number(data.rate_requests) || 100, window: (data.rate_window || '1m').trim(), burst: Number(data.rate_burst) || 0, key: rateKey };
    }
    if (data.gzip_enabled)     route.compression  = { enabled: 'on', type: 'gzip', level: 5 };
    if (data.firewall_enabled) route.firewall      = { enabled: 'on' };
    if (data.health_enabled) {
        route.health_check = { enabled: 'on', path: (data.health_path || '/health').trim(), interval: (data.health_interval || '10s').trim(), timeout: (data.health_timeout || '5s').trim() };
        if (data.health_threshold > 0)   route.health_check.threshold             = Number(data.health_threshold);
        if (data.health_accel)           route.health_check.accelerated_probing   = true;
        if (data.health_synthetic)       route.health_check.synthetic_when_idle   = true;
    }
    if (data.cb_enabled) {
        route.circuit_breaker = { enabled: 'on', threshold: Number(data.cb_threshold) || 5, duration: (data.cb_duration || '30s').trim() };
    }
    if (data.timeouts_enabled) {
        route.timeouts = { enabled: 'on' };
        if (data.timeout_request?.trim()) route.timeouts.request = data.timeout_request.trim();
    }
    if (data.allowed_ips?.trim())
        route.allowed_ips = data.allowed_ips.split(',').map(s => s.trim()).filter(Boolean);
    if (data.strip_prefixes?.trim())
        route.strip_prefixes = data.strip_prefixes.split(',').map(s => s.trim()).filter(s => s.startsWith('/'));
    if (Array.isArray(data.rewrites) && data.rewrites.length) {
        const rw = data.rewrites.filter(r => r.pattern?.trim() && r.target?.trim());
        if (rw.length) route.rewrites = rw.map(r => ({ pattern: r.pattern.trim(), target: r.target.trim() }));
    }
    // Fallback — alaye.Fallback{ Enabled, Type, RedirectURL, Timeout }
    if (data.fallback_enabled) {
        route.fallback = { enabled: 'on' };
        if (data.fallback_url?.trim())     route.fallback.redirect_url = data.fallback_url.trim();
        if (data.fallback_timeout?.trim()) route.fallback.timeout      = data.fallback_timeout.trim();
    }
    // Wasm — alaye.Wasm{ Enabled, Module, Config map, MaxBodySize, Access []string }
    if (data.wasm_enabled) {
        const mod = (data.wasm_module || '').trim();
        if (!mod) throw new Error('Wasm is enabled but no module path is set.');
        const access = [
            data.wasm_access_headers ? 'headers' : null,
            data.wasm_access_body    ? 'body'    : null,
            data.wasm_access_method  ? 'method'  : null,
            data.wasm_access_uri     ? 'uri'     : null,
            data.wasm_access_config  ? 'config'  : null,
        ].filter(Boolean);
        route.wasm = { enabled: 'on', module: mod, access };
        if (data.wasm_max_body > 0) route.wasm.max_body_size = Number(data.wasm_max_body);
    }
}

function applyAuth(route, data) {
    if (data.basic_enabled) {
        const users = (data.basic_users || '').split(/\n+/).map(s => s.trim()).filter(Boolean);
        if (users.length) route.basic_auth = { enabled: 'on', users };
    }
    if (data.jwt_enabled) {
        route.jwt_auth = { enabled: 'on', secret: (data.jwt_secret || '').trim() };
        if (data.jwt_issuer?.trim()) route.jwt_auth.issuer = data.jwt_issuer.trim();
    }
    if (data.forward_enabled && data.forward_url?.trim()) {
        route.forward_auth = { enabled: 'on', url: data.forward_url.trim(), on_failure: 'deny', timeout: '10s' };
    }
    if (data.oauth_enabled) {
        route.o_auth = {
            enabled:       'on',
            provider:      (data.oauth_provider      || '').trim(),
            client_id:     (data.oauth_client_id     || '').trim(),
            client_secret: (data.oauth_client_secret || '').trim(),
            redirect_url:  (data.oauth_redirect_url  || '').trim(),
            cookie_secret: (data.oauth_cookie_secret || '').trim(),
        };
        if (data.oauth_auth_url?.trim())      route.o_auth.auth_url     = data.oauth_auth_url.trim();
        if (data.oauth_token_url?.trim())     route.o_auth.token_url    = data.oauth_token_url.trim();
        if (data.oauth_user_api_url?.trim())  route.o_auth.user_api_url = data.oauth_user_api_url.trim();
        if (data.oauth_scopes?.trim())
            route.o_auth.scopes = data.oauth_scopes.split(',').map(s => s.trim()).filter(Boolean);
        if (data.oauth_email_domains?.trim())
            route.o_auth.email_domains = data.oauth_email_domains.split(',').map(s => s.trim()).filter(Boolean);
    }
}

function applyHeaders(route, data) {
    const req  = data.request  || {};
    const resp = data.response || {};
    const hasReq  = Object.keys(req.set  || {}).length || Object.keys(req.add  || {}).length || (req.remove  || []).length;
    const hasResp = Object.keys(resp.set || {}).length || Object.keys(resp.add || {}).length || (resp.remove || []).length;
    if (!hasReq && !hasResp) return;
    route.headers = { enabled: 'on' };
    if (hasReq) {
        route.headers.request = { enabled: 'on' };
        if (Object.keys(req.set  || {}).length) route.headers.request.set    = req.set;
        if (Object.keys(req.add  || {}).length) route.headers.request.add    = req.add;
        if ((req.remove || []).length)          route.headers.request.remove = req.remove;
    }
    if (hasResp) {
        route.headers.response = { enabled: 'on' };
        if (Object.keys(resp.set  || {}).length) route.headers.response.set    = resp.set;
        if (Object.keys(resp.add  || {}).length) route.headers.response.add    = resp.add;
        if ((resp.remove || []).length)          route.headers.response.remove = resp.remove;
    }
}

function buildLegacyRoute(data) {
    const route = { enabled: 'on', path: (data.route_path || '/').trim() || '/' };
    const hostType = data.host_type || 'proxy';
    if      (hostType === 'web')        route.web        = buildWebBlock(data);
    else if (hostType === 'proxy')      { const be = buildBackendBlock(data); if (be) route.backends = be; }
    else if (hostType === 'serverless') route.serverless = buildServerlessBlock(data);
    applyExtras (route, data);
    applyAuth   (route, data);
    applyHeaders(route, data);
    return route;
}

// HCL SERIALISER
// Converts a buildHostConfig() output object → HCL string the server can parse.
//
// HCL format rules (from _hclTemplate, live .hcl files, and parser source):
//   - Top-level scalars:  key = "value"  or  key = true  or  key = 123
//   - Top-level arrays:   key = ["a", "b"]
//   - Named blocks:       block_type "label" { ... }
//   - Unnamed blocks:     block_type { ... }
//   - route paths are block labels:  route "/" { ... }
//   - proxy name is a block label:   proxy "name" { ... }
//   - server address is a block label: server "http://..." { weight = 1 }

export function buildHostHCL(data) {
    const config = buildHostConfig(data);
    return _hostToHCL(config);
}

// Escape a string for HCL double-quoted strings
function _hq(s) {
    return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r') + '"';
}

// Render a string list as HCL array literal
function _strList(arr) {
    return '[' + arr.map(_hq).join(', ') + ']';
}

// Indent every line of a block body
function _indent(s, n = 2) {
    const pad = ' '.repeat(n);
    return s.split('\n').map(l => (l.trim() ? pad + l : '')).join('\n');
}

// Render a simple scalar value
function _scalar(v) {
    if (v === true  || v === 'on')  return '"on"';
    if (v === false || v === 'off') return '"off"';
    if (typeof v === 'number')      return String(v);
    return _hq(v);
}

function _hostToHCL(host) {
    const lines = [];

    // domains = [...]
    if (Array.isArray(host.domains) && host.domains.length)
        lines.push(`domains = ${_strList(host.domains)}`);

    // protected / not_found_page / compression / bind
    if (host.protected && host.protected !== 'unknown')
        lines.push(`protected = ${_scalar(host.protected)}`);
    if (host.not_found_page)
        lines.push(`not_found_page = ${_hq(host.not_found_page)}`);
    if (host.compression === true)
        lines.push(`compression = true`);
    if (Array.isArray(host.bind) && host.bind.length)
        lines.push(`bind = ${_strList(host.bind)}`);

    // limits block
    if (host.limits?.max_header_bytes > 0) {
        lines.push('', 'limits {', `  max_header_bytes = ${host.limits.max_header_bytes}`, '}');
    }

    // tls block
    if (host.tls) lines.push('', _tlsBlock(host.tls));

    // route blocks
    for (const route of (host.routes || [])) {
        lines.push('', _routeBlock(route));
    }

    // proxy blocks (TCP/UDP)
    for (const proxy of (host.proxies || [])) {
        lines.push('', _proxyBlock(proxy));
    }

    return lines.join('\n').replace(/\n{3,}/g, '\n\n').trimStart() + '\n';
}

function _tlsBlock(tls) {
    const inner = [];
    if (tls.mode) inner.push(`mode = ${_hq(tls.mode)}`);
    if (tls.client_auth) inner.push(`client_auth = ${_hq(tls.client_auth)}`);
    if (Array.isArray(tls.client_cas) && tls.client_cas.length)
        inner.push(`client_cas = ${_strList(tls.client_cas)}`);
    if (tls.letsencrypt) {
        const le = tls.letsencrypt;
        const sub = [`enabled = "on"`, `email   = ${_hq(le.email || '')}`];
        if (le.staging === 'on') sub.push(`staging = "on"`);
        inner.push('', 'lets_encrypt {', ...sub.map(l => '  ' + l), '}');
    }
    if (tls.local) {
        inner.push('', 'local {',
            `  enabled   = "on"`,
            `  cert_file = ${_hq(tls.local.cert_file || '')}`,
            `  key_file  = ${_hq(tls.local.key_file  || '')}`,
            '}');
    }
    if (tls.custom_ca) {
        inner.push('', 'custom_ca {', `  enabled = "on"`, `  root = ${_hq(tls.custom_ca.root || '')}`, '}');
    }
    const body = inner.filter((l, i) => !(i === 0 && l === '')).join('\n');
    return 'tls {\n' + _indent(body) + '\n}';
}

function _routeBlock(route) {
    const inner = [];

    // web block
    if (route.web) {
        const w = route.web;
        const wb = [];
        if (w.root)     wb.push(`root     = ${_hq(w.root)}`);
        if (w.spa === 'on')     wb.push(`spa      = "on"`);
        if (w.listing === 'on') wb.push(`listing  = "on"`);
        if (w.no_cache === 'on')wb.push(`no_cache = "on"`);
        if (Array.isArray(w.index) && w.index.length)
            wb.push(`index    = ${_strList(w.index)}`);
        if (w.php) {
            wb.push('', `php {`, `  enabled = "on"`, `  address = ${_hq(w.php.address || '')}`, `}`);
        }
        if (w.git) {
            const g = w.git;
            const gb = [`enabled = "on"`, `url     = ${_hq(g.url || '')}`, `branch  = ${_hq(g.branch || 'main')}`];
            if (g.id)       gb.push(`id       = ${_hq(g.id)}`);
            if (g.interval) gb.push(`interval = ${_hq(g.interval)}`);
            if (g.secret)   gb.push(`secret   = ${_hq(g.secret)}`);
            if (g.work_dir) gb.push(`work_dir = ${_hq(g.work_dir)}`);
            if (g.sub_dir)  gb.push(`sub_dir  = ${_hq(g.sub_dir)}`);
            if (g.auth?.type) {
                const ab = [`type = ${_hq(g.auth.type)}`];
                if (g.auth.username) ab.push(`username = ${_hq(g.auth.username)}`);
                if (g.auth.password) ab.push(`password = ${_hq(g.auth.password)}`);
                if (g.auth.ssh_key)  ab.push(`ssh_key  = ${_hq(g.auth.ssh_key)}`);
                gb.push('', 'auth {', ...ab.map(l => '  ' + l), '}');
            }
            wb.push('', 'git {', ...gb.map(l => '  ' + l), '}');
        }
        if (w.markdown) {
            const md = w.markdown;
            const mb = [`enabled = "on"`];
            if (md.view)    mb.push(`view    = ${_hq(md.view)}`);
            if (md.unsafe === 'on') mb.push(`unsafe  = "on"`);
            if (md.toc === 'on')    mb.push(`toc     = "on"`);
            if (md.highlight) {
                const hb = [`enabled = "on"`];
                if (md.highlight.theme) hb.push(`theme = ${_hq(md.highlight.theme)}`);
                mb.push('', 'highlight {', ...hb.map(l => '  ' + l), '}');
            }
            wb.push('', 'markdown {', ...mb.map(l => '  ' + l), '}');
        }
        inner.push('web {', ...wb.map(l => '  ' + l), '}');
    }

    // backends block
    if (route.backends) {
        const be = route.backends;
        const bb = [];
        if (be.strategy && be.strategy !== 'round_robin') bb.push(`strategy = ${_hq(be.strategy)}`);
        if (Array.isArray(be.keys) && be.keys.length) bb.push(`keys = ${_strList(be.keys)}`);
        for (const s of (be.servers || [])) {
            const sw = s.weight && s.weight !== 1 ? `weight = ${s.weight}` : '';
            bb.push(sw ? `server ${_hq(s.address)} { ${sw} }` : `server ${_hq(s.address)} {}`);
        }
        inner.push('backends {', ...bb.map(l => '  ' + l), '}');
    }

    // serverless block
    if (route.serverless) {
        const sl = route.serverless;
        const sb = [];
        if (sl.git) {
            const g = sl.git;
            const gb = [`enabled  = "on"`, `url      = ${_hq(g.url || '')}`, `id       = ${_hq(g.id || '')}`];
            if (g.branch)   gb.push(`branch   = ${_hq(g.branch)}`);
            if (g.interval) gb.push(`interval = ${_hq(g.interval)}`);
            sb.push('git {', ...gb.map(l => '  ' + l), '}');
        }
        for (const w of (sl.workers || [])) {
            const wb = [`enabled  = "on"`, `command  = ${_strList(Array.isArray(w.command) ? w.command : [w.command])}`];
            if (w.landlock === 'on') wb.push(`landlock = "on"`);
            if (w.engine)    wb.push(`engine   = ${_hq(w.engine)}`);
            if (w.background) wb.push(`background = true`);
            if (w.run_once)   wb.push(`run_once   = true`);
            if (w.restart)    wb.push(`restart    = ${_hq(w.restart)}`);
            if (w.schedule)   wb.push(`schedule   = ${_hq(w.schedule)}`);
            if (w.timeout)    wb.push(`timeout    = ${_hq(w.timeout)}`);
            sb.push('', `worker ${_hq(w.name)} {`, ...wb.map(l => '  ' + l), '}');
        }
        for (const r of (sl.replay || [])) {
            const rb = [`enabled = "on"`];
            if (r.url)            rb.push(`url            = ${_hq(r.url)}`);
            if (r.timeout)        rb.push(`timeout        = ${_hq(r.timeout)}`);
            if (r.referer_mode)   rb.push(`referer_mode   = ${_hq(r.referer_mode)}`);
            if (r.referer_value)  rb.push(`referer_value  = ${_hq(r.referer_value)}`);
            if (r.forward_query === 'on') rb.push(`forward_query  = "on"`);
            if (r.strip_headers === 'on') rb.push(`strip_headers  = "on"`);
            if (Array.isArray(r.methods) && r.methods.length)
                rb.push(`methods = ${_strList(r.methods)}`);
            if (Array.isArray(r.allowed_domains) && r.allowed_domains.length)
                rb.push(`allowed_domains = ${_strList(r.allowed_domains)}`);
            sb.push('', `replay ${_hq(r.name)} {`, ...rb.map(l => '  ' + l), '}');
        }
        inner.push('serverless {', ...sb.map(l => '  ' + l), '}');
    }

    // extras: health_check, circuit_breaker, rate_limit, cors, cache, timeouts, compression, firewall
    if (route.health_check) {
        const hc = route.health_check;
        const hb = [`enabled  = "on"`, `path     = ${_hq(hc.path || '/health')}`, `interval = ${_hq(hc.interval || '10s')}`, `timeout  = ${_hq(hc.timeout || '5s')}`];
        if (hc.threshold > 0)             hb.push(`threshold = ${hc.threshold}`);
        if (hc.accelerated_probing)       hb.push(`accelerated_probing  = true`);
        if (hc.synthetic_when_idle)       hb.push(`synthetic_when_idle  = true`);
        inner.push('', 'health_check {', ...hb.map(l => '  ' + l), '}');
    }
    if (route.circuit_breaker) {
        const cb = route.circuit_breaker;
        inner.push('', 'circuit_breaker {',
            `  enabled   = "on"`,
            `  threshold = ${cb.threshold || 5}`,
            `  duration  = ${_hq(cb.duration || '30s')}`,
            '}');
    }
    if (route.rate_limit) {
        const rl = route.rate_limit;
        const rb = [`enabled = "on"`];
        if (rl.ignore_global) rb.push(`ignore_global = true`);
        if (rl.use_policy)    rb.push(`use_policy    = ${_hq(rl.use_policy)}`);
        if (rl.rule) {
            const r = rl.rule;
            rb.push('', 'rule {',
                `  enabled  = "on"`,
                `  requests = ${r.requests || 100}`,
                `  window   = ${_hq(r.window || '1m')}`,
                ...(r.burst ? [`  burst    = ${r.burst}`] : []),
                ...(r.key   ? [`  key      = ${_hq(r.key)}`] : []),
                '}');
        }
        inner.push('', 'rate_limit {', ...rb.map(l => '  ' + l), '}');
    }
    if (route.cors) {
        const c = route.cors;
        const cb = [`enabled = "on"`];
        if (Array.isArray(c.allowed_origins) && c.allowed_origins.length)
            cb.push(`allowed_origins = ${_strList(c.allowed_origins)}`);
        if (Array.isArray(c.allowed_methods) && c.allowed_methods.length)
            cb.push(`allowed_methods = ${_strList(c.allowed_methods)}`);
        if (Array.isArray(c.allowed_headers) && c.allowed_headers.length)
            cb.push(`allowed_headers = ${_strList(c.allowed_headers)}`);
        if (c.allow_credentials) cb.push(`allow_credentials = true`);
        inner.push('', 'cors {', ...cb.map(l => '  ' + l), '}');
    }
    if (route.cache) {
        inner.push('', 'cache {',
            `  enabled = "on"`,
            `  driver  = ${_hq(route.cache.driver || 'memory')}`,
            `  ttl     = ${_hq(route.cache.ttl || '5m')}`,
            '}');
    }
    if (route.timeouts) {
        const tb = [`enabled = "on"`];
        if (route.timeouts.request) tb.push(`request = ${_hq(route.timeouts.request)}`);
        inner.push('', 'timeouts {', ...tb.map(l => '  ' + l), '}');
    }
    if (route.compression) {
        inner.push('', 'compression {',
            `  enabled = "on"`,
            `  type    = ${_hq(route.compression.type || 'gzip')}`,
            '}');
    }
    if (route.firewall) inner.push('', 'firewall {', '  enabled = "on"', '}');
    if (route.fallback) {
        const fb = [`enabled = "on"`];
        if (route.fallback.redirect_url) fb.push(`redirect_url = ${_hq(route.fallback.redirect_url)}`);
        if (route.fallback.timeout)      fb.push(`timeout      = ${_hq(route.fallback.timeout)}`);
        inner.push('', 'fallback {', ...fb.map(l => '  ' + l), '}');
    }
    if (route.wasm) {
        const wb = [`enabled = "on"`, `module  = ${_hq(route.wasm.module || '')}`];
        if (route.wasm.max_body_size > 0) wb.push(`max_body_size = ${route.wasm.max_body_size}`);
        if (Array.isArray(route.wasm.access) && route.wasm.access.length)
            wb.push(`access = ${_strList(route.wasm.access)}`);
        inner.push('', 'wasm {', ...wb.map(l => '  ' + l), '}');
    }

    // allowed_ips / strip_prefixes / rewrites
    if (Array.isArray(route.allowed_ips) && route.allowed_ips.length)
        inner.push('', `allowed_ips = ${_strList(route.allowed_ips)}`);
    if (Array.isArray(route.strip_prefixes) && route.strip_prefixes.length)
        inner.push(`strip_prefixes = ${_strList(route.strip_prefixes)}`);
    if (Array.isArray(route.rewrites) && route.rewrites.length) {
        for (const rw of route.rewrites) {
            inner.push('', `rewrite {`, `  pattern = ${_hq(rw.pattern)}`, `  target  = ${_hq(rw.target)}`, `}`);
        }
    }

    // auth blocks
    if (route.basic_auth) {
        const users = Array.isArray(route.basic_auth.users) ? route.basic_auth.users : [];
        inner.push('', 'basic_auth {',
            `  enabled = "on"`,
            ...users.map(u => `  user = ${_hq(u)}`),
            '}');
    }
    if (route.jwt_auth) {
        const jb = [`enabled = "on"`, `secret  = ${_hq(route.jwt_auth.secret || '')}`];
        if (route.jwt_auth.issuer) jb.push(`issuer  = ${_hq(route.jwt_auth.issuer)}`);
        inner.push('', 'jwt_auth {', ...jb.map(l => '  ' + l), '}');
    }
    if (route.forward_auth) {
        inner.push('', 'forward_auth {',
            `  enabled    = "on"`,
            `  url        = ${_hq(route.forward_auth.url || '')}`,
            `  on_failure = ${_hq(route.forward_auth.on_failure || 'deny')}`,
            '}');
    }
    if (route.o_auth) {
        const oa = route.o_auth;
        const ob = [`enabled       = "on"`, `provider      = ${_hq(oa.provider || '')}`, `client_id     = ${_hq(oa.client_id || '')}`, `client_secret = ${_hq(oa.client_secret || '')}`, `redirect_url  = ${_hq(oa.redirect_url || '')}`, `cookie_secret = ${_hq(oa.cookie_secret || '')}`];
        if (oa.auth_url)     ob.push(`auth_url     = ${_hq(oa.auth_url)}`);
        if (oa.token_url)    ob.push(`token_url    = ${_hq(oa.token_url)}`);
        if (oa.user_api_url) ob.push(`user_api_url = ${_hq(oa.user_api_url)}`);
        if (Array.isArray(oa.scopes) && oa.scopes.length)        ob.push(`scopes       = ${_strList(oa.scopes)}`);
        if (Array.isArray(oa.email_domains) && oa.email_domains.length) ob.push(`email_domains = ${_strList(oa.email_domains)}`);
        inner.push('', 'o_auth {', ...ob.map(l => '  ' + l), '}');
    }

    // headers block
    if (route.headers) {
        const hlines = _headersBlock(route.headers);
        if (hlines) inner.push('', hlines);
    }

    // Clean up leading blank lines inside the block
    const body = inner.join('\n').replace(/^\n+/, '');
    return `route ${_hq(route.path || '/')} {\n${_indent(body)}\n}`;
}

function _headersBlock(h) {
    const lines = [];
    const _section = (title, sec) => {
        if (!sec) return;
        const sl = [];
        for (const [k, v] of Object.entries(sec.set  || {})) sl.push(`set    = { ${_hq(k)}: ${_hq(v)} }`);
        for (const [k, v] of Object.entries(sec.add  || {})) sl.push(`add    = { ${_hq(k)}: ${_hq(v)} }`);
        for (const name    of (sec.remove || []))             sl.push(`remove = ${_hq(name)}`);
        if (!sl.length) return;
        lines.push(`${title} {`, ...sl.map(l => '  ' + l), '}');
    };
    _section('request',  h.request);
    _section('response', h.response);
    if (!lines.length) return '';
    return 'headers {\n' + _indent(lines.join('\n')) + '\n}';
}

function _proxyBlock(proxy) {
    const inner = [];
    inner.push(`enabled  = "on"`);
    inner.push(`listen   = ${_hq(proxy.listen || '')}`);
    if (proxy.strategy)        inner.push(`strategy = ${_hq(proxy.strategy)}`);
    if (proxy.protocol)        inner.push(`protocol = ${_hq(proxy.protocol)}`);
    if (proxy.matcher)         inner.push(`matcher  = ${_hq(proxy.matcher)}`);
    if (proxy.sni)             inner.push(`sni      = ${_hq(proxy.sni)}`);
    if (proxy.max_connections) inner.push(`max_connections = ${proxy.max_connections}`);
    if (proxy.proxy_protocol)  inner.push(`proxy_protocol  = true`);
    if (proxy.session_ttl)     inner.push(`session_ttl     = ${_hq(proxy.session_ttl)}`);
    if (proxy.max_sessions)    inner.push(`max_sessions    = ${proxy.max_sessions}`);
    for (const s of (proxy.backends || [])) {
        const sw = s.weight && s.weight !== 1 ? ` weight = ${s.weight}` : '';
        inner.push(`server ${_hq(s.address)} {${sw ? ' ' + sw + ' ' : ''}}`);
    }
    if (proxy.health_check) {
        const hc = proxy.health_check;
        const hb = [`enabled = "on"`];
        if (hc.interval) hb.push(`interval = ${_hq(hc.interval)}`);
        if (hc.timeout)  hb.push(`timeout  = ${_hq(hc.timeout)}`);
        if (hc.send)     hb.push(`send     = ${_hq(hc.send)}`);
        if (hc.expect)   hb.push(`expect   = ${_hq(hc.expect)}`);
        inner.push('', 'health_check {', ...hb.map(l => '  ' + l), '}');
    }
    return `proxy ${_hq(proxy.name || '')} {\n${_indent(inner.join('\n'))}\n}`;
}
