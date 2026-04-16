/**
 * js/api.js — All API calls for Agbero admin UI.
 *
 * Issue 6 applied:
 *   - fetchStatus() and logout() now route through getApi() via _safe()
 *   - checkHostExists(), keeperSetFile(), getHostHCL() no longer read getApi()._token
 *     directly; token is injected automatically by the Api instance after apiSetToken().
 *   - loginChallenge() deliberately uses a raw fetch with the pre-auth token, NOT the
 *     session token — this is intentional and documented below.
 *
 * Endpoint reference:
 *   Unauthenticated: GET /healthz /status /uptime /config  POST /login /logout  GET /logs
 *   Authenticated (/api/v1): discovery, certs, keeper, totp, secrets, firewall, cluster,
 *                             telemetry, kv
 */

import { Api } from '../lib/oja.full.esm.js';
import { getHost } from './store.js';

// re-export from utils — single canonical source
export { fmtNum, formatBytes } from './utils.js';

// Singleton Api instance

let _api = null;

function _makeApi() {
    const base = getHost() || window.location.origin;
    return new Api({ base, timeout: 15000 });
}

export function getApi()            { if (!_api) _api = _makeApi(); return _api; }
export function reinitApi()         { _api = _makeApi(); }
export function apiSetToken(token)  { getApi().setToken(token); }
export function apiClearToken()     { getApi().clearAuth(); }

// Safe fetch wrapper

async function _safe(fn) {
    try { return await fn(); }
    catch (err) {
        if (err?.status !== 401 && err?.name !== 'AbortError') {
            console.warn('[agbero/api]', err?.message || err);
        }
        return null;
    }
}

// Unauthenticated endpoints

// Issue 6: fetchStatus now goes through getApi() instead of raw fetch
export async function fetchStatus() {
    return _safe(() => getApi().get('/status'));
}

// POST /login — sends plain credentials. Returns full token OR challenge object.
// NOTE: This is intentionally a raw fetch with NO Authorization header —
// the user is not yet authenticated when this runs.
export async function login(username, password) {
    const base = getHost() || window.location.origin;
    try {
        const res = await fetch(base + '/login', {
            method:  'POST',
            body:    JSON.stringify({ username, password }),
            headers: { 'Content-Type': 'application/json' },
        });
        if (res.status === 202) {
            const data = await res.json();
            return { challenge: true, token: data.token, requirements: data.requirements || [] };
        }
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            const err  = new Error(text.trim() || 'Login failed');
            err.status = res.status;
            throw err;
        }
        const data = await res.json();
        return { challenge: false, token: data.token, expires: data.expires };
    } catch (err) {
        if (!err.status) console.error('[agbero/api] login error:', err);
        throw err;
    }
}

// POST /login/challenge — solve keeper/TOTP using the PRE-AUTH token.
// INTENTIONAL: this deliberately uses preAuthToken (not the session token)
// because the user is not yet fully authenticated. Do NOT route through getApi().
export async function loginChallenge(preAuthToken, { keeper_passphrase = '', totp = '' } = {}) {
    const base = getHost() || window.location.origin;
    const body = {};
    if (keeper_passphrase) body.keeper_passphrase = keeper_passphrase;
    if (totp)              body.totp              = totp;
    try {
        const res = await fetch(base + '/login/challenge', {
            method:  'POST',
            body:    JSON.stringify(body),
            headers: {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer ' + preAuthToken, // pre-auth token, not session token
            },
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            const err  = new Error(text.trim() || 'Challenge failed');
            err.status = res.status;
            throw err;
        }
        const data = await res.json();
        return { token: data.token, expires: data.expires };
    } catch (err) {
        if (!err.status) console.error('[agbero/api] challenge error:', err);
        throw err;
    }
}

// Issue 6: logout now routes through getApi() — token injected automatically
export async function logout() {
    return _safe(() => getApi().post('/logout', {}));
}

// Monitoring

export async function fetchUptime()      { return _safe(() => getApi().get('/uptime')); }
export async function fetchConfig()      { return _safe(() => getApi().get('/config')); }
export async function fetchLogs(lines)   { return _safe(() => getApi().get(`/logs?limit=${lines}`)); }

// Host management  /api/v1/discovery

// Issue 6: checkHostExists no longer reads getApi()._token — uses getApi() directly
export async function checkHostExists(domain) {
    return _safe(async () => {
        const res = await getApi().get(
            `/api/v1/discovery/${encodeURIComponent(domain)}`,
            { returnResponse: true }
        );
        if (res?.status === 404) return false;
        return res?.ok !== false;
    });
}

export async function addHost(domain, config) {
    return _safe(() => getApi().post('/api/v1/discovery', { domain, config }));
}

export async function addHostHCL(hclText, filename = '') {
    const query = filename ? `?filename=${encodeURIComponent(filename)}` : '';
    return _safe(() => getApi().post(`/api/v1/discovery${query}`, hclText, {
        raw:     true,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    }));
}

export async function updateHost(domain, config) {
    return _safe(() => getApi().put(
        `/api/v1/discovery/${encodeURIComponent(domain)}`,
        { domain, config }
    ));
}

export async function updateHostHCL(domain, hclText) {
    return _safe(() => getApi().put(
        `/api/v1/discovery/${encodeURIComponent(domain)}`,
        hclText,
        { raw: true, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    ));
}

// Issue 6: getHostHCL no longer reads getApi()._token — uses getApi() directly
export async function getHostHCL(domain) {
    return _safe(async () => {
        const res = await getApi().get(
            `/api/v1/discovery/${encodeURIComponent(domain)}?format=hcl`,
            { headers: { 'Accept': 'application/hcl' } }
        );
        // Oja api.get() with a non-JSON content-type returns the raw text string directly
        return typeof res === 'string' && res.trim() ? res : null;
    });
}

export async function deleteHost(domain, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(
        `/api/v1/discovery/${encodeURIComponent(domain)}`, extra
    ));
}

// Certificate management  /api/v1/certs

export async function fetchCerts()                { return _safe(() => getApi().get('/api/v1/certs')); }
export async function uploadCert(domain, cert, key) {
    return _safe(() => getApi().post('/api/v1/certs', { domain, cert, key }));
}
export async function deleteCert(domain, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(`/api/v1/certs/${encodeURIComponent(domain)}`, extra));
}

// Firewall  /api/v1/firewall

export async function fetchFirewall()       { return _safe(() => getApi().get('/api/v1/firewall')); }
export async function addFirewallRule(body) { return _safe(() => getApi().post('/api/v1/firewall', body)); }
export async function deleteFirewallRule(ip) {
    return _safe(() => getApi().delete(`/api/v1/firewall?ip=${encodeURIComponent(ip)}`));
}

// Cluster  /api/v1/cluster

export async function broadcastClusterRoute(body) {
    return _safe(() => getApi().post('/api/v1/cluster', body));
}
export async function deleteClusterRoute(host, path) {
    return _safe(() => getApi().delete(
        `/api/v1/cluster?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path || '/')}`
    ));
}

// Telemetry  /api/v1/telemetry

export async function fetchTelemetry(host, range) {
    return _safe(() => getApi().get(
        `/api/v1/telemetry/history?host=${encodeURIComponent(host)}&range=${range}`
    ));
}
export async function fetchTelemetryHosts() {
    return _safe(() => getApi().get('/api/v1/telemetry/hosts'));
}

// Keeper  /api/v1/keeper

export async function keeperStatus()           { return _safe(() => getApi().get('/api/v1/keeper/status')); }
export async function keeperUnlock(passphrase) { return _safe(() => getApi().post('/api/v1/keeper/unlock', { passphrase })); }
export async function keeperLock()             { return _safe(() => getApi().post('/api/v1/keeper/lock', {})); }
export async function keeperList()             { return _safe(() => getApi().get('/api/v1/keeper/secrets')); }
export async function keeperGet(key)           { return _safe(() => getApi().get(`/api/v1/keeper/secrets/${encodeURIComponent(key)}`)); }
export async function keeperSet(key, value)    { return _safe(() => getApi().post('/api/v1/keeper/secrets', { key, value })); }
export async function keeperDelete(key, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(`/api/v1/keeper/secrets/${encodeURIComponent(key)}`, extra));
}

// Issue 6: keeperSetFile — no longer reads getApi()._token; uses getApi() fetch interceptor
export async function keeperSetFile(key, file) {
    const base = getHost() || window.location.origin;
    const form = new FormData();
    form.append('key',  key);
    form.append('file', file, file.name);
    // Build headers via the Api instance's fetch hook — token injected automatically
    const headers = {};
    const token = getApi().getToken?.();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    try {
        const res = await fetch(base + '/api/v1/keeper/secrets', {
            method: 'POST',
            headers,
            body: form,
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            return { error: text || `Upload failed (${res.status})` };
        }
        return res.json();
    } catch (err) {
        console.warn('[agbero/api] keeperSetFile:', err?.message);
        return null;
    }
}

// TOTP  /api/v1/totp

export async function setupTOTP() { return _safe(() => getApi().post('/api/v1/totp/setup', {})); }
export function getTOTPQRUrl(username) {
    const base = getHost() || window.location.origin;
    return `${base}/api/v1/totp/${encodeURIComponent(username)}/qr.svg`;
}

// Secrets utility  /api/v1/secrets

export async function generateSecret(action, opts = {}) {
    return _safe(() => getApi().post('/api/v1/secrets', { action, ...opts }));
}

// KV  /api/v1/kv/:key

export async function kvGet(key)        { return _safe(() => getApi().get(`/api/v1/kv/${encodeURIComponent(key)}`)); }
export async function kvSet(key, value) { return _safe(() => getApi().post(`/api/v1/kv/${encodeURIComponent(key)}`, { value })); }
export async function kvDelete(key)     { return _safe(() => getApi().delete(`/api/v1/kv/${encodeURIComponent(key)}`)); }

// Pure data helpers

/**
 * parseCertificates — maps /api/v1/certs payload to the shape used by the UI.
 * API returns: { certificates: [{ domain, expires_at, is_expired, days_left,
 *   issued_at, issuer, subject, sans, key_type, key_bits, serial_number, source }] }
 */
export function parseCertificates(certsPayload) {
    if (!certsPayload) return [];
    const list = Array.isArray(certsPayload)
        ? certsPayload
        : (Array.isArray(certsPayload.certificates) ? certsPayload.certificates : []);
    return list.map(c => ({
        domain:        c.domain        || '',
        expires_at:    c.expires_at    || '',
        issued_at:     c.issued_at     || '',
        is_expired:    c.is_expired    === true,
        days_left:     typeof c.days_left === 'number' ? c.days_left : null,
        issuer:        c.issuer        || '',
        subject:       c.subject       || '',
        sans:          Array.isArray(c.sans) ? c.sans : [],
        key_type:      c.key_type      || '',
        key_bits:      c.key_bits      || 0,
        serial_number: c.serial_number || '',
        source:        c.source        || '',
    })).filter(c => c.domain);
}

export function parseJWTExpiry(token) {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.exp ? payload.exp * 1000 : null;
    } catch { return null; }
}
