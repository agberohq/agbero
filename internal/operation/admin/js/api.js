/**
 * js/api.js — All API calls for Agbero admin UI.
 *
 * Endpoint reference:
 *   Unauthenticated (admin root):
 *     GET  /healthz  /status  /uptime  /config
 *     POST /login  /logout
 *     GET  /logs?limit=N
 *
 *   Authenticated (/api/v1 prefix):
 *     hosts      → /api/v1/discovery[/{domain}]     GET/POST/PUT/DELETE
 *     certs      → /api/v1/certs[/{domain}]         GET/POST/DELETE
 *     keeper     → /api/v1/keeper/unlock|lock|secrets|totp
 *     totp       → /api/v1/totp/setup  /{user}/qr.svg
 *     secrets    → /api/v1/secrets
 *     firewall   → /api/v1/firewall
 *     cluster    → /api/v1/cluster (POST) + /api/v1/route (POST/DELETE)
 *     telemetry  → /api/v1/telemetry/history  /hosts
 *     kv         → /api/v1/kv/:key             GET/POST/DELETE (in-memory)
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

export function getApi()    { if (!_api) _api = _makeApi(); return _api; }
export function reinitApi() { _api = _makeApi(); }
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

export async function fetchStatus() {
    const base = getHost() || window.location.origin;
    try {
        const res  = await fetch(base + '/status');
        if (!res.ok) return null;
        return await res.json();
    } catch { return null; }
}

// POST /login — credentials only. Returns full token OR {status:"challenge_required", token, requirements}
export async function login(username, password) {
    const base = getHost() || window.location.origin;
    try {
        const res = await fetch(base + '/login', {
            method:  'POST',
            body:    JSON.stringify({ username, password }),
            headers: { 'Content-Type': 'application/json' },
        });
        // 202 = challenge required (pre-auth token returned)
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

// POST /login/challenge — solve keeper/TOTP challenges using pre-auth token
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
                'Authorization': 'Bearer ' + preAuthToken,
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

export async function logout() {
    const base  = getHost() || window.location.origin;
    const token = getApi()._token;
    try {
        await fetch(base + '/logout', {
            method:  'POST',
            headers: token ? { 'Authorization': 'Bearer ' + token } : {},
        });
    } catch { /* ignore */ }
}

// Monitoring

export async function fetchUptime()  { return _safe(() => getApi().get('/uptime')); }
export async function fetchConfig()  { return _safe(() => getApi().get('/config')); }
export async function fetchLogs(lines) {
    return _safe(() => getApi().get(`/logs?limit=${lines}`));
}

// Host management  /api/v1/discovery

export async function checkHostExists(domain) {
    const base  = getHost() || window.location.origin;
    const token = getApi()._token;
    const headers = { 'Accept': 'application/json' };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    try {
        const res = await fetch(
            `${base}/api/v1/discovery/${encodeURIComponent(domain)}`,
            { headers }
        );
        if (res.status === 404) return false;
        return res.ok;
    } catch { return false; }
}

export async function addHost(domain, config) {
    return _safe(() => getApi().post('/api/v1/discovery', { domain, config }));
}

export async function addHostHCL(hclText) {
    return _safe(() => getApi().post('/api/v1/discovery', hclText, {
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

export async function getHostHCL(domain) {
    const base  = getHost() || window.location.origin;
    const token = getApi()._token;
    const headers = { 'Accept': 'application/hcl' };
    if (token) headers['Authorization'] = 'Bearer ' + token;
    try {
        const res = await fetch(
            `${base}/api/v1/discovery/${encodeURIComponent(domain)}?format=hcl`,
            { headers }
        );
        if (!res.ok) return null;
        return res.text();
    } catch { return null; }
}

export async function deleteHost(domain, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(
        `/api/v1/discovery/${encodeURIComponent(domain)}`, extra
    ));
}

// Certificate management  /api/v1/certs

export async function fetchCerts() {
    return _safe(() => getApi().get('/api/v1/certs'));
}

export async function uploadCert(domain, cert, key) {
    return _safe(() => getApi().post('/api/v1/certs', { domain, cert, key }));
}

export async function deleteCert(domain, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(`/api/v1/certs/${encodeURIComponent(domain)}`, extra));
}

// Firewall  /api/v1/firewall

export async function fetchFirewall() {
    return _safe(() => getApi().get('/api/v1/firewall'));
}

export async function addFirewallRule(body) {
    return _safe(() => getApi().post('/api/v1/firewall', body));
}

export async function deleteFirewallRule(ip) {
    return _safe(() => getApi().delete(
        `/api/v1/firewall?ip=${encodeURIComponent(ip)}`
    ));
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

export async function keeperUnlock(passphrase) {
    return _safe(() => getApi().post('/api/v1/keeper/unlock', { passphrase }));
}

export async function keeperLock() {
    return _safe(() => getApi().post('/api/v1/keeper/lock', {}));
}

export async function keeperList() {
    return _safe(() => getApi().get('/api/v1/keeper/secrets'));
}

export async function keeperGet(key) {
    return _safe(() => getApi().get(`/api/v1/keeper/secrets/${encodeURIComponent(key)}`));
}

export async function keeperSet(key, value) {
    return _safe(() => getApi().post('/api/v1/keeper/secrets', { key, value }));
}

export async function keeperDelete(key, otpCode = '') {
    const extra = otpCode ? { headers: { 'X-TOTP-Code': otpCode } } : {};
    return _safe(() => getApi().delete(
        `/api/v1/keeper/secrets/${encodeURIComponent(key)}`, extra
    ));
}

// TOTP  /api/v1/totp

export async function setupTOTP() {
    return _safe(() => getApi().post('/api/v1/totp/setup', {}));
}

export function getTOTPQRUrl(username) {
    const base = getHost() || window.location.origin;
    return `${base}/api/v1/totp/${encodeURIComponent(username)}/qr.svg`;
}

// Secrets utility  /api/v1/secrets

export async function generateSecret(action, opts = {}) {
    return _safe(() => getApi().post('/api/v1/secrets', { action, ...opts }));
}

// KV  /api/v1/kv/:key (in-memory, gone on server restart)

export async function kvGet(key) {
    return _safe(() => getApi().get(`/api/v1/kv/${encodeURIComponent(key)}`));
}

export async function kvSet(key, value) {
    return _safe(() => getApi().post(`/api/v1/kv/${encodeURIComponent(key)}`, { value }));
}

export async function kvDelete(key) {
    return _safe(() => getApi().delete(`/api/v1/kv/${encodeURIComponent(key)}`));
}

// Pure data helpers

/**
 * parseCertificates — maps /api/v1/certs payload to the shape used by the UI.
 * API returns: { certificates: [{ domain, file, expires_at, is_expired, days_left }] }
 * days_left is server-computed (integer). expires_at drives the live countdown
 * for certs expiring within 30 days.
 */
export function parseCertificates(certsPayload) {
    if (!certsPayload) return [];

    const list = Array.isArray(certsPayload)
        ? certsPayload
        : (Array.isArray(certsPayload.certificates) ? certsPayload.certificates : []);

    return list.map(c => ({
        domain:     c.domain     || '',
        file:       c.file       || '',
        expires_at: c.expires_at || '',
        is_expired: c.is_expired === true,
        days_left:  typeof c.days_left === 'number' ? c.days_left : null,
    })).filter(c => c.domain);
}

export function parseJWTExpiry(token) {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.exp ? payload.exp * 1000 : null;
    } catch { return null; }
}
