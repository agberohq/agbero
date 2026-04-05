/**
 * js/api.js  —  All API calls for Agbero admin UI.
 *
 * Endpoint reference:
 *   Unauthenticated (admin root):
 *     GET  /healthz  /status  /uptime  /config
 *     POST /login  /logout
 *     GET  /logs?limit=N
 *
 *   Authenticated (/api/v1 prefix):
 *     hosts      → /api/v1/discovery[/{domain}]          GET/POST/PUT/DELETE
 *     certs      → /api/v1/certs[/{domain}]              GET/POST/DELETE
 *     keeper     → /api/v1/keeper/unlock|lock|secrets|totp
 *     totp       → /api/v1/totp/setup  /{user}/qr.svg
 *     secrets    → /api/v1/secrets
 *     firewall   → /api/v1/firewall
 *     cluster    → /api/v1/cluster (POST) + /api/v1/route (POST/DELETE)
 *     telemetry  → /api/v1/telemetry/history  /hosts
 */

import { Api } from '../lib/oja.full.esm.js';
import { getHost } from './store.js';


let _api = null;

function _makeApi() {
    const base = getHost() || window.location.origin;
    return new Api({ base, timeout: 15000 });
}

export function getApi() {
    if (!_api) _api = _makeApi();
    return _api;
}

export function reinitApi() { _api = _makeApi(); }

export function apiSetToken(token)  { getApi().setToken(token); }
export function apiClearToken()     { getApi().clearAuth(); }

// Returns null on error, never throws. 401s are handled globally by main.js.

async function _safe(fn) {
    try { return await fn(); }
    catch (err) {
        if (err?.status !== 401 && err?.name !== 'AbortError') {
            console.warn('[agbero/api]', err?.message || err);
        }
        return null;
    }
}


export async function fetchStatus() {
    const base = getHost() || window.location.origin;
    try {
        const res  = await fetch(base + '/status');
        if (!res.ok) return null;
        const data = await res.json();
        // /status returns auth/totp as string booleans
        return { auth: data.auth === 'true', totp: data.totp === 'true' };
    } catch { return null; }
}

export async function login(username, password, totp = '') {
    const base = getHost() || window.location.origin;
    const body = { username, password };
    if (totp) body.totp = totp;
    try {
        const res = await fetch(base + '/login', {
            method:  'POST',
            body:    JSON.stringify(body),
            headers: { 'Content-Type': 'application/json' },
        });
        if (!res.ok) {
            const text = await res.text().catch(() => '');
            const err  = new Error(text.trim() || 'Login failed');
            err.status = res.status;
            throw err;
        }
        const data = await res.json();
        if (!data.type && data.token) data.type = 'jwt';
        return data;
    } catch (err) {
        if (!err.status) console.error('[agbero/api] login error:', err);
        throw err;
    }
}

/** POST /logout — revokes the JWT server-side (JTI revocation list). */
export async function logout() {
    const base  = getHost() || window.location.origin;
    const token = getApi()._token;
    try {
        await fetch(base + '/logout', {
            method:  'POST',
            headers: token ? { 'Authorization': 'Bearer ' + token } : {},
        });
    } catch { /* ignore — always clear local credentials */ }
}


export async function fetchUptime()  { return _safe(() => getApi().get('/uptime')); }
export async function fetchConfig()  { return _safe(() => getApi().get('/config')); }

/** GET /logs?limit=N  (server param is 'limit', not 'lines') */
export async function fetchLogs(lines) {
    return _safe(() => getApi().get(`/logs?limit=${lines}`));
}


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

/** POST /api/v1/discovery — create new host (JSON). */
export async function addHost(domain, config) {
    return _safe(() => getApi().post('/api/v1/discovery', { domain, config }));
}

/** POST /api/v1/discovery — create new host (HCL text/plain). */
export async function addHostHCL(hclText) {
    return _safe(() => getApi().post('/api/v1/discovery', hclText, {
        raw:     true,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    }));
}

/** PUT /api/v1/discovery/{domain} — update existing host (JSON). */
export async function updateHost(domain, config) {
    return _safe(() => getApi().put(
        `/api/v1/discovery/${encodeURIComponent(domain)}`,
        { domain, config }
    ));
}

/** PUT /api/v1/discovery/{domain} — update existing host (HCL text/plain). */
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

export async function deleteHost(domain) {
    return _safe(() => getApi().delete(
        `/api/v1/discovery/${encodeURIComponent(domain)}`
    ));
}


export async function fetchCerts() {
    return _safe(() => getApi().get('/api/v1/certs'));
}

export async function uploadCert(domain, cert, key) {
    return _safe(() => getApi().post('/api/v1/certs', { domain, cert, key }));
}

export async function deleteCert(domain) {
    return _safe(() => getApi().delete(`/api/v1/certs/${encodeURIComponent(domain)}`));
}


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


export async function broadcastClusterRoute(body) {
    return _safe(() => getApi().post('/api/v1/cluster', body));
}

export async function deleteClusterRoute(host, path) {
    return _safe(() => getApi().delete(
        `/api/v1/cluster?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path || '/')}`
    ));
}


export async function fetchTelemetry(host, range) {
    return _safe(() => getApi().get(
        `/api/v1/telemetry/history?host=${encodeURIComponent(host)}&range=${range}`
    ));
}

export async function fetchTelemetryHosts() {
    return _safe(() => getApi().get('/api/v1/telemetry/hosts'));
}


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

export async function keeperDelete(key) {
    return _safe(() => getApi().delete(
        `/api/v1/keeper/secrets/${encodeURIComponent(key)}`
    ));
}

export async function keeperTOTPSetup(username) {
    return _safe(() => getApi().post(
        `/api/v1/keeper/totp/${encodeURIComponent(username)}`, {}
    ));
}

export function keeperTOTPQRUrl(username) {
    const base = getHost() || window.location.origin;
    return `${base}/api/v1/keeper/totp/${encodeURIComponent(username)}/qr.svg`;
}


export async function setupTOTP() {
    return _safe(() => getApi().post('/api/v1/totp/setup', {}));
}

export function getTOTPQRUrl(username) {
    const base = getHost() || window.location.origin;
    return `${base}/api/v1/totp/${encodeURIComponent(username)}/qr.svg`;
}


export async function generateSecret(action, opts = {}) {
    return _safe(() => getApi().post('/api/v1/secrets', { action, ...opts }));
}


export function parseCertificates(hosts) {
    const certs = [];
    for (const [host, cfg] of Object.entries(hosts || {})) {
        if (cfg.tls?.expiry) {
            const exp      = new Date(cfg.tls.expiry);
            const daysLeft = Math.floor((exp - Date.now()) / 86400000);
            certs.push({
                host, expiry: cfg.tls.expiry, daysLeft,
                issuer: cfg.tls.issuer || "Let's Encrypt",
            });
        }
    }
    return certs;
}

export function parseJWTExpiry(token) {
    try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        return payload.exp ? payload.exp * 1000 : null;
    } catch { return null; }
}

export function fmtNum(n) {
    if (n === undefined || n === null) return '0';
    if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
    if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'k';
    return String(n);
}

export function formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}