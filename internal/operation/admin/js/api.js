import { getHost } from './store.js';

const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN    = 403;

async function apiFetch(path, options = {}, creds = null) {
    const host    = getHost();
    const baseUrl = host || window.location.origin;
    const url     = baseUrl + path;
    const headers = { ...options.headers };

    if (creds && creds.token) {
        headers['Authorization'] = `${creds.type === 'basic' ? 'Basic' : 'Bearer'} ${creds.token}`;
    }

    try {
        const res = await fetch(url, { ...options, headers });
        if (res.status === HTTP_UNAUTHORIZED || res.status === HTTP_FORBIDDEN) return { __unauthorized: true };
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const ct = res.headers.get('content-type') || '';
        if (ct.includes('application/json')) return await res.json();
        return await res.text();
    } catch (e) {
        return { __offline: true, error: e.message };
    }
}

// fetchUptime - single source of truth for all live data
export async function fetchUptime(creds) {
    return apiFetch('/uptime', {}, creds);
}

// fetchConfig - static configuration tree; also the source of global.version
export async function fetchConfig(creds) {
    return apiFetch('/config', {}, creds);
}

// fetchTelemetry - historical performance data for the perf modal
export async function fetchTelemetry(creds, host, range) {
    return apiFetch(`/telemetry/history?host=${encodeURIComponent(host)}&range=${range}`, {}, creds);
}

// fetchFirewall - active firewall rules
export async function fetchFirewall(creds) {
    return apiFetch('/firewall', {}, creds);
}

// fetchLogs - latest log lines; old API uses ?lines=N
export async function fetchLogs(creds, lines) {
    return apiFetch(`/logs?lines=${lines}`, {}, creds);
}

export async function deleteFirewallRule(creds, ip) {
    return apiFetch(`/firewall?ip=${encodeURIComponent(ip)}`, { method: 'DELETE' }, creds);
}

export async function addFirewallRule(creds, body) {
    return apiFetch('/firewall', {
        method: 'POST', body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json' },
    }, creds);
}

export async function broadcastClusterRoute(creds, body) {
    return apiFetch('/cluster/route', {
        method: 'POST', body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json' },
    }, creds);
}

export async function addHost(creds, domain, config) {
    return apiFetch('/api/hosts', {
        method: 'POST', body: JSON.stringify({ domain, config }),
        headers: { 'Content-Type': 'application/json' },
    }, creds);
}

export async function deleteHost(creds, domain) {
    return apiFetch(`/api/hosts?domain=${encodeURIComponent(domain)}`, { method: 'DELETE' }, creds);
}

export async function login(username, password) {
    const host    = getHost();
    const baseUrl = host || window.location.origin;
    try {
        const res = await fetch(baseUrl + '/login', {
            method: 'POST', body: JSON.stringify({ username, password }),
            headers: { 'Content-Type': 'application/json' },
        });
        if (!res.ok) return null;
        const data = await res.json();
        if (!data.type && data.token) data.type = 'jwt';
        return data;
    } catch { return null; }
}

export function parseCertificates(hosts) {
    const certs = [];
    for (const [host, cfg] of Object.entries(hosts || {})) {
        if (cfg.tls?.expiry) {
            const exp      = new Date(cfg.tls.expiry);
            const daysLeft = Math.floor((exp - Date.now()) / 86400000);
            certs.push({ host, expiry: cfg.tls.expiry, daysLeft, issuer: cfg.tls.issuer || "Let's Encrypt" });
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
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000)    return (n / 1000).toFixed(1) + 'k';
    return String(n);
}

export function formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
