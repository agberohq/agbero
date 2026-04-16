/**
 * js/utils.js - single canonical source for all shared helpers
 *
 * CRITICAL: alaye Enabled type serialises as:
 *   "on"      (Active   = 1)
 *   "off"     (Inactive = -1)
 *   "unknown" (Unknown  = 0)
 * Check with isOn(v). Never === true. Never truthiness.
 *
 * Plain Go bool fields (web.listing, web.spa, etc.) arrive as actual booleans.
 * Check with isBool(v) or plain === true.
 *
 * KEEPER RULES (see plan.md Appendix D):
 *   - Key format: ss://[namespace]/[path]  — namespace is ALWAYS required
 *   - Values returned by GET /keeper/secrets/* are base64-encoded
 *   - Always decode with atob(result.value) before displaying
 *   - Never show raw base64 to the user
 */

export const isOn   = v => v === 'on';
export const isOff  = v => v === 'off';
export const isBool = v => v === true;

/** Human label for a Toggle value */
export function toggleLabel(v) {
    if (isOn(v))  return 'On';
    if (isOff(v)) return 'Off';
    return 'Default';
}

// Keeper helpers

const _RESERVED_NS = new Set(['__default__', 'internal', 'vault']);

/**
 * Validate a Keeper namespace + path pair before composing a ss:// reference.
 * Returns an error string, or null if valid.
 */
export function validateKeeperKey(namespace, path) {
    const ns = (namespace || '').trim();
    const p  = (path      || '').trim();
    if (!ns)              return 'Namespace is required (e.g. prod, db, tls)';
    if (!p)               return 'Key path is required';
    if (ns.includes('/')) return 'Namespace cannot contain slashes — use the path field for sub-keys';
    if (_RESERVED_NS.has(ns)) return `"${ns}" is a reserved namespace and cannot be used`;
    return null;
}

/**
 * Compose a ss:// reference from separate namespace and path inputs.
 * Both are trimmed; no scheme prefix is needed from the caller.
 */
export function composeKeeperRef(namespace, path) {
    return `ss://${(namespace || '').trim()}/${(path || '').trim()}`;
}

/**
 * Split a "namespace/path" key (as returned by GET /keeper/secrets) into parts.
 * Returns { namespace, path }.  The path may contain further slashes.
 */
export function splitKeeperKey(key) {
    const str = (key || '').replace(/^ss:\/\//, '');
    const idx = str.indexOf('/');
    if (idx < 0) return { namespace: str, path: '' };
    return { namespace: str.slice(0, idx), path: str.slice(idx + 1) };
}

/**
 * Decode a base64-encoded Keeper secret value for display.
 * The GET /keeper/secrets/* endpoint always returns { value: "<b64>", encoding: "base64" }.
 * Returns the decoded string, or null on error.
 */
export function decodeKeeperValue(b64) {
    try { return atob(b64); } catch { return null; }
}

export function isActive(v) {
    if (v === null || v === undefined) return false;
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number')  return v === 1;
    if (typeof v === 'string')  return ['on','true','enabled','enable','yes','1'].includes(v.toLowerCase());
    return false;
}

export function formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

export function fmtNum(n) {
    const v = Number(n || 0);
    if (v >= 1_000_000) return (v / 1_000_000).toFixed(1) + 'M';
    if (v >= 1_000)     return (v / 1_000).toFixed(1) + 'k';
    return String(v);
}

export function formatPercent(v) {
    return Number(v || 0).toFixed(1) + '%';
}

export function initials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/[\s._-]+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (name[0] || '?').toUpperCase();
}

/** Parse Go duration string "30m0s" → milliseconds */
export function parseDuration(s) {
    if (!s) return 0;
    let ms = 0;
    for (const m of (s.match(/(\d+(?:\.\d+)?)([hms])/g) || [])) {
        const num = parseFloat(m), unit = m.slice(-1);
        ms += unit === 'h' ? num*3_600_000 : unit === 'm' ? num*60_000 : num*1_000;
    }
    return ms || 0;
}

export function debounce(fn, ms) {
    let t;
    return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}
