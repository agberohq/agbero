/**
 * js/utils.js
 *
 * Shared utility helpers used across hosts.html, drawer-listeners.js and other pages.
 *
 * ─── CRITICAL: alaye Enabled type ────────────────────────────────────────────
 *
 * alaye serialises the custom Enabled int type as:
 *   "on"      (Active   = 1)
 *   "off"     (Inactive = -1)
 *   "unknown" (Unknown  = 0)
 *
 * Check these with isOn(v) — never === true, never truthiness.
 *
 * Plain Go bool fields (web.listing, web.spa, web.no_cache, host.compression,
 * cors.allow_credentials, health_check.accelerated_probing, etc.) arrive as
 * actual booleans. Check these with isBool(v) or plain === true.
 *
 * Mixing the two causes silent missing badges / hidden sections.
 */

/** True only for alaye Enabled fields serialised as "on". */
export const isOn = v => v === 'on';

/** True for actual Go bool fields (true / false). */
export const isBool = v => v === true;

/**
 * Broader check used for badge rendering where the field could be either type.
 * Accepts: "on", true, 1, "true", "enabled", "yes".
 * Use sparingly — prefer isOn() for Enabled fields and isBool() for bool fields.
 */
export function isActive(v) {
    if (v === null || v === undefined) return false;
    if (typeof v === 'boolean') return v;
    if (typeof v === 'number')  return v === 1;
    if (typeof v === 'string')  return ['on','true','enabled','enable','yes','1'].includes(v.toLowerCase());
    return false;
}

/** Format bytes to human-readable string. */
export function formatBytes(b) {
    if (!b) return '0 B';
    const k = 1024, sizes = ['B','KB','MB','GB','TB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/** Format large numbers with k/M suffix. */
export function fmtNum(n) {
    const v = Number(n || 0);
    if (v >= 1_000_000) return (v / 1_000_000).toFixed(1) + 'M';
    if (v >= 1_000)     return (v / 1_000).toFixed(1) + 'k';
    return String(v);
}

/** Initials from a full name or username (up to 2 chars). */
export function initials(name) {
    if (!name) return '?';
    const parts = name.trim().split(/[\s._-]+/).filter(Boolean);
    if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (name[0] || '?').toUpperCase();
}
