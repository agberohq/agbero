/**
 * pages/add-host/draft-store.js
 *
 * Single source of truth for add-host wizard draft state.
 * Uses Oja Store with session preference — clears on tab close, never persists.
 */
import { Store } from '../../lib/oja.full.esm.js';

const _store = new Store('agbero-draft-host', { prefer: 'session' });

export function draftGet(key) {
    const all = _store.get('draft') || {};
    return key === undefined ? { ...all } : all[key];
}

export function draftSet(key, val) {
    const all = _store.get('draft') || {};
    all[key] = val;
    _store.set('draft', all);
}

export function draftMerge(partial) {
    const all = _store.get('draft') || {};
    Object.assign(all, partial);
    _store.set('draft', all);
}

export function draftClear() {
    _store.set('draft', {});
}

export function draftHas() {
    const d = _store.get('draft') || {};
    return !!(d.host_type || d.domain);
}

export function draftSummary() {
    const d = draftGet();
    if (!d.host_type) return null;
    return d.domain ? `Unfinished config for "${d.domain}" (${d.host_type})` : `Unfinished ${d.host_type} host`;
}

export function newRoute(path = '/') {
    return {
        id: 'r' + Date.now() + Math.random().toString(36).slice(2, 6),
        path,
        engineData: {}, extras: {}, authData: {}, headers: {}, rewrites: [],
    };
}

export function getRoutes() { return draftGet('_routes') || [newRoute('/')]; }
export function setRoutes(routes) { draftSet('_routes', routes); }
export function getTcp() { return draftGet('_tcp') || {}; }
export function setTcp(data) { draftSet('_tcp', data); }
