/**
 * js/store.js — All store instances for agbero-ui.
 *
 * Three tiers, all backed by Oja Store. Never use raw localStorage/sessionStorage.
 *
 *   storeSession — tab-scoped plain sessionStorage  (metrics, UI state, config cache)
 *   storeLocal   — persistent plain localStorage    (user preferences, node list, theme)
 *   storeSecure  — AES-GCM encrypted sessionStorage (auth tokens — handled by auth.session)
 *
 * The default export `store` is storeSession — used throughout the app for runtime state.
 */
import { Store } from '../lib/oja.full.esm.js';
import { reinitApi } from './api.js';

export const storeSession = new Store('agbero',        { prefer: 'session' });
export const storeLocal   = new Store('agbero-prefs',  { prefer: 'local'   });
export const storeSecure  = new Store('agbero-secure', { prefer: 'session', encrypt: true });

// Canonical alias — most files just import { store }
export const store = storeSession;

// Target node preference (persists across tabs, never sensitive)

export function getHost() {
    return storeLocal.get('targetHost') || '';
}

export function setHost(url) {
    const clean = url ? url.replace(/\/+$/, '') : '';
    storeLocal.set('targetHost', clean);
    store.set('sys.targetHost', clean || 'local');
    reinitApi();
}

// Boot — restore target host display label
store.set('sys.targetHost', getHost() || 'local');
