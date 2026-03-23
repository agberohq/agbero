import { Store } from '../lib/oja.full.esm.js';

// prefer: 'session' — clears on tab close, correct for an admin UI.
// Ephemeral state (search term, chart tab, offline flag) should not
// survive a new session. Auth tokens use their own localStorage keys below.
export const store = new Store('agbero-admin', { prefer: 'session' });

// getCreds - retrieves stored authentication credentials
// Stored directly in localStorage so they survive tab close (intentional).
export function getCreds() {
    return {
        type:  localStorage.getItem('ag_auth_type'),
        token: localStorage.getItem('ag_auth_token'),
    };
}

// setCredentials - persists authentication credentials
export function setCredentials(type, token) {
    localStorage.setItem('ag_auth_type',  type);
    localStorage.setItem('ag_auth_token', token);
}

// clearCredentials - removes authentication credentials
export function clearCredentials() {
    localStorage.removeItem('ag_auth_type');
    localStorage.removeItem('ag_auth_token');
}

// isLoggedIn - synchronous check for a stored auth token
export function isLoggedIn() {
    return !!localStorage.getItem('ag_auth_token');
}

// getHost - retrieves the target Agbero node URL
export function getHost() {
    return localStorage.getItem('ag_target_host') || '';
}

// setHost - updates the target Agbero node URL
export function setHost(url) {
    const clean = url ? url.replace(/\/+$/, '') : '';
    localStorage.setItem('ag_target_host', clean);
    store.set('sys.targetHost', clean || 'local');
}

store.set('sys.targetHost', getHost() || 'local');
