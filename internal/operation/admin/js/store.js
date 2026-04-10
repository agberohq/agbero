import { Store } from '../lib/oja.full.esm.js';
import { apiSetToken, apiClearToken, reinitApi } from './api.js';

// prefer: 'session' — clears on tab close, correct for an admin UI.
export const store = new Store('agbero-admin', { prefer: 'session' });

// Auth
// Tokens are stored in localStorage so they survive tab close (intentional).
// Setting credentials also configures the shared Api instance immediately.

export function getCreds() {
    return {
        type:  localStorage.getItem('ag_auth_type'),
        token: localStorage.getItem('ag_auth_token'),
    };
}

export function setCredentials(type, token) {
    localStorage.setItem('ag_auth_type',  type);
    localStorage.setItem('ag_auth_token', token);
    // Keep Oja Api instance in sync — no more threading creds through every call
    if (type === 'jwt' || type === 'bearer') {
        apiSetToken(token);
    }
}

export function clearCredentials() {
    localStorage.removeItem('ag_auth_type');
    localStorage.removeItem('ag_auth_token');
    apiClearToken();
}

export function isLoggedIn() {
    return !!localStorage.getItem('ag_auth_token');
}

// Target node

export function getHost() {
    return localStorage.getItem('ag_target_host') || '';
}

export function setHost(url) {
    const clean = url ? url.replace(/\/+$/, '') : '';
    localStorage.setItem('ag_target_host', clean);
    store.set('sys.targetHost', clean || 'local');
    reinitApi(); // point the Api instance at the new node
}

// Boot — restore Api token if already logged in
const _boot = getCreds();
if (_boot.token) apiSetToken(_boot.token);

store.set('sys.targetHost', getHost() || 'local');
