/**
 * js/session-guard.js — Session expiry warning (extracted from shell.html)
 * updates toast in-place rather than dismiss+recreate every 10s
 */
import { listen, notify, modal } from '../lib/oja.full.esm.js';
import { store } from './store.js';
import { clearCredentials } from './store.js';

let _expiryToastId  = null;
let _expiryInterval = null;

export function initSessionGuard() {
    listen('auth:expiring', ({ expiresAt }) => {
        if (_expiryInterval) clearInterval(_expiryInterval);
        if (_expiryToastId)  notify.dismiss(_expiryToastId);

        function _left() {
            const ms = expiresAt - Date.now();
            if (ms <= 0) return '0s';
            const m = Math.floor(ms / 60000);
            const s = Math.floor((ms % 60000) / 1000);
            return m > 0 ? `${m}m ${s}s` : `${s}s`;
        }

        const renewFn = () => {
            clearCredentials();
            import('../lib/oja.full.esm.js').then(({ auth }) => auth.session.end());
            store.set('auth.isLoggedIn', false);
            window.location.reload();
        };

        // create once, find the DOM node and update textContent in-place
        _expiryToastId = notify.warn(`🔐 Session expires in ${_left()}`, {
            duration: 0, dismissible: true,
            action: { label: '↺ Renew', fn: renewFn },
        });

        _expiryInterval = setInterval(() => {
            const left = expiresAt - Date.now();
            if (left <= 0) {
                clearInterval(_expiryInterval);
                if (_expiryToastId) notify.dismiss(_expiryToastId);
                return;
            }
            // Update toast text in-place — find the toast's text node
            const toastEl = document.querySelector(`[data-toast-id="${_expiryToastId}"]`);
            if (toastEl) {
                const span = toastEl.querySelector('.notify-text');
                if (span) span.textContent = `🔐 Session expires in ${_left()}`;
            } else {
                // Fallback: dismiss + recreate if DOM element not found
                if (_expiryToastId) notify.dismiss(_expiryToastId);
                _expiryToastId = notify.warn(`🔐 Session expires in ${_left()}`, {
                    duration: 0, dismissible: true,
                    action: { label: '↺ Renew', fn: renewFn },
                });
            }
        }, 10_000);
    });

    listen('auth:expired', () => {
        if (_expiryInterval) { clearInterval(_expiryInterval); _expiryInterval = null; }
        if (_expiryToastId)  { notify.dismiss(_expiryToastId); _expiryToastId = null; }
        store.set('auth.isLoggedIn', false);
        clearCredentials();
        window._isPolling = window._latencyStarted = false;
        modal.open('loginModal');
    });
}
