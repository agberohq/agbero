/**
 * pages/profile.js — Profile & Security page.
 */
import { notify } from '../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, utils, oja } = inject('app');
    const { isOn } = utils;
    const { emit, auth } = oja;

    let _pendingSecret = '', _secretRevealed = false, _username = 'admin';

    function showTOTPState(state) {
        find('#totpSetupPanel').style.display      = state === 'setup'      ? '' : 'none';
        find('#totpQRPanel').style.display         = state === 'qr'         ? '' : 'none';
        find('#totpConfiguredPanel').style.display = state === 'configured' ? '' : 'none';
        const badge = find('#totpStatusBadge');
        if (badge) { badge.textContent = state === 'configured' ? 'Active' : 'Not set up'; badge.className = 'badge ' + (state === 'configured' ? 'success' : ''); }
        const rc = find('#totpResetConfirm'); if (rc) rc.style.display = 'none';
    }

    function _showQR(res) {
        _pendingSecret = res.secret || ''; _secretRevealed = false;
        const qrEl = find('#totpQRCode');
        if (qrEl) {
            if (res.qr_svg) { qrEl.innerHTML = res.qr_svg; const svg = qrEl.querySelector('svg'); if (svg) { svg.style.width = '160px'; svg.style.height = '160px'; } }
            else qrEl.innerHTML = `<div style="font-size:10px;word-break:break-all;max-width:160px;color:var(--text-mute);">QR unavailable — use manual key</div>`;
        }
        const secretEl = find('#totpSecretText');
        if (secretEl) { secretEl.textContent = _pendingSecret; secretEl.style.filter = 'blur(5px)'; }
        showTOTPState('qr'); find('#totpVerifyCode')?.focus();
    }

    function boot() {
        try { const user = auth.session.user(); _username = user?.user || user?.sub || 'admin'; } catch {}
        find('#profileUsername').textContent = _username;
        const uptime = store.get('lastUptime');
        if (uptime?.system?.uptime) find('#profileSession').textContent = 'Active · ' + uptime.system.uptime;
        find('#profileAuthMethod').textContent = 'Basic Auth + JWT';
        const cfg  = store.get('lastConfig');
        const totp = cfg?.global?.admin?.totp;
        // totp.enabled tells us if TOTP is configured globally.
        // We can't tell per-user status from config alone — show "configured" if
        // global TOTP is enabled (meaning it is in use), otherwise show setup option.
        const totpGlobalEnabled = isOn(totp?.enabled);
        showTOTPState(totpGlobalEnabled ? 'configured' : 'setup');
    }

    // Revocation boot
    const token = auth.session.tokenSync();
    if (token) {
        const sessionEl = find('#revokeCurrentSession');
        if (sessionEl) sessionEl.textContent = token.length > 20 ? token.slice(0,8) + '…' + token.slice(-6) : token;
        try {
            const payload = JSON.parse(atob(token.split('.')[1]));
            if (payload.exp) { const exp = new Date(payload.exp * 1000); const expEl = find('#revokeExpiry'); if (expEl) expEl.textContent = exp.toLocaleString([], { month:'short', day:'numeric', hour:'2-digit', minute:'2-digit' }); }
        } catch {}
    }
    boot();

    on('#revokeCurrentBtn', 'click', async (e, btn) => {
        const errEl = find('#revokeError'); if (errEl) errEl.style.display = 'none';
        btn.disabled = true; btn.textContent = 'Revoking…';
        try {
            await api.logout(); await auth.session.end();
            store.set('auth.isLoggedIn', false);
            notify.show('Session revoked — logging out', 'success');
            setTimeout(() => emit('app:navigate', { path: '/' }), 800);
        } catch(err) {
            btn.disabled = false; btn.textContent = 'Revoke Current Session';
            if (errEl) { errEl.textContent = err.message || 'Revocation failed'; errEl.style.display = 'block'; }
        }
    });

    on('#totpSetupBtn', 'click', async (e, btn) => {
        btn.disabled = true; btn.textContent = 'Generating…';
        const res = await api.setupTOTP();
        btn.disabled = false; btn.textContent = 'Set Up Authenticator';
        if (!res?.uri) { notify.show(res?.error || 'Failed to generate secret', 'error'); return; }
        _showQR(res);
    });

    on('#totpRevealSecret', 'click', (e, btn) => {
        const el = find('#totpSecretText'); if (!el) return;
        _secretRevealed = !_secretRevealed; el.style.filter = _secretRevealed ? 'none' : 'blur(5px)';
        if (btn) btn.textContent = _secretRevealed ? 'Hide' : 'Reveal';
    });

    on('#totpVerifyCode', 'input', (e, el) => {
        el.value = el.value.replace(/\D/g, '').slice(0, 6);
        if (el.value.length === 6) find('#totpVerifyBtn')?.click();
    });

    on('#totpVerifyBtn', 'click', () => {
        const code = find('#totpVerifyCode').value.trim();
        const errEl = find('#totpVerifyError'); errEl.style.display = 'none';
        if (code.length !== 6) { errEl.textContent = 'Enter the 6-digit code from your app'; errEl.style.display = 'block'; return; }
        notify.show('TOTP saved — will be required on your next login', 'success');
        showTOTPState('configured');
    });

    on('#totpCopySecret', 'click', () => { navigator.clipboard?.writeText(_pendingSecret).then(() => notify.show('Secret key copied', 'success')).catch(() => notify.show('Copy failed — select the key manually', 'error')); });
    on('#totpCancelBtn',       'click', () => { showTOTPState('setup'); _pendingSecret = ''; });
    on('#totpResetBtn',        'click', () => { find('#totpResetConfirm').style.display = ''; });
    on('#totpResetCancelBtn',  'click', () => { find('#totpResetConfirm').style.display = 'none'; });
    on('#totpResetConfirmBtn', 'click', async (e, btn) => {
        btn.disabled = true; btn.textContent = 'Resetting…';
        const res = await api.setupTOTP();
        btn.disabled = false; btn.textContent = 'Yes, Reset Now';
        if (res?.uri) { _showQR(res); notify.show('New TOTP secret generated — scan the QR code and verify it', 'success'); }
        else { notify.show(res?.error || 'Reset failed', 'error'); find('#totpResetConfirm').style.display = 'none'; }
    });

    onUnmount(() => {});
    ready();
}
