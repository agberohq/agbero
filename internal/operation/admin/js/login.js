/**
 * js/login.js — 2-token login with per-challenge wizard steps
 *
 * Flow:
 *   POST /login {username, password}
 *     → 200: full token, done
 *     → 202: pre-auth token + requirements[] e.g. ["keeper_unlock","totp"]
 *   Each requirement gets its own wizard step.
 *   POST /login/challenge Authorization: Bearer <pre-auth> {keeper_passphrase?, totp?}
 *     → 200: full token
 */
import { listen, on, emit, modal, query } from '../lib/oja.full.esm.js';
import { store, setCredentials, getHost, setHost } from './store.js';
import { login, loginChallenge, fetchStatus } from './api.js';

// In-memory state (never written to storage)
let _preAuthToken = null;
let _requirements = [];   // ordered list of challenges yet to solve
let _solved       = {};   // { keeper_passphrase:'...', totp:'...' }
let _stepIdx      = 0;    // current requirement index

// DOM helpers
const $  = sel => query(sel);
const show = sel => { const e=$( sel); if(e) e.style.display=''; };
const hide = sel => { const e=$(sel); if(e) e.style.display='none'; };

// Reset to step 1
export function _loginReset() {
    _preAuthToken = null;
    _requirements = [];
    _solved       = {};
    _stepIdx      = 0;
    show('#loginForm');
    hide('#loginChallengeForm');
    const e = $('#loginError'); if(e){e.style.display='none';e.textContent='';}
    const t = $('#totp'); if(t) t.value='';
    const p = $('#keeperPassphraseInput'); if(p) p.value='';
}

function _err(msg) { const e=$('#loginError'); if(e){e.textContent=msg;e.style.display='block';} }
function _clearErr() { const e=$('#loginError'); if(e){e.style.display='none';e.textContent='';} }

// Render the current challenge step
function _renderChallengeStep() {
    // Hide all challenge panels
    hide('#challengeStepKeeper');
    hide('#challengeStepTOTP');

    const current = _requirements[_stepIdx];
    const total   = _requirements.length;
    const isLast  = _stepIdx === total - 1;

    // Update progress dots when >1 challenge
    const prog = $('#challengeProgress');
    if (prog) {
        if (total > 1) {
            prog.style.display = 'flex';
            prog.innerHTML = _requirements.map((_, i) =>
                `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;
                 background:${i === _stepIdx ? 'var(--accent)' : i < _stepIdx ? 'var(--success)' : 'var(--border)'};
                 transition:background .2s;"></span>`
            ).join('');
        } else {
            prog.style.display = 'none';
        }
    }

    // Show the right panel and configure the Next button
    const nextBtn = $('#challengeNextBtn');
    if (current === 'keeper_unlock') {
        show('#challengeStepKeeper');
        if (nextBtn) nextBtn.textContent = isLast ? 'Verify' : 'Next →';
        requestAnimationFrame(() => $('#keeperPassphraseInput')?.focus());
    } else if (current === 'totp') {
        show('#challengeStepTOTP');
        if (nextBtn) nextBtn.textContent = isLast ? 'Verify' : 'Next →';
        requestAnimationFrame(() => $('#totp')?.focus());
    } else {
        // Unknown requirement — skip it
        _stepIdx++;
        if (_stepIdx < _requirements.length) { _renderChallengeStep(); return; }
        _submitChallenge();
        return;
    }

    show('#loginChallengeForm');
    hide('#loginForm');
    _clearErr();
}

// Advance wizard: collect current field, go to next or submit
async function _advanceChallenge() {
    _clearErr();
    const current = _requirements[_stepIdx];

    if (current === 'keeper_unlock') {
        const pass = ($('#keeperPassphraseInput')?.value || '').trim();
        if (!pass) { _err('Passphrase is required'); return; }
        _solved.keeper_passphrase = pass;
    } else if (current === 'totp') {
        const code = ($('#totp')?.value || '').trim();
        if (code.length !== 6) { _err('Enter the 6-digit code from your authenticator app'); return; }
        _solved.totp = code;
    }

    _stepIdx++;
    if (_stepIdx < _requirements.length) {
        _renderChallengeStep();
    } else {
        await _submitChallenge();
    }
}

async function _submitChallenge() {
    const btn = $('#challengeNextBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Verifying…'; }
    try {
        const result = await loginChallenge(_preAuthToken, _solved);
        _preAuthToken = null; // wipe immediately
        if (btn) { btn.disabled = false; }
        _onSuccess(result.token, result.expires);
    } catch (err) {
        if (btn) { btn.disabled = false; btn.textContent = 'Verify'; }
        _err(err.message || 'Verification failed');
        // On failure go back to first unsolved step
        _stepIdx = Math.max(0, _stepIdx - 1);
    }
}

export function updateNodeDisplay() {
    const h = getHost();
    $('#targetHostBtn')?.setAttribute('data-host', h || 'local');
    const nd = $('#loginNodeDisplay'); if(nd) nd.textContent = h || 'local';
    const ni = $('#loginTargetHost'); if(ni) ni.value = h || '';
}

export async function checkServerStatus() {
    const circle = $('#loginServerDotCircle');
    const label  = $('#loginServerDotLabel');
    if (!circle) return;
    try {
        const status = await fetchStatus();
        const reachable = status?.status === 'ok';
        circle.style.background = reachable ? 'var(--success)' : 'var(--danger)';
        if (label) label.textContent = reachable ? 'reachable' : 'unreachable';
    } catch {
        circle.style.background = 'var(--danger)';
        if (label) label.textContent = 'unreachable';
    }
}

export function initLogin() {
    // Node edit
    on('#loginEditNodeBtn', 'click', () => {
        const el = $('#loginNodeEdit');
        if (el) el.style.display = el.style.display === 'flex' ? 'none' : 'flex';
        checkServerStatus();
    });
    on('#loginResetHostBtn', 'click', () => {
        setHost(''); updateNodeDisplay();
        const e = $('#loginNodeEdit'); if(e) e.style.display = 'none';
        checkServerStatus();
    });
    on('#loginSaveHostBtn', 'click', () => {
        const val = ($('#loginTargetHost')?.value || '').trim();
        setHost(val); updateNodeDisplay();
        const e = $('#loginNodeEdit'); if(e) e.style.display = 'none';
        checkServerStatus();
    });

    // TOTP auto-submit at 6 digits
    on('#totp', 'input', (e, el) => {
        el.value = el.value.replace(/\D/g, '').slice(0, 6);
        if (el.value.length === 6 && _preAuthToken) _advanceChallenge();
    });

    // Step 1: credentials
    on('#loginForm', 'submit', async (e) => {
        e.preventDefault();
        _clearErr();
        const username = ($('#username')?.value || '').trim();
        const password = $('#password')?.value || '';
        if (!username || !password) { _err('Username and password are required'); return; }
        const btn = $('#loginForm [type="submit"]');
        if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }
        try {
            const result = await login(username, password);
            if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
            if (result.challenge) {
                _preAuthToken = result.token;
                _requirements = result.requirements || [];
                _solved       = {};
                _stepIdx      = 0;
                if (_requirements.length === 0) {
                    // No challenges but got 202 — shouldn't happen, treat as error
                    _err('Unexpected server response'); return;
                }
                _renderChallengeStep();
            } else {
                _onSuccess(result.token, result.expires);
            }
        } catch (err) {
            if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
            _err(err.message || 'Login failed');
        }
    });

    // Step 2: challenge wizard Next/Verify
    on('#loginChallengeForm', 'submit', async (e) => {
        e.preventDefault();
        await _advanceChallenge();
    });

    // Back — go to previous step or back to creds
    on('#loginChallengeBack', 'click', () => {
        if (_stepIdx > 0) {
            _stepIdx--;
            _renderChallengeStep();
        } else {
            _preAuthToken = null;
            _loginReset();
            requestAnimationFrame(() => $('#username')?.focus());
        }
    });

    listen('modal:close', ({ id }) => { if (id === 'loginModal') _loginReset(); });
}

function _onSuccess(token) {
    setCredentials('jwt', token);
    store.set('auth.isLoggedIn', true);
    emit('auth:login:success', { token });
    modal.closeAll();
    _loginReset();
}
