/**
 * js/login.js — Login modal state machine.
 *
 * Flow:
 *   open modal
 *     → probe GET /status
 *       → locked:true  → view:locked  (auto-retry every 15s, manual retry btn)
 *       → locked:false → view:creds
 *
 *   view:creds → POST /login {username, password}
 *     → 200 {token}              → session start → done
 *     → 202 {token, requirements}→ view:challenge
 *     → 401                      → error on creds view
 *     → 503                      → race: keeper just locked → view:locked
 *
 *   view:challenge → POST /login/challenge Bearer:<token> {key:value,...}
 *     → 200 {token}              → session start → done
 *     → 401                      → token consumed, back to view:creds
 *
 * Challenge segments:
 *   requirements[] drives what fields are rendered — no hardcoding.
 *   CHALLENGE_SEGMENTS maps requirement key → { render(), collect() }.
 *   Adding a new challenge type is adding one entry to that map.
 */
import { listen, auth } from '../lib/oja.full.esm.js';
import { storeLocal, getHost, setHost } from './store.js';
import { login, loginChallenge, fetchStatus } from './api.js';

const $ = id => document.getElementById(id);

// Challenge segment registry
// Each entry: { label, render(container), collect(container) → value|null, autoSubmit? }
// render()   — builds the field HTML inside container
// collect()  — returns the value to send, or null if invalid (shows own error)
// autoSubmit — if true, submitting verify is triggered automatically when complete

const CHALLENGE_SEGMENTS = {
    totp: {
        label: 'Authenticator Code',
        render(el) {
            el.innerHTML = `
                <p style="font-size:11px;color:var(--text-mute);text-align:center;margin:0 0 10px;">
                    Enter the 6-digit code from your authenticator app
                </p>
                <input type="text" id="cseg_totp"
                       inputmode="numeric" autocomplete="one-time-code"
                       maxlength="6" placeholder="000000"
                       style="text-align:center;letter-spacing:.35em;font-size:28px;
                              font-family:var(--font-mono);width:100%;padding:12px 0;
                              box-sizing:border-box;border-radius:8px;">`;
            const inp = el.querySelector('#cseg_totp');
            inp?.addEventListener('input', e => {
                e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
                if (e.target.value.length === 6) _submitChallenge();
            });
            setTimeout(() => inp?.focus(), 60);
        },
        collect(el) {
            const val = el.querySelector('#cseg_totp')?.value || '';
            return val.length === 6 ? val : null;
        },
        autoSubmit: true,
    },

    // Future segments added here — email, dob, security_question, etc.
    // Each is self-contained: render its own field, collect its own value.
};

// Node storage

const NODES_KEY = 'ag_nodes';
const _getNodes  = ()      => storeLocal.get(NODES_KEY) || [];
const _saveNodes = nodes   => storeLocal.set(NODES_KEY, nodes);

function _addNode(url, label) {
    const clean = (url || '').replace(/\/+$/, '');
    if (!clean) return;
    const nodes = _getNodes();
    const name  = (label || '').trim() || clean;
    const idx   = nodes.findIndex(n => n.url === clean);
    if (idx >= 0) { nodes[idx].label = name; }
    else           { nodes.push({ url: clean, label: name }); }
    _saveNodes(nodes);
}

function _removeNode(url) {
    _saveNodes(_getNodes().filter(n => n.url !== url));
}

// Per-node connectivity probe

const _probeCache = new Map();

async function _probe(url) {
    const hit = _probeCache.get(url);
    if (hit && Date.now() - hit.ts < 8000) return hit.ok;
    try {
        const res = await fetch((url || window.location.origin) + '/healthz', {
            method: 'GET', cache: 'no-store', signal: AbortSignal.timeout(4000),
        });
        _probeCache.set(url, { ok: res.ok, ts: Date.now() });
        return res.ok;
    } catch {
        _probeCache.set(url, { ok: false, ts: Date.now() });
        return false;
    }
}

// Node display

export function _syncNodeDisplay() {
    const h     = getHost();
    const match = _getNodes().find(n => n.url === h);
    const nd    = $('loginNodeDisplay');
    if (nd) nd.textContent = match?.label || h || 'local';
}

export const updateNodeDisplay = _syncNodeDisplay;

// Node list

function _renderNodeList() {
    const listEl  = $('loginNodeList');
    if (!listEl) return;
    const nodes   = _getNodes();
    const current = getHost();

    if (!nodes.length) {
        listEl.innerHTML = `<div style="font-size:11px;color:var(--text-mute);padding:2px 0 4px;">
            No saved nodes — add one below.</div>`;
        return;
    }

    listEl.innerHTML = nodes.map(n => {
        const active = n.url === current;
        const label  = n.label && n.label !== n.url ? n.label : null;
        return `<div class="login-node-row${active ? ' active' : ''}" data-node="${n.url}">
            <span class="ndot" data-url="${n.url}"
                  style="width:7px;height:7px;border-radius:50%;flex-shrink:0;
                         background:var(--text-mute);transition:background .25s;"></span>
            <div class="login-node-row-info">
                <span class="login-node-row-label">${label || n.url}</span>
                ${label ? `<span class="login-node-row-url">${n.url}</span>` : ''}
            </div>
            ${active
                ? `<span style="font-size:10px;color:var(--accent);font-weight:600;flex-shrink:0;">active</span>`
                : `<button type="button" data-connect="${n.url}" class="btn small"
                           style="font-size:11px;padding:2px 8px;">use</button>`}
            <button type="button" data-remove="${n.url}" class="btn small"
                    style="color:var(--danger);border-color:rgba(255,59,48,.3);padding:2px 7px;">✕</button>
        </div>`;
    }).join('');

    listEl.querySelectorAll('[data-connect]').forEach(btn =>
        btn.addEventListener('click', () => {
            setHost(btn.dataset.connect);
            _syncNodeDisplay();
            _probeCache.clear();
            _probeStatus();       // immediately re-probe on node switch
            _renderNodeList();
        })
    );

    listEl.querySelectorAll('[data-remove]').forEach(btn =>
        btn.addEventListener('click', () => {
            const url = btn.dataset.remove;
            if (getHost() === url) { setHost(''); _syncNodeDisplay(); }
            _removeNode(url);
            _probeCache.delete(url);
            _renderNodeList();
        })
    );

    // Probe all nodes in parallel, update dots
    nodes.forEach(n =>
        _probe(n.url).then(ok =>
            listEl.querySelectorAll(`[data-url="${CSS.escape(n.url)}"]`).forEach(dot => {
                dot.style.background = ok ? 'var(--success)' : 'var(--danger)';
            })
        )
    );
}

// Views

const VIEWS = ['loginViewProbing', 'loginViewLocked', 'loginViewCreds', 'loginViewChallenge'];

function _showView(id) {
    VIEWS.forEach(v => { const e = $(v); if (e) e.style.display = v === id ? '' : 'none'; });
    const panel   = $('loginNodeEdit');   if (panel)   panel.style.display = 'none';
    const editBtn = $('loginEditNodeBtn'); if (editBtn) editBtn.textContent  = 'change';
    _clearErr();
}

function _err(msg) {
    const e = $('loginError');
    if (e) { e.textContent = msg; e.style.display = 'block'; }
}

function _clearErr() {
    const e = $('loginError');
    if (e) { e.style.display = 'none'; e.textContent = ''; }
}

// Auto-retry timer (locked state)

let _retryTimer    = null;
let _retryCountdown = 0;
const RETRY_INTERVAL = 15;

function _startRetryTimer() {
    _stopRetryTimer();
    _retryCountdown = RETRY_INTERVAL;
    _updateRetryLabel();
    _retryTimer = setInterval(() => {
        _retryCountdown--;
        _updateRetryLabel();
        if (_retryCountdown <= 0) _probeStatus();
    }, 1000);
}

function _stopRetryTimer() {
    if (_retryTimer) { clearInterval(_retryTimer); _retryTimer = null; }
}

function _updateRetryLabel() {
    const el = $('loginRetryLabel');
    if (el) el.textContent = `Retrying in ${_retryCountdown}s…`;
}

// Status probe

export async function checkServerStatus() {
    const circle = $('loginServerDotCircle');
    const label  = $('loginServerDotLabel');
    if (circle) circle.style.background = 'var(--text-mute)';
    if (label)  label.textContent = '';
    const ok = await _probe(getHost());
    if (circle) circle.style.background = ok ? 'var(--success)' : 'var(--danger)';
}

async function _probeStatus() {
    _stopRetryTimer();
    _showView('loginViewProbing');

    const probingLabel = $('loginProbingLabel');
    if (probingLabel) probingLabel.textContent = 'Checking node…';

    // Update top-row dot
    const circle = $('loginServerDotCircle');
    const dotLabel = $('loginServerDotLabel');
    if (circle) circle.style.background = 'var(--text-mute)';
    if (dotLabel) dotLabel.textContent = '';

    let status;
    try {
        status = await fetchStatus();
    } catch {
        status = null;
    }

    const reachable = status?.status === 'ok';
    if (circle) circle.style.background = reachable ? 'var(--success)' : 'var(--danger)';
    if (dotLabel) dotLabel.textContent = reachable ? 'reachable' : 'unreachable';

    if (!reachable) {
        _showView('loginViewLocked');
        const msgEl = $('loginViewLocked')?.querySelector('div:nth-child(3)');
        if (msgEl) msgEl.textContent = 'Node is unreachable. Check the address and try again.';
        _startRetryTimer();
        return;
    }

    if (status.locked) {
        _showView('loginViewLocked');
        _startRetryTimer();
        return;
    }

    _showView('loginViewCreds');
    setTimeout(() => $('username')?.focus(), 60);
}

// Login state

let _chalToken    = null;
let _requirements = [];

export function _loginReset() {
    _chalToken    = null;
    _requirements = [];
    _stopRetryTimer();
    const u = $('username'); if (u) u.value = '';
    const p = $('password'); if (p) p.value = '';
    const s = $('challengeSegments'); if (s) s.innerHTML = '';
    const panel = $('loginNodeEdit'); if (panel) panel.style.display = 'none';
    _probeStatus();
}

// Challenge rendering

function _buildChallengeView(requirements) {
    const container = $('challengeSegments');
    if (!container) return;
    container.innerHTML = '';

    requirements.forEach(key => {
        const seg = CHALLENGE_SEGMENTS[key];
        const wrap = document.createElement('div');
        wrap.dataset.segment = key;
        wrap.style.cssText = 'margin-bottom:14px;';

        if (seg) {
            // Known segment — render its field
            seg.render(wrap);
        } else {
            // Unknown segment — render a generic text input so the UI never breaks
            wrap.innerHTML = `
                <label style="font-size:11px;color:var(--text-mute);display:block;margin-bottom:6px;">
                    ${key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
                </label>
                <input type="text" id="cseg_${key}" autocomplete="off"
                       style="width:100%;box-sizing:border-box;">`;
            setTimeout(() => wrap.querySelector('input')?.focus(), 60);
        }
        container.appendChild(wrap);
    });

    _showView('loginViewChallenge');
}

async function _submitChallenge() {
    const container = $('challengeSegments');
    if (!container) return;

    const payload = {};
    for (const key of _requirements) {
        const wrap = container.querySelector(`[data-segment="${key}"]`);
        const seg  = CHALLENGE_SEGMENTS[key];
        if (seg) {
            const val = seg.collect(wrap);
            if (val === null) return; // segment shows its own error
            payload[key] = val;
        } else {
            // Generic fallback
            const val = (wrap?.querySelector('input')?.value || '').trim();
            if (!val) { _err(`${key} is required`); return; }
            payload[key] = val;
        }
    }

    const btn = $('challengeVerifyBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Verifying…'; }
    _clearErr();

    try {
        const result = await loginChallenge(_chalToken, payload);
        if (btn) { btn.disabled = false; btn.textContent = 'Verify'; }
        await auth.session.start(result.token, null,
            result.token?.split('.').length === 3 ? {} : { expires: null });
        _loginReset();
    } catch (err) {
        if (btn) { btn.disabled = false; btn.textContent = 'Verify'; }
        _err(err.message || 'Verification failed — please sign in again');
        // Token is consumed on 401 — must restart from credentials
        setTimeout(_loginReset, 1800);
    }
}

// initLogin

export function initLogin() {

    // Node panel toggle
    const _editBtn = $('loginEditNodeBtn');
    function _toggleNodePanel() {
        const panel = $('loginNodeEdit');
        if (!panel) return;
        const open = panel.style.display === 'flex';
        if (open) {
            panel.style.display = 'none';
            if (_editBtn) _editBtn.textContent = 'change';
            _probeStatus();
        } else {
            VIEWS.forEach(v => { const e = $(v); if (e) e.style.display = 'none'; });
            const err = $('loginError'); if (err) err.style.display = 'none';
            panel.style.display = 'flex';
            if (_editBtn) _editBtn.textContent = 'cancel';
            _renderNodeList();
        }
    }
    _editBtn?.addEventListener('click', _toggleNodePanel);

    // Add node — reads label + url
    function _addAndRefresh() {
        const urlInp   = $('loginTargetHost');
        const labelInp = $('loginNodeLabel');
        const url      = (urlInp?.value   || '').trim();
        const label    = (labelInp?.value || '').trim();
        if (!url) return;
        _addNode(url, label);
        if (urlInp)   urlInp.value   = '';
        if (labelInp) labelInp.value = '';
        _syncNodeDisplay();
        _renderNodeList();
    }

    $('loginSaveHostBtn')?.addEventListener('click', _addAndRefresh);
    $('loginTargetHost')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); _addAndRefresh(); }
    });
    $('loginNodeLabel')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); $('loginTargetHost')?.focus(); }
    });

    $('loginResetHostBtn')?.addEventListener('click', () => {
        setHost(''); _syncNodeDisplay();
        _probeCache.clear(); _renderNodeList();
    });

    // Retry button (locked view)
    $('loginRetryBtn')?.addEventListener('click', () => {
        _probeCache.clear(); _probeStatus();
    });

    // Credentials submit
    $('loginViewCreds')?.addEventListener('submit', async e => {
        e.preventDefault();
        const username = ($('username')?.value  || '').trim();
        const password =  $('password')?.value  || '';
        if (!username || !password) { _err('Username and password are required'); return; }

        const btn = $('loginSubmitBtn');
        if (btn) { btn.disabled = true; btn.textContent = 'Signing in…'; }
        _clearErr();

        try {
            const result = await login(username, password);
            if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }

            if (!result.challenge) {
                await auth.session.start(result.token, null,
                    result.token?.split('.').length === 3 ? {} : { expires: null });
                _loginReset();
                return;
            }

            _chalToken    = result.token;
            _requirements = result.requirements || [];
            _buildChallengeView(_requirements);

        } catch (err) {
            if (btn) { btn.disabled = false; btn.textContent = 'Sign In'; }
            if (err.status === 503) {
                // Keeper just locked — race condition
                _probeCache.clear(); _probeStatus();
            } else {
                _err(err.message || 'Login failed');
            }
        }
    });

    // Challenge verify
    $('challengeVerifyBtn')?.addEventListener('click', _submitChallenge);

    // Back to login — re-probe so we start fresh
    $('challengeBackBtn')?.addEventListener('click', _loginReset);

    // Start probing when modal opens
    listen('modal:open', ({ id }) => {
        if (id !== 'loginModal') return;
        // Explicitly reset panel state before probing — inline styles from
        // previous sessions persist across modal open/close cycles
        const panel = $('loginNodeEdit');
        if (panel) panel.style.display = 'none';
        _syncNodeDisplay();
        _probeStatus();
    });

    listen('modal:close', ({ id }) => {
        if (id === 'loginModal') _stopRetryTimer();
    });
}
