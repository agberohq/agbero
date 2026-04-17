/**
 * pages/add-host/panels/value-input.js
 *
 * wz-value-input — reusable component for expect.Value fields.
 * Every field typed expect.Value in the Go structs accepts:
 *   literal    → plain string
 *   env        → env.VAR_NAME
 *   keeper     → ss://namespace/path  (namespace always required)
 *
 * Usage:
 *   import { renderValueInput, wireValueInput } from './panels/value-input.js';
 *
 *   // In HTML template string:
 *   el.innerHTML = renderValueInput('jwt_auth.secret', saved, { label: 'JWT Secret', required: true });
 *
 *   // After inserting into DOM:
 *   wireValueInput(el, 'jwt_auth.secret', (finalValue) => { route.authData.jwt_secret = finalValue; });
 */

import { validateKeeperKey, composeKeeperRef, splitKeeperKey } from '../../../js/utils.js';
import { keeperList } from '../../../js/api.js';

let _keeperCache = null;  // lazy-loaded once per session

async function _getKeeperKeys() {
    if (_keeperCache) return _keeperCache;
    try {
        const data = await keeperList();
        _keeperCache = data?.keys || [];
    } catch { _keeperCache = []; }
    return _keeperCache;
}

function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/"/g,'&quot;')
                           .replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// Detect the source type from a stored value string
function _detectSource(val) {
    if (!val) return 'literal';
    if (val.startsWith('ss://') || val.startsWith('keeper://')) return 'keeper';
    if (val.startsWith('env.')) return 'env';
    return 'literal';
}

/**
 * Render the HTML for a value input.
 * @param {string} fieldId  - unique DOM id prefix
 * @param {string} saved    - current stored value (e.g. "ss://prod/secret")
 * @param {object} opts     - { label, hint, required, password }
 */
export function renderValueInput(fieldId, saved = '', opts = {}) {
    const { label = '', hint = '', required = false, password = false } = opts;
    const src = _detectSource(saved);

    // Parse keeper ref if present
    let nsVal = '', pathVal = '';
    if (src === 'keeper') {
        const ref = saved.replace(/^keeper:\/\//, 'ss://');
        const { namespace, path } = splitKeeperKey(ref);
        nsVal = namespace; pathVal = path;
    }

    const envVal     = src === 'env'     ? saved.replace(/^env\./, '') : '';
    const literalVal = src === 'literal' ? saved : '';

    return `<div class="wz-value-input" data-vi-field="${_esc(fieldId)}">
        ${label ? `<label class="wz-label">${label}${required ? ' <span style="color:var(--danger)">*</span>' : ''}</label>` : ''}
        <div class="wz-vi-row">
            <select class="wz-vi-source" data-vi-source>
                <option value="literal"${src==='literal'?' selected':''}>Literal</option>
                <option value="env"${src==='env'?' selected':''}>env.</option>
                <option value="keeper"${src==='keeper'?' selected':''}>Keeper</option>
            </select>

            <!-- Literal input -->
            <input type="${password?'password':'text'}" class="wz-vi-value wz-vi-literal"
                   data-vi-literal placeholder="value"
                   value="${_esc(literalVal)}"
                   style="${src!=='literal'?'display:none':''}">

            <!-- env. input -->
            <span class="wz-vi-sep" style="${src!=='env'?'display:none':''}">env.</span>
            <input type="text" class="wz-vi-value wz-vi-env"
                   data-vi-env placeholder="VAR_NAME"
                   value="${_esc(envVal)}"
                   style="${src!=='env'?'display:none':''}">

            <!-- Keeper: namespace / path -->
            <input type="text" class="wz-vi-value wz-vi-ns"
                   data-vi-ns placeholder="namespace"
                   value="${_esc(nsVal)}"
                   style="${src!=='keeper'?'display:none':''}">
            <span class="wz-vi-sep" style="${src!=='keeper'?'display:none':''}">/</span>
            <input type="text" class="wz-vi-value wz-vi-path"
                   data-vi-path placeholder="key/path"
                   value="${_esc(pathVal)}"
                   style="${src!=='keeper'?'display:none':''}">
            <button type="button" class="wz-vi-pick btn small"
                    data-vi-pick title="Browse Keeper secrets"
                    style="${src!=='keeper'?'display:none':''}">⊞</button>
        </div>
        <!-- Live preview of generated reference -->
        <div class="wz-vi-preview" data-vi-preview style="${src==='keeper'?'':'display:none'}"></div>
        ${hint ? `<div class="wz-hint">${hint}</div>` : ''}
    </div>`;
}

/**
 * Wire interactivity for a rendered value input inside a container element.
 * @param {Element} container - element containing the value input
 * @param {string}  fieldId   - must match the data-vi-field used in renderValueInput
 * @param {Function} onChange - called with the final ss:// / env.VAR / literal string
 */
export function wireValueInput(container, fieldId, onChange) {
    const root    = container.querySelector(`[data-vi-field="${CSS.escape(fieldId)}"]`);
    if (!root) return;

    const sourceEl  = root.querySelector('[data-vi-source]');
    const literalEl = root.querySelector('[data-vi-literal]');
    const envEl     = root.querySelector('[data-vi-env]');
    const nsEl      = root.querySelector('[data-vi-ns]');
    const pathEl    = root.querySelector('[data-vi-path]');
    const pickBtn   = root.querySelector('[data-vi-pick]');
    const previewEl = root.querySelector('[data-vi-preview]');
    const sepEls    = root.querySelectorAll('.wz-vi-sep');

    function _currentValue() {
        const src = sourceEl?.value;
        if (src === 'env') {
            const v = (envEl?.value || '').trim();
            return v ? `env.${v}` : '';
        }
        if (src === 'keeper') {
            const ns   = (nsEl?.value   || '').trim();
            const path = (pathEl?.value || '').trim();
            const err  = validateKeeperKey(ns, path);
            return err ? '' : composeKeeperRef(ns, path);
        }
        return (literalEl?.value || '');
    }

    function _updateVisibility() {
        const src = sourceEl?.value;
        if (literalEl) literalEl.style.display = src === 'literal' ? '' : 'none';
        if (envEl)     envEl.style.display     = src === 'env'     ? '' : 'none';
        if (nsEl)      nsEl.style.display      = src === 'keeper'  ? '' : 'none';
        if (pathEl)    pathEl.style.display     = src === 'keeper'  ? '' : 'none';
        if (pickBtn)   pickBtn.style.display    = src === 'keeper'  ? '' : 'none';
        if (previewEl) previewEl.style.display  = src === 'keeper'  ? '' : 'none';
        sepEls.forEach(s => {
            // env sep shows with env, keeper sep shows with keeper
            const isEnvSep    = s.textContent.trim() === 'env.';
            const isKeeperSep = s.textContent.trim() === '/';
            s.style.display = (isEnvSep && src === 'env') || (isKeeperSep && src === 'keeper') ? '' : 'none';
        });
    }

    function _updatePreview() {
        if (!previewEl) return;
        const ns   = (nsEl?.value   || '').trim();
        const path = (pathEl?.value || '').trim();
        if (ns && path) {
            previewEl.textContent = `→ ${composeKeeperRef(ns, path)}`;
            previewEl.style.color = 'var(--accent)';
        } else {
            previewEl.textContent = ns ? `→ ss://${ns}/…` : '';
            previewEl.style.color = 'var(--text-mute)';
        }
    }

    function _emit() {
        _updatePreview();
        onChange?.(_currentValue());
    }

    sourceEl?.addEventListener('change', () => { _updateVisibility(); _emit(); });
    literalEl?.addEventListener('input', _emit);
    envEl?.addEventListener('input', _emit);
    nsEl?.addEventListener('input', () => { _updatePreview(); _emit(); });
    pathEl?.addEventListener('input', () => { _updatePreview(); _emit(); });

    // Keeper browser — lazy loads keys, shows inline select
    pickBtn?.addEventListener('click', async () => {
        pickBtn.textContent = '…';
        pickBtn.disabled    = true;
        const keys = await _getKeeperKeys();
        pickBtn.textContent = '⊞';
        pickBtn.disabled    = false;

        if (!keys.length) {
            // No secrets yet — show hint
            if (previewEl) { previewEl.textContent = 'No secrets in Keeper yet'; previewEl.style.color = 'var(--text-mute)'; previewEl.style.display = ''; }
            return;
        }

        // Replace pick button with a select, then restore on blur
        const sel = document.createElement('select');
        sel.className = 'wz-vi-source';
        sel.style.flex = '1';
        sel.innerHTML = `<option value="">— choose secret —</option>` +
            keys.map(k => {
                const { namespace, path } = splitKeeperKey(k);
                const ref = composeKeeperRef(namespace, path);
                return `<option value="${_esc(ref)}">${_esc(k)}</option>`;
            }).join('');

        sel.addEventListener('change', () => {
            if (!sel.value) return;
            const { namespace, path } = splitKeeperKey(sel.value);
            if (nsEl)   nsEl.value   = namespace;
            if (pathEl) pathEl.value = path;
            _updatePreview();
            _emit();
            sel.replaceWith(pickBtn);
        });
        sel.addEventListener('blur', () => { setTimeout(() => sel.replaceWith(pickBtn), 200); });
        pickBtn.replaceWith(sel);
        sel.focus();
    });

    _updateVisibility();
    _updatePreview();
}
