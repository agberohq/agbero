/**
 * pages/add-host/step-review.js — Review & submit step.
 *
 * Flow:
 *  1. Build JSON config from wizard draft (hostBuilder.buildHostConfig)
 *  2. POST to /api/v1/discovery/preview → server returns server-rendered HCL
 *     (applies woos.DefaultHost defaults + full validation)
 *  3. If preview fails (network / server not updated), fall back to
 *     client-side buildHostHCL so the step always shows something useful.
 *  4. User sees HCL, can edit freely. Toggle to JSON for debugging.
 *  5. Submit sends HCL via addHostHCL (text/plain POST).
 *     If user is in JSON mode, sends JSON via addHost instead.
 *
 * Validation errors from preview are shown inline — they surface problems
 * before the user hits Create, not after.
 */
import { emit, notify } from '../../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, props, inject }) {
    const { api, hostBuilder } = inject('app');
    const { wizard } = props;

    const hintEl     = find('#wzReviewHint');
    const modeEl     = find('#wzReviewMode');
    const toggleEl   = find('#wzReviewToggle');
    const ta         = find('#wzReviewEditor');
    const errBox     = find('#submitErrorBox');
    const submitBtn  = find('#wzSubmitBtn');
    const formatBtn  = find('#wzFormatBtn');

    let _config      = null;   // JSON config object
    let _hcl         = '';     // current HCL string (server-rendered or JS fallback)
    let _json        = '';     // JSON string
    let _mode        = 'hcl';  // 'hcl' | 'json'
    let _fromServer  = false;  // true when _hcl came from the preview endpoint

    // Helpers

    function _setLoading(msg) {
        if (ta)        { ta.value = ''; ta.placeholder = msg || 'Loading…'; ta.disabled = true; }
        if (submitBtn)   submitBtn.disabled = true;
        if (formatBtn)   formatBtn.disabled = true;
    }

    function _setReady() {
        if (ta)        { ta.placeholder = ''; ta.disabled = false; }
        if (submitBtn)   submitBtn.disabled = false;
        if (formatBtn)   formatBtn.disabled = false;
    }

    function _showError(msg) {
        if (errBox) { errBox.textContent = msg; errBox.classList.add('visible'); }
    }

    function _clearError() {
        if (errBox) { errBox.textContent = ''; errBox.classList.remove('visible'); }
    }

    function _showMode(mode) {
        _mode = mode;
        if (ta)       ta.value = mode === 'hcl' ? _hcl : _json;
        if (modeEl)   modeEl.textContent = mode === 'hcl' ? 'HCL' : 'JSON';
        if (toggleEl) toggleEl.textContent = mode === 'hcl' ? 'Switch to JSON' : 'Switch to HCL';
    }

    function _buildDraftData() {
        const draft  = wizard.draftGet();
        const isTcp  = draft.host_type === 'tcp';
        const routes = isTcp ? [] : wizard.getRoutes();
        const tcp    = isTcp ? wizard.getTcp() : undefined;
        return { draft, isTcp, routes, tcp };
    }

    // Initial load

    if (hintEl) hintEl.textContent = 'Reviewing your config — the server is rendering the exact HCL that will be written to disk.';
    _setLoading('Generating preview…');

    try {
        const { draft, isTcp, routes, tcp } = _buildDraftData();

        _config = hostBuilder.buildHostConfig({ ...draft, routes, _tcp: tcp });
        _json   = JSON.stringify(_config, null, 2);

        const domain = (draft.domain || '').trim().toLowerCase();

        // Try server-side preview first
        const preview = await api.previewHost(domain, _config);

        if (preview?.hcl) {
            _hcl        = preview.hcl;
            _fromServer = true;
            if (hintEl) hintEl.textContent = 'Server-rendered HCL — exactly what will be written to disk. You can edit it before creating.';
        } else if (preview?.status === 'invalid') {
            // Validation error — show it but still let user see/edit the config
            _hcl = hostBuilder.buildHostHCL({ ...draft, routes, _tcp: tcp });
            _showError('⚠ Validation: ' + preview.error);
            if (hintEl) hintEl.textContent = 'Fix the validation error above before creating.';
        } else {
            // Network error / server not updated — fall back to JS-built HCL
            _hcl = hostBuilder.buildHostHCL({ ...draft, routes, _tcp: tcp });
            if (hintEl) hintEl.textContent = 'Preview unavailable — showing client-rendered HCL. You can edit before creating.';
        }
    } catch (err) {
        // buildHostConfig threw (e.g. PHP enabled without address)
        _hcl  = `# Error: ${err.message}`;
        _json = JSON.stringify({ error: err.message }, null, 2);
        _showError(err.message);
        if (hintEl) hintEl.textContent = 'Fix the error above before creating.';
    }

    _setReady();
    _showMode('hcl');

    // Toggle HCL ↔ JSON

    toggleEl?.addEventListener('click', () => {
        // Snapshot edits before switching
        if (_mode === 'hcl') _hcl  = ta?.value ?? _hcl;
        else                 _json = ta?.value ?? _json;
        _showMode(_mode === 'hcl' ? 'json' : 'hcl');
    });

    // Format button
    // In HCL mode: re-call preview (or JS fallback) to get a clean version.
    // In JSON mode: pretty-print.

    on('#wzFormatBtn', 'click', async (_, btn) => {
        if (_mode === 'json') {
            try { if (ta) ta.value = JSON.stringify(JSON.parse(ta?.value || '{}'), null, 2); }
            catch (e) { notify.show('Invalid JSON: ' + e.message, 'error'); }
            return;
        }

        // HCL mode — re-call preview with current JSON
        btn.disabled = true; btn.textContent = '…';
        _clearError();
        try {
            const { draft, isTcp, routes, tcp } = _buildDraftData();
            const domain  = (draft.domain || '').trim().toLowerCase();
            // Use edited JSON if user has switched there, otherwise rebuild from draft
            let   config  = _config;
            try   { config = JSON.parse(_json); } catch {}
            const preview = await api.previewHost(domain, config);
            if (preview?.hcl) {
                _hcl = preview.hcl;
                if (ta) ta.value = _hcl;
            } else if (preview?.status === 'invalid') {
                _showError('⚠ Validation: ' + preview.error);
            } else {
                // Fallback
                if (ta) ta.value = hostBuilder.buildHostHCL({ ...draft, routes, _tcp: tcp });
            }
        } catch (e) { notify.show('Format error: ' + e.message, 'error'); }
        btn.disabled = false; btn.textContent = '✨ Format';
    });

    // Submit

    on('#wzSubmitBtn', 'click', async (_, btn) => {
        _clearError();
        btn.disabled = true; btn.textContent = 'Creating…';

        try {
            const domain = (wizard.draftGet('domain') || '').trim().toLowerCase();
            if (!domain) throw new Error('Domain is required');

            const raw = (ta?.value || '').trim();
            if (!raw) throw new Error('Configuration is empty');

            let result;
            if (_mode === 'hcl') {
                result = await api.addHostHCL(raw, domain);
            } else {
                const config = JSON.parse(raw);
                result = await api.addHost(domain, config);
            }

            if (result?.error) throw new Error(result.error);
            notify.show(domain + ' created successfully', 'success');
            emit('wizard:submit-success', { domain });
        } catch (err) {
            btn.disabled = false; btn.textContent = 'Create Host';
            emit('wizard:submit-error', {});
            _showError(err.message || 'Failed to create host — check your configuration');
        }
    });

    onUnmount(() => {});
    ready();
}
