/**
 * pages/keeper.js — Keeper secrets page.
 */
export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, utils, oja } = inject('app');
    const { validateKeeperKey, composeKeeperRef, splitKeeperKey, decodeKeeperValue } = utils;
    const { notify, ui, countdown, modal } = oja;

    const _revealed = new Map();
    let _autoLockCd = null;

    // Icons
    const _svgCopy   = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>`;
    const _eyeOpen   = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
    const _eyeClosed = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

    // Auto-lock countdown
    function _parseDuration(s) {
        if (!s) return 0;
        let ms = 0;
        for (const m of (s.match(/(\d+(?:\.\d+)?)([hms])/g) || [])) {
            const num = parseFloat(m), unit = m.slice(-1);
            ms += unit === 'h' ? num*3_600_000 : unit === 'm' ? num*60_000 : num*1_000;
        }
        return ms || 1_800_000;
    }

    function _startAutoLockTimer() {
        if (_autoLockCd) { _autoLockCd.stop(); _autoLockCd = null; }
        const cfg    = store.get('lastConfig')?.global?.security?.keep?.auto_lock || '30m0s';
        const totalMs = _parseDuration(cfg);
        const bar    = find('#keeperTimerBar');
        if (bar) bar.style.display = '';
        _autoLockCd = countdown.start(Date.now() + totalMs, {
            onTick(msLeft) {
                const textEl = find('#keeperTimerText');
                if (!textEl) return;
                const m = Math.floor(msLeft / 60_000), s = Math.floor((msLeft % 60_000) / 1_000);
                textEl.textContent = `Auto-locks in ${m}m ${s}s`;
            },
            async onExpire() { showLocked(); },
        });
    }

    // State transitions
    function showNotConfigured() {
        find('#keeperNotConfiguredPanel').style.display = '';
        find('#keeperLockedPanel').style.display        = 'none';
        find('#keeperUnlockedPanel').style.display      = 'none';
        find('#keeperAddBtn').style.display             = 'none';
    }

    function showLocked() {
        _revealed.forEach(({ timerId }) => clearTimeout(timerId));
        _revealed.clear();
        if (_autoLockCd) { _autoLockCd.stop(); _autoLockCd = null; }
        find('#keeperNotConfiguredPanel').style.display = 'none';
        find('#keeperLockedPanel').style.display        = '';
        find('#keeperUnlockedPanel').style.display      = 'none';
        find('#keeperAddBtn').style.display             = 'none';
    }

    function showUnlocked() {
        find('#keeperNotConfiguredPanel').style.display = 'none';
        find('#keeperLockedPanel').style.display        = 'none';
        find('#keeperUnlockedPanel').style.display      = '';
        find('#keeperAddBtn').style.display             = '';
        _startAutoLockTimer();
        loadKeys();
    }

    // Keys list
    function renderKeys(keys) {
        const el = find('#keeperList');
        if (!el) return;
        if (!keys?.length) {
            el.innerHTML = `<div class="empty-state"><span>🗝️ No secrets yet</span><span>Click <strong>+ Secret</strong> to add your first entry.</span></div>`;
            return;
        }

        const byNs = new Map();
        for (const k of keys) {
            const { namespace, path } = splitKeeperKey(k);
            if (!byNs.has(namespace)) byNs.set(namespace, []);
            byNs.get(namespace).push({ k, path });
        }

        el.innerHTML = [...byNs.keys()].sort().map(ns => {
            const entries = byNs.get(ns);
            const rows = entries.map(({ k, path }) => {
                const ref = composeKeeperRef(ns, path);
                return `<tr data-key="${k}">
                    <td class="mono" style="font-size:12px;padding:10px 14px;word-break:break-all;">${path}</td>
                    <td style="padding:10px 14px;">
                        <div style="display:flex;align-items:center;gap:5px;">
                            <code style="font-size:11px;background:var(--hover-bg);padding:3px 7px;border-radius:3px;border:1px solid var(--border);color:var(--accent);white-space:nowrap;">${ref}</code>
                            <button class="keeper-icon-btn" data-action="copy-ref" data-ref="${ref}" title="Copy reference">${_svgCopy}</button>
                        </div>
                    </td>
                    <td style="padding:10px 14px;">
                        <div class="keeper-value-wrap" data-key="${k}" style="display:none;">
                            <textarea class="keeper-value" data-key="${k}" readonly
                                style="width:100%;min-height:36px;max-height:100px;resize:vertical;font-family:var(--font-mono);font-size:11px;background:var(--panel-bg);border:1px solid var(--border);border-radius:4px;padding:5px 7px;line-height:1.5;word-break:break-all;white-space:pre-wrap;outline:none;margin:0;color:var(--fg);"></textarea>
                            <div style="margin-top:3px;text-align:right;">
                                <button class="keeper-icon-btn" data-action="copy-value" data-key="${k}" title="Copy value">${_svgCopy}</button>
                            </div>
                        </div>
                    </td>
                    <td style="padding:10px 14px;text-align:right;white-space:nowrap;">
                        <div style="display:flex;align-items:center;gap:4px;justify-content:flex-end;">
                            <button class="btn small" data-action="reveal-secret" data-key="${k}" title="Reveal" style="padding:0;width:var(--btn-h-sm);justify-content:center;">${_eyeOpen}</button>
                            <button class="btn small" data-action="delete-key" data-key="${k}" style="color:var(--danger);border-color:rgba(255,59,48,0.4);">Delete</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');

            return `<details class="keeper-ns-group" open>
                <summary class="keeper-ns-header">
                    <span class="keeper-ns-label">${ns}</span>
                    <span class="badge" style="font-family:var(--font-mono);margin-left:8px;">${entries.length}</span>
                </summary>
                <table style="width:100%;border-collapse:collapse;">
                    <thead>
                        <tr style="border-bottom:1px solid var(--border);">
                            <th style="text-align:left;padding:6px 14px;font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;width:25%;">Key</th>
                            <th style="text-align:left;padding:6px 14px;font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;width:30%;">Reference</th>
                            <th style="text-align:left;padding:6px 14px;font-size:10px;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;">Value</th>
                            <th style="width:90px;padding:6px 14px;"></th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </details>`;
        }).join('');
    }

    async function loadKeys() {
        const el = find('#keeperList');
        if (el) el.innerHTML = '<div class="loading-rows"><div class="loading-row"></div><div class="loading-row"></div></div>';
        const data = await api.keeperList();
        if (data?.keys !== undefined) renderKeys(data.keys);
        else showLocked();
    }

    // Initial load
    (async () => {
        const status = await api.keeperStatus();
        if (!status?.enabled) { showNotConfigured(); return; }
        if (status.locked)    { showLocked();        return; }
        showUnlocked();
    })();

    on('#keeperRefreshBtn', 'click', async (e, btn) => {
        ui.btn.loading(btn, '…');
        const status = await api.keeperStatus();
        ui.btn.reset(btn);
        if (!status?.enabled) { showNotConfigured(); return; }
        if (status.locked)    { showLocked();        return; }
        showUnlocked();
    });

    // Add modal — ref preview
    function _updateRefPreview() {
        const ns   = (find('#keeperNewNs')?.value   || '').trim();
        const path = (find('#keeperNewPath')?.value || '').trim();
        const prev = find('#keeperRefPreview');
        if (!prev) return;
        if (ns && path)  { prev.textContent = `→ ${composeKeeperRef(ns, path)}`; prev.style.color = 'var(--accent)'; }
        else if (ns)     { prev.textContent = `→ ss://${ns}/…`;                  prev.style.color = 'var(--text-mute)'; }
        else             { prev.textContent = '';                                                                        }
    }
    on('#keeperNewNs',   'input', _updateRefPreview);
    on('#keeperNewPath', 'input', _updateRefPreview);

    // Tabs
    let _activeTab = 'enter';

    function _switchTab(tab) {
        _activeTab = tab;
        find('#keeperPanelEnter').style.display  = tab === 'enter'  ? '' : 'none';
        find('#keeperPanelUpload').style.display = tab === 'upload' ? '' : 'none';
        find('#keeperTabEnter').classList.toggle('keeper-tab-active',  tab === 'enter');
        find('#keeperTabUpload').classList.toggle('keeper-tab-active', tab === 'upload');
    }

    on('#keeperTabEnter',  'click', () => _switchTab('enter'));
    on('#keeperTabUpload', 'click', () => _switchTab('upload'));

    // File picker label
    on('#keeperFileInput', 'change', (e, inp) => {
        const file   = inp.files?.[0];
        const nameEl = find('#keeperFileName');
        if (nameEl) nameEl.textContent = file ? file.name : 'No file chosen';
    });

    // Open / reset modal
    function _openAddModal() {
        find('#keeperNewNs').value    = '';
        find('#keeperNewPath').value  = '';
        find('#keeperNewValue').value = '';
        find('#keeperRefPreview').textContent = '';
        find('#keeperFileName').textContent   = 'No file chosen';
        find('#keeperFileInput').value        = '';
        find('#keeperModalError').style.display = 'none';
        _switchTab('enter');
        modal.open('keeperAddModal');
        requestAnimationFrame(() => find('#keeperNewNs')?.focus());
    }

    on('#keeperAddBtn', 'click', _openAddModal);

    // Save
    on('#keeperSaveBtn', 'click', async (e, btn) => {
        const ns    = (find('#keeperNewNs')?.value   || '').trim();
        const path  = (find('#keeperNewPath')?.value || '').trim();
        const errEl = find('#keeperModalError');
        errEl.style.display = 'none';

        const keyErr = validateKeeperKey(ns, path);
        if (keyErr) { errEl.textContent = keyErr; errEl.style.display = 'block'; return; }

        const key = `${ns}/${path}`;
        ui.btn.loading(btn, 'Saving…');

        let res;
        if (_activeTab === 'upload') {
            const file = find('#keeperFileInput')?.files?.[0];
            if (!file) { ui.btn.reset(btn); errEl.textContent = 'Choose a file first'; errEl.style.display = 'block'; return; }
            res = await api.keeperSetFile(key, file);
            if (res?.bytes !== undefined || res?.key) {
                notify.show(`ss://${key} uploaded (${file.name}, ${res.bytes ?? '?'} bytes)`, 'success');
            }
        } else {
            const value = (find('#keeperNewValue')?.value || '').trim();
            if (!value) { ui.btn.reset(btn); errEl.textContent = 'Value is required'; errEl.style.display = 'block'; return; }
            res = await api.keeperSet(key, value);
            if (res?.key || res?.bytes !== undefined) {
                notify.show(`ss://${key} saved`, 'success');
            }
        }

        ui.btn.reset(btn);
        if (res?.key || res?.bytes !== undefined) {
            modal.closeAll();
            loadKeys();
        } else {
            errEl.textContent = res?.error || 'Save failed';
            errEl.style.display = 'block';
        }
    });

    // Row actions
    on('[data-action="reveal-secret"]', 'click', async (e, btn) => {
        e.stopPropagation();
        const key  = btn?.dataset.key;
        if (!key) return;
        const wrap = find(`.keeper-value-wrap[data-key="${key}"]`);
        const ta   = find(`.keeper-value[data-key="${key}"]`);
        if (!wrap || !ta) return;

        if (_revealed.has(key)) {
            clearTimeout(_revealed.get(key).timerId);
            _revealed.delete(key);
            wrap.style.display = 'none'; ta.value = '';
            btn.innerHTML = _eyeOpen; btn.title = 'Reveal';
            return;
        }

        btn.disabled = true;
        const res = await api.keeperGet(key);
        btn.disabled = false;
        if (!res?.value) { notify.show('Could not fetch secret', 'error'); return; }
        const decoded = decodeKeeperValue(res.value);
        if (decoded === null) { notify.show('Could not decode secret', 'error'); return; }

        ta.value = decoded;
        ta.rows  = Math.min(Math.max(2, decoded.split('\n').length), 6);
        wrap.style.display = '';
        btn.innerHTML = _eyeClosed; btn.title = 'Hide (auto-hides in 30s)';

        const timerId = setTimeout(() => {
            wrap.style.display = 'none'; ta.value = '';
            btn.innerHTML = _eyeOpen; btn.title = 'Reveal';
            _revealed.delete(key);
        }, 30_000);
        _revealed.set(key, { timerId });
    });

    on('[data-action="copy-ref"]', 'click', (e, btn) => {
        e.stopPropagation();
        navigator.clipboard?.writeText(btn.dataset.ref)
            .then(() => notify.show('Reference copied', 'success'))
            .catch(() => {});
    });

    on('[data-action="copy-value"]', 'click', (e, btn) => {
        e.stopPropagation();
        const ta = find(`.keeper-value[data-key="${btn.dataset.key}"]`);
        if (!ta?.value) { notify.show('Reveal the value first', 'info'); return; }
        navigator.clipboard?.writeText(ta.value)
            .then(() => notify.show('Value copied', 'success'))
            .catch(() => {});
    });

    on('[data-action="delete-key"]', 'click', async (e, btn) => {
        e.stopPropagation();
        const key = btn?.dataset.key;
        if (!key) return;
        if (btn.dataset.confirm === '1') {
            ui.btn.loading(btn, '…');
            const res = await api.keeperDelete(key);
            if (res?.deleted) {
                notify.show(`"${key}" deleted`, 'success');
                _revealed.delete(key);
                loadKeys();
            } else {
                ui.btn.reset(btn);
                btn.dataset.confirm = '';
                notify.show(res?.error || 'Delete failed', 'error');
            }
        } else {
            btn.dataset.confirm = '1';
            btn.textContent = 'Sure?';
            btn.style.cssText = 'background:var(--danger);color:#fff;border-color:var(--danger);';
            setTimeout(() => {
                if (btn.dataset.confirm === '1') {
                    btn.dataset.confirm = '';
                    btn.textContent = 'Delete';
                    btn.style.cssText = 'color:var(--danger);border-color:rgba(255,59,48,0.4);';
                }
            }, 2500);
        }
    });

    onUnmount(() => {
        _revealed.forEach(({ timerId }) => clearTimeout(timerId));
        _revealed.clear();
        if (_autoLockCd) { _autoLockCd.stop(); _autoLockCd = null; }
    });
    ready();
}
