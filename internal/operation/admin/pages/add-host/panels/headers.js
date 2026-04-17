/**
 * pages/add-host/panels/headers.js
 * Per-route request + response header manipulation panel.
 * alaye.Headers{ Enabled, Request Header{Set,Add,Remove}, Response Header{Set,Add,Remove} }
 */

function _esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

export function headersHTML(route) {
    const h    = route.headers  || {};
    const req  = h.request      || {};
    const resp = h.response     || {};
    return `<div style="display:flex;flex-direction:column;gap:18px;padding-top:4px;">
        ${_sectionHTML('Request', 'req', req,  route.id)}
        ${_sectionHTML('Response', 'resp', resp, route.id)}
    </div>`;
}

function _sectionHTML(title, prefix, h, id) {
    const setEntries    = Object.entries(h.set    || {});
    const addEntries    = Object.entries(h.add    || {});
    const removeEntries = (h.remove || []);
    return `<div>
        <div style="font-size:12px;font-weight:500;color:var(--text-mute);text-transform:uppercase;letter-spacing:.5px;margin-bottom:10px;">${title} Headers</div>
        <div style="display:flex;flex-direction:column;gap:12px;">
            <div>
                <label class="wz-label" style="font-size:11px;">Set (replaces existing)</label>
                <div id="wz-h-set-${prefix}-${id}" class="wz-header-list"></div>
                <button type="button" class="btn small" data-action="add-header" data-prefix="${prefix}" data-op="set" data-route-id="${id}" style="margin-top:5px;">+ Set header</button>
            </div>
            <div>
                <label class="wz-label" style="font-size:11px;">Add (appends)</label>
                <div id="wz-h-add-${prefix}-${id}" class="wz-header-list"></div>
                <button type="button" class="btn small" data-action="add-header" data-prefix="${prefix}" data-op="add" data-route-id="${id}" style="margin-top:5px;">+ Add header</button>
            </div>
            <div>
                <label class="wz-label" style="font-size:11px;">Remove (deletes from request/response)</label>
                <div id="wz-h-rm-${prefix}-${id}" class="wz-header-list"></div>
                <button type="button" class="btn small" data-action="add-header" data-prefix="${prefix}" data-op="remove" data-route-id="${id}" style="margin-top:5px;">+ Remove header</button>
            </div>
        </div>
    </div>`;
}

export function wireHeaders(el, route, onSync) {
    if (!route.headers)          route.headers          = {};
    if (!route.headers.request)  route.headers.request  = { set: {}, add: {}, remove: [] };
    if (!route.headers.response) route.headers.response = { set: {}, add: {}, remove: [] };
    const h = route.headers;

    function _sync() { onSync?.(); }

    function _renderList(prefix, op, id) {
        const section = prefix === 'req' ? h.request : h.response;
        const listEl  = el.querySelector(`#wz-h-${op}-${prefix}-${id}`);
        if (!listEl) return;

        if (op === 'remove') {
            const arr = section.remove || [];
            listEl.innerHTML = arr.map((name, i) => `
                <div class="wz-item-row" data-idx="${i}" style="gap:6px;">
                    <input type="text" class="wz-input wz-h-rm-name" placeholder="Header-Name" value="${_esc(name)}" style="flex:1;">
                    <button type="button" class="btn small wz-h-rm-btn" style="padding:0;width:var(--btn-h-sm);color:var(--danger);border-color:var(--danger);">✕</button>
                </div>`).join('');
            listEl.querySelectorAll('[data-idx]').forEach(row => {
                const i = +row.dataset.idx;
                row.querySelector('.wz-h-rm-name')?.addEventListener('input', e => { section.remove[i] = e.target.value; _sync(); });
                row.querySelector('.wz-h-rm-btn')?.addEventListener('click', () => { section.remove.splice(i, 1); _renderList(prefix, op, id); _sync(); });
            });
        } else {
            const map = section[op] || {};
            const entries = Object.entries(map);
            listEl.innerHTML = entries.map(([k, v], i) => `
                <div class="wz-item-row" data-idx="${i}" data-key="${_esc(k)}" style="gap:6px;">
                    <input type="text" class="wz-input wz-h-key" placeholder="Header-Name" value="${_esc(k)}" style="flex:1;">
                    <input type="text" class="wz-input wz-h-val" placeholder="value or env.VAR" value="${_esc(v)}" style="flex:2;">
                    <button type="button" class="btn small wz-h-del-btn" style="padding:0;width:var(--btn-h-sm);color:var(--danger);border-color:var(--danger);">✕</button>
                </div>`).join('');
            listEl.querySelectorAll('[data-idx]').forEach(row => {
                const origKey = row.dataset.key;
                row.querySelector('.wz-h-key')?.addEventListener('input', e => {
                    const newKey = e.target.value;
                    const val    = section[op][origKey] ?? '';
                    delete section[op][origKey];
                    section[op][newKey] = val;
                    row.dataset.key = newKey;
                    _sync();
                });
                row.querySelector('.wz-h-val')?.addEventListener('input', e => {
                    const key = row.dataset.key;
                    section[op][key] = e.target.value;
                    _sync();
                });
                row.querySelector('.wz-h-del-btn')?.addEventListener('click', () => {
                    delete section[op][origKey];
                    _renderList(prefix, op, id);
                    _sync();
                });
            });
        }
    }

    // Render initial state
    ['req','resp'].forEach(prefix => {
        ['set','add','remove'].forEach(op => _renderList(prefix, op, route.id));
    });

    // Wire add buttons
    el.querySelectorAll('[data-action="add-header"]').forEach(btn => {
        btn.addEventListener('click', () => {
            const prefix = btn.dataset.prefix;
            const op     = btn.dataset.op;
            const id     = btn.dataset.routeId;
            const section = prefix === 'req' ? h.request : h.response;
            if (op === 'remove') {
                if (!section.remove) section.remove = [];
                section.remove.push('');
            } else {
                if (!section[op]) section[op] = {};
                section[op][''] = '';
            }
            _renderList(prefix, op, id);
        });
    });
}
