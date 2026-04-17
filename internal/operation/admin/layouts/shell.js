/**
 * layouts/shell.js — Application shell ES module.
 * Mounted via layout.apply('#shell', 'layouts/shell.html', 'layouts/shell.js').
 * Receives scope: { find, findAll, on, off, provide, onUnmount, onReady, signal, ready }
 */
import { modal, emit, listen, auth, ui, query, queryAll, notify, collapse, diffLines, renderDiff, autocomplete } from '../lib/oja.full.esm.js';
import { storeLocal } from '../js/store.js';
import { store, getHost, setHost } from '../js/store.js';
import { formatHCL, validateHCL } from '../js/hcl.js';
import { initials, debounce } from '../js/utils.js';
import { initLogin, updateNodeDisplay, _loginReset, checkServerStatus } from '../js/login.js';

export default async function({ find, findAll, on, provide, onUnmount, signal, data }) {

    // Make app services available to all pages via inject('app')
    if (data?.app) provide('app', data.app);
    const api = data?.app?.api;

    // Provide app services to all pages via inject('app')
    // main.js calls provide before layout.apply — this is a no-op placeholder
    // if already provided. Pages call inject('app') to get these.

    // Nav config
    const NAV_LINKS = [
        { path: '/',         label: 'dashboard',    primary: true,
            icon: '<path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>' },
        { path: '/hosts',    label: 'hosts',        primary: true,
            icon: '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>' },
        { path: '/logs',     label: 'logs',         primary: true,
            icon: '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>' },
        { path: '/config',   label: 'config',       primary: true,
            icon: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>' },
        { path: '/map',      label: 'Map',          primary: false,
            icon: '<polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"/><line x1="8" y1="2" x2="8" y2="18"/><line x1="16" y1="6" x2="16" y2="22"/>' },
        { path: '/firewall', label: 'Firewall',     primary: false,
            icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>' },
        { path: '/cluster',  label: 'Cluster',      primary: false,
            icon: '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>' },
        { path: '/keeper',   label: 'Keeper',       primary: false,
            icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>' },
        { path: '/certs',    label: 'Certs',        primary: false,
            icon: '<path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><polyline points="8 13 10 15 14 11"/>' },
    ];

    function buildNav() {
        const menuEl   = find('#navMenu');
        const mobileEl = find('#navMobileLinks');
        if (!menuEl) return;
        const primaryLinks = NAV_LINKS.filter(l => l.primary);
        const iconLinks    = NAV_LINKS.filter(l => !l.primary);
        menuEl.innerHTML = [
            ...primaryLinks.map(l =>
                `<a href="#${l.path}" class="nav-link" data-page="${l.path}">${l.label}</a>`),
            `<div class="nav-icon-group">` +
            iconLinks.map(l =>
                `<a href="#${l.path}" class="nav-icon-link" data-page="${l.path}" title="${l.label}">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${l.icon}</svg>
                </a>`).join('') + `</div>`,
        ].join('');
        if (mobileEl) {
            mobileEl.innerHTML = NAV_LINKS.map(l =>
                `<a href="#${l.path}" class="nav-mobile-link" data-page="${l.path}">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${l.icon}</svg>
                    ${l.label}
                </a>`
            ).join('');
        }
    }
    buildNav();

    // Active nav link
    function _updateActiveLinks(path) {
        const current = path || window.location.hash.replace('#', '') || '/';
        findAll('.nav-link, .nav-icon-link, .nav-mobile-link').forEach(el => {
            const page = el.dataset.page || '';
            el.classList.toggle('active', page === current || (page !== '/' && current.startsWith(page)));
        });
    }
    _updateActiveLinks();
    const unsubNav = listen('router:navigate', ({ path }) => _updateActiveLinks(path));

    // Node switcher
    const NODES_KEY = 'ag_nodes';
    const _getNodes  = () => storeLocal.get(NODES_KEY) || [];
    const _saveNodes = (nodes) => storeLocal.set(NODES_KEY, nodes);

    function _addNode(url, label) {
        const nodes = _getNodes();
        const clean = url.replace(/\/+$/, '');
        if (!clean) return;
        const idx = nodes.findIndex(n => n.url === clean);
        if (idx >= 0) { nodes[idx].label = label || nodes[idx].label; }
        else { nodes.push({ url: clean, label: label || clean }); }
        _saveNodes(nodes);
        return nodes;
    }

    function _removeNode(url) {
        const nodes = _getNodes().filter(n => n.url !== url);
        _saveNodes(nodes);
        return nodes;
    }

    function _renderNodeList() {
        const listEl  = find('#nodeList');
        if (!listEl) return;
        const nodes   = _getNodes();
        const current = getHost();
        if (!nodes.length) {
            listEl.innerHTML = `<div style="color:var(--text-mute);font-size:12px;padding:8px 0;">No saved nodes yet. Add one below.</div>`;
            return;
        }
        listEl.innerHTML = nodes.map(n => {
            const isActive = n.url === current;
            return `<div class="node-row${isActive ? ' active' : ''}" data-url="${n.url}">
                <div class="node-row-info">
                    <span class="node-row-label">${n.label || n.url}</span>
                    <span class="node-row-url">${n.url}</span>
                </div>
                <div class="node-row-actions">
                    ${isActive
                ? '<span class="badge success" style="font-size:10px;">active</span>'
                : `<button class="btn small" data-action="switch-node" data-url="${n.url}">Switch</button>`}
                    <button class="btn small" data-action="remove-node" data-url="${n.url}" style="color:var(--danger);border-color:rgba(255,59,48,0.3);">✕</button>
                </div>
            </div>`;
        }).join('');
        listEl.querySelectorAll('[data-action="switch-node"]').forEach(btn => {
            btn.addEventListener('click', () => { setHost(btn.dataset.url); modal.closeAll(); window.location.reload(); });
        });
        listEl.querySelectorAll('[data-action="remove-node"]').forEach(btn => {
            btn.addEventListener('click', () => { _removeNode(btn.dataset.url); _renderNodeList(); });
        });
    }

    function _syncNodeDisplay() {
        const h     = getHost();
        const match = _getNodes().find(n => n.url === h);
        const label = match?.label || h || 'local';
        const el    = find('#loginNodeDisplay');
        if (el) el.textContent = label;
        const btn = find('#targetHostBtn');
        if (btn) btn.setAttribute('data-host', h || 'local');
    }
    _syncNodeDisplay();

    on('#targetHostBtn', 'click', () => { _renderNodeList(); modal.open('targetHostModal'); });

    on('#addNodeForm', 'submit', (e) => {
        e.preventDefault();
        const url   = (find('#addNodeUrl')?.value   || '').trim();
        const label = (find('#addNodeLabel')?.value || '').trim();
        if (!url) return;
        _addNode(url, label || url);
        if (find('#addNodeUrl'))   find('#addNodeUrl').value   = '';
        if (find('#addNodeLabel')) find('#addNodeLabel').value = '';
        _renderNodeList();
    });

    on('#targetHostForm', 'submit', (e) => {
        e.preventDefault();
        const val = (find('#targetHostInput')?.value || '').trim();
        setHost(val); modal.closeAll(); window.location.reload();
    });

    on('#switchLocalBtn', 'click', () => { setHost(''); modal.closeAll(); window.location.reload(); });

    // Avatar
    function _updateAvatar() {
        let name = 'A';
        try { const user = auth.session.user(); name = user?.user || user?.sub || user?.username || 'A'; } catch {}
        const avatar = find('#profileNavLink');
        if (avatar) avatar.textContent = initials(name);
    }
    _updateAvatar();

    const unsubLogin   = listen('auth:login:success', () => { _setAuthIcon(true); _updateAvatar(); _syncNodeDisplay(); });
    const unsubExpired = listen('auth:expired',       () => _setAuthIcon(false));
    const unsubIcon    = listen('auth:icon:update',   ({ loggedIn }) => _setAuthIcon(loggedIn));

    // Theme
    const THEMES = ['light','dark','dracula','monokai','soft','ayu','tokyo-night',
        'catppuccin','solarized','gruvbox','one-dark','github-dark','rose-pine'];

    function _applyTheme(name) {
        document.documentElement.setAttribute('data-theme', name);
        storeLocal.set('ag-theme', name);
        findAll('[data-theme-pick]').forEach(btn => {
            btn.style.fontWeight = btn.dataset.themePick === name ? '600' : '';
        });
    }
    const _savedTheme = storeLocal.get('ag-theme');
    if (_savedTheme && THEMES.includes(_savedTheme)) _applyTheme(_savedTheme);
    else _applyTheme(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

    on('#themeToggle',    'click', (e) => { e.stopPropagation(); find('#themeOverflow')?.classList.toggle('open'); });
    on('[data-theme-pick]', 'click', (e, btn) => { _applyTheme(btn.dataset.themePick); find('#themeOverflow')?.classList.remove('open'); });

    // Mobile nav
    on('#navHamburger',   'click', () => find('#navMobileDrawer')?.classList.add('open'));
    on('#navMobileClose', 'click', () => find('#navMobileDrawer')?.classList.remove('open'));
    on('.nav-mobile-link','click', () => find('#navMobileDrawer')?.classList.remove('open'));
    document.addEventListener('click', (e) => {
        const drawer = find('#navMobileDrawer');
        if (drawer?.classList.contains('open') && !drawer.contains(e.target) && e.target !== find('#navHamburger')) {
            drawer.classList.remove('open');
        }
        findAll('.nav-overflow.open').forEach(el => el.classList.remove('open'));
    });

    // Auth icon
    function _setAuthIcon(loggedIn) {
        const btn = find('#loginBtn');
        if (!btn) return;
        if (loggedIn) {
            btn.title = 'Logout';
            btn.setAttribute('data-logged-in', 'true');
            btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 0 9.9-1"/></svg>`;
        } else {
            btn.title = 'Login';
            btn.setAttribute('data-logged-in', 'false');
            btn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`;
        }
    }
    _setAuthIcon(auth.session.isActive());

    on('#loginBtn', 'click', async () => {
        if (auth.session.isActive()) {
            try { await api.logout(); } catch {}
            await auth.session.end();
            store.set('auth.isLoggedIn', false);
            _setAuthIcon(false);
            return;
        }
        updateNodeDisplay(); _syncNodeDisplay(); _loginReset();
        modal.open('loginModal'); checkServerStatus();
        requestAnimationFrame(() => find('#username')?.focus());
    });

    initLogin();

    on('[data-modal="shortcutsModal"]', 'click', () => modal.closeById('shortcutsModal'));

    // Firewall rule form
    let _fwAutoHandle = null;

    function _openRuleModal({ ip = '', host = '' } = {}) {
        const ipEl     = find('#ruleIp');
        const hostEl   = find('#ruleHost');
        const reasonEl = find('#ruleReason');
        const pathEl   = find('#rulePath');
        const durEl    = find('#ruleDuration');
        const errEl    = find('#ruleError');
        if (ipEl)     ipEl.value     = ip;
        if (hostEl)   hostEl.value   = host;
        if (reasonEl) reasonEl.value = '';
        if (pathEl)   pathEl.value   = '';
        if (durEl)    durEl.value    = '0';
        if (errEl)    errEl.style.display = 'none';

        // Attach host autocomplete from known hosts list
        if (_fwAutoHandle) { _fwAutoHandle.destroy(); _fwAutoHandle = null; }
        const hostNames = Object.keys((store.get('lastConfig') || {}).hosts || {});
        if (hostEl && hostNames.length) {
            _fwAutoHandle = autocomplete.attach(hostEl, {
                source:   hostNames,
                minChars: 1,
                limit:    10,
                onSelect: (val) => { hostEl.value = val; },
            });
        }

        modal.open('ruleModal');
        requestAnimationFrame(() => (ip ? find('#ruleReason') : ipEl)?.focus());
    }

    // Triggered from firewall page button, drawer, or log entries
    const unsubFwOpen = listen('firewall:open-rule', ({ ip = '', host = '' } = {}) => {
        _openRuleModal({ ip, host });
    });

    on('#ruleForm', 'submit', async (e) => {
        e.preventDefault();
        const errEl    = find('#ruleError');
        if (errEl) errEl.style.display = 'none';
        const submitBtn = find('#ruleForm [type="submit"]');
        ui.btn.loading(submitBtn, 'Blocking…');
        try {
            const ip     = (find('#ruleIp')?.value    || '').trim();
            const reason = (find('#ruleReason')?.value || '').trim();
            const host   = (find('#ruleHost')?.value   || '').trim();
            const path   = (find('#rulePath')?.value   || '').trim();
            const durSec = parseInt(find('#ruleDuration')?.value || '0') || 0;
            if (!ip) throw new Error('IP address is required');
            await api.addFirewallRule({ ip, reason, host, path, duration_sec: durSec });
            modal.closeAll(); ui.btn.reset(submitBtn);
            emit('firewall:refresh'); notify.show(`${ip} blocked`, 'success');
        } catch (err) {
            ui.btn.reset(submitBtn);
            if (errEl) { errEl.textContent = err.message || 'Failed'; errEl.style.display = 'block'; }
        }
    });

    // Cluster route form
    on('#clusterRouteForm', 'submit', async (e) => {
        e.preventDefault();
        const submitBtn = find('#clusterRouteForm [type="submit"]');
        ui.btn.loading(submitBtn, 'Broadcasting…');
        try {
            const host   = (find('#clusterRouteHost')?.value   || '').trim();
            const path   = (find('#clusterRoutePath')?.value   || '/').trim();
            const target = (find('#clusterRouteTarget')?.value || '').trim();
            if (!host || !target) throw new Error('Host and target are required');
            await api.broadcastClusterRoute({ host, path, target });
            modal.closeAll(); ui.btn.reset(submitBtn);
            notify.show('Route broadcast', 'success');
        } catch (err) {
            ui.btn.reset(submitBtn);
            notify.show(err.message || 'Broadcast failed', 'error');
        }
    });

    // Drawers
    on('[data-action="close-drawer"]', 'click', (e, btn) => { modal.closeById(btn.dataset.target); });

    // Latency indicator
    let _latencyTimer = null;
    async function checkLatency() {
        const base = getHost() || window.location.origin;
        try {
            const start = Date.now();
            const res   = await fetch(base + '/healthz', { method: 'GET', cache: 'no-store', signal });
            if (res.ok) { store.set('sys.latency', Date.now() - start); emit('sys:latency', { ms: Date.now() - start }); }
        } catch { store.set('sys.latency', null); }
        _latencyTimer = setTimeout(checkLatency, 30_000);
    }
    checkLatency();

    // HCL Host editor
    let _hclOriginal = '';
    let _hclDomain   = '';
    let _hclMode     = 'edit'; // 'edit' | 'create'

    const _hclTemplate = `domains = ["example.localhost"]

route "/" {
  backends {
    server "http://127.0.0.1:3000" {}
  }
}
`;

    function _showEditView() {
        const ev = find('#hclEditView');
        const dv = find('#hclDiffView');
        if (ev) ev.style.display = '';
        if (dv) dv.style.display = 'none';
        const e = find('#hclEditorError');
        if (e) e.style.display = 'none';
    }

    function _showDiffView(hunks) {
        const body    = find('#hclDiffBody');
        const stats   = find('#hclDiffStats');
        const title   = find('#hclDiffTitle');
        const added   = hunks.filter(h => h.type === 'add').length;
        const removed = hunks.filter(h => h.type === 'remove').length;
        if (title) title.textContent = _hclMode === 'create' ? 'New Host' : _hclDomain;
        if (stats) stats.textContent = `+${added} added · −${removed} removed`;
        if (body)  body.innerHTML    = renderDiff(hunks, { context: 4 });
        find('#hclEditView').style.display = 'none';
        find('#hclDiffView').style.display = 'flex';
        const confirmBtn = find('#hclConfirmBtn');
        if (confirmBtn) confirmBtn.textContent = _hclMode === 'create' ? 'Create Host' : 'Confirm & Save';
        const de = find('#hclDiffError');
        if (de) de.style.display = 'none';
    }

    const unsubHclOpen = listen('host:open-edit-hcl', ({ domain, hcl }) => {
        _hclMode     = 'edit';
        _hclOriginal = hcl || '';
        _hclDomain   = domain;
        const titleEl    = find('#hclEditorTitle');
        const ta         = find('#hclEditorTextarea');
        const hintEl     = find('#hclEditorHint');
        const filenameRow= find('#hclFilenameRow');
        if (titleEl)     titleEl.textContent = `Edit: ${domain}`;
        if (hintEl)      hintEl.textContent  = 'Edit raw HCL — Tab inserts 2 spaces. Changes save to disk and hot-reload.';
        if (filenameRow) filenameRow.style.display = 'none';
        if (ta)          ta.value = hcl || '';
        _showEditView();
        modal.open('hclEditorModal');
        requestAnimationFrame(() => ta?.focus());
    });

    const unsubHclCreate = listen('host:open-create-hcl', () => {
        _hclMode     = 'create';
        _hclOriginal = '';
        _hclDomain   = '';
        const titleEl    = find('#hclEditorTitle');
        const ta         = find('#hclEditorTextarea');
        const hintEl     = find('#hclEditorHint');
        const filenameRow= find('#hclFilenameRow');
        const filenameIn = find('#hclFilenameInput');
        if (titleEl)     titleEl.textContent = 'New Host';
        if (hintEl)      hintEl.textContent  = 'Write the full host config as HCL. The filename will be used to identify this host on disk.';
        if (filenameRow) filenameRow.style.display = '';
        if (filenameIn)  filenameIn.value = '';
        if (ta)          ta.value = _hclTemplate;
        _showEditView();
        modal.open('hclEditorModal');
        requestAnimationFrame(() => filenameIn?.focus());
    });

    on('#hclEditorTextarea', 'keydown', (e, ta) => {
        if (e.key !== 'Tab') return;
        e.preventDefault();
        const s = ta.selectionStart, end = ta.selectionEnd;
        ta.value = ta.value.slice(0, s) + '  ' + ta.value.slice(end);
        ta.selectionStart = ta.selectionEnd = s + 2;
    });

    on('#formatHostJsonBtn', 'click', () => {
        const ta    = find('#hclEditorTextarea');
        const errEl = find('#hclEditorError');
        if (!ta) return;
        try {
            ta.value = formatHCL(ta.value);
            if (errEl) errEl.style.display = 'none';
        } catch (err) {
            if (errEl) { errEl.textContent = 'Format failed: ' + (err.message || err); errEl.style.display = 'block'; }
        }
    });

    on('#hclReviewBtn', 'click', () => {
        const ta     = find('#hclEditorTextarea');
        const errEl  = find('#hclEditorError');
        const edited = ta?.value || '';
        if (errEl) errEl.style.display = 'none';

        if (_hclMode === 'create') {
            const fname = (find('#hclFilenameInput')?.value || '').trim();
            if (!fname) {
                if (errEl) { errEl.textContent = 'Filename is required (e.g. myapp → saves as myapp.hcl)'; errEl.style.display = 'block'; }
                find('#hclFilenameInput')?.focus();
                return;
            }
        }

        const valErr = validateHCL(edited);
        if (valErr) {
            if (errEl) { errEl.textContent = 'HCL error: ' + valErr; errEl.style.display = 'block'; }
            return;
        }

        if (_hclMode === 'create') {
            _showDiffView(diffLines('', edited));
        } else {
            const hunks = diffLines(_hclOriginal, edited);
            if (!hunks.some(h => h.type !== 'keep')) {
                if (errEl) { errEl.textContent = 'No changes detected.'; errEl.style.display = 'block'; }
                return;
            }
            _showDiffView(hunks);
        }
    });

    on('#hclBackBtn', 'click', () => _showEditView());

    on('#hclConfirmBtn', 'click', async (e, btn) => {
        const ta     = find('#hclEditorTextarea');
        const errEl  = find('#hclDiffError');
        const edited = ta?.value || '';
        if (errEl) errEl.style.display = 'none';
        ui.btn.loading(btn, 'Saving…');
        try {
            let res;
            if (_hclMode === 'create') {
                const fname = (find('#hclFilenameInput')?.value || '').trim().replace(/\.hcl$/i, '');
                res = await api.addHostHCL(edited, fname);
            } else {
                res = await api.updateHostHCL(_hclDomain, edited);
            }
            if (res?.error) throw new Error(res.error);
            modal.closeAll();
            ui.btn.reset(btn);
            const msg = _hclMode === 'create' ? 'Host created' : `${_hclDomain} updated`;
            notify.show(msg, 'success');
            emit('hosts:refresh');
            emit('config:reload');
        } catch (err) {
            ui.btn.reset(btn);
            if (errEl) { errEl.textContent = err.message || 'Save failed'; errEl.style.display = 'block'; }
        }
    });
    // Strict delete modal
    const unsubDelete = listen('app:strict-delete', ({ message, targetText, onConfirm }) => {
        const msgEl     = find('#strictDeleteMessage');
        const targetEl  = find('#strictDeleteTarget');
        const inputEl   = find('#strictDeleteInput');
        const errEl     = find('#strictDeleteError');
        if (msgEl)    msgEl.innerHTML = message || '';
        if (targetEl) targetEl.textContent = targetText || '';
        if (inputEl)  { inputEl.value = ''; inputEl.placeholder = targetText || ''; }
        if (errEl)    errEl.style.display = 'none';

        // Clone confirm button fresh — removes any previous click handler
        const oldConfirm = find('#strictDeleteConfirmBtn');
        const confirmEl  = oldConfirm ? oldConfirm.cloneNode(true) : null;
        if (confirmEl && oldConfirm) {
            confirmEl.disabled = true;          // start disabled
            oldConfirm.parentNode.replaceChild(confirmEl, oldConfirm);
        }

        // Enable/disable as user types
        const _updateBtn = () => {
            if (confirmEl) confirmEl.disabled = (inputEl?.value.trim() !== targetText);
        };
        inputEl?.addEventListener('input', _updateBtn);

        modal.open('strictDeleteModal');
        requestAnimationFrame(() => inputEl?.focus());

        const _doDelete = async () => {
            const typed = inputEl?.value.trim();
            if (typed !== targetText) {
                if (errEl) { errEl.textContent = `Type "${targetText}" to confirm`; errEl.style.display = 'block'; }
                return;
            }
            ui.btn.loading(confirmEl, 'Deleting…');
            try { await onConfirm(); modal.closeAll(); ui.btn.reset(confirmEl); }
            catch (err) {
                ui.btn.reset(confirmEl);
                if (errEl) { errEl.textContent = err.message || 'Delete failed'; errEl.style.display = 'block'; }
            }
        };
        confirmEl?.addEventListener('click', _doDelete, { once: true });
    });

    on('#strictDeleteCancelBtn', 'click', () => modal.closeAll());

    on('#sysBar', 'click', () => {
        const bar  = find('#sysBar');
        const hint = find('#sysBar .sys-bar-expand-hint');
        if (!bar) return;
        const expanded = bar.classList.toggle('sys-bar-expanded');
        if (hint) hint.textContent = expanded ? '▼' : '▲';
    });

    // Token expiry warning (Phase 6 #43)
    // Show a dismissible notify banner 5 minutes before session expires.
    let _expiryWarnTimer = null;
    let _expiryWarnFired = false;

    function _scheduleExpiryWarning() {
        if (_expiryWarnTimer) clearTimeout(_expiryWarnTimer);
        _expiryWarnFired = false;
        try {
            const token = auth.session.tokenSync();
            if (!token) return;
            const payload = JSON.parse(atob(token.split('.')[1]));
            if (!payload.exp) return;
            const expiresMs  = payload.exp * 1000;
            const warnAt     = expiresMs - 5 * 60 * 1000;   // 5 min before
            const delayMs    = warnAt - Date.now();
            if (delayMs < 0) return; // already past the warn point
            _expiryWarnTimer = setTimeout(() => {
                if (_expiryWarnFired) return;
                _expiryWarnFired = true;
                notify.banner('⏱️ Session expires in 5 minutes', {
                    type: 'warn',
                    action: { label: 'Renew', fn: async () => {
                            try {
                                // Refresh endpoint reissues a fresh token
                                const res = await api.getApi ? null : null; // api is not directly available here
                                // Signal main.js to renew via event
                                emit('auth:renew:request');
                                notify.dismissBanner();
                            } catch {}
                        }},
                });
            }, delayMs);
        } catch {}
    }

    const unsubSessionStart = listen('auth:login:success', () => {
        _expiryWarnFired = false;
        _scheduleExpiryWarning();
    });
    // Schedule immediately if already logged in
    _scheduleExpiryWarning();

    // Cleanup
    onUnmount(() => {
        clearTimeout(_latencyTimer);
        clearTimeout(_expiryWarnTimer);
        unsubNav(); unsubLogin(); unsubExpired(); unsubIcon();
        unsubHclOpen(); unsubDelete(); unsubFwOpen(); unsubHclCreate();
        unsubSessionStart();
    });
}
