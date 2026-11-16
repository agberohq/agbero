/**
 * pages/intercept.js — route-level authentication manager.
 *
 * URL: #/intercept?host=example.com&route=/admin&mode=protect
 *
 * The page deliberately edits route auth only. It is separate from Focus (which
 * is a read-only telemetry dashboard) so an operator can find credential
 * management without opening a monitoring view.
 *
 * Security invariants:
 *   - the API never returns a bcrypt hash, so this page never renders one;
 *   - new/reset passwords go straight to POST/PUT and are never persisted in
 *     the browser or written into HCL;
 *   - deletes use the shell's typed-confirmation modal.
 */
import { notify } from '../lib/oja.full.esm.js';

export default async function({ find, findAll, on, ready, inject }) {
    const { store, api, oja } = inject('app');

    const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));

    const params = new URLSearchParams((window.location.hash.replace(/^#/, '').split('?')[1] || ''));
    const state = {
        host:  params.get('host') || '',
        route: params.get('route') || '',
        mode:  params.get('mode') === 'basic' ? 'basic' : 'protect',
        data:  null,
    };

    function setURL() {
        const p = new URLSearchParams();
        if (state.host) p.set('host', state.host);
        if (state.route) p.set('route', state.route);
        p.set('mode', state.mode);
        history.replaceState(null, '', '#/intercept?' + p.toString());
    }

    function opError(res, fallback) {
        return api.hostOpError ? api.hostOpError(res, fallback) : fallback;
    }

    function opOK(res) {
        return api.hostOpOK ? api.hostOpOK(res) : !!res && res.status === 'ok';
    }

    function setTab(mode) {
        state.mode = mode === 'basic' ? 'basic' : 'protect';
        findAll('[data-auth-tab]').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.authTab === state.mode);
        });
        findAll('[data-auth-panel]').forEach(panel => {
            panel.classList.toggle('active', panel.dataset.authPanel === state.mode);
        });
        setURL();
    }

    function currentRoute() {
        return (state.data?.routes || []).find(r => r.path === state.route) || null;
    }

    function renderUsers(mode, users) {
        const tbody = find(`#${mode}AuthUsers tbody`);
        if (!tbody) return;
        if (!Array.isArray(users) || users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="route-auth-note" style="padding:14px 8px;">No users yet — add one below.</td></tr>';
            return;
        }
        tbody.innerHTML = users.map(u => {
            const source = u.source === 'keeper' ? 'Keeper' : (u.source === 'invalid' ? 'Invalid' : 'Inline');
            const badgeClass = u.source === 'keeper' ? 'success' : (u.source === 'invalid' ? 'danger' : '');
            const keyLine = u.keeper_key ? `<span class="route-auth-key">${esc(u.keeper_key)}</span>` : '';
            return `<tr>
                <td class="mono">${esc(u.username)}</td>
                <td><span class="badge ${badgeClass}">${source}</span>${keyLine}</td>
                <td><div class="route-auth-actions">
                    <button class="btn small" type="button" data-auth-action="reset"
                            data-mode="${mode}" data-username="${esc(u.username)}">Reset</button>
                    <button class="btn small" type="button" data-auth-action="delete"
                            data-mode="${mode}" data-username="${esc(u.username)}"
                            style="color:var(--danger);border-color:rgba(255,59,48,.35);">Delete</button>
                </div></td>
            </tr>`;
        }).join('');
    }

    function routeMarks(route) {
        const marks = [];
        if (route.basic_auth?.enabled) marks.push('Basic');
        if (route.protect?.enabled) marks.push('Protect');
        return marks;
    }

    function syncRouteChips() {
        findAll('[data-route-pick]').forEach(btn => {
            const active = btn.dataset.routePick === state.route;
            btn.classList.toggle('active', active);
            btn.setAttribute('aria-selected', String(active));
        });
    }

    function renderRouteSelect() {
        const sel = find('#routeAuthRoute');
        if (!sel) return;
        const routes = state.data?.routes || [];
        sel.innerHTML = routes.map(r => {
            const marks = routeMarks(r);
            const suffix = marks.length ? ` — ${marks.join(' + ')}` : '';
            return `<option value="${esc(r.path)}">${esc(r.path + suffix)}</option>`;
        }).join('');
        sel.value = state.route;

        const list = find('#routeAuthRouteList');
        if (list) {
            list.innerHTML = routes.map(r => {
                const marks = routeMarks(r);
                const badge = marks.length ? `<span class="route-auth-chip-badge">${esc(marks.join('+'))}</span>` : '';
                return `<button type="button" class="route-auth-chip" data-route-pick="${esc(r.path)}"
                        role="option" aria-selected="false" title="Edit auth for ${esc(r.path)}">${esc(r.path)}${badge}</button>`;
            }).join('');
        }
        syncRouteChips();

        const count = find('#routeAuthRouteCount');
        if (count) {
            count.textContent = routes.length === 0
                ? 'No routes on this host'
                : `${routes.length} route${routes.length === 1 ? '' : 's'} on this host — pick one to protect`;
        }
    }

    function pickRoute(path) {
        if (!path || path === state.route) return;
        state.route = path;
        const sel = find('#routeAuthRoute');
        if (sel) sel.value = path;
        render();
    }

    function render() {
        const empty = find('#routeAuthEmpty');
        const content = find('#routeAuthContent');
        const route = currentRoute();
        if (!route) {
            if (empty) empty.style.display = '';
            if (content) content.style.display = 'none';
            return;
        }
        if (empty) empty.style.display = 'none';
        if (content) content.style.display = '';

        const meta = find('#routeAuthMeta');
        if (meta) {
            const proto = route.protocol ? ` · ${route.protocol.toUpperCase()}` : '';
            meta.textContent = `${state.host} · ${route.path}${proto}`;
        }

        find('#basicAuthEnabled').checked = !!route.basic_auth?.enabled;
        find('#basicAuthRealm').value = route.basic_auth?.realm || '';

        find('#protectEnabled').checked = !!route.protect?.enabled;
        find('#protectTitle').value = route.protect?.title || '';
        find('#protectSessionTTL').value = route.protect?.session_ttl || '8h';
        find('#protectCookieName').value = route.protect?.cookie_name || '';

        renderUsers('basic', route.basic_auth?.users);
        renderUsers('protect', route.protect?.users);
        syncRouteChips();

        closeReset('basic');
        closeReset('protect');
        setTab(state.mode);
    }

    async function loadHosts() {
        let hosts = Object.keys((store.get('lastConfig') || {}).hosts || {});
        if (hosts.length === 0) {
            const cfg = await api.fetchConfig();
            if (cfg?.hosts) {
                store.set('lastConfig', cfg);
                hosts = Object.keys(cfg.hosts || {});
            }
        }
        const sel = find('#routeAuthHost');
        if (!sel) return hosts;
        sel.innerHTML = hosts.map(h => `<option value="${esc(h)}">${esc(h)}</option>`).join('');
        if (!hosts.includes(state.host)) state.host = hosts[0] || '';
        sel.value = state.host;
        return hosts;
    }

    async function loadAuth() {
        if (!state.host) {
            state.data = null;
            render();
            return;
        }
        const data = await api.fetchRouteAuth(state.host);
        if (!data || !Array.isArray(data.routes)) {
            state.data = null;
            state.route = '';
            render();
            notify.show('Could not load route auth for ' + state.host, 'error');
            return;
        }
        state.data = data;
        const routes = data.routes;
        if (!routes.some(r => r.path === state.route)) {
            const active = routes.find(r => r.protect?.enabled) ||
                           routes.find(r => r.basic_auth?.enabled) ||
                           routes[0];
            state.route = active?.path || '';
        }
        renderRouteSelect();
        render();
    }

    async function saveSettings(mode) {
        if (!state.route) return;
        const payload = { route: state.route, mode };
        if (mode === 'basic') {
            payload.enabled = !!find('#basicAuthEnabled')?.checked;
            payload.realm = find('#basicAuthRealm')?.value || '';
        } else {
            payload.enabled = !!find('#protectEnabled')?.checked;
            payload.title = find('#protectTitle')?.value || '';
            payload.session_ttl = find('#protectSessionTTL')?.value || '';
            payload.cookie_name = find('#protectCookieName')?.value || '';
        }
        const res = await api.updateRouteAuthConfig(state.host, payload);
        if (!opOK(res)) {
            notify.show(opError(res, 'Could not save ' + mode + ' auth settings'), 'error');
            return;
        }
        notify.show(mode === 'basic' ? 'Basic Auth settings saved' : 'Protect settings saved', 'success');
        await loadAuth();
    }

    async function addUser(mode) {
        const userEl = find(`#${mode}AuthAddUsername`);
        const passEl = find(`#${mode}AuthAddPassword`);
        const username = (userEl?.value || '').trim();
        const password = passEl?.value || '';
        if (!username || !password) {
            notify.show('Username and password are required', 'error');
            return;
        }
        if (password.length < 8) {
            notify.show('Use a password of at least 8 characters', 'error');
            return;
        }
        const res = await api.addRouteAuthUser(state.host, {
            route: state.route, mode, username, password,
        });
        if (!opOK(res)) {
            notify.show(opError(res, 'Could not add user'), 'error');
            return;
        }
        if (userEl) userEl.value = '';
        if (passEl) passEl.value = '';
        notify.show(`Added ${username} — password stored in Keeper`, 'success');
        await loadAuth();
    }

    function openReset(mode, username) {
        const form = find(`#${mode}AuthResetForm`);
        if (!form) return;
        find(`#${mode}AuthResetUser`).value = username;
        const pass = find(`#${mode}AuthResetPassword`);
        if (pass) pass.value = '';
        form.classList.add('active');
        pass?.focus();
    }

    function closeReset(mode) {
        find(`#${mode}AuthResetForm`)?.classList.remove('active');
    }

    async function resetUser(mode) {
        const username = find(`#${mode}AuthResetUser`)?.value || '';
        const password = find(`#${mode}AuthResetPassword`)?.value || '';
        if (!username) return;
        if (password.length < 8) {
            notify.show('Use a password of at least 8 characters', 'error');
            return;
        }
        const res = await api.resetRouteAuthUser(state.host, {
            route: state.route, mode, username, password,
        });
        if (!opOK(res)) {
            notify.show(opError(res, 'Could not reset password'), 'error');
            return;
        }
        closeReset(mode);
        notify.show(`Password reset for ${username}`, 'success');
        await loadAuth();
    }

    function deleteUser(mode, username) {
        oja.emit('app:strict-delete', {
            message: `Remove <strong>${esc(username)}</strong> from the <strong>${mode === 'basic' ? 'Basic Auth' : 'Protect'}</strong> users of <strong>${esc(state.route)}</strong>. Keeper credentials are deleted too.`,
            targetText: username,
            onConfirm: async () => {
                const res = await api.deleteRouteAuthUser(state.host, state.route, mode, username);
                if (!opOK(res)) throw new Error(opError(res, 'Delete failed'));
                notify.show(`Deleted ${username}`, 'success');
                await loadAuth();
            },
        });
    }

    on('#routeAuthHost', 'change', async (e, el) => {
        state.host = el.value;
        state.route = '';
        await loadAuth();
    });
    on('#routeAuthRoute', 'change', (e, el) => pickRoute(el.value));
    on('[data-route-pick]', 'click', (e, el) => pickRoute(el.dataset.routePick));
    on('#routeAuthRefresh', 'click', () => loadAuth());
    on('[data-auth-tab]', 'click', (e, el) => setTab(el.dataset.authTab));
    on('#basicAuthSave', 'click', () => saveSettings('basic'));
    on('#protectSave', 'click', () => saveSettings('protect'));
    on('#basicAuthAddForm', 'submit', (e) => { e.preventDefault(); addUser('basic'); });
    on('#protectAddForm', 'submit', (e) => { e.preventDefault(); addUser('protect'); });
    on('#basicAuthResetCancel', 'click', () => closeReset('basic'));
    on('#protectResetCancel', 'click', () => closeReset('protect'));
    on('#basicAuthResetSave', 'click', () => resetUser('basic'));
    on('#protectResetSave', 'click', () => resetUser('protect'));
    on('[data-auth-action]', 'click', (e, el) => {
        const mode = el.dataset.mode;
        const username = el.dataset.username;
        if (!mode || !username) return;
        if (el.dataset.authAction === 'reset') openReset(mode, username);
        else if (el.dataset.authAction === 'delete') deleteUser(mode, username);
    });

    await ready();
    await loadHosts();
    await loadAuth();
}
