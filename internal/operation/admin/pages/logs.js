/**
 * pages/logs.js — Logs page.
 */
import { emit } from '../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { store, api, oja } = inject('app');
    const { ui } = oja;

    const ICON_PAUSE  = `<rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/>`;
    const ICON_RESUME = `<polygon points="5 3 19 12 5 21 5 3"/>`;

    let paused = false, filter = store.get('logFilter') || 'ALL', logs = [], pollTimer = null, isAllExpanded = false;
    let searchTerm = '';

    function parseEntry(l) {
        let lvl = 'INFO', msg = '', ts = '', fields = {};
        if (typeof l === 'string') {
            try { const p = JSON.parse(l); lvl = p.lvl||p.level||'INFO'; msg = p.msg||p.message||l; ts = p.ts||p.time||''; fields = p.fields ? {...p.fields} : {}; } catch { msg = l; }
        } else if (l && typeof l === 'object') {
            lvl = l.lvl||l.level||'INFO'; msg = l.msg||l.message||''; ts = l.ts||l.time||''; fields = l.fields ? {...l.fields} : {};
        }
        if (ts?.includes('T')) ts = ts.split('T')[1]?.split('.')[0] || ts;
        let full = msg;
        // Strip port from remote — "[::1]:56893" → "::1", "1.2.3.4:8080" → "1.2.3.4"
        let rawIp = fields.ip || fields.remote || fields.client_ip || '';
        if (rawIp.startsWith('[')) rawIp = rawIp.replace(/^\[([^\]]+)\].*$/, '$1');
        else if (rawIp.includes(':') && rawIp.split(':').length === 2) rawIp = rawIp.split(':')[0];
        const ip   = rawIp;
        const host = fields.host || fields.domain || '';
        if (fields.method && fields.path) { full += ` ${fields.method} ${fields.path}`; delete fields.method; delete fields.path; }
        if (fields.status)   { full += ` [${fields.status}]`; delete fields.status; }
        if (fields.duration) { full += ` (${(fields.duration / 1e6).toFixed(2)}ms)`; delete fields.duration; }
        delete fields.ip; delete fields.remote; delete fields.client_ip;
        return { lvl, ts, full, fields, ip, host };
    }

    // Syntax-highlight JSON for the expanded body
    function _highlightJson(obj) {
        return JSON.stringify(obj, null, 2)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, m => {
                let cls = 'json-num';
                if (/^"/.test(m)) cls = /:$/.test(m) ? 'json-key' : 'json-str';
                else if (/true|false/.test(m)) cls = 'json-bool';
                else if (/null/.test(m)) cls = 'json-null';
                return `<span class="${cls}">${m}</span>`;
            });
    }

    // Rebuild the host filter dropdown from current logs
    function _updateHostFilter() {
        const sel = find('#logsHostFilter');
        if (!sel) return;
        const hosts = new Set();
        logs.forEach(l => { const { host } = parseEntry(l); if (host) hosts.add(host); });
        const current = sel.value;
        sel.innerHTML = '<option value="">All hosts</option>' +
            [...hosts].sort().map(h => `<option value="${h}"${h === current ? ' selected' : ''}>${h}</option>`).join('');
    }

    function renderLogs() {
        const el = find('#logsList');
        if (!el) return;
        if (!logs.length) {
            el.innerHTML = `<div style="color:var(--text-mute);text-align:center;padding:40px;"><span style="display:block;font-size:24px;margin-bottom:10px;">📭</span>No logs yet. Waiting for traffic...</div>`;
            return;
        }
        _updateHostFilter();
        const term       = searchTerm.toLowerCase();
        const hostFilter = find('#logsHostFilter')?.value || '';
        const filtered = logs.filter(l => {
            const { lvl, full, host } = parseEntry(l);
            if (filter !== 'ALL' && lvl !== filter) return false;
            if (hostFilter && host !== hostFilter) return false;
            if (term && !full.toLowerCase().includes(term) && !JSON.stringify(l).toLowerCase().includes(term)) return false;
            return true;
        });
        if (!filtered.length) {
            el.innerHTML = `<div style="color:var(--text-mute);text-align:center;padding:20px;">No ${searchTerm ? `results for "${searchTerm}"` : filter + ' logs'}</div>`;
            return;
        }
        el.innerHTML = filtered.map(l => {
            const { lvl, ts, full, fields, ip, host } = parseEntry(l);
            const color   = lvl === 'ERROR' ? 'var(--danger)' : lvl === 'WARN' ? 'var(--warning)' : 'var(--text-mute)';
            const hasJson = Object.keys(fields).length > 0;
            const highlightedFull = term
                ? full.replace(new RegExp(term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'),
                    m => `<mark style="background:var(--warning);color:#000;border-radius:2px;padding:0 1px;">${m}</mark>`)
                : full;
            const ipBadge    = ip ? `<span class="log-ip" data-ip="${ip}" data-host="${host}" style="font-family:var(--font-mono);font-size:10px;color:var(--text-mute);margin-left:6px;padding:1px 4px;border:1px solid var(--border);border-radius:3px;cursor:pointer;" title="Click to block">${ip}</span>` : '';
            const jsonToggle = hasJson ? `<details class="log-details"${isAllExpanded ? ' open' : ''}><summary class="log-json-toggle">{…}</summary><div class="log-json-body"><pre class="log-json-pre">${_highlightJson(fields)}</pre></div></details>` : '';
            return `<div class="log-entry" data-ip="${ip}" data-host="${host}"><span class="log-ts">${ts}</span><span class="log-lvl" style="color:${color};">${lvl}</span><span class="log-msg">${highlightedFull}${ipBadge} ${jsonToggle}</span></div>`;
        }).join('');
    }

    async function fetchAndRender() {
        if (paused) return;
        const lines = find('#logsTailSelect')?.value || '100';
        const data  = await api.fetchLogs(lines);
        if (data && Array.isArray(data)) { logs = [...data].reverse(); renderLogs(); }
    }

    async function exportLogs() {
        const btn   = find('#logsExportBtn');
        const lines = find('#logsTailSelect')?.value || '100';
        ui.btn.loading(btn);
        const data = await api.fetchLogs(lines);
        if (!data || !Array.isArray(data)) { ui.btn.reset(btn); return; }
        const out  = data.map(l => { if (typeof l === 'string') { try { return JSON.parse(l); } catch { return { raw: l }; } } return l; });
        const blob = new Blob([JSON.stringify(out, null, 2)], { type: 'application/json' });
        const a    = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `agbero-logs-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.json` });
        a.click(); URL.revokeObjectURL(a.href);
        ui.btn.done(btn, '✓');
    }

    findAll('.chip').forEach(c => c.classList.remove('active'));
    const activeChip = find(`.chip[data-level="${filter}"]`);
    if (activeChip) activeChip.classList.add('active');

    // Show skeleton on first paint before fetch completes
    const logsList = find('#logsList');
    if (logsList && !logs.length) {
        logsList.innerHTML = `<div class="loading-rows" style="padding:8px 0;">
            <div class="loading-row"></div><div class="loading-row"></div>
            <div class="loading-row"></div><div class="loading-row"></div>
        </div>`;
    }

    fetchAndRender();
    pollTimer = setInterval(fetchAndRender, 2000);

    on('#logsPauseBtn', 'click', (e, btn) => {
        paused = !paused;
        if (btn) btn.title = paused ? 'Resume live updates' : 'Pause live updates';
        const svg = find('#logsPauseIcon');
        if (svg) svg.innerHTML = paused ? ICON_RESUME : ICON_PAUSE;
    });
    on('#logsExpandAllBtn',   'click', () => { isAllExpanded = true;  findAll('.log-details').forEach(el => el.open = true);  });
    on('#logsCollapseAllBtn', 'click', () => { isAllExpanded = false; findAll('.log-details').forEach(el => el.open = false); });
    on('#logsExportBtn',  'click', exportLogs);
    on('#logsClearBtn',   'click', () => { logs = []; renderLogs(); });
    on('#logsTailSelect', 'change', fetchAndRender);

    on('#logsSearch', 'input', (e, inp) => {
        searchTerm = inp.value.trim();
        const clearBtn = find('#logsSearchClear');
        if (clearBtn) clearBtn.style.display = searchTerm ? '' : 'none';
        renderLogs();
    });
    on('#logsSearchClear', 'click', () => {
        const inp = find('#logsSearch');
        if (inp) { inp.value = ''; inp.focus(); }
        searchTerm = '';
        const clearBtn = find('#logsSearchClear');
        if (clearBtn) clearBtn.style.display = 'none';
        renderLogs();
    });
    on('.chip', 'click', (e, chip) => {
        findAll('.chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        filter = chip.dataset.level;
        store.set('logFilter', filter);
        renderLogs();
    });

    // Expanding a JSON detail pauses polling to prevent flicker; collapsing resumes
    on('.log-details', 'toggle', (e, det) => {
        if (det.open && !paused) {
            paused = true;
            const btn = find('#logsPauseBtn');
            if (btn) btn.title = 'Resume live updates';
            const svg = find('#logsPauseIcon');
            if (svg) svg.innerHTML = ICON_RESUME;
        }
    });

    // Host filter
    on('#logsHostFilter', 'change', () => renderLogs());
    on('.log-ip', 'click', (e, el) => {
        e.stopPropagation();
        const ip   = el.dataset.ip   || '';
        const host = el.dataset.host || '';
        if (ip) emit('firewall:open-rule', { ip, host });
    });

    // Right-click log row → contextmenu with block option
    on('.log-entry', 'contextmenu', (e, row) => {
        const ip   = row.dataset.ip   || '';
        const host = row.dataset.host || '';
        if (!ip) return;
        e.preventDefault();
        const { clickmenu } = oja;
        clickmenu.show(e.clientX, e.clientY, [
            { label: `Block ${ip}`, icon: '🛡️', action: () => emit('firewall:open-rule', { ip, host }) },
        ]);
    });

    onUnmount(() => { if (pollTimer) clearInterval(pollTimer); paused = false; logs = []; });
    ready();
}
