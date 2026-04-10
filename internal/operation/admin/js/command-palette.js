/**
 * js/command-palette.js — Command palette logic (extracted from shell.html S-02)
 */
import { listen, on, emit, modal, query, queryAll } from '../lib/oja.full.esm.js';

const CMD_PAGES = [
    { label: 'Dashboard',    path: '/',         keys: 'Ctrl+1', icon: '🏠' },
    { label: 'Hosts',        path: '/hosts',    keys: 'Ctrl+2', icon: '🖥' },
    { label: 'Cluster',      path: '/cluster',  keys: 'Ctrl+3', icon: '🔗' },
    { label: 'Map',          path: '/map',      keys: 'Ctrl+4', icon: '🗺' },
    { label: 'Firewall',     path: '/firewall', keys: 'Ctrl+5', icon: '🛡' },
    { label: 'Logs',         path: '/logs',     keys: 'Ctrl+6', icon: '📄' },
    { label: 'Config',       path: '/config',   keys: 'Ctrl+7', icon: '⚙️' },
    { label: 'Keeper',       path: '/keeper',   keys: 'Ctrl+8', icon: '🔐' },
    { label: 'Profile',      path: '/profile',  keys: 'Ctrl+9', icon: '👤' },
    { label: 'Certificates', path: '/certs',    keys: 'Ctrl+0', icon: '📜' },
    { label: 'Add Host',     path: '/add-host', keys: '',       icon: '➕' },
];

function _renderResults(term) {
    const el = query('#cmdPaletteResults');
    if (!el) return;
    const filtered = term
        ? CMD_PAGES.filter(p => p.label.toLowerCase().includes(term.toLowerCase()))
        : CMD_PAGES;
    if (!filtered.length) {
        el.innerHTML = `<div style="padding:14px 16px;font-size:13px;color:var(--text-mute);">No results</div>`;
        return;
    }
    el.innerHTML = filtered.map((p, i) => `
        <button class="cmd-item${i === 0 ? ' cmd-item-active' : ''}" data-path="${p.path}"
                style="width:100%;display:flex;align-items:center;gap:12px;padding:10px 14px;
                       background:${i === 0 ? 'var(--hover-bg)' : 'none'};border:none;border-radius:6px;
                       cursor:pointer;text-align:left;font-family:var(--font-sans);transition:background .1s;">
            <span style="font-size:15px;width:20px;text-align:center;">${p.icon}</span>
            <span style="flex:1;font-size:13px;color:var(--text-main);">${p.label}</span>
            ${p.keys ? `<kbd style="font-size:10px;padding:2px 6px;border:1px solid var(--border);border-radius:4px;color:var(--text-mute);font-family:var(--font-mono);">${p.keys}</kbd>` : ''}
        </button>`).join('');
}

export function initCommandPalette() {
    listen('app:command-palette', () => {
        modal.open('commandPaletteModal');
        const inp = query('#cmdPaletteInput');
        if (inp) { inp.value = ''; _renderResults(''); }
        requestAnimationFrame(() => inp?.focus());
    });

    listen('app:command-palette-close', () => modal.closeById('commandPaletteModal'));

    on('#cmdPaletteInput', 'input', (e, el) => _renderResults(el.value));

    on('#cmdPaletteInput', 'keydown', (e) => {
        const items = queryAll('#cmdPaletteResults .cmd-item');
        if (!items.length) return;
        const active = Array.from(items).findIndex(i => i.classList.contains('cmd-item-active'));
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            const next = (active + 1) % items.length;
            items.forEach((it, i) => { it.classList.toggle('cmd-item-active', i === next); it.style.background = i === next ? 'var(--hover-bg)' : 'none'; });
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            const prev = (active - 1 + items.length) % items.length;
            items.forEach((it, i) => { it.classList.toggle('cmd-item-active', i === prev); it.style.background = i === prev ? 'var(--hover-bg)' : 'none'; });
        } else if (e.key === 'Enter') {
            e.preventDefault();
            const activeItem = items[active] || items[0];
            if (activeItem?.dataset.path) {
                modal.closeById('commandPaletteModal');
                emit('app:navigate', { path: activeItem.dataset.path });
            }
        }
    });

    on('.cmd-item', 'click', (e, btn) => {
        if (btn.dataset.path) {
            modal.closeById('commandPaletteModal');
            emit('app:navigate', { path: btn.dataset.path });
        }
    });

    on('#commandPaletteModal', 'click', (e) => {
        if (e.target === query('#commandPaletteModal')) modal.closeById('commandPaletteModal');
    });
}
