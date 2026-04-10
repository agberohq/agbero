/**
 * js/perf.js — Performance modal logic (extracted from shell.html S-01)
 */
import { listen, on, chart, modal, query } from '../lib/oja.full.esm.js';
import { fetchTelemetry } from './api.js';
import { store } from './store.js';

let _perfCharts = null;

function _initPerfCharts() {
    _perfCharts = {
        reqs:     chart.line('#perfChartReqs',    [], [], { unit: '/s',  color: 'var(--accent)' }),
        p99:      chart.line('#perfChartP99',     [], [], { unit: 'ms',  color: 'var(--warning)' }),
        errors:   chart.line('#perfChartErrors',  [], [], { unit: '%',   color: 'var(--danger)',  maxY: 100 }),
        backends: chart.line('#perfChartBE',      [], [], { unit: '',    color: 'var(--success)', isInt: true }),
    };
}

export async function loadPerfData(hostname, range) {
    // Re-init charts if stale (modal was closed and reopened)
    if (!_perfCharts) _initPerfCharts();

    const telEnabled = store.get('lastConfig')?.global?.admin?.telemetry?.enabled;
    if (telEnabled && telEnabled !== 'on') {
        ['perfChartReqs','perfChartP99','perfChartErrors','perfChartBE'].forEach(id => {
            const el = query('#' + id);
            if (el) el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;text-align:center;padding:0 12px;">
                Telemetry not enabled.<br>Add <code style="background:var(--hover-bg);padding:1px 4px;border-radius:3px;">telemetry { enabled = "on" }</code> to your admin block.
            </div>`;
        });
        return;
    }

    const skel = '<div class="perf-skeleton"></div>';
    ['perfChartReqs','perfChartP99','perfChartErrors','perfChartBE'].forEach(id => {
        const el = query('#' + id);
        if (el) el.innerHTML = skel;
    });

    const data = await fetchTelemetry(hostname, range);
    if (!data?.samples?.length) {
        ['perfChartReqs','perfChartP99','perfChartErrors','perfChartBE'].forEach(id => {
            const el = query('#' + id);
            if (el) el.innerHTML = '<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">No history data yet — data accumulates over time</div>';
        });
        return;
    }

    const s = data.samples;
    _perfCharts.reqs.update(s.map(x => x.requests_sec),        s.map(x => x.ts));
    _perfCharts.p99.update(s.map(x => x.p99_ms),               s.map(x => x.ts));
    _perfCharts.errors.update(s.map(x => x.error_rate),        s.map(x => x.ts));
    _perfCharts.backends.update(s.map(x => x.active_backends), s.map(x => x.ts));

    if (s.length >= 2) {
        const fmt = ts => new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        const el = query('#perfDataRange');
        if (el) el.textContent = `${fmt(s[0].ts)} – ${fmt(s[s.length - 1].ts)} · ${s.length} points`;
    }
}

export function initPerfListeners() {
    listen('perf:open', async ({ hostname }) => {
        const titleEl = query('#perfModalTitle');
        const hostEl  = query('#perfModalHost');
        const rangeEl = query('#perfDataRange');
        if (titleEl) titleEl.textContent = 'Performance History';
        if (hostEl)  hostEl.textContent  = hostname;
        if (rangeEl) rangeEl.textContent = '';
        modal.open('perfModal');
        window._perfHost = hostname;
        await loadPerfData(hostname, query('#perfRangeSelect')?.value || '1h');
    });

    on('#perfRangeSelect', 'change', async (e, el) => {
        if (window._perfHost) await loadPerfData(window._perfHost, el.value);
    });

    // reset charts when modal closes so they re-attach on next open
    listen('modal:close', ({ id }) => {
        if (id === 'perfModal') {
            _perfCharts = null;
        }
    });
}
