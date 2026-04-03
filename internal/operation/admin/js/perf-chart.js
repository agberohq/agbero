/**
 * js/perf-chart.js
 * Self-contained SVG performance chart — no D3 dependency.
 * Extracted verbatim from ui.js PerfChart object.
 * Used by the perf modal in shell.html.
 *
 * Oja note: This is exactly the kind of primitive that belongs in Oja as
 * Out.chart(series, opts) — a zero-dependency inline SVG chart type.
 * The pattern is common enough (spark lines, time series) that it should
 * be a first-class Out type rather than a copy-pasted helper.
 */

export const PerfChart = {
    render(containerId, values, timestamps, opts = {}) {
        const el = document.getElementById(containerId);
        if (!el) return;

        const W = el.clientWidth  || 360;
        const H = el.clientHeight || 110;
        const P = { top: 14, right: 8, bottom: 20, left: 36 };
        const iW = W - P.left - P.right;
        const iH = H - P.top  - P.bottom;

        if (!values?.length) {
            el.innerHTML = `<div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-mute);font-size:11px;">No data</div>`;
            return;
        }

        const unit  = opts.unit  ?? '';
        const color = opts.color ?? 'var(--accent)';
        const isInt = opts.isInt ?? false;
        const warnAt = opts.warnAt ?? null;
        const rawMax = Math.max(...values);
        let yMax = opts.maxY !== undefined ? opts.maxY : (rawMax === 0 ? 1 : rawMax * 1.15);
        const yMin = opts.minY !== undefined ? opts.minY : 0;
        if (yMax <= yMin) yMax = yMin + 1;

        const n  = values.length;
        const xS = i => P.left + (i / Math.max(n - 1, 1)) * iW;
        const yS = v => P.top + iH - ((Math.min(v, yMax) - yMin) / (yMax - yMin)) * iH;
        const pts = values.map((v, i) => `${xS(i).toFixed(1)},${yS(v).toFixed(1)}`).join(' ');
        const fX  = xS(0).toFixed(1), lX = xS(n - 1).toFixed(1), bY = (P.top + iH).toFixed(1);
        const area = `M${fX},${bY} ` + values.map((v, i) => `L${xS(i).toFixed(1)},${yS(v).toFixed(1)}`).join(' ') + ` L${lX},${bY} Z`;
        const lc   = (warnAt !== null && rawMax >= warnAt) ? 'var(--danger)' : color;
        const fmt  = v => isInt ? Math.round(v)+'' : (v >= 1000 ? (v/1000).toFixed(1)+'k' : v < 10 ? v.toFixed(1) : v.toFixed(0));
        const ytks = [yMin, (yMin+yMax)/2, yMax].map(v => ({ y: yS(v), l: fmt(v)+unit }));
        const tL   = ts => new Date(ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
        const mid  = Math.floor((n-1)/2);
        const xlbs = [
            { x: xS(0),   l: tL(timestamps[0]),   a: 'start'  },
            { x: xS(mid), l: tL(timestamps[mid]),  a: 'middle' },
            { x: xS(n-1), l: tL(timestamps[n-1]),  a: 'end'    },
        ];
        const gid = 'pg_' + containerId;

        el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
            <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%"   stop-color="${lc}" stop-opacity="0.18"/>
                <stop offset="100%" stop-color="${lc}" stop-opacity="0.01"/>
            </linearGradient></defs>
            ${ytks.map(t=>`<line x1="${P.left}" y1="${t.y.toFixed(1)}" x2="${P.left+iW}" y2="${t.y.toFixed(1)}" stroke="var(--border)" stroke-width="1" stroke-dasharray="3 3"/>`).join('')}
            <path d="${area}" fill="url(#${gid})"/>
            <polyline points="${pts}" fill="none" stroke="${lc}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
            <circle cx="${xS(n-1).toFixed(1)}" cy="${yS(values[n-1]).toFixed(1)}" r="3" fill="${lc}" stroke="var(--bg)" stroke-width="1.5"/>
            ${ytks.map(t=>`<text x="${P.left-4}" y="${(t.y+3.5).toFixed(1)}" font-size="9" font-family="monospace" fill="var(--text-mute)" text-anchor="end">${t.l}</text>`).join('')}
            ${xlbs.map(xl=>`<text x="${xl.x.toFixed(1)}" y="${H-3}" font-size="9" font-family="monospace" fill="var(--text-mute)" text-anchor="${xl.a}">${xl.l}</text>`).join('')}
        </svg>`;
    }
};

// Make available globally for shell.html (loaded before ESM modules init)
window.PerfChart = PerfChart;
