/**
 * pages/add-host/step-type.js — Type selection step.
 */
import { emit } from '../../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, props }) {
    const { wizard } = props;

    const TYPES = [
        { type:'web',        icon:'🌐', title:'Web / Frontend',    sub:'Static files, SPA, PHP, Markdown, Git deploy',       feats:['Serve files from any directory on disk','Git-based auto-deploy with webhooks','Markdown — website or browse mode','PHP-FPM via FastCGI'] },
        { type:'proxy',      icon:'⚡', title:'Backend / Proxy',   sub:'Reverse proxy to upstream services',                  feats:['Load balancing: 11 strategies including adaptive and consistent hash','Health checks and circuit breaker','Rate limiting, CORS, caching','JWT / Basic / Forward / OAuth auth'] },
        { type:'serverless', icon:'λ',  title:'Serverless',        sub:'Managed workers and REST proxy endpoints',             feats:['HTTP-triggered, cron, background, or run-once workers','REST proxies with server-side credential injection','Git-sourced worker code with auto-deploy','env.VAR keeps secrets off the browser'] },
        { type:'tcp',        icon:'⟷', title:'TCP Proxy',         sub:'Raw TCP/TLS load balancing',                          feats:['Redis, PostgreSQL, MQTT — any TCP protocol','SNI-based routing for TLS passthrough','Health checks with custom send/expect probes','Round-robin, least-conn, sticky, adaptive'] },
    ];

    const current = wizard.draftGet('host_type');
    const grid    = find('#typeGrid');
    if (grid) {
        grid.innerHTML = TYPES.map(c => `
            <button class="host-type-card${current===c.type?' selected':''}" data-type="${c.type}">
                <span class="htc-icon">${c.icon}</span>
                <div class="htc-body"><strong>${c.title}</strong><span>${c.sub}</span><ul class="htc-features">${c.feats.map(f=>`<li>${f}</li>`).join('')}</ul></div>
                <span class="htc-arrow">→</span>
            </button>`).join('');
        on('.host-type-card', 'click', (e, card) => {
            findAll('.host-type-card').forEach(c => c.classList.remove('selected'));
            card.classList.add('selected');
            setTimeout(() => emit('wizard:type-selected', { type: card.dataset.type }), 160);
        });
    }

    onUnmount(() => {});
    ready();
}