/**
 * pages/add-host/panels/extras.js
 * Extras panel builder — Cache, CORS, Rate Limit, Health Check,
 * Circuit Breaker, Firewall, GZIP, Timeouts, AllowedIPs, StripPrefixes, Rewrites.
 *
 * All fields from alaye.Route that were missing from the original UI are here.
 * Import and call extrasHTML(route) + wireExtras(el, route) inside a route panel.
 */

function _esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/"/g,'&quot;')
                           .replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

export function extrasHTML(route) {
    const ex = route.extras || {};
    const id = route.id;
    return `<div class="wz-toggle-grid">

        <!-- Cache -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztCache_${id}">
                <div><strong>Cache</strong><span class="wz-toggle-sub">Memory or Redis response cache</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.cache_enabled"${ex.cache_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztCache_${id}" style="display:none;">
                <div class="wz-inline-row">
                    <select data-wz-route-field="extras.cache_driver" class="wz-select-inline">
                        <option value="memory"${ex.cache_driver!=='redis'?' selected':''}>Memory</option>
                        <option value="redis"${ex.cache_driver==='redis'?' selected':''}>Redis</option>
                    </select>
                    <input type="text" data-wz-route-field="extras.cache_ttl" class="wz-input-sm" placeholder="TTL e.g. 5m" value="${_esc(ex.cache_ttl||'')}">
                </div>
            </div>
        </div>

        <!-- CORS -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztCORS_${id}">
                <div><strong>CORS</strong><span class="wz-toggle-sub">Cross-origin resource sharing</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.cors_enabled"${ex.cors_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztCORS_${id}" style="display:none;">
                <textarea data-wz-route-field="extras.cors_origins" class="wz-input" rows="2"
                          placeholder="One origin per line, or * for all" style="resize:vertical;">${_esc(ex.cors_origins||'')}</textarea>
                <label class="wz-check" style="margin-top:6px;">
                    <input type="checkbox" data-wz-route-field="extras.cors_credentials"${ex.cors_credentials?' checked':''}> Allow credentials
                </label>
            </div>
        </div>

        <!-- Rate Limit (expanded) -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztRate_${id}">
                <div><strong>Rate Limit</strong><span class="wz-toggle-sub">Throttle requests by key</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.rate_enabled"${ex.rate_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztRate_${id}" style="display:none;">
                <label class="wz-check" style="margin-bottom:8px;">
                    <input type="checkbox" data-wz-route-field="extras.rate_ignore_global"${ex.rate_ignore_global?' checked':''}> Ignore global rate limits for this route
                </label>
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-bottom:8px;">
                    <div><label class="wz-label" style="font-size:11px;">Requests</label>
                        <input type="number" data-wz-route-field="extras.rate_requests" class="wz-input" placeholder="100" value="${_esc(ex.rate_requests||'100')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Window</label>
                        <input type="text" data-wz-route-field="extras.rate_window" class="wz-input" placeholder="1m" value="${_esc(ex.rate_window||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Burst</label>
                        <input type="number" data-wz-route-field="extras.rate_burst" class="wz-input" placeholder="0" value="${_esc(ex.rate_burst||'')}"></div>
                </div>
                <label class="wz-label" style="font-size:11px;">Rate limit key</label>
                <select data-wz-route-field="extras.rate_key" class="wz-select-inline" style="margin-bottom:8px;">
                    <option value=""${!ex.rate_key?' selected':''}>IP address (default)</option>
                    <option value="header:X-API-Key"${ex.rate_key==='header:X-API-Key'?' selected':''}>Header: X-API-Key</option>
                    <option value="header:Authorization"${ex.rate_key==='header:Authorization'?' selected':''}>Header: Authorization</option>
                    <option value="custom"${ex.rate_key&&!['','header:X-API-Key','header:Authorization'].includes(ex.rate_key)?' selected':''}>Custom…</option>
                </select>
                <input type="text" data-wz-route-field="extras.rate_key_custom" id="rateKeyCustom_${id}"
                       class="wz-input" placeholder="e.g. header:X-User-ID or cookie:session"
                       value="${_esc(ex.rate_key_custom||'')}"
                       style="display:${ex.rate_key&&!['','header:X-API-Key','header:Authorization'].includes(ex.rate_key)?'':'none'}">
            </div>
        </div>

        <!-- Health Check (expanded) -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztHealth_${id}">
                <div><strong>Health Check</strong><span class="wz-toggle-sub">Active backend probe</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.health_enabled"${ex.health_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztHealth_${id}" style="display:none;">
                <div style="display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:8px;margin-bottom:8px;">
                    <div><label class="wz-label" style="font-size:11px;">Path</label>
                        <input type="text" data-wz-route-field="extras.health_path" class="wz-input" placeholder="/health" value="${_esc(ex.health_path||'/health')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Interval</label>
                        <input type="text" data-wz-route-field="extras.health_interval" class="wz-input" placeholder="10s" value="${_esc(ex.health_interval||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Timeout</label>
                        <input type="text" data-wz-route-field="extras.health_timeout" class="wz-input" placeholder="5s" value="${_esc(ex.health_timeout||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Threshold</label>
                        <input type="number" data-wz-route-field="extras.health_threshold" class="wz-input" placeholder="2" min="1" value="${_esc(ex.health_threshold||'')}"></div>
                </div>
                <div class="wz-inline-checks">
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.health_accel"${ex.health_accel?' checked':''}> Accelerated probing on failure</label>
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.health_synthetic"${ex.health_synthetic?' checked':''}> Synthetic probe when idle</label>
                </div>
            </div>
        </div>

        <!-- Circuit Breaker -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztCB_${id}">
                <div><strong>Circuit Breaker</strong><span class="wz-toggle-sub">Open after N consecutive failures</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.cb_enabled"${ex.cb_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztCB_${id}" style="display:none;">
                <div class="wz-inline-row" style="gap:8px;">
                    <div style="flex:1;"><label class="wz-label">Threshold (failures)</label>
                        <input type="number" data-wz-route-field="extras.cb_threshold" class="wz-input" placeholder="5" min="1" value="${_esc(ex.cb_threshold||5)}"></div>
                    <div style="flex:1;"><label class="wz-label">Reset after</label>
                        <input type="text" data-wz-route-field="extras.cb_duration" class="wz-input" placeholder="30s" value="${_esc(ex.cb_duration||'')}"></div>
                </div>
            </div>
        </div>

        <!-- GZIP -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header">
                <div><strong>GZIP</strong><span class="wz-toggle-sub">Compress responses automatically</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.gzip_enabled"${ex.gzip_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
        </div>

        <!-- Firewall -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header">
                <div><strong>Firewall</strong><span class="wz-toggle-sub">Enable per-route IP blocking</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.firewall_enabled"${ex.firewall_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
        </div>

        <!-- Timeouts (NEW) -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztTimeout_${id}">
                <div><strong>Timeouts</strong><span class="wz-toggle-sub">Request and response limits</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.timeouts_enabled"${ex.timeouts_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztTimeout_${id}" style="display:none;">
                <div><label class="wz-label">Request timeout</label>
                    <input type="text" data-wz-route-field="extras.timeout_request" class="wz-input" placeholder="30s" value="${_esc(ex.timeout_request||'')}">
                    <div class="wz-hint">Maximum time allowed for the entire request/response cycle.</div>
                </div>
            </div>
        </div>

        <!-- Fallback (NEW) -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztFallback_${id}">
                <div><strong>Fallback</strong><span class="wz-toggle-sub">Serve fallback when all backends fail</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.fallback_enabled"${ex.fallback_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztFallback_${id}" style="display:none;">
                <label class="wz-label">Fallback URL</label>
                <input type="text" data-wz-route-field="extras.fallback_url" class="wz-input" placeholder="https://fallback.example.com" value="${_esc(ex.fallback_url||'')}">
                <label class="wz-label" style="margin-top:8px;">Timeout</label>
                <input type="text" data-wz-route-field="extras.fallback_timeout" class="wz-input" placeholder="10s" value="${_esc(ex.fallback_timeout||'')}">
                <div class="wz-hint">The fallback upstream is tried only after all primary backends have failed.</div>
            </div>
        </div>

        <!-- Wasm (NEW) -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztWasm_${id}">
                <div><strong>Wasm</strong><span class="wz-toggle-sub">WebAssembly middleware module</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.wasm_enabled"${ex.wasm_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztWasm_${id}" style="display:none;">
                <label class="wz-label">Module path <span style="color:var(--danger)">*</span></label>
                <input type="text" data-wz-route-field="extras.wasm_module" class="wz-input" placeholder="/opt/modules/auth.wasm" value="${_esc(ex.wasm_module||'')}">
                <label class="wz-label" style="margin-top:8px;">Max body size (bytes)</label>
                <input type="number" data-wz-route-field="extras.wasm_max_body" class="wz-input" placeholder="0 = unlimited" min="0" value="${_esc(ex.wasm_max_body||'')}">
                <label class="wz-label" style="margin-top:8px;">Access capabilities</label>
                <div class="wz-inline-checks">
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.wasm_access_headers"${ex.wasm_access_headers?' checked':''}> headers</label>
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.wasm_access_body"${ex.wasm_access_body?' checked':''}> body</label>
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.wasm_access_method"${ex.wasm_access_method?' checked':''}> method</label>
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.wasm_access_uri"${ex.wasm_access_uri?' checked':''}> uri</label>
                    <label class="wz-check"><input type="checkbox" data-wz-route-field="extras.wasm_access_config"${ex.wasm_access_config?' checked':''}> config</label>
                </div>
                <div class="wz-hint" style="margin-top:6px;">Module receives only the capabilities you grant. Start with the minimum needed.</div>
            </div>
        </div>

    </div>

    <!-- Below-grid extras: AllowedIPs, StripPrefixes, URL Rewrites (NEW) -->
    <div style="margin-top:16px;display:flex;flex-direction:column;gap:14px;">

        <div>
            <label class="wz-label">Allowed IPs <span style="font-size:10px;font-weight:400;color:var(--text-mute);">— route-level allowlist, separate from firewall</span></label>
            <input type="text" data-wz-route-field="extras.allowed_ips" class="wz-input"
                   placeholder="10.0.0.0/8, 192.168.1.1" value="${_esc(ex.allowed_ips||'')}">
            <div class="wz-hint">Comma-separated IPs or CIDR ranges. Leave blank to allow all.</div>
        </div>

        <div>
            <label class="wz-label">Strip prefixes <span style="font-size:10px;font-weight:400;color:var(--text-mute);">— removed from the path before forwarding to upstream</span></label>
            <input type="text" data-wz-route-field="extras.strip_prefixes" class="wz-input"
                   placeholder="/api/v1, /internal" value="${_esc(ex.strip_prefixes||'')}">
            <div class="wz-hint">Comma-separated. Each prefix must start with /.</div>
        </div>

        <div>
            <label class="wz-label">URL Rewrites</label>
            <div id="wzRewrites_${id}" class="wz-backend-list"></div>
            <button type="button" class="btn small" data-action="add-rewrite" data-route-id="${id}" style="margin-top:6px;">+ Add Rewrite</button>
            <div class="wz-hint">Pattern is a Go regexp. Capture groups available as $1, $2 in target.</div>
        </div>

    </div>`;
}

export function wireExtras(el, route, onSync) {
    // Rate key custom field show/hide
    const rateKeySelect = el.querySelector('[data-wz-route-field="extras.rate_key"]');
    const rateKeyCustom = el.querySelector(`#rateKeyCustom_${route.id}`);
    if (rateKeySelect && rateKeyCustom) {
        rateKeySelect.addEventListener('change', () => {
            rateKeyCustom.style.display = rateKeySelect.value === 'custom' ? '' : 'none';
        });
    }

    // Rewrite rows
    if (!Array.isArray(route.extras.rewrites)) route.extras.rewrites = [];
    const rewriteList = el.querySelector(`#wzRewrites_${route.id}`);

    function renderRewrites() {
        if (!rewriteList) return;
        rewriteList.innerHTML = (route.extras.rewrites || []).map((rw, i) => `
            <div class="wz-item-row" data-idx="${i}" style="gap:6px;">
                <input type="text" class="wz-input wz-rw-pattern" placeholder="^/old/(.*)" value="${_esc(rw.pattern||'')}" style="flex:1;" title="Pattern (regexp)">
                <span style="color:var(--text-mute);font-size:12px;">→</span>
                <input type="text" class="wz-input wz-rw-target"  placeholder="/new/$1" value="${_esc(rw.target||'')}"  style="flex:1;" title="Target">
                <button type="button" class="btn small wz-rw-rm" style="padding:0;width:var(--btn-h-sm);color:var(--danger);border-color:var(--danger);">✕</button>
            </div>`).join('') || '';

        rewriteList.querySelectorAll('[data-idx]').forEach(row => {
            const i = +row.dataset.idx;
            row.querySelector('.wz-rw-pattern')?.addEventListener('input', e => { route.extras.rewrites[i].pattern = e.target.value; onSync?.(); });
            row.querySelector('.wz-rw-target')?.addEventListener('input',  e => { route.extras.rewrites[i].target  = e.target.value; onSync?.(); });
            row.querySelector('.wz-rw-rm')?.addEventListener('click', () => { route.extras.rewrites.splice(i, 1); renderRewrites(); onSync?.(); });
        });
    }

    el.querySelector(`[data-action="add-rewrite"][data-route-id="${route.id}"]`)
        ?.addEventListener('click', () => {
            route.extras.rewrites.push({ pattern: '', target: '' });
            renderRewrites();
            onSync?.();
        });

    renderRewrites();
}

// Expose for classic script use