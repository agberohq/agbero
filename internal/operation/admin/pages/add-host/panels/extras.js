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
                    <select data-wz-route-field="extras.cache_driver" id="wzCacheDriver_${id}" class="wz-select-inline">
                        <option value="memory"${ex.cache_driver!=='redis'?' selected':''}>Memory</option>
                        <option value="redis"${ex.cache_driver==='redis'?' selected':''}>Redis</option>
                    </select>
                    <input type="text" data-wz-route-field="extras.cache_ttl" class="wz-input-sm" placeholder="TTL e.g. 5m" value="${_esc(ex.cache_ttl||'')}">
                    <input type="number" data-wz-route-field="extras.cache_memory_items" id="wzCacheMemItems_${id}" class="wz-input-sm"
                           placeholder="max items" min="0" title="Maximum cached entries (memory driver)"
                           value="${_esc(ex.cache_memory_items||'')}"
                           style="display:${ex.cache_driver==='redis'?'none':''}">
                </div>
                <div id="wzCacheRedis_${id}" style="display:${ex.cache_driver==='redis'?'':'none'};margin-top:8px;">
                    <div style="display:grid;grid-template-columns:2fr 1fr;gap:8px;">
                        <div><label class="wz-label" style="font-size:11px;">Redis host</label>
                            <input type="text" data-wz-route-field="extras.cache_redis_host" class="wz-input" placeholder="localhost" value="${_esc(ex.cache_redis_host||'')}"></div>
                        <div><label class="wz-label" style="font-size:11px;">Port</label>
                            <input type="number" data-wz-route-field="extras.cache_redis_port" class="wz-input" placeholder="6379" min="1" max="65535" value="${_esc(ex.cache_redis_port||'')}"></div>
                    </div>
                    <div style="display:grid;grid-template-columns:2fr 1fr 1fr;gap:8px;margin-top:8px;">
                        <div><label class="wz-label" style="font-size:11px;">Password</label>
                            <input type="password" data-wz-route-field="extras.cache_redis_pass" class="wz-input" placeholder="optional" value="${_esc(ex.cache_redis_pass||'')}"></div>
                        <div><label class="wz-label" style="font-size:11px;">DB</label>
                            <input type="number" data-wz-route-field="extras.cache_redis_db" class="wz-input" placeholder="0" min="0" value="${_esc(ex.cache_redis_db||'')}"></div>
                        <div><label class="wz-label" style="font-size:11px;">Key prefix</label>
                            <input type="text" data-wz-route-field="extras.cache_redis_prefix" class="wz-input" placeholder="agbero:cache:" value="${_esc(ex.cache_redis_prefix||'')}"></div>
                    </div>
                </div>
                <label class="wz-check" style="margin-top:8px;">
                    <input type="checkbox" data-wz-route-field="extras.cache_policy_enabled" id="wzCachePolicy_${id}"${ex.cache_policy_enabled?' checked':''}> Content-aware TTL policy
                </label>
                <div id="wzCachePolicyBody_${id}" style="display:${ex.cache_policy_enabled?'':'none'};margin-top:6px;">
                    <div style="display:grid;grid-template-columns:1fr 2fr;gap:8px;">
                        <div><label class="wz-label" style="font-size:11px;">Default TTL</label>
                            <input type="text" data-wz-route-field="extras.cache_policy_default" class="wz-input" placeholder="1m" value="${_esc(ex.cache_policy_default||'')}"></div>
                        <div><label class="wz-label" style="font-size:11px;">Key scope (comma-separated)</label>
                            <input type="text" data-wz-route-field="extras.cache_policy_scope" class="wz-input" placeholder="path, query, header:Accept-Language" value="${_esc(ex.cache_policy_scope||'')}"></div>
                    </div>
                    <div class="wz-hint">Controls how far apart two requests must be to share a cached entry.</div>
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
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;">
                    <div><label class="wz-label" style="font-size:11px;">Allowed methods</label>
                        <input type="text" data-wz-route-field="extras.cors_methods" class="wz-input"
                               placeholder="GET, POST, PUT, DELETE" value="${_esc(ex.cors_methods||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Max age (seconds)</label>
                        <input type="number" data-wz-route-field="extras.cors_max_age" class="wz-input" min="0"
                               placeholder="600" value="${_esc(ex.cors_max_age||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Allowed headers</label>
                        <input type="text" data-wz-route-field="extras.cors_headers" class="wz-input"
                               placeholder="*, or Content-Type, Authorization" value="${_esc(ex.cors_headers||'')}"></div>
                    <div><label class="wz-label" style="font-size:11px;">Exposed headers</label>
                        <input type="text" data-wz-route-field="extras.cors_exposed" class="wz-input"
                               placeholder="X-Request-ID, X-RateLimit-Remaining" value="${_esc(ex.cors_exposed||'')}"></div>
                </div>
                <label class="wz-check" style="margin-top:6px;">
                    <input type="checkbox" data-wz-route-field="extras.cors_credentials"${ex.cors_credentials?' checked':''}> Allow credentials
                </label>
                <div class="wz-hint">Credentials require explicit origins — <code>*</code> is rejected by browsers.</div>
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
                        <input type="number" data-wz-route-field="extras.rate_burst" class="wz-input" placeholder="0" min="0" value="${_esc(ex.rate_burst||'')}"></div>
                </div>
                <div class="wz-hint" style="margin-bottom:8px;">Burst must be greater than or equal to requests — leave it empty to match the request count.</div>
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
                <label class="wz-label" style="font-size:11px;margin-top:8px;">Use shared policy (optional)</label>
                <input type="text" data-wz-route-field="extras.rate_use_policy" class="wz-input"
                       placeholder="global-policy-name" value="${_esc(ex.rate_use_policy||'')}">
                <div class="wz-hint">Named policy from the global <code>rate_limits { rule "name" {} }</code> block. When set it overrides the inline rule above.</div>
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

        <!-- Compression -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztComp_${id}">
                <div><strong>Compression</strong><span class="wz-toggle-sub">GZIP or Brotli response encoding</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.compression_on"${(ex.compression_on ?? (!!ex.compression_type && ex.compression_type!=='off'))?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztComp_${id}" style="display:none;">
                <div class="wz-inline-row">
                    <select data-wz-route-field="extras.compression_type" class="wz-select-inline">
                        <option value="gzip"${(ex.compression_type||'gzip')==='gzip'?' selected':''}>GZIP</option>
                        <option value="brotli"${ex.compression_type==='brotli'?' selected':''}>Brotli</option>
                    </select>
                    <input type="number" data-wz-route-field="extras.compression_level" class="wz-input-sm"
                           placeholder="level" min="0" max="11" title="Compression level (0 = default)"
                           value="${_esc(ex.compression_level||'')}">
                </div>
                <div class="wz-hint">Brotli is preferred when the client sends <code>Accept-Encoding: br</code>. Level 0 uses the built-in default.</div>
            </div>
        </div>

        <!-- Firewall -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztFW_${id}">
                <div><strong>Firewall</strong><span class="wz-toggle-sub">Apply named IP/request rules</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.firewall_enabled"${ex.firewall_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztFW_${id}" style="display:none;">
                <label class="wz-label" style="font-size:11px;">Apply rules (comma-separated names)</label>
                <input type="text" data-wz-route-field="extras.firewall_apply_rules" class="wz-input"
                       placeholder="block-scanners, allow-office" value="${_esc(ex.firewall_apply_rules||'')}">
                <label class="wz-check" style="margin-top:8px;">
                    <input type="checkbox" data-wz-route-field="extras.firewall_ignore_global"${ex.firewall_ignore_global?' checked':''}> Ignore global firewall rules for this route
                </label>
                <div class="wz-hint">Rules are defined in the global <code>firewall { rule "name" {} }</code> block.</div>
            </div>
        </div>

        <!-- WAF -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztWAF_${id}">
                <div><strong>WAF</strong><span class="wz-toggle-sub">Coraza rules for this route</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.waf_enabled"${ex.waf_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztWAF_${id}" style="display:none;">
                <div class="wz-inline-row">
                    <select data-wz-route-field="extras.waf_mode" class="wz-select-inline">
                        <option value="monitor"${(ex.waf_mode||'monitor')==='monitor'?' selected':''}>Monitor (log only)</option>
                        <option value="active"${ex.waf_mode==='active'?' selected':''}>Active (block)</option>
                    </select>
                </div>
                <label class="wz-label" style="font-size:11px;margin-top:8px;">Directives (one per line)</label>
                <textarea data-wz-route-field="extras.waf_directives" class="wz-input" rows="3"
                          placeholder="SecRuleEngine On" style="resize:vertical;font-family:var(--font-mono);font-size:11px;">${_esc(ex.waf_directives||'')}</textarea>
                <label class="wz-check" style="margin-top:6px;">
                    <input type="checkbox" data-wz-route-field="extras.waf_ignore_global"${ex.waf_ignore_global?' checked':''}> Ignore global WAF directives
                </label>
            </div>
        </div>

        <!-- Error pages -->
        <div class="wz-toggle-card">
            <div class="wz-toggle-header" data-target="wztErr_${id}">
                <div><strong>Error Pages</strong><span class="wz-toggle-sub">Custom bodies per status code</span></div>
                <label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="extras.errorpages_enabled"${ex.errorpages_enabled?' checked':''}><span class="wz-slider"></span></label>
            </div>
            <div class="wz-toggle-body" id="wztErr_${id}" style="display:none;">
                <label class="wz-label" style="font-size:11px;">Status → file (one per line)</label>
                <textarea data-wz-route-field="extras.errorpages_pages" class="wz-input" rows="3"
                          placeholder="404=/var/www/errors/404.html&#10;503=/var/www/errors/maintenance.html"
                          style="resize:vertical;font-family:var(--font-mono);font-size:11px;">${_esc(ex.errorpages_pages||'')}</textarea>
                <label class="wz-label" style="font-size:11px;margin-top:8px;">Default page</label>
                <input type="text" data-wz-route-field="extras.errorpages_default" class="wz-input"
                       placeholder="/var/www/errors/error.html" value="${_esc(ex.errorpages_default||'')}">
                <div class="wz-hint">Files must exist on disk at config load — paths are validated.</div>
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
                <label class="wz-label">Fallback type</label>
                <select data-wz-route-field="extras.fallback_type" class="wz-select">
                    <option value="proxy"${(ex.fallback_type||'proxy')==='proxy'?' selected':''}>Proxy — try another upstream</option>
                    <option value="redirect"${ex.fallback_type==='redirect'?' selected':''}>Redirect — send to another URL</option>
                    <option value="static"${ex.fallback_type==='static'?' selected':''}>Static — serve a fixed body</option>
                </select>
                <label class="wz-label" style="margin-top:8px;">URL (proxy target or redirect location)</label>
                <input type="text" data-wz-route-field="extras.fallback_url" class="wz-input" placeholder="https://fallback.example.com" value="${_esc(ex.fallback_url||'')}">
                <label class="wz-label" style="margin-top:8px;">Static body (type = static)</label>
                <textarea data-wz-route-field="extras.fallback_body" class="wz-input" rows="2" placeholder="Service temporarily unavailable">${_esc(ex.fallback_body||'')}</textarea>
                <div style="display:flex;gap:8px;margin-top:8px;">
                    <div style="flex:1;"><label class="wz-label">Status code</label>
                        <input type="number" data-wz-route-field="extras.fallback_status_code" class="wz-input" min="100" max="599" placeholder="503" value="${ex.fallback_status_code||''}"></div>
                    <div style="flex:1;"><label class="wz-label">Cache TTL (s)</label>
                        <input type="number" data-wz-route-field="extras.fallback_cache_ttl" class="wz-input" min="0" placeholder="0" value="${ex.fallback_cache_ttl||''}"></div>
                </div>
                <div class="wz-hint">Tried only after all primary backends have failed. A type is required: proxy needs a URL, redirect needs a URL, static needs a body.</div>
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
            <label class="wz-label">Environment variables <span style="font-size:10px;font-weight:400;color:var(--text-mute);">— passed to worker processes</span></label>
            <textarea data-wz-route-field="extras.env_vars" class="wz-input" rows="2"
                      placeholder="NODE_ENV=production&#10;API_URL=https://api.internal"
                      style="resize:vertical;font-family:var(--font-mono);font-size:11px;">${_esc(ex.env_vars||'')}</textarea>
            <div class="wz-hint">One <code>KEY=VALUE</code> pair per line.</div>
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
    // Cache driver → show Redis / memory-specific fields.
    const cacheDriver = el.querySelector(`#wzCacheDriver_${route.id}`);
    const cacheRedis  = el.querySelector(`#wzCacheRedis_${route.id}`);
    const cacheItems  = el.querySelector(`#wzCacheMemItems_${route.id}`);
    if (cacheDriver && cacheRedis) {
        const syncDriver = () => {
            const isRedis = cacheDriver.value === 'redis';
            cacheRedis.style.display = isRedis ? '' : 'none';
            if (cacheItems) cacheItems.style.display = isRedis ? 'none' : '';
        };
        cacheDriver.addEventListener('change', syncDriver);
        syncDriver();
    }
    const cachePolicy = el.querySelector(`#wzCachePolicy_${route.id}`);
    const cachePolicyBody = el.querySelector(`#wzCachePolicyBody_${route.id}`);
    if (cachePolicy && cachePolicyBody) {
        const syncPolicy = () => { cachePolicyBody.style.display = cachePolicy.checked ? '' : 'none'; };
        cachePolicy.addEventListener('change', syncPolicy);
        syncPolicy();
    }

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