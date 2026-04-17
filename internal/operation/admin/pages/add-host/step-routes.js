/**
 * pages/add-host/step-routes.js — HTTP routes step.
 */
import { emit } from '../../lib/oja.full.esm.js';
import { tabs } from '../../lib/oja.full.esm.js';
import { extrasHTML, wireExtras }         from './panels/extras.js';
import { headersHTML, wireHeaders }        from './panels/headers.js';
import { renderValueInput, wireValueInput } from './panels/value-input.js';

export default async function({ find, findAll, on, onUnmount, ready, props }) {
    const { wizard } = props;

    const hostType       = wizard.draftGet('host_type') || 'proxy';
    let   _routes        = wizard.getRoutes();
    let   _activeRouteId = _routes[0]?.id || '';

    function _esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
    function _sync() { wizard.setRoutes(_routes); }

    function _wireToggleCards(container) {
        container.querySelectorAll('.wz-toggle-card input[type="checkbox"]').forEach(cb => {
            const card=cb.closest('.wz-toggle-card'), header=card?.querySelector('.wz-toggle-header[data-target]'), bodyId=header?.dataset.target, body=bodyId?(container.querySelector('#'+bodyId)??document.getElementById(bodyId)):null;
            if(!body)return;
            const _open=()=>{body.style.display='';}, _close=()=>{body.style.display='none';};
            if(cb.checked)_open();else _close();
            cb.addEventListener('change',()=>cb.checked?_open():_close());
            if(header)header.addEventListener('click',e=>{if(e.target.closest('.wz-switch'))return;e.stopPropagation();const nowOpen=body.style.display!=='none';if(nowOpen){_close();cb.checked=false;}else{_open();cb.checked=true;}cb.dispatchEvent(new Event('change',{bubbles:true}));});
        });
    }

    function _collect(el, route) {
        el.querySelectorAll('[data-wz-route-field]').forEach(inp=>{
            const key=inp.dataset.wzRouteField;if(!key)return;const[sec,field]=key.split('.');if(!route[sec])route[sec]={};
            if(inp.type==='checkbox')route[sec][field]=inp.checked;else if(inp.type==='radio'){if(inp.checked)route[sec][field]=inp.value;}else route[sec][field]=inp.value;
        });
    }

    // Engine HTML builders
    function _webEngineHTML(route) {
        const ed=route.engineData||{};
        return `<div class="wz-toggle-grid">
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztStatic_${route.id}"><div><strong>Static Files</strong><span class="wz-toggle-sub">Serve a directory from disk</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="engineData.web_static_on"${ed.web_static_on?' checked':''}><span class="wz-slider"></span></label></div>
        <div class="wz-toggle-body" id="wztStatic_${route.id}" style="display:none;"><input type="text" data-wz-route-field="engineData.web_root" class="wz-input" placeholder="/var/www/html" value="${_esc(ed.web_root||'')}"><div class="wz-hint">Full absolute server path</div><div class="wz-inline-checks" style="margin-top:8px;"><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.web_listing"${ed.web_listing?' checked':''}> Directory listing</label><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.web_spa"${ed.web_spa?' checked':''}> SPA mode (fallback to index.html)</label><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.web_nocache"${ed.web_nocache?' checked':''}> Disable caching headers</label></div><label class="wz-label" style="font-size:11px;margin-top:10px;">Index files (comma-separated)</label><input type="text" data-wz-route-field="engineData.web_index" class="wz-input" placeholder="index.html, index.php, index.md" value="${_esc(ed.web_index||'index.html, index.htm, index.php, index.md, README.md')}"><div class="wz-hint">Files tried in order when a directory is requested.</div></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztPHP_${route.id}"><div><strong>PHP</strong><span class="wz-toggle-sub">via PHP-FPM FastCGI</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="engineData.php_enabled"${ed.php_enabled?' checked':''}><span class="wz-slider"></span></label></div>
        <div class="wz-toggle-body" id="wztPHP_${route.id}" style="display:none;"><label class="wz-label">FastCGI address <span style="color:var(--danger)">*</span></label><input type="text" data-wz-route-field="engineData.php_address" class="wz-input" placeholder="127.0.0.1:9000  or  /run/php/php8.1-fpm.sock" value="${_esc(ed.php_address||'')}"></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztGit_${route.id}"><div><strong>Git Deploy</strong><span class="wz-toggle-sub">Pull + optional webhook trigger</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="engineData.git_enabled"${ed.git_enabled?' checked':''}><span class="wz-slider"></span></label></div>
        <div class="wz-toggle-body" id="wztGit_${route.id}" style="display:none;"><input type="text" data-wz-route-field="engineData.git_url" class="wz-input" placeholder="https://github.com/org/repo.git" value="${_esc(ed.git_url||'')}" style="margin-bottom:6px;"><div style="display:flex;gap:8px;margin-bottom:6px;"><input type="text" data-wz-route-field="engineData.git_branch" class="wz-input" placeholder="Branch (default: main)" value="${_esc(ed.git_branch||'')}" style="flex:1;"><input type="text" data-wz-route-field="engineData.git_id" class="wz-input" placeholder="Deploy ID (e.g. my-site)" value="${_esc(ed.git_id||'')}" style="flex:1;"></div><div style="display:flex;gap:8px;margin-bottom:6px;"><div style="flex:1;"><label class="wz-label" style="font-size:11px;">Poll interval</label><input type="text" data-wz-route-field="engineData.git_interval" class="wz-input" placeholder="5m — blank = webhook only" value="${_esc(ed.git_interval||'')}"></div><div style="flex:1;"><label class="wz-label" style="font-size:11px;">Webhook secret</label><input type="text" data-wz-route-field="engineData.git_secret" class="wz-input" placeholder="Must match GitHub/GitLab setting" value="${_esc(ed.git_secret||'')}"></div></div><label class="wz-label" style="font-size:11px;">Auth (private repos)</label><select data-wz-route-field="engineData.git_auth_type" class="wz-select-inline" style="margin-bottom:6px;"><option value="">None (public)</option><option value="basic"${ed.git_auth_type==='basic'?' selected':''}>Basic</option><option value="ssh-key"${ed.git_auth_type==='ssh-key'?' selected':''}>SSH Key</option><option value="ssh-agent"${ed.git_auth_type==='ssh-agent'?' selected':''}>SSH Agent</option></select><div class="wz-git-auth-fields"></div></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztMd_${route.id}"><div><strong>Markdown</strong><span class="wz-toggle-sub">Render .md files as HTML</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="engineData.markdown_enabled"${ed.markdown_enabled?' checked':''}><span class="wz-slider"></span></label></div>
        <div class="wz-toggle-body" id="wztMd_${route.id}" style="display:none;"><div class="wz-radio-group" style="flex-direction:row;gap:16px;margin-bottom:8px;"><label class="wz-radio"><input type="radio" name="md_view_${route.id}" data-wz-route-field="engineData.markdown_view" value=""${!ed.markdown_view?' checked':''}> <span>Website</span></label><label class="wz-radio"><input type="radio" name="md_view_${route.id}" data-wz-route-field="engineData.markdown_view" value="browse"${ed.markdown_view==='browse'?' checked':''}> <span>Browse</span></label></div><div class="wz-inline-checks"><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.markdown_toc"${ed.markdown_toc?' checked':''}> Table of contents</label><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.markdown_highlight"${ed.markdown_highlight?' checked':''}> Syntax highlighting</label><label class="wz-check"><input type="checkbox" data-wz-route-field="engineData.markdown_unsafe"${ed.markdown_unsafe?' checked':''}> Allow raw HTML</label></div></div></div>
        </div>`;
    }

    function _wireWebEngine(el, route) {
        const authSel=el.querySelector('[data-wz-route-field="engineData.git_auth_type"]'),authBox=el.querySelector('.wz-git-auth-fields');
        function updateGitAuth(){if(!authBox)return;const v=authSel?.value||'',ed=route.engineData||{};authBox.innerHTML=v==='basic'?`<input type="text" data-wz-route-field="engineData.git_auth_user" class="wz-input" placeholder="Username" style="margin-bottom:4px;" value="${_esc(ed.git_auth_user||'')}"><input type="password" data-wz-route-field="engineData.git_auth_pass" class="wz-input" placeholder="Password / token" value="${_esc(ed.git_auth_pass||'')}">`:v==='ssh-key'?`<textarea data-wz-route-field="engineData.git_ssh_key" class="wz-input" rows="3" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----" style="font-family:var(--font-mono);font-size:11px;resize:vertical;">${_esc(ed.git_ssh_key||'')}</textarea>`:'';}

        authSel?.addEventListener('change',updateGitAuth);updateGitAuth();
    }

    const ALL_STRATEGIES=[{val:'round_robin',label:'Round Robin',desc:'Balanced, default'},{val:'least_conn',label:'Least Connections',desc:'Lowest active load'},{val:'least_response_time',label:'Least Response Time',desc:'Fastest backend'},{val:'weighted_least_conn',label:'Weighted Least Conn',desc:'Weight-aware load'},{val:'sticky',label:'Sticky Sessions',desc:'Same client → same server'},{val:'ip_hash',label:'IP Hash',desc:'Consistent by client IP'},{val:'url_hash',label:'URL Hash',desc:'Consistent by request URL'},{val:'consistent_hash',label:'Consistent Hash',desc:'Hash on custom key'},{val:'power_of_two',label:'Power of Two',desc:'Two random, pick best'},{val:'random',label:'Random',desc:'Uniform random selection'},{val:'adaptive',label:'Adaptive',desc:'Auto-tune by health score'}];

    function _proxyEngineHTML(route) {
        const ed=route.engineData||{},s=ed.lb_strategy||'round_robin',needsKey=['consistent_hash','sticky'].includes(s);
        return `<div class="wz-section-heading">Backends</div><div class="wz-hint" style="margin-bottom:8px;">Add one or more upstream servers.</div><div id="wzProxyBackends_${route.id}" class="wz-backend-list"></div><button type="button" class="btn small wz-add-backend" style="margin-top:8px;">+ Add Backend</button><input type="hidden" data-wz-route-field="engineData.backends_list" class="wz-backends-field" value="${_esc(ed.backends_list||'[]')}">
        <div class="wz-section-heading" style="margin-top:20px;">Load Balancing Strategy</div><div class="wz-strategy-grid">${ALL_STRATEGIES.map(st=>`<label class="wz-strategy-opt"><input type="radio" name="lb_${route.id}" data-wz-route-field="engineData.lb_strategy" value="${st.val}"${s===st.val?' checked':''}><span><strong>${st.label}</strong><em>${st.desc}</em></span></label>`).join('')}</div>
        <div id="wzHashKeysRow_${route.id}" style="margin-top:10px;${needsKey?'':'display:none;'}"><label class="wz-label">Hash keys</label><input type="text" data-wz-route-field="engineData.backend_keys" class="wz-input" placeholder="ip, header:X-User-ID, cookie:session" value="${_esc(ed.backend_keys||'')}"></div>`;
    }

    function _wireProxyEngine(el, route) {
        let backends=[];try{backends=JSON.parse(route.engineData?.backends_list||'[]');}catch{}if(!backends.length)backends=[{address:'',weight:1}];
        const listEl=el.querySelector('#wzProxyBackends_'+route.id),fieldEl=el.querySelector('.wz-backends-field'),addBtn=el.querySelector('.wz-add-backend'),hashRow=el.querySelector('#wzHashKeysRow_'+route.id);
        function syncField(){if(fieldEl){fieldEl.value=JSON.stringify(backends);route.engineData=route.engineData||{};route.engineData.backends_list=fieldEl.value;}}
        function renderBEs(){if(!listEl)return;listEl.innerHTML=backends.map((b,i)=>`<div class="wz-backend-row" data-idx="${i}"><input type="text" class="wz-input wz-be-addr" value="${_esc(b.address||'')}" placeholder="http://10.0.0.5:8080" style="flex:1;"><input type="number" class="wz-input-sm wz-be-weight" value="${b.weight||1}" min="1" max="100" style="width:60px;"><span class="wz-hint-inline" style="font-size:10px;white-space:nowrap;">weight</span><button type="button" class="btn small wz-be-remove" style="color:var(--danger);border-color:var(--danger);padding:4px 8px;">✕</button></div>`).join('');listEl.querySelectorAll('.wz-be-addr').forEach((inp,i)=>inp.addEventListener('input',()=>{backends[i].address=inp.value;syncField();}));listEl.querySelectorAll('.wz-be-weight').forEach((inp,i)=>inp.addEventListener('input',()=>{backends[i].weight=Number(inp.value)||1;syncField();}));listEl.querySelectorAll('.wz-be-remove').forEach(btn=>btn.addEventListener('click',()=>{backends.splice(+btn.closest('[data-idx]').dataset.idx,1);renderBEs();}));}
        addBtn?.addEventListener('click',()=>{backends.push({address:'',weight:1});renderBEs();listEl?.querySelectorAll('.wz-be-addr')[backends.length-1]?.focus();});
        el.querySelectorAll(`[name="lb_${route.id}"]`).forEach(r=>r.addEventListener('change',()=>{if(hashRow)hashRow.style.display=['consistent_hash','sticky'].includes(r.value)?'':'none';}));
        renderBEs();syncField();
    }

    function _authPlaceholder(route) {
        const au=route.authData||{};
        return `<div class="wz-toggle-grid">
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztBasicAuth_${route.id}"><div><strong>Basic Auth</strong><span class="wz-toggle-sub">Username / bcrypt password</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="authData.basic_enabled"${au.basic_enabled?' checked':''}><span class="wz-slider"></span></label></div><div class="wz-toggle-body" id="wztBasicAuth_${route.id}" style="display:none;"><div class="wz-hint" style="margin-bottom:6px;">One entry per line: <code>username:$2y$10$…</code></div><textarea data-wz-route-field="authData.basic_users" class="wz-input" rows="3" placeholder="admin:$2y$10$hash" style="resize:vertical;font-family:var(--font-mono);font-size:11px;">${_esc(au.basic_users||'')}</textarea></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztJWT_${route.id}"><div><strong>JWT Auth</strong><span class="wz-toggle-sub">Validate Bearer tokens</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="authData.jwt_enabled"${au.jwt_enabled?' checked':''}><span class="wz-slider"></span></label></div><div class="wz-toggle-body" id="wztJWT_${route.id}" style="display:none;">${renderValueInput(`jwt_secret_${route.id}`,au.jwt_secret||'',{label:'JWT Secret',required:true,password:true})}<input type="text" data-wz-route-field="authData.jwt_issuer" class="wz-input" placeholder="Issuer (optional)" value="${_esc(au.jwt_issuer||'')}" style="margin-top:6px;"></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztForward_${route.id}"><div><strong>Forward Auth</strong><span class="wz-toggle-sub">Delegate auth to external service</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="authData.forward_enabled"${au.forward_enabled?' checked':''}><span class="wz-slider"></span></label></div><div class="wz-toggle-body" id="wztForward_${route.id}" style="display:none;"><input type="text" data-wz-route-field="authData.forward_url" class="wz-input" placeholder="https://auth.example.com/validate" value="${_esc(au.forward_url||'')}"></div></div>
        <div class="wz-toggle-card"><div class="wz-toggle-header" data-target="wztOAuth_${route.id}"><div><strong>OAuth</strong><span class="wz-toggle-sub">SSO via Google, GitHub, GitLab, or custom</span></div><label class="wz-switch" onclick="event.stopPropagation()"><input type="checkbox" data-wz-route-field="authData.oauth_enabled"${au.oauth_enabled?' checked':''}><span class="wz-slider"></span></label></div><div class="wz-toggle-body" id="wztOAuth_${route.id}" style="display:none;"><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;"><div><label class="wz-label" style="font-size:11px;">Provider</label><select data-wz-route-field="authData.oauth_provider" class="wz-select-inline"><option value="google"${au.oauth_provider==='google'||!au.oauth_provider?' selected':''}>Google</option><option value="github"${au.oauth_provider==='github'?' selected':''}>GitHub</option><option value="gitlab"${au.oauth_provider==='gitlab'?' selected':''}>GitLab</option><option value="custom"${au.oauth_provider==='custom'?' selected':''}>Custom</option></select></div><div><label class="wz-label" style="font-size:11px;">Client ID <span style="color:var(--danger)">*</span></label><input type="text" data-wz-route-field="authData.oauth_client_id" class="wz-input" value="${_esc(au.oauth_client_id||'')}"></div></div><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px;">${renderValueInput(`oauth_client_secret_${route.id}`,au.oauth_client_secret||'',{label:'Client Secret *',password:true})}${renderValueInput(`oauth_cookie_secret_${route.id}`,au.oauth_cookie_secret||'',{label:'Cookie Secret *',password:true,hint:'min 16 chars'})}</div><div><label class="wz-label" style="font-size:11px;">Redirect URL <span style="color:var(--danger)">*</span></label><input type="text" data-wz-route-field="authData.oauth_redirect_url" class="wz-input" placeholder="https://app.example.com/auth/callback" value="${_esc(au.oauth_redirect_url||'')}"></div></div></div>
        </div>`;
    }

    function _buildServerlessEngine(el, route) {
        const tabNav=document.createElement('div'),workers=document.createElement('div'),rests=document.createElement('div');
        workers.style.paddingTop='10px'; rests.style.cssText='padding-top:10px;display:none;';
        el.appendChild(tabNav);el.appendChild(workers);el.appendChild(rests);
        tabs.render(tabNav,[{key:'workers',label:'Workers'},{key:'rests',label:'Replay Proxies'}],{active:'workers',variant:'pill',onChange:k=>{workers.style.display=k==='workers'?'':'none';rests.style.display=k==='rests'?'':'none';}});

        // Workers
        let wkList=[];try{wkList=JSON.parse(route.engineData?.serverless_workers||'[]');}catch{}
        const wkEl=document.createElement('div');wkEl.className='wz-backend-list';
        const wkAddBtn=document.createElement('button');wkAddBtn.className='btn small';wkAddBtn.textContent='+ Add Worker';wkAddBtn.style.marginTop='8px';
        workers.innerHTML=`<div class="wz-hint" style="margin-bottom:8px;">Workers are managed OS processes — HTTP-triggered, cron, background daemons, or one-shot startup tasks.</div>`;
        workers.appendChild(wkEl);workers.appendChild(wkAddBtn);
        function syncW(){route.engineData=route.engineData||{};route.engineData.serverless_workers=JSON.stringify(wkList);}
        function renderWorkers(){wkEl.innerHTML=wkList.map((w,i)=>`<div class="wz-item-card" data-idx="${i}"><div class="wz-item-row"><input type="text" class="wz-input wz-wk-name" placeholder="Name (e.g. pdf-renderer)" value="${_esc(w.name||'')}" style="flex:1;min-width:0;"><input type="text" class="wz-input-sm wz-wk-engine" placeholder="Engine" value="${_esc(w.engine||'')}" style="width:90px;" title="Execution engine: node, python3, native, etc."><button type="button" class="btn small wz-wk-remove" style="color:var(--danger);border-color:rgba(255,59,48,0.4);flex-shrink:0;width:var(--btn-h-sm);padding:0;">✕</button></div><input type="text" class="wz-input wz-wk-command" placeholder="Command — e.g. node scripts/pdf.js" value="${_esc((w.command||[]).join(' '))}" style="margin-top:5px;"><div class="wz-item-row" style="margin-top:8px;gap:16px;flex-wrap:wrap;"><label class="wz-check"><input type="checkbox" class="wz-wk-bg"${w.background?' checked':''}> Background daemon</label><label class="wz-check"><input type="checkbox" class="wz-wk-once"${w.run_once?' checked':''}> Run once at startup</label><label class="wz-check"><input type="checkbox" class="wz-wk-landlock"${w.landlock!==false?' checked':''}> Landlock sandbox</label></div><div class="wz-item-row" style="margin-top:8px;gap:8px;"><div style="flex:1;"><label class="wz-label" style="font-size:11px;">Schedule (cron)</label><input type="text" class="wz-input wz-wk-schedule" placeholder="0 2 * * * or blank" value="${_esc(w.schedule||'')}"></div><div style="width:90px;flex-shrink:0;"><label class="wz-label" style="font-size:11px;">Timeout</label><input type="text" class="wz-input wz-wk-timeout" placeholder="30s" value="${_esc(w.timeout||'')}"></div><div style="width:90px;flex-shrink:0;"><label class="wz-label" style="font-size:11px;">Restart</label><select class="wz-select-inline wz-wk-restart" style="width:100%;"><option value=""${!w.restart?' selected':''}>No</option><option value="always"${w.restart==='always'?' selected':''}>Always</option><option value="on-failure"${w.restart==='on-failure'?' selected':''}>On failure</option></select></div></div></div>`).join('')||'<div class="wz-hint" style="padding:6px 0;">No workers yet.</div>';
        wkEl.querySelectorAll('[data-idx]').forEach(row=>{const i=+row.dataset.idx;row.querySelector('.wz-wk-name')?.addEventListener('input',e=>{wkList[i].name=e.target.value;syncW();});row.querySelector('.wz-wk-engine')?.addEventListener('input',e=>{wkList[i].engine=e.target.value;syncW();});row.querySelector('.wz-wk-command')?.addEventListener('input',e=>{wkList[i].command=e.target.value.split(/\s+/).filter(Boolean);syncW();});row.querySelector('.wz-wk-schedule')?.addEventListener('input',e=>{wkList[i].schedule=e.target.value;syncW();});row.querySelector('.wz-wk-timeout')?.addEventListener('input',e=>{wkList[i].timeout=e.target.value;syncW();});row.querySelector('.wz-wk-restart')?.addEventListener('change',e=>{wkList[i].restart=e.target.value;syncW();});row.querySelector('.wz-wk-bg')?.addEventListener('change',e=>{wkList[i].background=e.target.checked;syncW();});row.querySelector('.wz-wk-once')?.addEventListener('change',e=>{wkList[i].run_once=e.target.checked;syncW();});row.querySelector('.wz-wk-landlock')?.addEventListener('change',e=>{wkList[i].landlock=e.target.checked;syncW();});row.querySelector('.wz-wk-remove')?.addEventListener('click',()=>{wkList.splice(i,1);renderWorkers();syncW();});});}
        wkAddBtn.addEventListener('click',()=>{wkList.push({name:'',command:[],background:false,run_once:false,landlock:true,schedule:'',timeout:'',engine:'',restart:''});renderWorkers();syncW();});
        renderWorkers();

        // REST Proxies
        let restList=[];try{restList=JSON.parse(route.engineData?.serverless_rests||'[]');}catch{}
        const restEl=document.createElement('div');restEl.className='wz-backend-list';
        const restAddBtn=document.createElement('button');restAddBtn.className='btn small';restAddBtn.textContent='+ Add REST Proxy';restAddBtn.style.marginTop='8px';
        rests.innerHTML=`<div class="wz-hint" style="margin-bottom:8px;">Each Replay proxy forwards requests to an external API and injects credentials server-side. Leave URL empty to use relay mode (specify allowed_domains instead).</div>`;
        rests.appendChild(restEl);rests.appendChild(restAddBtn);
        function syncR(){route.engineData=route.engineData||{};route.engineData.serverless_rests=JSON.stringify(restList);}
        function renderRests(){restEl.innerHTML=restList.map((r,i)=>`<div class="wz-item-card" data-idx="${i}"><div class="wz-item-row"><input type="text" class="wz-input wz-rest-name" placeholder="Name (e.g. stripe)" value="${_esc(r.name||'')}" style="flex:1;min-width:0;"><select class="wz-select-inline wz-rest-method" style="width:80px;flex-shrink:0;">${['GET','POST','PUT','DELETE','PATCH'].map(m=>`<option${r.method===m?' selected':''}>${m}</option>`).join('')}</select><button type="button" class="btn small wz-rest-remove" style="color:var(--danger);border-color:rgba(255,59,48,0.4);flex-shrink:0;width:var(--btn-h-sm);padding:0;">✕</button></div><input type="text" class="wz-input wz-rest-url" placeholder="https://api.example.com/endpoint" value="${_esc(r.url||'')}" style="margin-top:5px;"><div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:8px;"><div><label class="wz-label" style="font-size:11px;">Timeout</label><input type="text" class="wz-input wz-rest-timeout" placeholder="30s" value="${_esc(r.timeout||'')}"></div><div><label class="wz-label" style="font-size:11px;">Referer mode</label><select class="wz-select-inline wz-rest-referer"><option value=""${!r.referer_mode?' selected':''}>Auto</option><option value="forward"${r.referer_mode==='forward'?' selected':''}>Forward</option><option value="none"${r.referer_mode==='none'?' selected':''}>None</option><option value="fixed"${r.referer_mode==='fixed'?' selected':''}>Fixed</option></select></div></div><div class="wz-item-row wz-rest-referer-val-row" style="margin-top:5px;${r.referer_mode==='fixed'?'':'display:none;'}"><input type="text" class="wz-input wz-rest-referer-val" placeholder="https://fixed-referer.example.com" value="${_esc(r.referer_value||'')}"></div><div class="wz-item-row" style="margin-top:8px;gap:16px;flex-wrap:wrap;"><label class="wz-check"><input type="checkbox" class="wz-rest-fwdq"${r.forward_query?' checked':''}> Forward query params</label><label class="wz-check"><input type="checkbox" class="wz-rest-striphdr"${r.strip_headers?' checked':''}> Strip request headers</label></div></div>`).join('')||'<div class="wz-hint" style="padding:6px 0;">No REST proxies yet.</div>';
        restEl.querySelectorAll('[data-idx]').forEach(row=>{const i=+row.dataset.idx;row.querySelector('.wz-rest-name')?.addEventListener('input',e=>{restList[i].name=e.target.value;syncR();});row.querySelector('.wz-rest-url')?.addEventListener('input',e=>{restList[i].url=e.target.value;syncR();});row.querySelector('.wz-rest-timeout')?.addEventListener('input',e=>{restList[i].timeout=e.target.value;syncR();});row.querySelector('.wz-rest-method')?.addEventListener('change',e=>{restList[i].method=e.target.value;syncR();});row.querySelector('.wz-rest-fwdq')?.addEventListener('change',e=>{restList[i].forward_query=e.target.checked;syncR();});row.querySelector('.wz-rest-striphdr')?.addEventListener('change',e=>{restList[i].strip_headers=e.target.checked;syncR();});row.querySelector('.wz-rest-remove')?.addEventListener('click',()=>{restList.splice(i,1);renderRests();syncR();});const refererSel=row.querySelector('.wz-rest-referer'),refererValRow=row.querySelector('.wz-rest-referer-val-row');refererSel?.addEventListener('change',e=>{restList[i].referer_mode=e.target.value;if(refererValRow)refererValRow.style.display=e.target.value==='fixed'?'':'none';syncR();});row.querySelector('.wz-rest-referer-val')?.addEventListener('input',e=>{restList[i].referer_value=e.target.value;syncR();});});}
        restAddBtn.addEventListener('click',()=>{restList.push({name:'',method:'GET',url:'',allowed_domains:[],timeout:'',forward_query:false,strip_headers:false,referer_mode:'',referer_value:'',headers:[]});renderRests();syncR();});
        renderRests();
    }

    // Route panel builder
    function renderRoutePanel(route, panelsEl) {
        const div=document.createElement('div');div.setAttribute('data-tab',route.id);div.style.padding='2px 0';
        const pathRow=document.createElement('div');pathRow.className='wz-field-group';pathRow.innerHTML=`<label class="wz-label">Route Path</label><input type="text" class="wz-input wz-route-path" placeholder="/api" value="${_esc(route.path)}"><div class="wz-hint">Must start with <code>/</code></div>`;
        pathRow.querySelector('.wz-route-path').addEventListener('input',e=>{route.path=e.target.value;_sync();rebuildTabs();});
        div.appendChild(pathRow);

        const subTabNav=document.createElement('div');subTabNav.id='wzSubTabs_'+route.id;
        const subPanels=document.createElement('div');subPanels.id='wzSubPanels_'+route.id;
        div.appendChild(subTabNav);div.appendChild(subPanels);

        const enginePanel=document.createElement('div');enginePanel.style.paddingTop='12px';
        if(hostType==='web'){enginePanel.innerHTML=_webEngineHTML(route);_wireToggleCards(enginePanel);_wireWebEngine(enginePanel,route);}
        else if(hostType==='proxy'){enginePanel.innerHTML=_proxyEngineHTML(route);_wireProxyEngine(enginePanel,route);}
        else if(hostType==='serverless'){_buildServerlessEngine(enginePanel,route);}

        const extrasPanel=document.createElement('div');extrasPanel.style.cssText='padding-top:12px;display:none;';extrasPanel.innerHTML=extrasHTML(route);_wireToggleCards(extrasPanel);wireExtras(extrasPanel,route,_sync);
        const authPanel=document.createElement('div');authPanel.style.cssText='padding-top:12px;display:none;';authPanel.innerHTML=_authPlaceholder(route);_wireToggleCards(authPanel);
        const headersPanel=document.createElement('div');headersPanel.style.cssText='padding-top:12px;display:none;';headersPanel.innerHTML=headersHTML(route);wireHeaders(headersPanel,route,_sync);

        subPanels.appendChild(enginePanel);subPanels.appendChild(extrasPanel);subPanels.appendChild(authPanel);subPanels.appendChild(headersPanel);

        tabs.render(subTabNav,[{key:'engine',label:'Engine'},{key:'extras',label:'Extras'},{key:'auth',label:'Auth'},{key:'headers',label:'Headers'}],{active:'engine',variant:'pill',onChange:k=>{enginePanel.style.display=k==='engine'?'':'none';extrasPanel.style.display=k==='extras'?'':'none';authPanel.style.display=k==='auth'?'':'none';headersPanel.style.display=k==='headers'?'':'none';}});

        div.addEventListener('change',()=>{_collect(div,route);_sync();});
        div.addEventListener('input', ()=>{_collect(div,route);_sync();});
        wireValueInput(div,`jwt_secret_${route.id}`,v=>{route.authData=route.authData||{};route.authData.jwt_secret=v;_sync();});
        wireValueInput(div,`oauth_client_secret_${route.id}`,v=>{route.authData=route.authData||{};route.authData.oauth_client_secret=v;_sync();});
        wireValueInput(div,`oauth_cookie_secret_${route.id}`,v=>{route.authData=route.authData||{};route.authData.oauth_cookie_secret=v;_sync();});
        panelsEl.appendChild(div);
    }

    // Tab management
    const tabNavEl=find('#wzRouteTabs'), panelsEl=find('#wzRoutePanels');

    function rebuildTabs(){if(tabNavEl)tabNavEl.innerHTML='';tabs.render(tabNavEl,_routes.map(r=>({key:r.id,label:r.path||'/'})),{panels:panelsEl,active:_activeRouteId,variant:'line',onChange:k=>{_activeRouteId=k;}});}

    _routes.forEach(r=>renderRoutePanel(r,panelsEl));
    rebuildTabs();

    on('#wzAddRouteBtn','click',()=>{const nr=wizard.newRoute('/new');_routes.push(nr);_activeRouteId=nr.id;renderRoutePanel(nr,panelsEl);rebuildTabs();_sync();});

    emit('wizard:set-validate',{validate:()=>{
        if(!_routes.length)return'Add at least one route';
        for(const r of _routes){if(!r.path?.startsWith('/'))return'Route path must start with /';if(r.engineData?.web_static_on&&!(r.engineData?.web_root||'').trim())return`Route "${r.path}": Static Files requires a root directory path`;if(r.engineData?.git_enabled&&!(r.engineData?.git_url||'').trim())return`Route "${r.path}": Git Deploy requires a repository URL`;if(r.engineData?.php_enabled&&!(r.engineData?.php_address||'').trim())return`Route "${r.path}": PHP is enabled but FastCGI address is missing`;}
        return null;
    }});

    onUnmount(()=>{});
    ready();
}
