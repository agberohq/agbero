/**
 * pages/hosts/index.js — Hosts list page.
 */
import { emit, listen, ui, clipboard, notify, pagination, Search, countdown } from '../../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { store, api, utils, oja } = inject('app');
    const { isOn, fmtNum } = utils;
    const { modal } = oja;

    function esc(str) { return String(str||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    function healthDot(b, has) {
        if (!has) return { cls:'warn', title:'No data' };
        const s = b.health?.status || 'Unknown';
        if (!b.alive||s==='Dead'||s==='Unhealthy') return { cls:'down', title:s!=='Unknown'?s:'Dead' };
        if (s==='Degraded') return { cls:'warn', title:'Degraded' };
        if (s==='Healthy')  return { cls:'ok',   title:'Healthy' };
        return { cls:b.alive?'info':'down', title:b.alive?'Unverified':'Dead' };
    }

    function backendRowHtml(b, cfgB, statBEs, bIdx) {
        const url=b.url||b.address||cfgB.address||'',w=cfgB.weight!==undefined?cfgB.weight:(b.weight||1);
        const {cls,title}=healthDot(b,!!statBEs[bIdx]);
        const p99=b.latency_us?.p99?(b.latency_us.p99/1000).toFixed(0)+'ms':null,p95=b.latency_us?.p95?(b.latency_us.p95/1000).toFixed(0)+'ms':null;
        const score=b.health?.score??null,trend=b.health?.trend??0,reqs=b.total_reqs||0,consec=b.health?.consecutive_failures||0,downtime=b.health?.downtime||null;
        const trendArrow=trend>0?`<span class="be-trend up">↑</span>`:trend<0?`<span class="be-trend dn">↓</span>`:'';
        const tags=[score!==null?`<span class="be-tag" style="color:${score>=80?'var(--success)':score>=50?'var(--warning)':'var(--danger)'}">${score}${trendArrow}</span>`:null,p99?`<span class="be-tag" style="color:var(--info)">p99 ${p99}</span>`:null,p95?`<span class="be-tag" style="color:var(--text-mute)">p95 ${p95}</span>`:null,consec>0?`<span class="be-tag" style="color:var(--danger)">${consec}f</span>`:null,`<span class="be-tag" style="color:var(--text-mute)">W:${w}</span>`,reqs?`<span class="be-tag" style="color:var(--text-main)">${fmtNum(reqs)}</span>`:null].filter(Boolean).join('');
        const downtimeHtml=(downtime&&cls==='down')?`<span class="be-downtime">down ${esc(downtime)}</span>`:'';
        return `<div class="backend-row ${cls==='down'?'down':''}"><div class="be-left"><span class="dot ${cls}" title="${esc(title)}"></span><span class="be-url copyable" data-action="copy-url" data-url="${esc(url)}">${esc(url)}</span>${b.in_flight>0?`<span class="be-tag be-tag-warn">⚡ ${b.in_flight}</span>`:''}${downtimeHtml}</div><div class="be-tags">${tags}</div></div>`;
    }

    function routeBadges(r) {
        const t=[];
        if(r.web){if(isOn(r.web.git?.enabled))t.push(`<span class="badge info">GIT ${r.web.git.mode?r.web.git.mode.toUpperCase():''}</span>`);if(r.web.root){if(isOn(r.web.markdown?.enabled)){t.push(`<span class="badge info">${r.web.markdown?.view==='browse'?'📖 BROWSE':'MD'}</span>`);}else{t.push('<span class="badge">STATIC</span>');}}if(r.web.listing)t.push('<span class="badge">LISTING</span>');if(isOn(r.web.php?.enabled))t.push('<span class="badge" style="background:#6a73a6;color:#fff;border-color:#6a73a6;">PHP</span>');}
        if(r.serverless&&isOn(r.serverless.enabled)){const wc=(r.serverless.workers||[]).length,rc=(r.serverless.replay||[]).length;if(wc)t.push(`<span class="badge warn">WORKER (${wc})</span>`);if(rc)t.push(`<span class="badge info">REPLAY (${rc})</span>`);if(isOn(r.serverless.git?.enabled))t.push('<span class="badge info">GIT</span>');}
        const beServers=r.backends?.servers||[];if(isOn(r.backends?.enabled)&&beServers.length>0){if(beServers.length===1){t.push('<span class="badge info">PROXY</span>');}else{const s=(r.backends.strategy||'round_robin').replace(/_/g,' ').replace(/\b\w/g,c=>c.toUpperCase());t.push(`<span class="badge info">LB: ${s} (${beServers.length})</span>`);}}
        if(isOn(r.cache?.enabled))t.push('<span class="badge success">CACHE</span>');if(isOn(r.wasm?.enabled))t.push('<span class="badge transform">WASM</span>');if(isOn(r.rate_limit?.enabled))t.push('<span class="badge traffic">RATE LIMIT</span>');if(isOn(r.cors?.enabled))t.push('<span class="badge">CORS</span>');if(isOn(r.compression?.enabled))t.push('<span class="badge">GZIP</span>');if(isOn(r.firewall?.enabled))t.push('<span class="badge danger">FIREWALL</span>');if(r.allowed_ips?.length)t.push('<span class="badge warn">IP FILTER</span>');if(isOn(r.fallback?.enabled))t.push('<span class="badge">FALLBACK</span>');if(r.rewrites?.length)t.push(`<span class="badge">REWRITE (${r.rewrites.length})</span>`);if(r.strip_prefixes?.length)t.push(`<span class="badge">STRIP (${r.strip_prefixes.length})</span>`);if(r.env&&Object.keys(r.env).length)t.push('<span class="badge">ENV</span>');
        const auths=[];if(isOn(r.basic_auth?.enabled))auths.push('BASIC');if(isOn(r.jwt_auth?.enabled))auths.push('JWT');if(isOn(r.forward_auth?.enabled))auths.push('FWD');if(isOn(r.oauth?.enabled))auths.push('OAUTH');if(auths.length)t.push(`<span class="badge sec">🔒 ${auths.join(', ')}</span>`);
        return t.length?`<div style="display:flex;gap:5px;flex-wrap:wrap;margin-left:10px;">${t.join('')}</div>`:'';
    }

    function hostAggregateDot(hStats){const all=[...(hStats.routes||[]).flatMap(r=>r.backends||[]),...(hStats.proxies||[]).flatMap(p=>p.backends||[])];if(!all.length)return{cls:'info',label:''};const dead=all.filter(b=>!b.alive).length,degraded=all.filter(b=>b.health?.status==='Degraded').length;if(dead===all.length)return{cls:'down',label:'all down'};if(dead>0)return{cls:'warn',label:`${dead} down`};if(degraded>0)return{cls:'warn',label:'degraded'};return{cls:'ok',label:''};}

    function sparkBarHtml(hostname) {
        const spark  = store.get('sparklines.' + hostname) || {};
        const points = spark.p99 || [];
        if (points.length < 3) return '';
        const maxVal = Math.max(...points, 1);
        const segs   = points.map(v => {
            const ratio  = Math.min(v / maxVal, 1);
            const hPct   = Math.max(Math.round(ratio * 100), v > 0 ? 8 : 2);
            const hue    = Math.round(120 - Math.min(v / 500, 1) * 120);
            const color  = v > 2000 ? 'var(--danger)' : v > 500 ? 'var(--warning)' : `hsl(${hue},65%,48%)`;
            return `<span class="spark-seg" style="background:${color};flex:1;min-width:3px;height:${hPct}%;border-radius:1px 1px 0 0;" title="${v > 0 ? v.toFixed(0) + 'ms' : 'idle'}"></span>`;
        }).join('');
        return `<div class="host-spark-bar" data-action="open-perf" data-hostname="${esc(hostname)}" style="display:flex;align-items:flex-end;gap:1px;height:24px;cursor:pointer;min-width:60px;">${segs}</div>`;
    }

    function hostCardHtml(hostname,hStats,cfgHost,term,certificates){
        const cfgRoutes=cfgHost.routes||[],cfgProxies=cfgHost.proxies||[],isProtected=isOn(cfgHost.protected),agg=hostAggregateDot(hStats),tlsMode=cfgHost.tls?.mode||'';
        let tlsText='AUTO TLS',tlsClass='success',tlsTitle='Managed by Agbero';
        if(tlsMode===''||tlsMode==='none'){tlsClass='error';tlsText='NO TLS';tlsTitle='HTTP only';}else if(tlsMode==='local'){tlsClass='warning';tlsText='LOCAL TLS';}else if(tlsMode==='custom_ca'){tlsClass='warning';tlsText='CUSTOM CA';}
        const cert=certificates.find(c=>c.domain===hostname);
        if(cert?.days_left!=null){const expDate=cert.expires_at?new Date(cert.expires_at).toLocaleDateString():'—';tlsTitle=`Expires: ${expDate} (${countdown.daysLabel(cert.days_left)})`;if(cert.days_left<7){tlsClass=cert.days_left<0?'error':'warning';tlsText=cert.days_left<0?'EXPIRED':`${cert.days_left}d left`;}}
        const kebab = `<button class="btn-kebab" data-action="host-menu" data-hostname="${esc(hostname)}" data-protected="${isProtected}" title="Actions">⋮</button>`;
        const statRoutes=hStats.routes||[];
        let routesHtml='';
        for(let idx=0;idx<Math.max(cfgRoutes.length,statRoutes.length);idx++){const cfgRoute=cfgRoutes[idx]||{},statRoute=statRoutes[idx]||{},path=esc(cfgRoute.path||statRoute.path||'/'),proto=esc((cfgRoute.protocol||statRoute.protocol||'http').toUpperCase()),configBEs=cfgRoute.backends?.servers||[],statBEs=statRoute.backends||[],displayBEs=statBEs.length?statBEs:configBEs,backendsHtml=displayBEs.length?`<div class="backend-list">${displayBEs.map((b,i)=>backendRowHtml(b,configBEs[i]||{},statBEs,i)).join('')}</div>`:'';routesHtml+=`<div class="route-block clickable" data-action="open-route" data-host="${esc(hostname)}" data-idx="${idx}" data-type="route"><div class="route-header"><span class="badge ${proto==='HTTP'?'success':'info'}">${proto}</span><span class="route-path">${path}</span>${routeBadges(cfgRoute)}</div>${backendsHtml}</div>`;}
        for(let idx=0;idx<Math.max(cfgProxies.length,(hStats.proxies||[]).length);idx++){const cfgProxy=cfgProxies[idx]||{},statProxy=(hStats.proxies||[])[idx]||{},proxyName=esc(cfgProxy.name||statProxy.name||statProxy.path||'*'),listenAddr=esc(cfgProxy.listen||statProxy.name?.replace(/\s.*$/,'')||''),statBEs=statProxy.backends||[],configBEs=cfgProxy.backends||[],displayBEs=statBEs.length?statBEs:configBEs,backendsHtml=displayBEs.length?`<div class="backend-list">${displayBEs.map((b,i)=>backendRowHtml(b,configBEs[i]||{},statBEs,i)).join('')}</div>`:'';
            // Detect protocol from config or stat
            const isUDP=(cfgProxy.protocol||statProxy.protocol||'').toLowerCase()==='udp';
            const protoBadge=isUDP?'<span class="badge info">UDP</span>':'<span class="badge info">TCP</span>';
            const matcherBadge=isUDP&&(cfgProxy.matcher||statProxy.matcher)?`<span class="badge">${esc(cfgProxy.matcher||statProxy.matcher)}</span>`:'';
            const activeSessions=isUDP&&statProxy.active_sessions>0?`<span class="badge" style="background:var(--hover-bg);color:var(--text-mute);border:1px solid var(--border);">${fmtNum(statProxy.active_sessions)} sessions</span>`:'';
            routesHtml+=`<div class="route-block clickable" data-action="open-route" data-host="${esc(hostname)}" data-idx="${idx}" data-type="proxy"><div class="route-header">${protoBadge}${matcherBadge}<span class="route-path">${listenAddr?listenAddr+' → ':''}${proxyName}</span>${cfgProxy.sni?`<span class="badge">SNI: ${esc(cfgProxy.sni)}</span>`:''}${activeSessions}</div>${backendsHtml}</div>`;}
        const hostMeta=[];if(cfgHost.compression)hostMeta.push('<span class="badge">GZIP</span>');if(cfgHost.bind?.length)hostMeta.push(`<span class="badge">:${cfgHost.bind.join(', :')}</span>`);
        const sourceFile=cfgHost.source_file?`<span class="host-source-file" title="Config file">${esc(cfgHost.source_file)}</span>`:'';
        return `<div class="host-row" data-hostname="${esc(hostname)}"><div class="host-header"><div class="host-header-left"><span class="dot ${agg.cls}" title="${esc(agg.label||agg.cls)}" style="flex-shrink:0;margin-right:6px;"></span><span class="host-name clickable" data-action="open-host-route" data-hostname="${esc(hostname)}">${esc(hostname)}</span><span class="badge ${tlsClass}" title="${esc(tlsTitle)}" style="margin-left:6px;">${tlsText}</span>${isProtected?`<span class="badge" style="background:var(--hover-bg);color:var(--text-mute);border:1px solid var(--border);margin-left:2px;" title="Protected">PROTECTED</span>`:''}${hStats.total_reqs?`<span class="badge" style="background:var(--hover-bg);color:var(--text-mute);border:1px solid var(--border);margin-left:2px;">${fmtNum(hStats.total_reqs)} reqs</span>`:''} ${hostMeta.join('')}</div><div class="host-header-right">${sourceFile}${sparkBarHtml(hostname)}${kebab}</div></div>${cfgHost.domains?.length>1?`<div class="host-meta" style="padding:2px 12px 4px;font-size:11px;color:var(--text-mute);">${cfgHost.domains.map(esc).join(', ')}</div>`:''} ${routesHtml}</div>`;
    }

    const pg = pagination({ pageSize: store.get('hosts.pageSize')||20, pageSizes:[10,20,50,100], onPageChange:(p,size)=>{store.set('hosts.pageSize',size);renderPage();} });
    let stopPager=null, _searchIndex=null;

    function _buildSearchIndex(){const hostsStats=(store.get('hostsData')||{}).stats||{},configHosts=(store.get('lastConfig')||{}).hosts||{};const docs=Object.entries(hostsStats).map(([hostname,hStats])=>{const cfg=configHosts[hostname]||{};return{id:hostname,hostname,domains:(cfg.domains||[hostname]).join(' '),backends:(hStats.routes||[]).flatMap(r=>(r.backends||[]).map(b=>b.url||b.address||'')).join(' '),paths:(hStats.routes||[]).map(r=>r.path||'/').join(' ')};});_searchIndex=new Search(docs,{fields:['hostname','domains','backends','paths'],weights:{hostname:3,domains:2,backends:1,paths:1},fuzzy:false});}
    function filteredEntries(){const hostsStats=(store.get('hostsData')||{}).stats||{},configHosts=(store.get('lastConfig')||{}).hosts||{},term=(store.get('searchTerm')||'').trim();if(!term)return Object.entries(hostsStats);if(term.length<3){const t=term.toLowerCase();return Object.entries(hostsStats).filter(([h])=>h.toLowerCase().includes(t));}if(!_searchIndex)_buildSearchIndex();return _searchIndex.search(term).map(r=>[r.doc.hostname,hostsStats[r.doc.hostname]]).filter(([,v])=>v!==undefined);}

    function renderPage(){const configHosts=(store.get('lastConfig')||{}).hosts||{},certificates=store.get('certificates')||[],containerEl=find('#hostsContainer');if(!containerEl)return;const hostsStats=(store.get('hostsData')||{}).stats||{};if(!Object.keys(hostsStats).length){containerEl.innerHTML=`<div class="empty-state"><span>🔮 No hosts configured</span><span>Add a host in agbero.hcl and restart</span></div>`;pg.updateTotal(0);return;}const all=filteredEntries(),term=(store.get('searchTerm')||'').toLowerCase();if(!all.length){containerEl.innerHTML=`<div class="empty-state"><span>🔍 No hosts matching "${esc(term)}"</span></div>`;pg.updateTotal(0);return;}pg.updateTotal(all.length);containerEl.innerHTML=pg.slice(all).map(([hostname,hStats])=>hostCardHtml(hostname,hStats,configHosts[hostname]||{},term,certificates)).join('');}

    function syncList(){_searchIndex=null;pg.reset();renderPage();}

    async function refresh(){const btn=find('#refreshHostsBtn');if(btn)ui.btn.loading(btn,'…');const data=await api.fetchUptime();if(btn)ui.btn.reset(btn);if(!data)return;store.set('hostsData',{stats:data.hosts||{}});syncList();}

    const savedTerm=store.get('searchTerm')||'', searchInput=find('#hostSearch');
    if(searchInput&&savedTerm)searchInput.value=savedTerm;
    if(!store.get('hostsData')){find('#hostsContainer').innerHTML=`<div class="loading-rows"><div class="loading-row"></div><div class="loading-row"></div><div class="loading-row"></div></div>`;}else{syncList();}
    const pagerEl=find('#hostsPager');if(pagerEl)stopPager=pg.mount(pagerEl);

    let searchTimeout;
    on('#hostSearch','input',(e,el)=>{clearTimeout(searchTimeout);const cb=find('#hostSearchClear');if(cb)cb.style.display=el.value?'':'none';searchTimeout=setTimeout(()=>{store.set('searchTerm',el.value.trim());syncList();},150);});
    on('#hostSearchClear','click',()=>{const inp=find('#hostSearch');if(inp){inp.value='';inp.focus();}find('#hostSearchClear').style.display='none';store.set('searchTerm','');syncList();});
    if(savedTerm&&find('#hostSearchClear'))find('#hostSearchClear').style.display='';
    on('#addHostBtn',          'click', () => emit('app:navigate', { path: '/add-host' }));
    on('#addHostAdvancedBtn',  'click', () => emit('host:open-create-hcl'));
    on('#refreshHostsBtn', 'click', refresh);
    on('[data-action="open-route"]',     'click',(e,b)=>emit('drawer:open-route',{host:b.dataset.host,idx:parseInt(b.dataset.idx),type:b.dataset.type}));
    on('[data-action="open-host-route"]','click',(e,b)=>{e.stopPropagation();emit('drawer:open-route',{host:b.dataset.hostname,idx:0,type:'route'});});
    on('[data-action="host-menu"]', 'click', async (e, btn) => {
        e.stopPropagation();
        const h          = btn?.dataset.hostname;
        const protected_ = btn?.dataset.protected === 'true';
        if (!h) return;
        const { clickmenu } = inject('app').oja;
        const items = [];
        if (!protected_) {
            items.push({ label: 'Edit HCL', icon: '✏️', action: async () => {
                    ui.btn.loading(btn, '…');
                    const hcl = await api.getHostHCL(h);
                    ui.btn.reset(btn);
                    if (!hcl) { notify.show('Could not load HCL — try again', 'error'); return; }
                    emit('host:open-edit-hcl', { domain: h, hcl });
                }});
            items.push({ separator: true });
            items.push({ label: 'Block IP…', icon: '🛡️', action: () => {
                    emit('firewall:open-rule', { host: h });
                }});
            items.push({ separator: true });
            items.push({ label: 'Delete', icon: '🗑️', danger: true, action: () => {
                    emit('app:strict-delete', {
                        message: `Permanently delete configuration for <strong>${esc(h)}</strong>. This drops all traffic immediately.`,
                        targetText: h,
                        onConfirm: async () => { await api.deleteHost(h); notify.show(`${h} deleted`, 'success'); refresh(); },
                    });
                }});
        } else {
            items.push({ label: 'Protected — cannot edit or delete', icon: '🔒', disabled: true });
        }
        clickmenu.show(e.clientX, e.clientY, items);
    });
    on('[data-action="open-perf"]','click',(e,el)=>{if(e.target.closest('.btn'))return;emit('perf:open',{hostname:el.dataset.hostname});});
    on('[data-action="copy-url"]','click',(e,btn)=>{e.stopPropagation();clipboard.write(btn.dataset.url).then(()=>notify.show('Copied','success')).catch(()=>{});});


    const unsubSearch  = listen('hosts:search',   ({term})=>{const el=find('#hostSearch');if(el)el.value=term;store.set('searchTerm',term);syncList();});
    const unsubEdit    = listen('host:open-edit',  ({domain}) => {
        // Shell.js handles this event with its own scoped find() — we just emit it
        // Do NOT attempt find() on #editHostTitle etc here — those elements are in shell.html
        // This listener is kept only to avoid the event being unhandled; shell.js is the actor.
    });
    const unsubRefresh = listen('hosts:refresh', refresh);
    const unsubMetrics = listen('metrics:updated', renderPage);
    if(!store.get('hostsData'))refresh();

    onUnmount(()=>{unsubSearch();unsubEdit();unsubRefresh();unsubMetrics();stopPager?.();stopPager=null;});
    ready();
}