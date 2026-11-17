/**
 * pages/add-host/step-domain.js — Domain + TLS step.
 */
import { emit } from '../../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, props, inject }) {
    const { api } = inject('app');
    const { wizard } = props;

    function _isLocal(d) {
        const h=(d||'').trim().toLowerCase();
        if(!h)return false;
        if(/^\d+\.\d+\.\d+\.\d+$/.test(h))return true;
        const exact=['localhost'];
        const suffixes=['.localhost','.local','.internal','.test','.example'];
        return exact.includes(h)||suffixes.some(s=>h===s.slice(1)||h.endsWith(s));
    }
    function _currentMode(){return find('[name="tls_mode"]:checked')?.value||'auto';}
    function _applyTLSVisibility(){
        const local=_isLocal(find('#wzDomainInput')?.value||''),mode=_currentMode(),tlsSection=find('#wzTLSSection');
        if(tlsSection)tlsSection.classList.toggle('wz-collapsed',local);
        const leF=find('#wzLEFields'),localF=find('#wzLocalCertFields'),caF=find('#wzCustomCAFields');
        if(leF)leF.style.display=(!local&&mode==='auto')?'':'none';
        if(localF)localF.style.display=(!local&&mode==='local')?'':'none';
        if(caF)caF.style.display=(!local&&mode==='custom_ca')?'':'none';
    }

    const d = wizard.draftGet();
    const domainInput=find('#wzDomainInput');
    if(domainInput)domainInput.value=d.domain||'';
    if(find('#wzLEEmail'))find('#wzLEEmail').value=d.tls_le_email||'';
    if(find('#wzLEStaging'))find('#wzLEStaging').checked=d.tls_le_staging==='on';
    if(find('#wzTLSCert'))find('#wzTLSCert').value=d.tls_cert||'';
    if(find('#wzTLSKey'))find('#wzTLSKey').value=d.tls_key||'';
    if(find('#wzCARoot'))find('#wzCARoot').value=d.tls_ca_root||'';
    if(find('#wzClientAuth'))find('#wzClientAuth').value=d.tls_client_auth||'';
    if(find('#wzClientCAs'))find('#wzClientCAs').value=(d.tls_client_cas||[]).join('\n');
    if(find('#wzNotFoundPage'))find('#wzNotFoundPage').value=d.host_not_found_page||'';
    if(find('#wzBind'))find('#wzBind').value=(d.host_bind||[]).join(', ');
    if(find('#wzHostCompression'))find('#wzHostCompression').checked=!!d.host_compression;
    if(find('#wzMaxBodySize'))find('#wzMaxBodySize').value=d.host_max_body_size||'';
    if(d.tls_mode){const radio=find(`[name="tls_mode"][value="${d.tls_mode}"]`);if(radio)radio.checked=true;}
    const protectedTristate=find('[data-field="host_protected"]');
    if(protectedTristate&&d.host_protected){protectedTristate.querySelectorAll('.wz-ts-opt').forEach(btn=>btn.classList.toggle('active',btn.dataset.val===d.host_protected));}
    _applyTLSVisibility();

    let _domainDebounce=null;
    domainInput?.addEventListener('input',()=>{
        const val=(domainInput.value||'').trim().toLowerCase();
        wizard.draftSet('domain',val);_applyTLSVisibility();
        const domainStatus=find('#wzDomainStatus');if(domainStatus)domainStatus.textContent='';
        clearTimeout(_domainDebounce);if(!val||val.includes('://')||val.length<3)return;
        _domainDebounce=setTimeout(async()=>{try{const exists=await api.checkHostExists(val);const ds=find('#wzDomainStatus');if(ds){ds.textContent=exists?'⚠ already exists':'✓ available';ds.style.color=exists?'var(--warning)':'var(--success)';}}catch{}},600);
    });

    findAll('[name="tls_mode"]').forEach(r=>{r.addEventListener('change',()=>{wizard.draftSet('tls_mode',r.value);_applyTLSVisibility();});});
    find('#wzLEEmail')?.addEventListener('input',    e=>wizard.draftSet('tls_le_email',    e.target.value));
    find('#wzLEStaging')?.addEventListener('change', e=>wizard.draftSet('tls_le_staging',  e.target.checked?'on':'off'));
    find('#wzTLSCert')?.addEventListener('input',    e=>wizard.draftSet('tls_cert',        e.target.value));
    find('#wzTLSKey')?.addEventListener('input',     e=>wizard.draftSet('tls_key',         e.target.value));
    find('#wzCARoot')?.addEventListener('input',     e=>wizard.draftSet('tls_ca_root',     e.target.value));
    find('#wzClientAuth')?.addEventListener('change',e=>wizard.draftSet('tls_client_auth', e.target.value));
    find('#wzClientCAs')?.addEventListener('input',  e=>wizard.draftSet('tls_client_cas',  e.target.value.split('\n').map(s=>s.trim()).filter(Boolean)));
    find('#wzNotFoundPage')?.addEventListener('input',     e=>wizard.draftSet('host_not_found_page',  e.target.value));
    find('#wzBind')?.addEventListener('input',             e=>wizard.draftSet('host_bind',            e.target.value.split(',').map(s=>s.trim()).filter(Boolean)));
    find('#wzHostCompression')?.addEventListener('change', e=>wizard.draftSet('host_compression',     e.target.checked));
    find('#wzMaxBodySize')?.addEventListener('input',   e=>wizard.draftSet('host_max_body_size',e.target.value?parseInt(e.target.value):0));
    find('[data-field="host_protected"]')?.querySelectorAll('.wz-ts-opt').forEach(btn=>{btn.addEventListener('click',()=>{btn.closest('.wz-tristate')?.querySelectorAll('.wz-ts-opt').forEach(b=>b.classList.remove('active'));btn.classList.add('active');wizard.draftSet('host_protected',btn.dataset.val);});});

    // Relay
    const _relayText={wzRelayAgentName:'relay_agent_name',wzRelayAgentURL:'relay_agent_url',wzRelayAgentEnroll:'relay_agent_enroll',wzRelayAgentLocal:'relay_agent_local',wzRelayExposeID:'relay_expose_id',wzRelayServerName:'relay_server_name',wzRelayServerAddress:'relay_server_address',wzRelayServerPort:'relay_server_port',wzRelayServerToken:'relay_server_token',wzRelayServerTCP:'relay_server_tcp_ports',wzRelayServerUDP:'relay_server_udp_ports',wzRelayServerMaxAgents:'relay_server_max_agents',wzRelayServerMaxStreams:'relay_server_max_streams'};
    const _relayCheck={wzRelayAgentInsecure:['relay_agent_local_insecure',false],wzRelayExposePath:['relay_expose_path',true],wzRelayExposeSub:['relay_expose_subdomain',false],wzRelayServerHTTP:['relay_server_allow_http',true],wzRelayServerSub:['relay_server_allow_subdomain',false]};
    function _applyRelayVisibility(){
        const mode=wizard.draftGet('relay_mode')||'';
        const a=find('#wzRelayAgentFields'),sv=find('#wzRelayServerFields');
        if(a)a.style.display=mode==='agent'?'flex':'none';
        if(sv)sv.style.display=mode==='server'?'flex':'none';
        if(mode&&find('#wzRelayOptions'))find('#wzRelayOptions').open=true;
    }
    Object.entries(_relayText).forEach(([id,key])=>{const el=find('#'+id);if(!el)return;if(d[key]!=null)el.value=d[key];el.addEventListener('input',e=>wizard.draftSet(key,e.target.value));});
    Object.entries(_relayCheck).forEach(([id,[key,def]])=>{const el=find('#'+id);if(!el||!key)return;el.checked=d[key]!=null?!!d[key]:def;el.addEventListener('change',e=>wizard.draftSet(key,e.target.checked));});
    if(d.relay_mode){const r=find(`[name="relay_mode"][value="${d.relay_mode}"]`);if(r)r.checked=true;}
    findAll('[name="relay_mode"]').forEach(r=>r.addEventListener('change',()=>{wizard.draftSet('relay_mode',r.value);_applyRelayVisibility();}));
    _applyRelayVisibility();

    function _validateRelay(){
        const g=k=>(wizard.draftGet(k)||'').toString().trim();
        const idRe=/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, reserved=['admin','api','www','mail','relay','_agbero','well-known'];
        const mode=wizard.draftGet('relay_mode')||'';
        if(mode==='agent'){
            if(!idRe.test(g('relay_agent_name')))return{msg:'Agent name: lowercase letters, digits and dashes',field:'wzRelayAgentName'};
            if(!/^https?:\/\/[^/]+/.test(g('relay_agent_url')))return{msg:'Relay URL must start with https://',field:'wzRelayAgentURL'};
            if(!g('relay_agent_enroll'))return{msg:'Enrollment secret is required',field:'wzRelayAgentEnroll'};
            const id=g('relay_expose_id');
            if(!idRe.test(id)||reserved.includes(id))return{msg:'Public ID: a single DNS label, not a reserved name',field:'wzRelayExposeID'};
            if(wizard.draftGet('relay_expose_path')===false&&wizard.draftGet('relay_expose_subdomain')!==true)return{msg:'Choose path, subdomain, or both',field:'wzRelayExposePath'};
            if(wizard.draftGet('host_type')==='tcp')return{msg:'Relay publishing applies to HTTP routes; TCP hosts are not supported here yet',field:'wzRelayExposeID'};
        }
        if(mode==='server'){
            if(!g('relay_server_token'))return{msg:'Enrollment token is required',field:'wzRelayServerToken'};
            const port=Number(g('relay_server_port')||8443);
            if(!(port>0&&port<65536))return{msg:'Port must be 1–65535',field:'wzRelayServerPort'};
        }
        return null;
    }

    emit('wizard:set-validate',{validate:()=>{
        const relayErr=_validateRelay();
        if(relayErr)return relayErr;
        const dom=(wizard.draftGet('domain')||'').trim();
        if(!dom)return{msg:'Domain is required',field:'wzDomainInput'};
        if(dom.includes('://'))return{msg:'Domain must not include a protocol prefix',field:'wzDomainInput'};
        if(dom.includes('..'))return{msg:'Invalid domain',field:'wzDomainInput'};
        const mode=wizard.draftGet('tls_mode')||'auto',local=_isLocal(dom);
        if(!local){
            if(mode==='auto'&&!(wizard.draftGet('tls_le_email')||'').includes('@'))return{msg:"Let's Encrypt requires a valid email address",field:'wzLEEmail'};
            if(mode==='local'){
                if(!(wizard.draftGet('tls_cert')||'').trim())return{msg:'Certificate file path is required',field:'wzTLSCert'};
                if(!(wizard.draftGet('tls_key')||'').trim())return{msg:'Key file path is required',field:'wzTLSKey'};
            }
            if(mode==='custom_ca'&&!(wizard.draftGet('tls_ca_root')||'').trim())return{msg:'CA root path is required for Custom CA mode',field:'wzCARoot'};
        }
        return null;
    }});

    onUnmount(()=>{clearTimeout(_domainDebounce);});
    ready();
}
