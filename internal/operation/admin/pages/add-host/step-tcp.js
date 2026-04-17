/**
 * pages/add-host/step-tcp.js — TCP/UDP proxy step.
 */
import { emit } from '../../lib/oja.full.esm.js';

export default async function({ find, findAll, on, onUnmount, ready, props }) {
    const { wizard } = props;
    const tcp = wizard.getTcp();
    let backends = tcp.backends || [{ address:'', weight:1 }];

    function _esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

    // Restore saved values
    const isUDP = (tcp.protocol || '') === 'udp';
    if (isUDP) {
        const udpRadio = find('#wzProtoUdp');
        if (udpRadio) udpRadio.checked = true;
    }
    if(find('#wzTcpName'))           find('#wzTcpName').value            = tcp.name          || '';
    if(find('#wzTcpListen'))         find('#wzTcpListen').value          = tcp.listen         || '';
    if(find('#wzTcpSNI'))            find('#wzTcpSNI').value             = tcp.sni            || '';
    if(find('#wzTcpMaxConn'))        find('#wzTcpMaxConn').value         = tcp.max_connections|| '';
    if(find('#wzTcpProxyProtocol'))  find('#wzTcpProxyProtocol').checked = !!tcp.proxy_protocol;
    if(find('#wzTcpHcInterval'))     find('#wzTcpHcInterval').value      = tcp.hc_interval    || '';
    if(find('#wzTcpHcTimeout'))      find('#wzTcpHcTimeout').value       = tcp.hc_timeout     || '';
    if(find('#wzTcpHcSend'))         find('#wzTcpHcSend').value          = tcp.hc_send        || '';
    if(find('#wzTcpHcExpect'))       find('#wzTcpHcExpect').value        = tcp.hc_expect      || '';
    // UDP fields
    if(find('#wzUdpMatcher'))        find('#wzUdpMatcher').value         = tcp.matcher        || '';
    if(find('#wzUdpSessionTTL'))     find('#wzUdpSessionTTL').value      = tcp.session_ttl    || '';
    if(find('#wzUdpMaxSessions'))    find('#wzUdpMaxSessions').value     = tcp.max_sessions   || '';

    // Show/hide protocol-specific panels
    function _updateProtocolUI() {
        const proto = find('[name="wzTcpProtocol"]:checked')?.value || '';
        const tcpFields = find('#wzTcpOnlyFields');
        const udpFields = find('#wzUdpOnlyFields');
        if (tcpFields) tcpFields.style.display = proto === 'udp' ? 'none' : '';
        if (udpFields) udpFields.style.display = proto === 'udp' ? ''     : 'none';
    }
    _updateProtocolUI();

    const STRATEGIES=[{val:'round_robin',label:'Round Robin',desc:'Default'},{val:'least_conn',label:'Least Conn',desc:'Lowest active load'},{val:'sticky',label:'Sticky',desc:'Same client → same server'},{val:'ip_hash',label:'IP Hash',desc:'Consistent by IP'},{val:'random',label:'Random',desc:'Uniform random'},{val:'adaptive',label:'Adaptive',desc:'Auto-tune by health'}];
    const grid=find('#wzTcpStrategyGrid');
    if(grid){const cur=tcp.strategy||'round_robin';grid.innerHTML=STRATEGIES.map(st=>`<label class="wz-strategy-opt"><input type="radio" name="tcp_strategy" value="${st.val}"${cur===st.val?' checked':''}><span><strong>${st.label}</strong><em>${st.desc}</em></span></label>`).join('');}

    const listEl=find('#wzTcpBackends');
    function _sync(){
        const proto   = find('[name="wzTcpProtocol"]:checked')?.value || '';
        const strat   = find('[name="tcp_strategy"]:checked')?.value  || 'round_robin';
        const tcpData = {
            name:            (find('#wzTcpName')?.value||'').trim(),
            listen:          (find('#wzTcpListen')?.value||'').trim(),
            sni:             (find('#wzTcpSNI')?.value||'').trim(),
            strategy:        strat,
            max_connections: parseInt(find('#wzTcpMaxConn')?.value||'0')||0,
            proxy_protocol:  find('#wzTcpProxyProtocol')?.checked||false,
            backends,
            hc_interval:     (find('#wzTcpHcInterval')?.value||'').trim(),
            hc_timeout:      (find('#wzTcpHcTimeout')?.value||'').trim(),
            hc_send:         (find('#wzTcpHcSend')?.value||'').trim(),
            hc_expect:       (find('#wzTcpHcExpect')?.value||'').trim(),
        };
        if (proto === 'udp') {
            tcpData.protocol     = 'udp';
            tcpData.matcher      = (find('#wzUdpMatcher')?.value||'').trim();
            tcpData.session_ttl  = (find('#wzUdpSessionTTL')?.value||'').trim();
            tcpData.max_sessions = parseInt(find('#wzUdpMaxSessions')?.value||'0')||0;
        } else {
            tcpData.protocol = '';
        }
        wizard.setTcp(tcpData);
    }

    function renderBackends(){if(!listEl)return;listEl.innerHTML=backends.map((b,i)=>`<div class="wz-backend-row" data-idx="${i}"><input type="text" class="wz-input wz-be-addr" value="${_esc(b.address||'')}" placeholder="10.0.0.5:6379 or unix:/run/redis.sock" style="flex:1;"><input type="number" class="wz-input-sm wz-be-weight" value="${b.weight||1}" min="1" max="100" title="Weight" style="width:60px;"><span class="wz-hint-inline" style="font-size:10px;white-space:nowrap;">weight</span><button type="button" class="btn small wz-be-remove" style="color:var(--danger);border-color:var(--danger);padding:4px 8px;">✕</button></div>`).join('');listEl.querySelectorAll('.wz-be-addr').forEach((inp,i)=>inp.addEventListener('input',()=>{backends[i].address=inp.value;_sync();}));listEl.querySelectorAll('.wz-be-weight').forEach((inp,i)=>inp.addEventListener('input',()=>{backends[i].weight=Number(inp.value)||1;_sync();}));listEl.querySelectorAll('.wz-be-remove').forEach(btn=>btn.addEventListener('click',()=>{backends.splice(+btn.closest('[data-idx]').dataset.idx,1);renderBackends();_sync();}));}

    find('#wzTcpAddBackend')?.addEventListener('click',()=>{backends.push({address:'',weight:1});renderBackends();listEl?.querySelectorAll('.wz-be-addr')[backends.length-1]?.focus();_sync();});
    renderBackends();

    ['#wzTcpName','#wzTcpListen','#wzTcpSNI','#wzTcpMaxConn','#wzTcpHcInterval','#wzTcpHcTimeout','#wzTcpHcSend','#wzTcpHcExpect','#wzUdpMatcher','#wzUdpSessionTTL','#wzUdpMaxSessions'].forEach(sel=>find(sel)?.addEventListener('input',_sync));
    find('#wzTcpProxyProtocol')?.addEventListener('change',_sync);
    find('#wzTcpStrategyGrid')?.addEventListener('change',_sync);
    // Protocol toggle
    findAll('[name="wzTcpProtocol"]').forEach(r => r.addEventListener('change', () => { _updateProtocolUI(); _sync(); }));

    emit('wizard:set-validate',{validate:()=>{
        const name=(find('#wzTcpName')?.value||'').trim();
        const listen=(find('#wzTcpListen')?.value||'').trim();
        if(!name) return {msg:'Proxy name is required', field:'wzTcpName'};
        if(!/^[a-z0-9-]+$/.test(name)) return {msg:'Name must be lowercase alphanumeric and hyphens only', field:'wzTcpName'};
        if(!listen) return {msg:'Listen address is required (e.g. 0.0.0.0:6379)', field:'wzTcpListen'};
        if(!listen.includes(':')) return {msg:'Listen address must be host:port format (e.g. 0.0.0.0:6379)', field:'wzTcpListen'};
        if(!backends.some(b=>b.address.trim())) return {msg:'At least one backend address is required'};
        return null;
    }});

    onUnmount(()=>{});
    ready();
}
