/**
 * pages/certs.js — Certificates page.
 */
import { listen, notify, ui, countdown } from '../lib/oja.full.esm.js';

export default async function({ find, on, onUnmount, ready, inject }) {
    const { store, api, oja } = inject('app');
    const { emit } = oja;
    const _certCountdowns = new Map();

    function _destroyCertCountdowns() { for (const h of _certCountdowns.values()) h.destroy(); _certCountdowns.clear(); }

    function emptyRow(html) { return `<tr><td colspan="5" style="padding:24px;"><div class="empty-state">${html}</div></td></tr>`; }

    function certRow(c) {
        const daysLeft = c.days_left;
        const expired  = c.is_expired || (daysLeft !== null && daysLeft < 0);
        const expiry   = c.expires_at ? new Date(c.expires_at).toLocaleDateString([], { year:'numeric', month:'short', day:'numeric' }) : '—';
        const color    = countdown.daysColor(daysLeft);
        const useLive  = !expired && daysLeft !== null && daysLeft < 30 && c.expires_at;
        const cdId     = `cert-cd-${c.domain}`;
        const label    = expired
            ? '<span style="color:var(--danger);font-family:var(--font-mono);font-size:12px;">Expired</span>'
            : useLive
                ? `<span id="${cdId}" style="color:${color};font-family:var(--font-mono);font-size:12px;"></span>`
                : `<span style="color:${color};font-family:var(--font-mono);font-size:12px;">${countdown.daysLabel(daysLeft)}</span>`;
        const sourceLabel = c.source === 'letsencrypt' ? "Let's Encrypt" : c.source === 'local_auto' ? 'Auto' : c.source === 'custom' ? 'Custom' : '—';
        const sourceBadge = c.source === 'letsencrypt'
            ? `<span class="badge success" style="font-size:10px;">${sourceLabel}</span>`
            : c.source === 'custom'
                ? `<span class="badge warning" style="font-size:10px;">${sourceLabel}</span>`
                : `<span class="badge" style="font-size:10px;">${sourceLabel}</span>`;
        const keyInfo  = c.key_type ? `${c.key_type}${c.key_bits ? '-' + c.key_bits : ''}` : '—';
        const certData = encodeURIComponent(JSON.stringify(c));
        return `<tr class="clickable" data-cert="${certData}" style="cursor:pointer;" title="Click for details">
            <td class="mono" style="font-size:12px;">${c.domain}</td>
            <td class="hide-mobile">${sourceBadge}</td>
            <td class="hide-mobile mono" style="font-size:11px;color:var(--text-mute);">${keyInfo}</td>
            <td>${label}<span style="font-size:11px;color:var(--text-mute);margin-left:6px;">${expiry}</span></td>
            <td><button class="btn small certs-delete-btn" data-domain="${c.domain}" style="color:var(--danger);border-color:rgba(255,59,48,0.4);">Delete</button></td>
        </tr>`;    }

    function _attachCertCountdowns(parsed) {
        _destroyCertCountdowns();
        for (const c of parsed) {
            if (!c.is_expired && c.days_left !== null && c.days_left < 30 && c.expires_at) {
                const el = document.getElementById(`cert-cd-${c.domain}`);
                if (!el) continue;
                const handle = countdown.attach(el, new Date(c.expires_at).getTime(), {
                    format(ms) {
                        if (ms <= 0) return 'Expiring…';
                        const d = Math.floor(ms / 86_400_000), h = Math.floor((ms % 86_400_000) / 3_600_000), m = Math.floor((ms % 3_600_000) / 60_000), s = Math.floor((ms % 60_000) / 1_000);
                        if (d > 0) return `${d}d ${h}h ${m}m`;
                        if (h > 0) return `${h}h ${m}m ${s}s`;
                        return `${m}m ${s}s`;
                    },
                });
                _certCountdowns.set(c.domain, handle);
            }
        }
    }

    function render(parsed) {
        const tbody   = find('#certsTable');
        const countEl = find('#certsCount');
        if (!tbody) return;
        _destroyCertCountdowns();
        if (!parsed) { tbody.innerHTML = emptyRow('⚠️ Could not load certificates'); if (countEl) countEl.textContent = '—'; return; }
        if (countEl) countEl.textContent = String(parsed.length);
        if (!parsed.length) { tbody.innerHTML = emptyRow('<span>📜 No custom certificates</span><span>Agbero manages Let\'s Encrypt certificates automatically.</span>'); return; }
        tbody.innerHTML = parsed.map(certRow).join('');
        requestAnimationFrame(() => _attachCertCountdowns(parsed));
    }

    async function refresh() {
        const btn  = find('#certsRefreshBtn');
        if (btn) ui.btn.loading(btn, '…');
        const data = await api.fetchCerts();
        if (btn) ui.btn.reset(btn);
        const parsed = data ? api.parseCertificates(data) : null;
        if (parsed) store.set('certificates', parsed);
        render(parsed);
    }

    function _populateDomainList() {
        const dl = find('#certDomainList');
        if (!dl) return;
        const domains = Object.keys((store.get('lastConfig') || {}).hosts || {});
        dl.innerHTML = domains.map(d => `<option value="${d}">`).join('');
    }

    function _openCertDetail(cert) {
        const titleEl = find('#certPageDetailTitle');
        const bodyEl  = find('#certPageDetailBody');
        if (!titleEl || !bodyEl) return;
        titleEl.textContent = cert.domain;
        const expiry   = cert.expires_at ? new Date(cert.expires_at).toLocaleDateString([], { year:'numeric', month:'short', day:'numeric' }) : '—';
        const issued   = cert.issued_at  ? new Date(cert.issued_at).toLocaleDateString([], { year:'numeric', month:'short', day:'numeric' }) : '—';
        const color    = countdown.daysColor(cert.days_left);
        const daysNum  = cert.days_left != null ? (cert.days_left <= 0 ? 'Expired' : `${cert.days_left} days`) : '—';
        const sourceLabel = cert.source === 'letsencrypt' ? "Let's Encrypt" : cert.source === 'local_auto' ? 'Auto (local)' : cert.source === 'custom' ? 'Custom' : '—';
        const keyInfo  = cert.key_type ? `${cert.key_type}${cert.key_bits ? ' ' + cert.key_bits + '-bit' : ''}` : '—';
        const sansHtml = cert.sans?.length
            ? cert.sans.map(s => `<span style="font-family:var(--font-mono);font-size:10px;background:var(--hover-bg);padding:1px 5px;border-radius:3px;margin:1px 2px;display:inline-block;">${s}</span>`).join('')
            : '—';
        bodyEl.innerHTML = [
            ['Domain',    cert.domain],
            ['Status',    cert.is_expired ? '<span style="color:var(--danger);font-weight:500;">Expired</span>' : cert.days_left != null && cert.days_left < 7 ? '<span style="color:var(--warning);font-weight:500;">Expiring soon</span>' : '<span style="color:var(--success);">Valid</span>'],
            ['Days Left', `<span style="color:${color};font-weight:500;">${daysNum}</span>`],
            ['Expires',   expiry],
            ['Issued',    issued],
            ['Source',    sourceLabel],
            ['Key',       keyInfo],
            ['Issuer',    cert.issuer  || '—'],
            ['Serial',    cert.serial_number ? `<span style="font-family:var(--font-mono);font-size:10px;">${cert.serial_number}</span>` : '—'],
            ['SANs',      sansHtml],
        ].map(([k,v]) => `<div class="detail-row"><span class="detail-label">${k}</span><span class="detail-value">${v}</span></div>`).join('');
        oja.modal.open('certPageDetailModal');
    }

    on('#certsTable', 'click', (e) => {
        if (e.target.closest('.certs-delete-btn')) return;
        const row = e.target.closest('tr[data-cert]');
        if (!row) return;
        try { _openCertDetail(JSON.parse(decodeURIComponent(row.dataset.cert))); } catch {}
    });

    on('#certsUploadBtn', 'click', () => { _populateDomainList(); find('#certsUploadForm').style.display = ''; find('#certDomain')?.focus(); });
    on('#certsUploadCancelBtn', 'click', () => {
        find('#certsUploadForm').style.display  = 'none';
        find('#certDomain').value = ''; find('#certPem').value = ''; find('#certKey').value = '';
        find('#certsUploadError').style.display = 'none';
    });

    on('#certsUploadSaveBtn', 'click', async (e, btn) => {
        const domain = (find('#certDomain').value  || '').trim();
        const cert   = (find('#certPem').value     || '').trim();
        const key    = (find('#certKey').value     || '').trim();
        const errEl  = find('#certsUploadError');
        errEl.style.display = 'none';
        if (!domain) { errEl.textContent = 'Domain is required';       errEl.style.display = 'block'; return; }
        if (!cert)   { errEl.textContent = 'Certificate PEM required'; errEl.style.display = 'block'; return; }
        if (!key)    { errEl.textContent = 'Private key PEM required'; errEl.style.display = 'block'; return; }
        ui.btn.loading(btn, 'Uploading…');
        const res = await api.uploadCert(domain, cert, key);
        ui.btn.reset(btn);
        if (res?.status === 'ok') {
            notify.show(`Certificate for ${domain} applied`, 'success');
            find('#certsUploadForm').style.display = 'none';
            find('#certDomain').value = ''; find('#certPem').value = ''; find('#certKey').value = '';
            refresh();
        } else { errEl.textContent = res?.error || res?.message || 'Upload failed'; errEl.style.display = 'block'; }
    });

    on('.certs-delete-btn', 'click', (e, btn) => {
        const domain = btn?.dataset.domain;
        if (!domain) return;
        emit('app:strict-delete', {
            message:    `Delete the certificate for <strong>${domain}</strong>?`,
            targetText: domain,
            onConfirm:  async (otpCode) => {
                const res = await api.deleteCert(domain, otpCode);
                if (res?.status === 'ok' || !res?.error) { notify.show(`Certificate for ${domain} deleted`, 'success'); refresh(); }
                else notify.show(res?.error || 'Delete failed', 'error');
            },
        });
    });

    on('#certPemFile', 'change', (e, inp) => {
        const file = inp.files?.[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = ev => { const ta = find('#certPem'); if (ta) ta.value = ev.target.result; };
        reader.readAsText(file);
    });

    on('#certKeyFile', 'change', (e, inp) => {
        const file = inp.files?.[0]; if (!file) return;
        const reader = new FileReader();
        reader.onload = ev => { const ta = find('#certKey'); if (ta) ta.value = ev.target.result; };
        reader.readAsText(file);
    });

    const unsubRefresh = listen('certs:refresh', refresh);

    // Show skeleton while loading if no cached data
    const cached = store.get('certificates');
    if (cached) render(cached);
    else {
        const tbody = find('#certsTable');
        if (tbody) tbody.innerHTML = `<tr><td colspan="5"><div class="loading-rows"><div class="loading-row"></div><div class="loading-row"></div><div class="loading-row"></div></div></td></tr>`;
    }
    refresh();

    onUnmount(() => { unsubRefresh(); _destroyCertCountdowns(); });
    ready();
}