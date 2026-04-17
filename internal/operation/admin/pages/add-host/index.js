/**
 * pages/add-host/index.js — Add-host wizard orchestrator.
 */
import { Out, emit, listen } from '../../lib/oja.full.esm.js';
import { draftGet, draftSet, draftClear, draftHas, draftSummary, newRoute, getRoutes, setRoutes, getTcp, setTcp } from './draft-store.js';

export default async function({ find, findAll, on, onUnmount, ready, inject }) {
    const { progress } = inject('app');
    const p = progress('add-host');

    const wizardApi = {
        draftGet, draftSet, draftMerge: (partial) => { Object.entries(partial).forEach(([k,v]) => draftSet(k,v)); },
        draftClear, draftHas, draftSummary,
        newRoute, getRoutes, setRoutes, getTcp, setTcp,
    };

    function buildSteps() {
        const type = draftGet('host_type');
        const steps = [
            { key:'type',   label:'Type',   html:'/pages/add-host/step-type.html',   js:'/pages/add-host/step-type.js'   },
            { key:'domain', label:'Domain', html:'/pages/add-host/step-domain.html', js:'/pages/add-host/step-domain.js' },
        ];
        if (type === 'tcp') steps.push({ key:'tcp',    label:'Proxy',  html:'/pages/add-host/step-tcp.html',    js:'/pages/add-host/step-tcp.js'    });
        else if (type)      steps.push({ key:'routes', label:'Routes', html:'/pages/add-host/step-routes.html', js:'/pages/add-host/step-routes.js' });
        steps.push({ key:'review', label:'Review', html:'/pages/add-host/step-review.html', js:'/pages/add-host/step-review.js' });
        return steps;
    }

    let _step = draftGet('_step') || 0;
    let _navAbort = null;
    let _validate = null;

    function _updateBreadcrumb() {
        const stepsEl = find('#addHostSteps');
        if (!stepsEl) return;
        const steps = buildSteps();
        stepsEl.innerHTML = steps.map((s, i) => {
            const isDone=i<_step, isActive=i===_step, cls=isDone?'done':isActive?'active':'', num=isDone?'✓':String(i+1), click=isDone?`data-action="jump-step" data-idx="${i}"`:'';
            return `<div class="add-host-step ${cls}" ${click} style="${isDone?'cursor:pointer':''}"><span class="add-host-step-num">${num}</span> ${s.label}</div>${i<steps.length-1?'<span class="add-host-step-sep">›</span>':''}`;
        }).join('');
        p.set(steps.length > 1 ? (_step / (steps.length - 1)) * 100 : 0);
    }

    // Clear any previously highlighted field error
    function _clearFieldErrors() {
        find('#addHostContent')?.querySelectorAll('.wz-input-error,.wz-select-error')
            .forEach(el => el.classList.remove('wz-input-error', 'wz-select-error'));
    }

    // Highlight a field by id or data-wz-field attribute
    function _highlightField(fieldId) {
        if (!fieldId) return;
        const container = find('#addHostContent');
        if (!container) return;
        const el = container.querySelector(`#${CSS.escape(fieldId)},[name="${CSS.escape(fieldId)}"]`);
        if (el) {
            el.classList.add('wz-input-error');
            el.focus();
            el.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        }
    }

    function _wireNav() {
        if (_navAbort) _navAbort.abort();
        _navAbort = new AbortController();
        const sig = _navAbort.signal;
        const steps=buildSteps(), isLast=_step===steps.length-1, navEl=find('#addHostNav'), nextEl=find('#addHostNextBtn'), errEl=find('#addHostValidError');
        if (navEl)  navEl.style.display  = _step === 0 ? 'none' : 'flex';
        if (nextEl) nextEl.style.display = isLast ? 'none' : '';
        find('#addHostPrevBtn')?.addEventListener('click', () => {
            if (errEl) errEl.style.display='none';
            _clearFieldErrors();
            _goStep(Math.max(0, _step-1));
        }, { signal: sig });
        find('#addHostNextBtn')?.addEventListener('click', async () => {
            if (errEl) errEl.style.display='none';
            _clearFieldErrors();
            if (_validate) {
                const result = await _validate();
                if (result) {
                    // Support both plain string errors and {msg, field} objects
                    const msg   = typeof result === 'string' ? result : (result.msg   || result.message || String(result));
                    const field = typeof result === 'string' ? null   : (result.field || null);
                    if (errEl) { errEl.textContent = msg; errEl.style.display = 'block'; }
                    if (field) _highlightField(field);
                    return;
                }
            }
            draftSet('_step', _step+1); _goStep(_step+1);
        }, { signal: sig });
    }

    async function _goStep(idx) {
        const steps = buildSteps();
        _step = Math.max(0, Math.min(idx, steps.length-1));
        _validate = null;
        _updateBreadcrumb();
        _wireNav();
        const outlet  = find('#addHostContent');
        if (!outlet) return;
        const stepDef = steps[_step];
        // Pass wizard API to each step via props
        await Out.to(outlet).module(stepDef.js, stepDef.html, { wizard: wizardApi }).render();
    }

    listen('wizard:set-validate',  ({ validate }) => { _validate = validate; });
    listen('wizard:type-selected', ({ type }) => { draftSet('host_type', type); draftSet('_step', 1); _goStep(1); });
    listen('wizard:submit-success', ({ domain }) => { draftClear(); p.done(); emit('hosts:refresh'); emit('config:reload'); emit('app:navigate', { path: '/hosts' }); });
    listen('wizard:submit-error',  () => p.fail());

    on('[data-action="jump-step"]', 'click', (e, el) => { const idx=parseInt(el?.dataset.idx); if(!isNaN(idx)&&idx<_step)_goStep(idx); });
    on('#addHostBackBtn', 'click', () => emit('app:navigate', { path: '/hosts' }));

    // Draft resume banner
    if (!draftHas()) {
        _goStep(0);
    } else {
        const banner=find('#draftResumeBanner'), desc=find('#draftResumeDesc');
        if (banner) banner.style.display='';
        if (desc)   desc.textContent = draftSummary() || '';
        on('#draftResumeBtn', 'click', () => { if(banner)banner.style.display='none'; _step=draftGet('_step')||0; _goStep(_step); });
        on('#draftDiscardBtn','click', () => { draftClear(); if(banner)banner.style.display='none'; _goStep(0); });
    }

    onUnmount(() => { if (_navAbort) _navAbort.abort(); p.reset(); });
    ready();
}