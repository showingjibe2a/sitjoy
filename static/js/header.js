// 在页面加载时动态注入顶部导航，保持各模板统一
(function(){
    (function ensureSitjoyThemeScript() {
        if (window.SitjoyTheme || document.querySelector('script[data-sitjoy-theme="1"]')) return;
        const s = document.createElement('script');
        s.src = '/static/js/theme.js';
        s.async = false;
        s.dataset.sitjoyTheme = '1';
        document.head.appendChild(s);
    })();

    const universalSelectState = new Map();
    const managedTableState = new Map();
    const PAGE_SIZE_OPTIONS = [20, 50, 100, 300, 500, 1000];
    const responseToastState = new WeakMap();
    let toastStack = null;
    let activeColumnsPanelState = null;
    let activeResetMenuState = null;
    let activeResizeState = null;
    let resizePendingFrame = null;
    let resizePendingWidth = null;
    let activeHelpDotTooltip = null;
    let activeHelpDotAnchor = null;
    let helpDotDelegationInstalled = false;
    let activeDatePickerState = null;
    let activeDateTimePickerState = null;
    let activeGridSelection = null;
    let activeBatchConfirmState = null;
    let suppressSortUntil = 0;

    function isElementVisibleForEnhance(el){
        if(!el) return false;
        const style = window.getComputedStyle(el);
        return style.display !== 'none' && style.visibility !== 'hidden';
    }

    function shouldEnhanceSelect(select){
        if(!select || select.tagName !== 'SELECT') return false;
        if(select.multiple) return false;
        if(select.dataset.searchableEnhanced === '1') return false;
        if(select.dataset.disableSearchable === '1') return false;
        if(select.classList.contains('no-searchable-select')) return false;
        if(select.classList.contains('thumb-dropdown-select')) return false;
        if(!isElementVisibleForEnhance(select)) return false;
        return true;
    }

    function createOptionButton(option, currentValue, select, state){
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'feature-category-option universal-select-option';
        button.textContent = option.textContent || '';
        if(String(option.value || '') === String(currentValue || '')) {
            button.classList.add('is-active');
        }
        if(option.disabled){
            button.disabled = true;
            button.classList.add('is-disabled');
        }
        button.addEventListener('click', () => {
            if(option.disabled) return;
            if(select.value !== option.value){
                select.value = option.value;
                select.dispatchEvent(new Event('change', { bubbles: true }));
            } else {
                select.dispatchEvent(new Event('change', { bubbles: true }));
            }
            if(state.searchInput) state.searchInput.value = '';
            renderDropdownOptions(select, state);
            closeDropdown(select, state);
            syncTriggerFromSelect(select, state);
        });
        return button;
    }

    function resolvePlaceholderText(select){
        const placeholderOption = Array.from(select.options || []).find(option => String(option.value || '').trim() === '');
        return (placeholderOption && placeholderOption.textContent ? placeholderOption.textContent : '')
            || select.dataset.placeholder
            || select.getAttribute('placeholder')
            || '请选择';
    }

    function syncTriggerFromSelect(select, state){
        if(!state) return;
        state.placeholderText = resolvePlaceholderText(select);
        const selectedIndex = select.selectedIndex;
        const option = selectedIndex >= 0 ? select.options[selectedIndex] : null;
        const selectedValue = option ? String(option.value || '').trim() : '';
        const fallbackText = state.placeholderText || select.options[0]?.textContent || '请选择';
        const text = option && selectedValue !== '' && option.textContent ? option.textContent : fallbackText;
        state.trigger.textContent = text || fallbackText;
        state.trigger.classList.toggle('has-value', !!(select.value || '').toString().trim());
        state.trigger.disabled = !!select.disabled;
        state.lastValue = String(select.value || '');
        if(state.trigger.classList.contains('universal-select-trigger--compact')){
            state.trigger.title = String(state.trigger.textContent || '').trim();
        } else {
            state.trigger.removeAttribute('title');
        }
    }

    function renderDropdownOptions(select, state){
        if(!state) return;
        const keyword = state.searchInput ? (state.searchInput.value || '').trim().toLowerCase() : '';
        const currentValue = String(select.value || '');
        state.list.innerHTML = '';

        let count = 0;
        Array.from(select.options || []).forEach(option => {
            if(String(option.value || '').trim() === '') return;
            const text = (option.textContent || '').toLowerCase();
            if(keyword && !text.includes(keyword)) return;
            const button = createOptionButton(option, currentValue, select, state);
            state.list.appendChild(button);
            count += 1;
        });

        if(!count){
            const empty = document.createElement('div');
            empty.className = 'feature-category-empty';
            empty.textContent = '无匹配项';
            state.list.appendChild(empty);
        }

        syncTriggerFromSelect(select, state);
    }

    function closeDropdown(select, state){
        if(!state) return;
        state.wrapper.classList.remove('open');
        state.wrapper.classList.remove('expanded');
        state.wrapper.classList.remove('open-upward');
        if(state.menu){
            state.menu.classList.remove('universal-select-floating-menu');
            state.menu.style.display = '';
            state.menu.style.position = '';
            state.menu.style.left = '';
            state.menu.style.top = '';
            state.menu.style.right = '';
            state.menu.style.bottom = '';
            state.menu.style.width = '';
            state.menu.style.minWidth = '';
            state.menu.style.maxWidth = '';
            state.menu.style.zIndex = '';
            if(state.menu.parentElement !== state.wrapper){
                state.wrapper.appendChild(state.menu);
            }
        }
    }

    function positionFloatingDropdown(select, state){
        if(!state || !state.menu || !state.wrapper.classList.contains('open')) return;
        const triggerRect = state.trigger.getBoundingClientRect();
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
        const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
        const spaceBelow = viewportHeight - triggerRect.bottom;
        const spaceAbove = triggerRect.top;
        const preferHeight = 280;
        const openUpward = spaceBelow < 180 && spaceAbove > spaceBelow && spaceAbove >= 140;
        state.wrapper.classList.toggle('open-upward', openUpward);
        const availableSpace = (openUpward ? spaceAbove : spaceBelow) - 20;
        const maxHeight = Math.max(120, Math.min(preferHeight, availableSpace));
        state.list.style.maxHeight = `${maxHeight}px`;

        const width = Math.min(Math.max(triggerRect.width, 180), Math.max(200, viewportWidth - 16));
        const left = Math.max(8, Math.min(triggerRect.left, viewportWidth - width - 8));

        state.menu.style.position = 'fixed';
        state.menu.style.left = `${left}px`;
        state.menu.style.right = 'auto';
        state.menu.style.width = `${width}px`;
        state.menu.style.minWidth = `${width}px`;
        state.menu.style.maxWidth = `${width}px`;
        /* 须高于 .pm-modal(15000) / 嵌套 NAS(15100) / .pm-modal--stack(15150)，否则挂到 body 的下拉会被遮罩盖住；低于 .app-toast-stack(16000) */
        state.menu.style.zIndex = '15600';
        if(openUpward){
            state.menu.style.top = 'auto';
            state.menu.style.bottom = `${Math.max(8, viewportHeight - triggerRect.top + 6)}px`;
        } else {
            state.menu.style.top = `${Math.max(8, triggerRect.bottom + 6)}px`;
            state.menu.style.bottom = 'auto';
        }
    }

    function repositionOpenDropdowns(){
        universalSelectState.forEach((state, select) => {
            if(state.wrapper.classList.contains('open')){
                positionFloatingDropdown(select, state);
            }
        });
    }

    function openDropdown(select, state){
        if(!state || state.trigger.disabled) return;
        closeAllDropdowns();
        if(state.menu.parentElement !== document.body){
            document.body.appendChild(state.menu);
        }
        renderDropdownOptions(select, state);
        state.menu.classList.add('universal-select-floating-menu');
        state.menu.style.display = 'block';
        state.wrapper.classList.add('expanded');
        window.setTimeout(() => {
            state.wrapper.classList.add('open');
            positionFloatingDropdown(select, state);
            if(state.searchInput){
                state.searchInput.focus();
                state.searchInput.select();
            }
        }, 90);
    }

    function closeAllDropdowns(){
        universalSelectState.forEach((state, select) => {
            closeDropdown(select, state);
        });
    }

    function enhanceSingleSelect(select){
        if(!shouldEnhanceSelect(select)) return;
        const noSearch = select.dataset.universalNoSearch === '1';

        const wrapper = document.createElement('div');
        wrapper.className = 'feature-category-dropdown universal-select-dropdown';

        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'universal-select-trigger';
        trigger.textContent = '请选择';

        const compact = String(select.dataset.universalCompact || '') === '1'
            || select.classList.contains('mj-rule-preset-select--compact')
            || select.classList.contains('pm-table-page-size')
            || select.classList.contains('pm-inline-compact-select')
            || select.classList.contains('sf-compact-select');
        if(compact){
            wrapper.classList.add('universal-select-dropdown--compact');
            trigger.classList.add('universal-select-trigger--compact');
        }

        const menu = document.createElement('div');
        menu.className = 'feature-category-menu';

        const list = document.createElement('div');
        list.className = 'feature-category-list universal-select-list';

        let searchInput = null;
        if(!noSearch){
            searchInput = document.createElement('input');
            searchInput.type = 'text';
            searchInput.className = 'universal-select-search';
            searchInput.placeholder = select.dataset.searchPlaceholder || '搜索';
            if(compact) searchInput.classList.add('universal-select-search--compact');
            menu.appendChild(searchInput);
        } else {
            menu.classList.add('menu-no-search');
        }
        menu.appendChild(list);
        wrapper.appendChild(trigger);
        wrapper.appendChild(menu);

        select.classList.add('universal-select-native');
        select.dataset.searchableEnhanced = '1';
        select.insertAdjacentElement('afterend', wrapper);

        const state = {
            wrapper,
            trigger,
            menu,
            searchInput,
            list,
            lastValue: String(select.value || ''),
            placeholderText: resolvePlaceholderText(select)
        };
        universalSelectState.set(select, state);

        trigger.addEventListener('click', () => {
            if(wrapper.classList.contains('open')) {
                closeDropdown(select, state);
                return;
            }
            openDropdown(select, state);
        });

        if(searchInput){
            searchInput.addEventListener('input', () => renderDropdownOptions(select, state));
        }

        select.addEventListener('change', () => {
            renderDropdownOptions(select, state);
            syncTriggerFromSelect(select, state);
        });

        const observer = new MutationObserver(() => {
            renderDropdownOptions(select, state);
            syncTriggerFromSelect(select, state);
        });
        observer.observe(select, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['disabled', 'label', 'value', 'selected'] });
        state.observer = observer;

        renderDropdownOptions(select, state);
        syncTriggerFromSelect(select, state);
    }

    function initUniversalSingleSelects(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('select').forEach(enhanceSingleSelect);
    }

    function refreshUniversalSingleSelect(target){
        const select = typeof target === 'string' ? document.getElementById(target) : target;
        if(!select) return;
        const state = universalSelectState.get(select);
        if(!state) {
            enhanceSingleSelect(select);
            return;
        }
        renderDropdownOptions(select, state);
        syncTriggerFromSelect(select, state);
    }

    function startUniversalSelectValueSync(){
        window.setInterval(() => {
            universalSelectState.forEach((state, select) => {
                const value = String(select.value || '');
                if(value !== state.lastValue){
                    syncTriggerFromSelect(select, state);
                    renderDropdownOptions(select, state);
                }
            });
        }, 400);
    }

    function ensureToastStack(){
        if(toastStack && document.body.contains(toastStack)) return toastStack;
        toastStack = document.createElement('div');
        toastStack.className = 'app-toast-stack';
        document.body.appendChild(toastStack);
        return toastStack;
    }

    function computeAppBottomOverlayOffset(){
        // 计算右下角固定控件的最大高度，用于给 toast stack 腾位置，避免重叠
        let maxHeight = 0;
        const candidates = [
            '.app-upload-progress-panel.show',
            '.pm-batch-float-bar.active:not(.pm-batch-float-bar--embedded)',
            '.preview-savebar.active',
        ];
        candidates.forEach(selector => {
            document.querySelectorAll(selector).forEach(el => {
                try {
                    const style = window.getComputedStyle(el);
                    if(style.display === 'none' || style.visibility === 'hidden') return;
                    const rect = el.getBoundingClientRect();
                    if(!rect || rect.height <= 0) return;
                    maxHeight = Math.max(maxHeight, Math.ceil(rect.height) + 18);
                } catch(_e){
                }
            });
        });
        return maxHeight;
    }

    function syncAppToastStackOffset(){
        try {
            const offset = computeAppBottomOverlayOffset();
            document.documentElement.style.setProperty('--app-toast-bottom-offset', `${Math.max(0, offset)}px`);
        } catch(_e){
        }
    }

    function copyTextToClipboard(text){
        const value = String(text || '');
        if(!value) return Promise.resolve(false);
        if(navigator.clipboard && navigator.clipboard.writeText){
            return navigator.clipboard.writeText(value).then(() => true).catch(() => false);
        }
        const ta = document.createElement('textarea');
        ta.value = value;
        ta.setAttribute('readonly', 'readonly');
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        ta.style.pointerEvents = 'none';
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try {
            ok = !!document.execCommand('copy');
        } catch(_err){
            ok = false;
        }
        if(ta.parentNode) ta.parentNode.removeChild(ta);
        return Promise.resolve(ok);
    }

    function showAppToast(message, isError, duration){
        const text = String(message || '').trim();
        if(!text) return;
        const isErr = !!isError;
        /* 成功类提示出现时立即收起右下角「上传/保存中」进度条，避免与成功 toast 叠在一起 */
        if(!isErr){
            hideAppUploadProgress();
        }
        syncAppToastStackOffset();
        const stack = ensureToastStack();
        const toast = document.createElement('div');
        toast.className = `app-toast ${isErr ? 'error' : 'success'}`;

        const messageEl = document.createElement('div');
        messageEl.className = 'app-toast-message';
        messageEl.textContent = text;
        toast.appendChild(messageEl);

        const actions = document.createElement('div');
        actions.className = 'app-toast-actions';

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'btn-secondary btn-small';
        copyBtn.textContent = '复制';
        actions.appendChild(copyBtn);

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'modal-close';
        closeBtn.setAttribute('aria-label', '关闭提示');
        closeBtn.textContent = '×';
        actions.appendChild(closeBtn);

        toast.appendChild(actions);
        stack.appendChild(toast);
        window.requestAnimationFrame(() => toast.classList.add('show'));

        const removeToast = () => {
            toast.classList.remove('show');
            window.setTimeout(() => {
                if(toast.parentNode) toast.parentNode.removeChild(toast);
            }, 180);
        };

        closeBtn.addEventListener('click', removeToast);
        copyBtn.addEventListener('click', async () => {
            const ok = await copyTextToClipboard(text);
            copyBtn.textContent = ok ? '已复制' : '复制失败';
            window.setTimeout(() => { copyBtn.textContent = '复制'; }, 1200);
        });

        // duration:
        // - <= 0: sticky（不自动关闭）
        // - > 0 : 自动关闭
        const timeout = Number(duration);
        if(Number.isFinite(timeout) && timeout <= 0){
            return;
        }
        const finalTimeout = Number.isFinite(timeout) ? timeout : 10000;
        window.setTimeout(removeToast, Math.max(800, finalTimeout));
    }

    function parseDownloadFilename(contentDisposition, fallbackName){
        const fallback = String(fallbackName || '导入模板.xlsx');
        const header = String(contentDisposition || '');
        if(!header) return fallback;
        const starMatch = header.match(/filename\*=UTF-8''([^;]+)/i);
        if(starMatch && starMatch[1]){
            try {
                return decodeURIComponent(starMatch[1]).replace(/[\\/:*?"<>|]/g, '_') || fallback;
            } catch(_e){
                return starMatch[1].replace(/[\\/:*?"<>|]/g, '_') || fallback;
            }
        }
        const basicMatch = header.match(/filename="?([^";]+)"?/i);
        if(basicMatch && basicMatch[1]){
            return String(basicMatch[1]).replace(/[\\/:*?"<>|]/g, '_') || fallback;
        }
        return fallback;
    }

    async function downloadTemplateWithIds(endpoint, ids, fallbackName){
        const path = String(endpoint || '').trim();
        if(!path) return;

        const uniqueIds = [];
        (Array.isArray(ids) ? ids : []).forEach(v => {
            const n = Number(v);
            if(!Number.isFinite(n) || n <= 0) return;
            const val = Math.trunc(n);
            if(!uniqueIds.includes(val)) uniqueIds.push(val);
        });

        const query = uniqueIds.length ? `?ids=${uniqueIds.join(',')}` : '';
        const getUrl = `${path}${query}`;

        const shouldUsePost = uniqueIds.length > 80 || getUrl.length > 900;
        if(!shouldUsePost){
            window.location.href = getUrl;
            return;
        }

        const resp = await fetch(path, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ids: uniqueIds })
        });

        const contentType = String(resp.headers.get('content-type') || '').toLowerCase();
        if(contentType.includes('application/json')){
            let msg = `下载失败（HTTP ${resp.status}）`;
            try {
                const data = await resp.json();
                msg = data && data.message ? data.message : msg;
            } catch(_e){ }
            throw new Error(msg);
        }
        if(!resp.ok){
            throw new Error(`下载失败（HTTP ${resp.status}）`);
        }

        const blob = await resp.blob();
        const filename = parseDownloadFilename(resp.headers.get('content-disposition'), fallbackName || '导入模板.xlsx');
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        if(a.parentNode) a.parentNode.removeChild(a);
        window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
    }

    /**
     * 点击遮罩关闭：用「坐标是否在所有 .pm-modal-content 的 border box 之外」判断，而不是仅靠 target.closest。
     * 宽弹窗 content 的矩形常铺满视口（min-height/width:100%），视觉上深色边仍在矩形内，DOM 委托会误判为「点在卡片上」从而永远不关。
     * 使用捕获阶段，避免子节点 stopPropagation 阻断冒泡到壳层。
     * 手势：必须在 pointerdown/mousedown（捕获）时主键就落在壳层遮罩（所有面板外），且 click/dblclick 时坐标仍在面板外才关闭；
     * 避免「在卡片内按下、拖到遮罩上松开」误触关闭。
     * 调试：刷新前执行 window.__SITJOY_DEBUG_MODAL_BACKDROP = true 或 localStorage.setItem('sj.debug.modalBackdrop','1')（setItem 返回 undefined 属正常），
     * 再点弹窗区域，控制台过滤 [modalBackdrop] 可见 insidePanel / primDownOutside 等日志。
     */
    function bindPmModalBackdropClose(modalEl, onClose){
        if(!modalEl || typeof onClose !== 'function') return;

        if(typeof modalEl._pmBackdropCloseCleanup === 'function'){
            try { modalEl._pmBackdropCloseCleanup(); } catch(_e){}
            modalEl._pmBackdropCloseCleanup = null;
        }

        for(let c = modalEl.firstElementChild; c; ){
            const nx = c.nextElementSibling;
            if(c.classList && c.classList.contains('pm-modal-backdrop')) c.remove();
            c = nx;
        }

        let debugBackdrop = false;
        try {
            debugBackdrop = window.__SITJOY_DEBUG_MODAL_BACKDROP === true
                || !!(window.localStorage && window.localStorage.getItem('sj.debug.modalBackdrop') === '1');
        } catch(_e2){
            debugBackdrop = window.__SITJOY_DEBUG_MODAL_BACKDROP === true;
        }
        const dbg = (...args) => {
            if(!debugBackdrop) return;
            try { console.log('[modalBackdrop]', ...args); } catch(_e3){}
        };

        const isPrimaryMouseButton = (e) => {
            if(!e) return false;
            const bt = Number(e.button);
            if(Number.isFinite(bt) && bt !== 0) return false;
            return true;
        };

        const pointInRect = (x, y, r) => {
            if(!r) return false;
            return x >= r.left && x <= r.right && y >= r.top && y <= r.bottom;
        };

        const isElementVisibleForHitTest = (el) => {
            if(!el || typeof el.getBoundingClientRect !== 'function') return false;
            let style;
            try { style = window.getComputedStyle(el); } catch(_e4) { return false; }
            if(!style || style.display === 'none' || style.visibility === 'hidden') return false;
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
        };

        const isMenuOwnedByModal = (menu) => {
            if(!menu) return false;
            if(modalEl.contains(menu)){
                const dd = menu.closest('.feature-category-dropdown');
                return !!(dd && dd.classList.contains('open'));
            }
            if(menu.classList.contains('universal-select-floating-menu')){
                let owned = false;
                universalSelectState.forEach((state) => {
                    if(!state || state.menu !== menu) return;
                    if(!state.wrapper || !state.wrapper.classList.contains('open')) return;
                    if(modalEl.contains(state.wrapper)) owned = true;
                });
                return owned;
            }
            return false;
        };

        /** 点击点是否落在弹窗安全区：白卡片 + 弹窗内已展开的下拉/多选菜单（菜单常超出 .pm-modal-content 矩形） */
        const isPointInsideAnyContentPanel = (clientX, clientY) => {
            const panels = modalEl.querySelectorAll('.pm-modal-content');
            for(let i = 0; i < panels.length; i++){
                const r = panels[i].getBoundingClientRect();
                if(pointInRect(clientX, clientY, r)) return true;
            }

            const openDropdowns = modalEl.querySelectorAll('.feature-category-dropdown.open');
            for(let i = 0; i < openDropdowns.length; i++){
                const menu = openDropdowns[i].querySelector('.feature-category-menu');
                if(!menu || !isElementVisibleForHitTest(menu)) continue;
                const r = menu.getBoundingClientRect();
                if(pointInRect(clientX, clientY, r)) return true;
            }

            let hitFloatingMenu = false;
            universalSelectState.forEach((state) => {
                if(hitFloatingMenu || !state || !state.menu || !state.wrapper) return;
                if(!state.wrapper.classList.contains('open')) return;
                if(!modalEl.contains(state.wrapper)) return;
                if(!isElementVisibleForHitTest(state.menu)) return;
                const r = state.menu.getBoundingClientRect();
                if(pointInRect(clientX, clientY, r)) hitFloatingMenu = true;
            });
            if(hitFloatingMenu) return true;

            return false;
        };

        const isEventTargetInsideModalSafeArea = (e) => {
            const t = e && e.target;
            if(!t || typeof t.closest !== 'function') return false;
            if(t.closest('.pm-modal-content')) return true;
            const menu = t.closest('.feature-category-menu');
            return !!(menu && isMenuOwnedByModal(menu));
        };

        /** 本次完整按压是否从遮罩（所有 .pm-modal-content 外）开始；由 pointerdown 写入，click 消费 */
        let primDownOutside = false;

        const onPointerDownPrimary = (e) => {
            if(!modalEl.classList.contains('active')){
                primDownOutside = false;
                return;
            }
            if(!isPrimaryMouseButton(e)) return;
            const x = Number(e.clientX);
            const y = Number(e.clientY);
            if(!Number.isFinite(x) || !Number.isFinite(y)){
                primDownOutside = false;
                return;
            }
            primDownOutside = !isPointInsideAnyContentPanel(x, y);
            dbg(String(e.type), 'down', 'client', x, y, 'insidePanel', !primDownOutside, 'primDownOutside', primDownOutside, 'target', e.target && e.target.nodeName);
        };

        const onBackdropMouseActivate = (e) => {
            if(!modalEl.classList.contains('active')) return;
            if(!isPrimaryMouseButton(e)) return;
            if(isEventTargetInsideModalSafeArea(e)) return;
            const x = Number(e.clientX);
            const y = Number(e.clientY);
            if(!Number.isFinite(x) || !Number.isFinite(y)) return;
            const inside = isPointInsideAnyContentPanel(x, y);
            dbg(String(e.type), 'up', 'client', x, y, 'insidePanel', inside, 'primDownOutside', primDownOutside, 'target', e.target && e.target.nodeName);
            if(!primDownOutside || inside) return;
            primDownOutside = false;
            try { e.stopPropagation(); } catch(_err){}
            onClose();
        };

        const onSelectStart = (ev) => {
            if(!modalEl.classList.contains('active')) return;
            const t = ev && ev.target;
            if(!t || typeof t.closest !== 'function') return;
            if(t.closest('.pm-modal-content')) return;
            try { ev.preventDefault(); } catch(_e2){}
        };

        /* pointerdown + mousedown：部分环境/控件只稳定触发其一，缺一则 click 时 primDownOutside 一直为 false，遮罩永远不关 */
        modalEl.addEventListener('pointerdown', onPointerDownPrimary, true);
        modalEl.addEventListener('mousedown', onPointerDownPrimary, true);
        modalEl.addEventListener('click', onBackdropMouseActivate, true);
        modalEl.addEventListener('dblclick', onBackdropMouseActivate, true);
        modalEl.addEventListener('selectstart', onSelectStart, true);

        modalEl._pmBackdropCloseCleanup = () => {
            modalEl.removeEventListener('pointerdown', onPointerDownPrimary, true);
            modalEl.removeEventListener('mousedown', onPointerDownPrimary, true);
            modalEl.removeEventListener('click', onBackdropMouseActivate, true);
            modalEl.removeEventListener('dblclick', onBackdropMouseActivate, true);
            modalEl.removeEventListener('selectstart', onSelectStart, true);
            modalEl._pmBackdropCloseCleanup = null;
        };
        modalEl.dataset.pmBackdropCloseBound = '1';
    }

    /**
     * 为未显式调用 bindPmModalBackdropClose 的 .pm-modal 补绑遮罩关闭（避免二级页/脚本顺序导致完全不响应）。
     * 跳过 #confirm-modal（常见为内联 Promise 对话框，需页面自行处理取消逻辑）及 data-pm-backdrop-no-auto="1"。
     */
    function tryAutoBindPmModalBackdrop(el){
        if(!el || el.nodeType !== 1) return;
        if(!el.classList || !el.classList.contains('pm-modal')) return;
        if(el.dataset.pmBackdropCloseBound === '1') return;
        if(String(el.id || '') === 'confirm-modal') return;
        if(String(el.dataset.pmBackdropNoAuto || '').trim() === '1') return;
        bindPmModalBackdropClose(el, () => {
            try {
                el.classList.remove('active');
            } catch(_e){}
            if(typeof syncModalScrollLock === 'function'){
                try { syncModalScrollLock(); } catch(_e2){}
            }
            try {
                el.dispatchEvent(new CustomEvent('pm-modal-backdrop-close', { bubbles: false }));
            } catch(_e3){}
        });
    }

    function initPmModalBackdropAutoBind(){
        if(document.documentElement.dataset.pmBackdropAutoInit === '1') return;
        document.documentElement.dataset.pmBackdropAutoInit = '1';
        const scan = (root) => {
            if(!root || root.nodeType !== 1) return;
            if(root.matches && root.matches('.pm-modal')) tryAutoBindPmModalBackdrop(root);
            if(root.querySelectorAll) root.querySelectorAll('.pm-modal').forEach(tryAutoBindPmModalBackdrop);
        };
        if(document.body) scan(document.body);
        const obs = new MutationObserver((muts) => {
            muts.forEach((m) => {
                (m.addedNodes || []).forEach((n) => {
                    if(!n || n.nodeType !== 1) return;
                    scan(n);
                });
            });
        });
        try {
            if(document.body) obs.observe(document.body, { childList: true, subtree: true });
        } catch(_e){}
        window.addEventListener('load', () => {
            window.setTimeout(() => scan(document.body), 0);
        });
    }

    function ensureAppConfirmModal(){
        let modal = document.getElementById('app-confirm-modal');
        if(modal && document.body.contains(modal)) return modal;
        modal = document.createElement('div');
        modal.id = 'app-confirm-modal';
        modal.className = 'pm-modal';
        modal.innerHTML = [
            '<div class="pm-modal-content" style="max-width:520px;">',
            '  <h3 class="app-confirm-title" style="margin-top:0;">确认操作</h3>',
            '  <p class="app-confirm-message" style="margin:.5rem 0 0;color:var(--morandi-ink);line-height:1.6;white-space:pre-line;"></p>',
            '  <div class="app-confirm-check-row" style="display:none;">',
            '    <label class="app-confirm-check-label">',
            '      <input type="checkbox" class="app-confirm-check-input">',
            '      <span class="app-confirm-check-text">我已知晓此操作不可恢复，确认继续删除</span>',
            '    </label>',
            '  </div>',
            '  <div class="pm-modal-actions" style="margin-top:1rem;">',
            '    <button type="button" class="btn-secondary" data-action="cancel">取消</button>',
            '    <button type="button" class="btn-danger" data-action="confirm">确认</button>',
            '  </div>',
            '</div>'
        ].join('');
        document.body.appendChild(modal);
        return modal;
    }

    function showAppConfirm(options){
        const opt = options && typeof options === 'object' ? options : { message: String(options || '') };
        const title = String(opt.title || '确认操作').trim() || '确认操作';
        const message = String(opt.message || '确认继续执行该操作？').trim() || '确认继续执行该操作？';
        const confirmText = String(opt.confirmText || '确认').trim() || '确认';
        const cancelText = String(opt.cancelText || '取消').trim() || '取消';
        const extraButtons = Array.isArray(opt.extraButtons) ? opt.extraButtons.filter(x => x && x.id && x.text) : [];
        const checkText = String(opt.confirmCheckText || '我已知晓此操作不可恢复，确认继续删除').trim() || '我已知晓此操作不可恢复，确认继续删除';
        const explicitRequireCheck = (typeof opt.requireConfirmCheck === 'boolean') ? opt.requireConfirmCheck : null;
        const autoDanger = /删除|移除|清空|永久|不可恢复|彻底/.test(`${title} ${message} ${confirmText}`);
        const requireCheck = explicitRequireCheck === null ? autoDanger : explicitRequireCheck;

        const modal = ensureAppConfirmModal();
        const titleEl = modal.querySelector('.app-confirm-title');
        const msgEl = modal.querySelector('.app-confirm-message');
        const confirmBtn = modal.querySelector('[data-action="confirm"]');
        const cancelBtn = modal.querySelector('[data-action="cancel"]');
        const checkRow = modal.querySelector('.app-confirm-check-row');
        const checkInput = modal.querySelector('.app-confirm-check-input');
        const checkTextEl = modal.querySelector('.app-confirm-check-text');
        const actionsRow = modal.querySelector('.pm-modal-actions');
        if(titleEl) titleEl.textContent = title;
        if(msgEl) msgEl.textContent = message;
        if(confirmBtn) confirmBtn.textContent = confirmText;
        if(cancelBtn) cancelBtn.textContent = cancelText;
        if(checkTextEl) checkTextEl.textContent = checkText;
        if(checkRow) checkRow.style.display = requireCheck ? '' : 'none';
        if(checkInput) checkInput.checked = false;
        if(requireCheck) modal.classList.add('app-confirm-modal--danger');
        else modal.classList.remove('app-confirm-modal--danger');

        // rebuild extra buttons each time to avoid stale handlers
        const extraCreated = [];
        if(actionsRow){
            actionsRow.querySelectorAll('[data-action="extra"]').forEach(node => node.parentNode && node.parentNode.removeChild(node));
            extraButtons.forEach(btn => {
                const b = document.createElement('button');
                b.type = 'button';
                b.setAttribute('data-action', 'extra');
                b.setAttribute('data-extra-id', String(btn.id));
                b.className = btn.danger ? 'btn-danger' : 'btn-secondary';
                b.textContent = String(btn.text || '').trim() || String(btn.id);
                // insert before cancel button to keep confirm at the end
                const anchor = cancelBtn && cancelBtn.parentNode === actionsRow ? cancelBtn : actionsRow.firstChild;
                actionsRow.insertBefore(b, anchor);
                extraCreated.push(b);
            });
        }

        const updateConfirmState = () => {
            if(!confirmBtn) return;
            if(!requireCheck) {
                confirmBtn.disabled = false;
                return;
            }
            confirmBtn.disabled = !(checkInput && checkInput.checked);
        };
        updateConfirmState();

        const cleanup = () => {
            modal.classList.remove('active');
            modal.classList.remove('app-confirm-modal--danger');
            if(confirmBtn) confirmBtn.removeEventListener('click', onConfirm);
            if(cancelBtn) cancelBtn.removeEventListener('click', onCancel);
            if(checkInput) checkInput.removeEventListener('change', updateConfirmState);
            modal.removeEventListener('pointerdown', onBackdropPointerDown);
            modal.removeEventListener('pointerup', onBackdropPointerUp);
            modal.removeEventListener('pointerleave', onBackdropPointerReset);
            modal.removeEventListener('pointercancel', onBackdropPointerReset);
            document.removeEventListener('keydown', onEsc);
            extraCreated.forEach(b => b && b.removeEventListener && b.removeEventListener('click', onExtra));
            syncModalScrollLock();
        };

        const onConfirm = () => {
            if(requireCheck && checkInput && !checkInput.checked) return;
            cleanup();
            if(typeof opt.onConfirm === 'function') opt.onConfirm();
            if(typeof opt.onClose === 'function') opt.onClose(true);
        };

        const onCancel = () => {
            cleanup();
            if(typeof opt.onCancel === 'function') opt.onCancel();
            if(typeof opt.onClose === 'function') opt.onClose(false);
        };

        const onExtra = (event) => {
            if(event){
                event.preventDefault();
                event.stopPropagation();
            }
            const btn = event && event.currentTarget ? event.currentTarget : null;
            if(!btn) return;
            const id = String(btn.getAttribute('data-extra-id') || '').trim();
            if(!id) return;
            cleanup();
            if(typeof opt.onExtra === 'function') {
                try { opt.onExtra(id); } catch(_) {}
            }
            if(typeof opt.onClose === 'function') opt.onClose({ id });
        };

        let backdropArmed = false;
        const onBackdropPointerDown = (event) => {
            backdropArmed = (event.target === modal);
        };
        const onBackdropPointerUp = (event) => {
            if(backdropArmed && event.target === modal) onCancel();
            backdropArmed = false;
        };
        const onBackdropPointerReset = () => { backdropArmed = false; };

        const onEsc = (event) => {
            if(event.key === 'Escape') onCancel();
        };

        if(confirmBtn) confirmBtn.addEventListener('click', onConfirm);
        if(cancelBtn) cancelBtn.addEventListener('click', onCancel);
        if(checkInput) checkInput.addEventListener('change', updateConfirmState);
        extraCreated.forEach(b => b.addEventListener('click', onExtra));
        modal.addEventListener('pointerdown', onBackdropPointerDown);
        modal.addEventListener('pointerup', onBackdropPointerUp);
        modal.addEventListener('pointerleave', onBackdropPointerReset);
        modal.addEventListener('pointercancel', onBackdropPointerReset);
        document.addEventListener('keydown', onEsc);

        modal.classList.add('active');
        syncModalScrollLock();
    }

    function showAppConfirmAsync(options){
        return new Promise((resolve) => {
            showAppConfirm(Object.assign({}, (options || {}), {
                onClose: (result) => resolve(result)
            }));
        });
    }

    /**
     * 解除全部图片关联并移入「上架资源」/回收站。须先勾选确认框再点确认。
     * @returns {Promise<boolean>}
     */
    function confirmUnlinkAllBindingsMoveToRecycleAsync(options) {
        const opt = options && typeof options === 'object' ? options : {};
        const message = String(opt.message || '').trim()
            || '将解除该图片与面料、销售规格、下单产品的全部关联。\n\n解除全部关联后，若无其他引用，图片文件将移入「上架资源」/回收站，且无法从回收站自动还原到原路径。';
        const checkText = String(opt.confirmCheckText || '').trim()
            || '我已知晓：解除全部关联将把图片移入回收站';
        return showAppConfirmAsync({
            title: String(opt.title || '解除全部关联').trim() || '解除全部关联',
            message,
            confirmText: String(opt.confirmText || '确认解除并移入回收站').trim() || '确认解除并移入回收站',
            cancelText: String(opt.cancelText || '取消').trim() || '取消',
            requireConfirmCheck: true,
            confirmCheckText: checkText,
        }).then((result) => result === true);
    }

    function ensureHelpDotTooltip(){
        if(activeHelpDotTooltip && document.body.contains(activeHelpDotTooltip)) return activeHelpDotTooltip;
        const tooltip = document.createElement('div');
        tooltip.className = 'app-help-floating-tip';
        tooltip.setAttribute('role', 'tooltip');
        tooltip.style.display = 'none';
        document.body.appendChild(tooltip);
        activeHelpDotTooltip = tooltip;
        return tooltip;
    }

    function hideHelpDotTooltip(){
        activeHelpDotAnchor = null;
        if(!activeHelpDotTooltip) return;
        activeHelpDotTooltip.style.display = 'none';
        activeHelpDotTooltip.textContent = '';
    }

    function resolveHelpDotTipText(dot){
        if(!dot) return '';
        const dataTip = String(dot.getAttribute('data-tip') || '').trim();
        if(dataTip) return dataTip;
        const bubble = dot.querySelector('.help-dot-bubble');
        return bubble ? String(bubble.textContent || '').trim() : '';
    }

    /** 去掉与 help-dot 文案相同的原生 title，避免浏览器自带黄框与 .app-help-floating-tip 叠两层 */
    function stripNativeTitlesMirroringHelpDot(dot){
        if(!dot || !dot.classList || !dot.classList.contains('help-dot')) return;
        const tip = String(resolveHelpDotTipText(dot) || '').trim();
        dot.removeAttribute('title');
        if(!tip) return;
        let el = dot.parentElement;
        for(let i = 0; i < 6 && el; i++, el = el.parentElement){
            try{
                if(!el.hasAttribute || !el.hasAttribute('title')) continue;
                const pt = String(el.getAttribute('title') || '').trim();
                if(pt && pt === tip){
                    el.removeAttribute('title');
                }
            }catch(_){ /* ignore */ }
        }
    }

    function positionHelpDotTooltip(dot, tooltip){
        if(!dot || !tooltip) return;
        const dotRect = dot.getBoundingClientRect();
        const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
        const tipRect = tooltip.getBoundingClientRect();

        let left = dotRect.right + 8;
        if(left + tipRect.width > viewportWidth - 8){
            left = dotRect.left - tipRect.width - 8;
        }
        left = Math.max(8, Math.min(left, viewportWidth - tipRect.width - 8));

        let top = dotRect.top - 4;
        if(top + tipRect.height > viewportHeight - 8){
            top = viewportHeight - tipRect.height - 8;
        }
        top = Math.max(8, top);

        tooltip.style.left = `${left}px`;
        tooltip.style.top = `${top}px`;
    }

    function repositionActiveHelpDotTip(){
        if(!activeHelpDotAnchor || !activeHelpDotTooltip) return;
        if(activeHelpDotTooltip.style.display === 'none') return;
        positionHelpDotTooltip(activeHelpDotAnchor, activeHelpDotTooltip);
    }

    function showHelpDotTooltip(dot){
        const text = resolveHelpDotTipText(dot);
        if(!text) return;
        stripNativeTitlesMirroringHelpDot(dot);
        const tooltip = ensureHelpDotTooltip();
        activeHelpDotAnchor = dot;
        tooltip.textContent = text;
        tooltip.style.display = 'block';
        tooltip.style.visibility = 'hidden';
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                if(activeHelpDotAnchor !== dot) return;
                positionHelpDotTooltip(dot, tooltip);
                tooltip.style.visibility = 'visible';
            });
        });
    }

    /** 全站委托：任意 .help-dot 均使用挂到 body 的浮层，避免表格/顶栏裁剪与 z-index 叠层问题 */
    function ensureGlobalHelpDotDelegation(){
        if(helpDotDelegationInstalled) return;
        helpDotDelegationInstalled = true;

        document.addEventListener('pointerover', (e) => {
            if(e.pointerType === 'touch') return;
            const dot = e.target && e.target.closest ? e.target.closest('.help-dot') : null;
            if(!dot) return;
            showHelpDotTooltip(dot);
        }, true);

        document.addEventListener('pointerout', (e) => {
            const dot = e.target && e.target.closest ? e.target.closest('.help-dot') : null;
            if(!dot) return;
            const rel = e.relatedTarget;
            if(rel && dot.contains(rel)) return;
            if(activeHelpDotTooltip && rel && (rel === activeHelpDotTooltip || activeHelpDotTooltip.contains(rel))) return;
            hideHelpDotTooltip();
        }, true);

        document.addEventListener('focusin', (e) => {
            const t = e.target;
            if(t && t.classList && t.classList.contains('help-dot')){
                showHelpDotTooltip(t);
            }
        }, true);

        document.addEventListener('focusout', (e) => {
            const t = e.target;
            if(!t || !t.classList || !t.classList.contains('help-dot')) return;
            const rel = e.relatedTarget;
            if(rel && t.contains(rel)) return;
            hideHelpDotTooltip();
        }, true);
    }

    function bindFloatingHelpDots(root){
        ensureGlobalHelpDotDelegation();
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.help-dot').forEach(dot => {
            dot.classList.add('help-dot--floating');
            stripNativeTitlesMirroringHelpDot(dot);
        });
    }

    /**
     * 将 .card.pm-card 内首个 .pm-toolbar 中、以 .pm-divider 分隔的工具条拆成多块分区（搜索 / 筛选 / 导入导出等），
     * 样式由 .pm-card-zone* 承载；无分隔符的页面保持原单行布局。
     */
    function partitionPmCardToolbars(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.card.pm-card, section.card.pm-card').forEach((card) => {
            if(card.closest && card.closest('.pm-modal')) return;
            const toolbars = Array.from(card.children || []).filter(ch => ch && ch.classList && ch.classList.contains('pm-toolbar'));
            toolbars.forEach((toolbar) => {
                if(toolbar.dataset.pmToolbarZoned === '1') return;
                const actions = toolbar.querySelector(':scope > .pm-toolbar-actions');
                if(!actions || actions.dataset.pmCardPartitioned === '1'){
                    toolbar.dataset.pmToolbarZoned = '1';
                    return;
                }
                const children = Array.from(actions.children || []).filter(ch => ch && ch.nodeType === 1);
                if(!children.length){
                    toolbar.dataset.pmToolbarZoned = '1';
                    return;
                }

                const zones = [];
                let bucket = [];
                for(const el of children){
                    if(el.classList && el.classList.contains('pm-divider')){
                        if(bucket.length){
                            zones.push(bucket);
                            bucket = [];
                        }
                    } else {
                        bucket.push(el);
                    }
                }
                if(bucket.length) zones.push(bucket);
                if(zones.length < 2){
                    toolbar.dataset.pmToolbarZoned = '1';
                    return;
                }

                while(actions.firstChild){
                    actions.removeChild(actions.firstChild);
                }
                zones.forEach((nodes, idx) => {
                    const z = document.createElement('div');
                    let zoneClass = 'pm-card-zone';
                    if(idx === 0){
                        zoneClass += ' pm-card-zone--search';
                    } else if(idx === zones.length - 1){
                        zoneClass += ' pm-card-zone--bulk';
                    } else {
                        zoneClass += ' pm-card-zone--filters';
                    }
                    z.className = zoneClass;
                    nodes.forEach((n) => z.appendChild(n));
                    actions.appendChild(z);
                });
                toolbar.classList.add('pm-toolbar--zoned');
                actions.dataset.pmCardPartitioned = '1';
                toolbar.dataset.pmToolbarZoned = '1';
            });
        });
    }

    function showAppResultPanel(options){
        showAppSaveResult(options);
    }

    /** 数据写入库后的统一右下角结果提示（成功自动收起，失败常驻可手动关闭） */
    function showAppSaveResult(options){
        const opt = options && typeof options === 'object' ? options : { message: String(options || '') };
        const isError = !!opt.isError || opt.success === false;
        const actionLabels = {
            save: ['保存成功', '保存失败'],
            delete: ['删除成功', '删除失败'],
            update: ['更新成功', '更新失败'],
            import: ['导入成功', '导入失败'],
            create: ['创建成功', '创建失败'],
        };
        const action = String(opt.action || 'save').trim().toLowerCase();
        const labels = actionLabels[action] || ['操作成功', '操作失败'];
        let title = String(opt.title || '').trim();
        if(!title) title = isError ? labels[1] : labels[0];

        const message = String(opt.message || opt.summary || '').trim();
        const details = [];
        if(Array.isArray(opt.details)){
            opt.details.forEach(item => {
                const text = String(item || '').trim();
                if(text) details.push(text);
            });
        }
        if(Array.isArray(opt.errors)){
            opt.errors.forEach(err => {
                if(!err) return;
                if(typeof err === 'string'){
                    const text = String(err).trim();
                    if(text) details.push(text);
                    return;
                }
                const row = err.row || err.id || err.sku || '-';
                const msg = err.error || err.message || '失败';
                details.push(`${row}: ${msg}`);
            });
        }

        const lines = [title];
        if(message) lines.push(message);
        if(details.length) lines.push(details.filter(Boolean).slice(0, 10).join('\n'));
        const text = lines.filter(Boolean).join('\n');
        const duration = opt.duration !== undefined ? Number(opt.duration) : (isError ? 0 : 2800);
        showAppToast(text, isError, Number.isFinite(duration) ? duration : (isError ? 0 : 2800));
    }

    function ensureUploadProgressPanel(){
        let panel = document.getElementById('app-upload-progress-panel');
        if(panel && document.body.contains(panel)) return panel;
        panel = document.createElement('div');
        panel.id = 'app-upload-progress-panel';
        panel.className = 'app-upload-progress-panel';
        panel.innerHTML = [
            '<div class="app-upload-progress-head">',
            '  <div class="app-upload-progress-title">上传中...</div>',
            '  <button type="button" class="app-upload-progress-close" aria-label="关闭">×</button>',
            '</div>',
            '<div class="app-upload-progress-summary"></div>',
            '<div class="app-upload-progress-bar"><span></span></div>'
        ].join('');
        document.body.appendChild(panel);
        const closeBtn = panel.querySelector('.app-upload-progress-close');
        if(closeBtn){
            closeBtn.addEventListener('click', () => panel.classList.remove('show'));
        }
        return panel;
    }

    function showAppUploadProgress(options){
        const opt = options && typeof options === 'object' ? options : { title: String(options || '上传中...') };
        const panel = ensureUploadProgressPanel();
        const title = String(opt.title || '上传中...').trim() || '上传中...';
        const summary = String(opt.summary || '').trim();
        const percent = Math.max(0, Math.min(100, Number(opt.percent || 0)));
        const titleEl = panel.querySelector('.app-upload-progress-title');
        const summaryEl = panel.querySelector('.app-upload-progress-summary');
        const fillEl = panel.querySelector('.app-upload-progress-bar span');

        if(titleEl) titleEl.textContent = title;
        if(summaryEl){
            summaryEl.textContent = summary;
            summaryEl.style.display = summary ? '' : 'none';
        }
        if(fillEl){
            fillEl.style.width = `${percent}%`;
        }
        panel.classList.add('show');
        syncAppToastStackOffset();
    }

    function hideAppUploadProgress(){
        const panel = document.getElementById('app-upload-progress-panel');
        if(panel) panel.classList.remove('show');
        syncAppToastStackOffset();
    }

    function uploadBatchImportFile(options){
        const opt = options && typeof options === 'object' ? options : {};
        const file = opt.file;
        const url = String(opt.url || '').trim();
        const title = String(opt.title || '批量上传').trim() || '批量上传';
        const uploadSummary = String(opt.uploadSummary || '正在上传文件...').trim() || '正在上传文件...';
        const processSummary = String(opt.processSummary || '正在解析并写入数据...').trim() || '正在解析并写入数据...';
        if(!file || !url){
            return Promise.reject(new Error('缺少 file 或 url'));
        }

        const formData = new FormData();
        formData.append('file', file);
        if(opt.extraFormData && typeof opt.extraFormData === 'object'){
            Object.keys(opt.extraFormData).forEach(key => {
                formData.append(key, opt.extraFormData[key]);
            });
        }

        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            let processingShown = false;
            xhr.open('POST', url);

            if(showAppUploadProgress){
                showAppUploadProgress({ title, summary: uploadSummary, percent: 5 });
            }

            xhr.upload.addEventListener('progress', evt => {
                if(!evt.lengthComputable || !showAppUploadProgress) return;
                const pct = Math.round((evt.loaded / evt.total) * 55) + 5;
                showAppUploadProgress({
                    title,
                    summary: uploadSummary,
                    percent: Math.max(5, Math.min(60, pct)),
                });
            });

            xhr.addEventListener('readystatechange', () => {
                if(processingShown || !showAppUploadProgress) return;
                if(xhr.readyState === XMLHttpRequest.HEADERS_RECEIVED || xhr.readyState === XMLHttpRequest.LOADING){
                    processingShown = true;
                    showAppUploadProgress({ title, summary: processSummary, percent: 72 });
                }
            });

            xhr.addEventListener('load', () => {
                if(showAppUploadProgress){
                    showAppUploadProgress({ title: '即将完成', summary: '正在整理结果...', percent: 92 });
                }
                let data = null;
                try{
                    data = JSON.parse(xhr.responseText || '{}');
                }catch(e){
                    hideAppUploadProgress();
                    const snippet = String(xhr.responseText || '').replace(/\s+/g, ' ').trim().slice(0, 180);
                    const hint = snippet
                        ? `（HTTP ${xhr.status}，非 JSON 响应：${snippet}）`
                        : `（HTTP ${xhr.status}，响应为空或非 JSON，可能请求超时）`;
                    reject(new Error('响应解析失败' + hint));
                    return;
                }
                hideAppUploadProgress();
                if(xhr.status >= 200 && xhr.status < 300){
                    resolve(data);
                    return;
                }
                reject(new Error((data && data.message) ? data.message : `请求失败 (${xhr.status})`));
            });

            xhr.addEventListener('error', () => {
                hideAppUploadProgress();
                reject(new Error('网络错误'));
            });

            xhr.addEventListener('abort', () => {
                hideAppUploadProgress();
                reject(new Error('已取消'));
            });

            xhr.send(formData);
        });
    }

    function handleBatchImportResponse(data, options){
        const opt = options && typeof options === 'object' ? options : {};
        const title = String(opt.title || '批量导入').trim() || '批量导入';
        const onSuccess = typeof opt.onSuccess === 'function' ? opt.onSuccess : null;

        if(!data || data.status !== 'success'){
            const msg = (data && data.message) ? data.message : '导入失败';
            if(showAppResultPanel){
                showAppResultPanel({
                    title: '导入失败',
                    summary: msg,
                    details: Array.isArray(data && data.errors)
                        ? data.errors.map(item => `${item.row || '-'}: ${item.error || item.message || '校验失败'}`)
                        : [],
                    isError: true,
                });
            }else if(showAppToast){
                showAppToast(msg, true);
            }
            return false;
        }

        const errCount = Array.isArray(data.errors) ? data.errors.length : 0;
        const skipped = Number(data.skipped_sample_rows || 0) > 0
            ? `，跳过示例 ${data.skipped_sample_rows}`
            : '';
        const skippedExisting = Number(data.skipped_existing || 0) > 0
            ? `，跳过已存在 ${data.skipped_existing}`
            : '';
        const truncated = data.errors_truncated
            ? `（${data.errors_message || '错误列表已截断'}）`
            : '';
        const summary = `导入完成：新增 ${data.created || 0}，更新 ${data.updated || 0}，未变更 ${data.unchanged || 0}${errCount ? `，失败 ${errCount}` : ''}${skipped}${skippedExisting}${truncated}`;

        if(errCount && showAppResultPanel){
            showAppResultPanel({
                title: '导入完成，但有失败记录',
                summary,
                details: data.errors.map(item => `${item.row || '-'}: ${item.error || item.message || '校验失败'}`),
                isError: true,
            });
        }else if(showAppToast){
            showAppToast(summary, false, errCount ? 6500 : 4200);
        }

        if(onSuccess) onSuccess(data);
        return true;
    }

    function syncModalScrollLock(){
        const hasActiveModal = !!document.querySelector('.pm-modal.active');
        document.documentElement.classList.toggle('has-active-modal', hasActiveModal);
        document.body.classList.toggle('has-active-modal', hasActiveModal);
    }

    function inferErrorFromResponseEl(el){
        const cls = String(el.className || '').toLowerCase();
        const style = String(el.getAttribute('style') || '').toLowerCase();
        if(cls.includes('error') || style.includes('ffecec') || style.includes('#a33') || style.includes('rgb(163')) return true;
        if(cls.includes('success') || style.includes('f0fff0') || style.includes('2f6f2f')) return false;
        const text = String(el.textContent || '').toLowerCase();
        if(/\(\d{4}\s*,\s*"unknown column|unknown column|sql|traceback|exception|error|missing|invalid|failed|denied/.test(text)) return true;
        if(/success|成功|完成|已保存/.test(text)) return false;
        return false;
    }

    function bridgeLegacyResponseToToast(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.response').forEach(el => {
            if(responseToastState.has(el)) return;
            const state = { lastSig: '', lastToastAt: 0 };
            responseToastState.set(el, state);
            el.style.display = 'none';

            const flushToast = () => {
                const text = String(el.textContent || '').trim();
                if(!text){
                    state.lastSig = '';
                    return;
                }
                const isError = inferErrorFromResponseEl(el);
                const sig = `${isError ? 'e' : 's'}:${text}`;
                const now = Date.now();
                /* 仅抑制极短时间内的重复触发（同一轮 DOM 更新可能多次回调），不抑制用户多次操作后的相同文案 */
                if(sig === state.lastSig && (now - state.lastToastAt) < 90){
                    return;
                }
                state.lastSig = sig;
                state.lastToastAt = now;
                showAppToast(text, isError);
            };

            const observer = new MutationObserver(() => {
                flushToast();
            });
            observer.observe(el, { childList: true, subtree: true, characterData: true });

            state.observer = observer;
            flushToast();
        });
    }

    function makeStorageKey(table, suffix){
        const pathKey = String(location.pathname || '/').replace(/[^a-zA-Z0-9/_-]+/g, '_');
        const tableKey = table.id || table.dataset.manageKey || 'table';
        return `sitjoy:${pathKey}:${tableKey}:${suffix}`;
    }

    /** 月份等宽表：与 column-widths 分文件存「统一月份列宽」，避免换一批月份键时 JSON 里旧 m_* 与整表重写互相覆盖 */
    const PM_MONTH_COL_GROUP_WIDTH_KEY = '__pm_month_col_group__';

    function makePmMonthGroupWidthStorageKey(table){
        return makeStorageKey(table, 'pm-month-group-w');
    }

    const PAGE_PREFS_COLUMN_FILTERS_SUFFIX = 'column-filters';
    const PAGE_PREFS_CUSTOM_SUFFIX = 'page-filters';
    const PAGE_PREFS_SORT_STACK_SUFFIX = 'sort-stack';
    const tableFilterProviders = new Map();
    const tablePagePrefsSaveTimers = new Map();

    function resolveTableForPagePrefs(tableOrSelector){
        if(!tableOrSelector) return null;
        if(typeof tableOrSelector === 'string') return document.querySelector(tableOrSelector);
        if(tableOrSelector.tagName === 'TABLE') return tableOrSelector;
        return null;
    }

    function tableRegistryKeyForPagePrefs(table){
        if(!table) return '';
        return String(table.id || table.dataset.manageKey || '').trim();
    }

    function tableSkipsFilterPersist(table){
        return String(table && table.dataset ? table.dataset.pmNoFilterPersist || '' : '') === '1';
    }

    function readJsonStorage(key){
        try {
            const raw = localStorage.getItem(key);
            if(!raw) return null;
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    function writeJsonStorage(key, value){
        try {
            localStorage.setItem(key, JSON.stringify(value));
        } catch (_) {}
    }

    function removeStorageKey(key){
        try { localStorage.removeItem(key); } catch (_) {}
    }

    function readPersistedColumnFilters(table){
        if(!table || tableSkipsFilterPersist(table)) return null;
        const parsed = readJsonStorage(makeStorageKey(table, PAGE_PREFS_COLUMN_FILTERS_SUFFIX));
        if(!parsed || typeof parsed !== 'object') return null;
        return parsed;
    }

    function persistManagedColumnFilters(table, snapshot){
        if(!table || tableSkipsFilterPersist(table)) return;
        writeJsonStorage(makeStorageKey(table, PAGE_PREFS_COLUMN_FILTERS_SUFFIX), snapshot || {});
    }

    function clearPersistedFiltersForTable(table){
        if(!table) return;
        removeStorageKey(makeStorageKey(table, PAGE_PREFS_COLUMN_FILTERS_SUFFIX));
        removeStorageKey(makeStorageKey(table, PAGE_PREFS_CUSTOM_SUFFIX));
    }

    function normalizeManagedSortStack(raw){
        if(!Array.isArray(raw)) return [];
        const out = [];
        const seen = new Set();
        raw.forEach((item) => {
            const key = String(item && item.key != null ? item.key : '').trim();
            if(!key || seen.has(key)) return;
            const dir = String(item && item.dir != null ? item.dir : 'desc').trim().toLowerCase() === 'asc' ? 'asc' : 'desc';
            seen.add(key);
            out.push({ key, dir });
        });
        return out;
    }

    function readPersistedSortStack(table){
        if(!table || tableSkipsFilterPersist(table)) return [];
        const parsed = readJsonStorage(makeStorageKey(table, PAGE_PREFS_SORT_STACK_SUFFIX));
        if(Array.isArray(parsed)) return normalizeManagedSortStack(parsed);
        if(parsed && Array.isArray(parsed.stack)) return normalizeManagedSortStack(parsed.stack);
        return [];
    }

    function persistManagedSortStack(table, stack){
        if(!table || tableSkipsFilterPersist(table)) return;
        writeJsonStorage(makeStorageKey(table, PAGE_PREFS_SORT_STACK_SUFFIX), normalizeManagedSortStack(stack));
    }

    function clearPersistedSortStack(table){
        if(!table) return;
        removeStorageKey(makeStorageKey(table, PAGE_PREFS_SORT_STACK_SUFFIX));
    }

    function syncLegacySortFieldsFromStack(state){
        if(!state) return;
        const stack = normalizeManagedSortStack(state.sortStack);
        state.sortStack = stack;
        const first = stack[0] || null;
        state.sortOrigin = first ? first.key : null;
        state.sortDir = first ? first.dir : null;
    }

    function managedSortStackHasEntries(state){
        return normalizeManagedSortStack(state && state.sortStack).length > 0;
    }

    function resolveTableFilterProvider(table){
        const key = tableRegistryKeyForPagePrefs(table);
        if(!key) return null;
        return tableFilterProviders.get(key) || null;
    }

    function sitjoyPersistRegisteredTablePageFilters(table){
        if(!table || tableSkipsFilterPersist(table)) return;
        const provider = resolveTableFilterProvider(table);
        if(!provider || typeof provider.collect !== 'function') return;
        let data = null;
        try { data = provider.collect(); } catch (_) { return; }
        writeJsonStorage(makeStorageKey(table, PAGE_PREFS_CUSTOM_SUFFIX), { v: 1, data });
    }

    function sitjoySchedulePersistRegisteredTablePageFilters(table, delayMs){
        const key = tableRegistryKeyForPagePrefs(table);
        if(!key) return;
        const prev = tablePagePrefsSaveTimers.get(key);
        if(prev) window.clearTimeout(prev);
        tablePagePrefsSaveTimers.set(key, window.setTimeout(() => {
            tablePagePrefsSaveTimers.delete(key);
            sitjoyPersistRegisteredTablePageFilters(table);
        }, Math.max(0, Number(delayMs) || 240)));
    }

    function sitjoyRestoreRegisteredTablePageFilters(table){
        if(!table || tableSkipsFilterPersist(table)) return;
        const provider = resolveTableFilterProvider(table);
        if(!provider || typeof provider.apply !== 'function') return;
        const parsed = readJsonStorage(makeStorageKey(table, PAGE_PREFS_CUSTOM_SUFFIX));
        if(!parsed) return;
        const data = parsed && parsed.data != null ? parsed.data : parsed;
        try { provider.apply(data, { source: 'storage' }); } catch (_) {}
    }

    window.SitjoyPagePrefs = Object.assign({}, window.SitjoyPagePrefs || {}, {
        makeKey: makeStorageKey,
        load(scopeTable, suffix){
            const table = resolveTableForPagePrefs(scopeTable);
            if(!table) return null;
            const parsed = readJsonStorage(makeStorageKey(table, String(suffix || PAGE_PREFS_CUSTOM_SUFFIX)));
            if(!parsed) return null;
            if(parsed && parsed.data != null) return parsed.data;
            return parsed;
        },
        save(scopeTable, data, suffix){
            const table = resolveTableForPagePrefs(scopeTable);
            if(!table || tableSkipsFilterPersist(table)) return;
            writeJsonStorage(makeStorageKey(table, String(suffix || PAGE_PREFS_CUSTOM_SUFFIX)), { v: 1, data });
        },
        clear(scopeTable, suffix){
            const table = resolveTableForPagePrefs(scopeTable);
            if(!table) return;
            if(!suffix){
                clearPersistedFiltersForTable(table);
                return;
            }
            removeStorageKey(makeStorageKey(table, String(suffix)));
        },
        registerTableFilters(tableOrSelector, handlers){
            const table = resolveTableForPagePrefs(tableOrSelector);
            if(!table) return false;
            const key = tableRegistryKeyForPagePrefs(table);
            if(!key) return false;
            tableFilterProviders.set(key, Object.assign({ table }, handlers || {}));
            sitjoyRestoreRegisteredTablePageFilters(table);
            return true;
        },
        saveTablePageFilters(tableOrSelector, debounceMs){
            const table = resolveTableForPagePrefs(tableOrSelector);
            if(!table) return;
            if(debounceMs != null && Number(debounceMs) > 0){
                sitjoySchedulePersistRegisteredTablePageFilters(table, debounceMs);
                return;
            }
            sitjoyPersistRegisteredTablePageFilters(table);
        }
    });

    function shouldManageTable(table){
        if(!table || table.tagName !== 'TABLE') return false;
        if(table.dataset.disableTableManage === '1') return false;
        if(!table.tHead || !table.tBodies || !table.tBodies[0]) return false;
        if(!table.tHead.rows.length) return false;
        const firstRow = table.tHead.rows[0];
        if(!firstRow || firstRow.cells.length < 2) return false;
        return true;
    }

    /** 分离克隆表头已禁用：双表 colgroup/列序易与表体错位，统一使用单表 sticky */
    function managedTableUsesDetachedHeader(_tableOrState){
        return false;
    }

    function getHeaderMeta(table){
        if(!table.tHead || !table.tHead.rows.length) return [];
        const cells = Array.from(table.tHead.rows[0].cells || []);
        const meta = cells.map((cell, idx) => {
            if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
            const origin = Number(cell.dataset.manageColOrigin);
            const rawLabel = extractHeaderLabelText(cell);
            const key = String(cell.dataset.manageColKey || rawLabel || `字段${origin + 1}`).trim();
            if(!cell.dataset.manageColKey) cell.dataset.manageColKey = key;
            const fallback = cell.querySelector('input[type="checkbox"]')
                ? '多选框'
                : (key === '__sj_agg__' ? '展开收起' : `字段${origin + 1}`);
            return {
                origin,
                key,
                label: rawLabel || fallback,
                cell
            };
        });
        return disambiguateDuplicateManagedHeaderLabels(meta);
    }

    function extractHeaderLabelText(cell){
        if(!cell) return '';
        const clone = cell.cloneNode(true);
        clone.querySelectorAll('.pm-col-resizer, .transit-sub-sort-btn, button, input, select, textarea, .help-dot, script, style, svg').forEach(node => {
            if(node && node.parentNode) node.parentNode.removeChild(node);
        });
        return String(clone.textContent || '')
            .replace(/[↕↑↓▲▼▴▾]/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    /** 表头可见文案重复时，用 manageColKey 区分，避免列筛选/字段面板与持久化键冲突 */
    function disambiguateDuplicateManagedHeaderLabels(meta){
        if(!Array.isArray(meta) || meta.length < 2) return meta;
        const groups = new Map();
        meta.forEach((entry, idx) => {
            const lbl = String(entry.label || '').trim();
            if(!lbl) return;
            if(!groups.has(lbl)) groups.set(lbl, []);
            groups.get(lbl).push({ entry, idx });
        });
        groups.forEach((items) => {
            if(items.length <= 1) return;
            items.forEach(({ entry }, dupIdx) => {
                const lbl = String(entry.label || '').trim();
                const key = String(entry.key || '').trim();
                entry.label = (key && key !== lbl)
                    ? key
                    : `${lbl}${items.length > 1 ? String(dupIdx + 1) : ''}`;
            });
        });
        return meta;
    }

    /** 全站数值展示：需显示小数时统一两位；百分数亦保留两位小数 */
    const SITJOY_PERCENT_COLUMN_KEY_RE = /(?:^|_)(?:acos|acoas|ctr|cvr|a_to_z|defect|negative_feedback|chargeback|late_shipment|cancel|tracking|delivery|discount_rate|refund_rate|commission_rate|net_margin_rate|pct|percent)(?:_|$)|_rate$/i;
    const SITJOY_INTEGER_COLUMN_KEY_RE = /(?:^|_)(?:qty|quantity|impressions|clicks|orders|order_qty|sales_qty|session|rows|__rows|index|seq|sort_order|count|pack_qty|carton_qty)(?:_|$)/i;
    const SITJOY_DECIMAL_COLUMN_KEY_RE = /(?:^|_)(?:amount|price|cost|spend|sales|profit|freight|refund|margin|commission|cpc|bid|usd|cny|eur|avg|average|weight|net_sales|gross_sales|estimated_|est_|last_mile|warehouse_cost|rois)(?:_|$)/i;
    const SITJOY_PERCENT_LABEL_RE = /(?:率|占比|ACOS|ACOAS|CTR|CVR)$/i;
    const SITJOY_INTEGER_LABEL_RE = /(?:销量|数量|件数|点击|展示|订单量|记录数|Sessions)/i;
    const SITJOY_DECIMAL_LABEL_RE = /(?:金额|花费|销售额|成本|费用|价格|单价|运费|佣金|利润|USD|usd)/i;

    function sitjoyResolveNumberDisplayKind(key, label){
        const k = String(key || '').trim();
        const lab = String(label || '').trim();
        if(SITJOY_PERCENT_COLUMN_KEY_RE.test(k) || (lab && SITJOY_PERCENT_LABEL_RE.test(lab))) return 'percent';
        if(SITJOY_INTEGER_COLUMN_KEY_RE.test(k) || (lab && SITJOY_INTEGER_LABEL_RE.test(lab) && !SITJOY_DECIMAL_LABEL_RE.test(lab))) return 'integer';
        if(SITJOY_DECIMAL_COLUMN_KEY_RE.test(k) || (lab && SITJOY_DECIMAL_LABEL_RE.test(lab))) return 'decimal';
        return 'auto';
    }

    function formatSitjoyNumber(value, options){
        const opts = options && typeof options === 'object' ? options : {};
        const empty = opts.empty != null ? opts.empty : '';
        if(value === null || value === undefined || value === '') return empty;

        let text = String(value).trim();
        if(!text || text === '-' || text === '—') return text;

        let parsedFromPercent = false;
        if(text.endsWith('%')){
            parsedFromPercent = true;
            text = text.slice(0, -1).replace(/[,\s\u00a0]/g, '');
        } else {
            text = text.replace(/[,\s\u00a0]/g, '');
        }

        const n = Number(text);
        if(!Number.isFinite(n)) return String(value);

        let kind = String(opts.kind || opts.mode || 'auto').toLowerCase();
        if(kind === 'auto') kind = sitjoyResolveNumberDisplayKind(opts.key, opts.label);

        if(kind === 'percent' || parsedFromPercent){
            let pct = n;
            if(!parsedFromPercent){
                const ratio = opts.ratio;
                if(ratio === true) pct = n * 100;
                else if(ratio === false) pct = n;
                else if(Math.abs(n) <= 1.5) pct = n * 100;
            }
            return pct.toFixed(2) + '%';
        }

        if(kind === 'integer'){
            if(Math.abs(n - Math.round(n)) < 1e-9) return String(Math.round(n));
            return n.toFixed(2);
        }

        if(kind === 'decimal'){
            return n.toFixed(2);
        }

        if(Math.abs(n - Math.round(n)) < 1e-9) return String(Math.round(n));
        return n.toFixed(2);
    }

    function formatSitjoyTableCellDisplayText(text, key, label){
        const raw = String(text ?? '').trim();
        if(!raw || raw === '-' || raw === '—' || /加载|暂无|失败/.test(raw)) return raw;
        return formatSitjoyNumber(raw, { key, label, kind: 'auto' });
    }

    /** 全局表格数值列右对齐：显式 data-pm-align="num|text|center" 可覆盖启发式 */
    const PM_NUM_ALIGN_NON_NUMERIC_KEYS = new Set([
        '__toggle', '__sku', '__fabric', '__spec', '__perf_chk__', '__perf_op__', '__transit_chk__',
        '__sj_agg__', '__sj_group_actions__', '__sj_group_middle__',
        'record_date', 'shop_name', 'platform_sku', 'sku_family', 'platform_type', 'operation_type_name',
        'target_object', 'detail', 'campaign', 'ad_name', 'keyword', 'asin', 'fnsku', 'color', 'colour',
        'fabric', 'spec_name', 'spec', 'material', 'category', 'brand', 'status', 'status_name',
        'type_name', 'name', 'title', 'label', 'remark', 'note', 'comment', 'description',
        'operator', 'employee', 'user', 'email', 'phone', 'address', 'url', 'path', 'file', 'barcode',
        'tracking_no', 'waybill', 'container_no', 'warehouse', 'location', 'carrier'
    ]);
    const PM_NUM_ALIGN_NON_NUMERIC_KEY_RE = /(?:^|_)(?:name|title|label|sku|desc|description|remark|notes?|comment|status|type_name|shop|platform|color|colour|fabric|spec|material|category|brand|operator|employee|user|email|phone|address|url|path|file|barcode|asin|fnsku|keyword|campaign|target|object|detail|toggle|chk|check|thumb|image|photo|banner|icon|actions?|operation_type|delivery|warehouse|location|carrier|tracking|waybill|container|certification|feature|audit|log|message|error|warning|date|time|datetime|month_label)(?:_|$)/i;
    const PM_NUM_ALIGN_NUMERIC_KEY_RE = /(?:^|_)(?:qty|quantity|amount|price|cost|count|total|num|number|rate|pct|percent|acos|acoas|rois|ctr|cvr|cpc|spend|sales|profit|margin|commission|freight|refund|impressions|clicks|orders|session|rows|weight|volume|cbm|days|stock|inventory|surplus|shortage|pack|carton|unit|usd|cny|eur|moq|lead_time|width|height|length|depth|ratio|score|rank|index|seq|sort_order|gap|delta|diff|avg|average|min|max|sum|listed|shipped|received|allocated|available|reserved|pending|completed|progress)(?:_|$)|^__rows$|^\d{4}-\d{2}$/;
    const PM_NUM_ALIGN_NUMERIC_LABEL_RE = /(?:销量|数量|件数|订单|点击|展示|花费|销售额|金额|成本|费用|价格|单价|运费|佣金|利润|退款|库存|在途|缺口|盈余|周转|天数|重量|体积|占比|比率|率)$|^(?:ACOS|ACOAS|ROIS|CTR|CVR|CPC|Sessions)/i;

    function managedHeaderCellIsCenterAligned(cell){
        if(!cell) return false;
        if(cell.querySelector('input[type="checkbox"]')) return true;
        const ta = String(cell.style.textAlign || '').trim().toLowerCase();
        if(ta === 'center') return true;
        if(cell.classList && cell.classList.contains('pm-col-center')) return true;
        return false;
    }

    function isManagedNonNumericColumnKey(key){
        const k = String(key || '').trim();
        if(!k) return true;
        if(PM_NUM_ALIGN_NON_NUMERIC_KEYS.has(k)) return true;
        if(/^__/.test(k) && k !== '__rows') return true;
        return PM_NUM_ALIGN_NON_NUMERIC_KEY_RE.test(k);
    }

    function isManagedNumericColumnKey(key, label){
        const k = String(key || '').trim();
        if(!k || isManagedNonNumericColumnKey(k)) return false;
        if(PM_NUM_ALIGN_NUMERIC_KEY_RE.test(k)) return true;
        const lab = String(label || '').trim();
        if(lab && PM_NUM_ALIGN_NUMERIC_LABEL_RE.test(lab)) return true;
        return false;
    }

    function managedCellLooksNonNumeric(cell){
        if(!cell) return true;
        if(cell.querySelector('input[type="checkbox"], select, textarea, button, a, img, .universal-select, .pm-actions, .sj-group-row-actions, .pm-table-note-wrap')){
            if(cell.querySelector('input[type="number"]') && !cell.querySelector('input:not([type="number"]), select, textarea, button:not([type="button"])')) return false;
            return true;
        }
        if(cell.querySelector('input[type="date"], input[type="datetime-local"], input[type="text"], input[type="email"], input[type="tel"], input[type="url"], input[type="search"]')) return true;
        return false;
    }

    function managedCellIsPlainNumericText(cell){
        if(!cell || managedCellLooksNonNumeric(cell)) return false;
        const children = Array.from(cell.children || []);
        if(!children.length) return true;
        if(children.length === 1 && children[0].classList && children[0].classList.contains('sf-cell-num-text')) return true;
        return false;
    }

    function managedCellSampleIsNumeric(cell){
        if(managedCellLooksNonNumeric(cell)) return false;
        const text = String(cell.textContent || '').trim();
        if(!text || text === '-' || text === '—' || text === '...' || text === '加载中...' || text === '暂无数据') return null;
        if(/^-?\d[\d,]*(?:\.\d+)?%?$/.test(text.replace(/\s/g, ''))) return true;
        return false;
    }

    function resolveManagedNumericColumnKeys(state, table, headerMeta){
        const numericKeys = new Set();
        (Array.isArray(headerMeta) ? headerMeta : []).forEach((meta) => {
            const key = String(meta && meta.key || '').trim();
            const cell = meta && meta.cell;
            if(!key || managedHeaderCellIsCenterAligned(cell)) return;
            const explicit = cell ? String(cell.dataset.pmAlign || cell.dataset.pmColAlign || '').trim().toLowerCase() : '';
            if(explicit === 'num' || explicit === 'number' || explicit === 'right'){
                numericKeys.add(key);
                return;
            }
            if(explicit === 'text' || explicit === 'left' || explicit === 'center') return;
            if(isManagedNumericColumnKey(key, meta.label)) numericKeys.add(key);
        });

        const rows = state
            ? getDataRows(state).filter((row) => row && row.style.display !== 'none').slice(0, 40)
            : Array.from((table && table.tBodies && table.tBodies[0] && table.tBodies[0].rows) || [])
                .filter((row) => row && row.style.display !== 'none')
                .slice(0, 40);

        (Array.isArray(headerMeta) ? headerMeta : []).forEach((meta) => {
            const key = String(meta && meta.key || '').trim();
            if(!key || numericKeys.has(key) || managedHeaderCellIsCenterAligned(meta.cell)) return;
            if(isManagedNonNumericColumnKey(key)) return;
            let num = 0;
            let total = 0;
            for(const row of rows){
                let cell = null;
                if(state){
                    cell = mapRowByKey(row).get(key);
                } else {
                    const idx = headerMeta.findIndex((m) => String(m.key || '').trim() === key);
                    cell = idx >= 0 ? row.cells[idx] : null;
                }
                if(!cell) continue;
                const sample = managedCellSampleIsNumeric(cell);
                if(sample === null) continue;
                total += 1;
                if(sample) num += 1;
            }
            if(total >= 3 && num / total >= 0.8) numericKeys.add(key);
        });
        return numericKeys;
    }

    function applyNumericColumnAlignForTable(table){
        if(!table || table.tagName !== 'TABLE') return;
        if(String(table.dataset.pmDisableNumAlign || '') === '1') return;
        if(!table.tHead || !table.tHead.rows || !table.tHead.rows.length) return;
        const headerMeta = getHeaderMeta(table);
        if(!headerMeta.length) return;
        const state = managedTableState.get(table) || null;
        const numericKeys = resolveManagedNumericColumnKeys(state, table, headerMeta);
        const headerRow = table.tHead.rows[0];

        const applyToCell = (cell, headerCell) => {
            if(!cell) return;
            if(managedHeaderCellIsCenterAligned(cell)){
                cell.classList.remove('pm-col-num');
                return;
            }
            const key = String((headerCell && headerCell.dataset.manageColKey) || cell.dataset.manageColKey || '').trim();
            const explicit = String(cell.dataset.pmAlign || cell.dataset.pmColAlign || '').trim().toLowerCase();
            if(explicit === 'text' || explicit === 'left' || explicit === 'center'){
                cell.classList.remove('pm-col-num');
                return;
            }
            const isNum = explicit === 'num' || explicit === 'number' || explicit === 'right' || (key && numericKeys.has(key));
            cell.classList.toggle('pm-col-num', !!isNum);
        };

        Array.from(table.tHead.rows || []).forEach((row) => {
            Array.from(row.cells || []).forEach((cell, idx) => {
                applyToCell(cell, headerRow.cells[idx] || cell);
            });
        });

        const bodyRows = state
            ? getDataRows(state)
            : Array.from(table.tBodies[0]?.rows || []).filter((row) => {
                const tag = row && row.parentNode ? String(row.parentNode.tagName || '').toUpperCase() : '';
                return tag === 'TBODY';
            });
        bodyRows.forEach((row) => {
            Array.from(row.cells || []).forEach((cell, idx) => {
                applyToCell(cell, headerRow.cells[idx]);
            });
        });
    }

    function applyNumericColumnDisplayFormatForTable(table){
        if(!table || table.tagName !== 'TABLE') return;
        if(String(table.dataset.pmDisableNumFormat || table.dataset.pmDisableNumAlign || '') === '1') return;
        if(!table.tHead || !table.tHead.rows || !table.tHead.rows.length) return;
        const headerMeta = getHeaderMeta(table);
        if(!headerMeta.length) return;
        const headerRow = table.tHead.rows[0];
        const keyLabelMap = new Map(headerMeta.map((meta) => [String(meta.key || '').trim(), String(meta.label || '').trim()]));

        const formatCell = (cell, headerCell) => {
            if(!cell || !cell.classList || !cell.classList.contains('pm-col-num')) return;
            if(String(cell.dataset.pmSkipNumFormat || '') === '1') return;
            if(!managedCellIsPlainNumericText(cell)) return;
            const key = String((headerCell && headerCell.dataset.manageColKey) || cell.dataset.manageColKey || '').trim();
            const label = keyLabelMap.get(key) || (headerCell ? extractHeaderLabelText(headerCell) : '');
            const fmtKind = String(cell.dataset.pmNumFormat || (headerCell && headerCell.dataset.pmNumFormat) || '').trim().toLowerCase();
            const next = fmtKind
                ? formatSitjoyNumber(cell.textContent, { key, label, kind: fmtKind, ratio: fmtKind === 'percent' })
                : formatSitjoyTableCellDisplayText(cell.textContent, key, label);
            const cur = String(cell.textContent || '').trim();
            if(next !== cur) cell.textContent = next;
        };

        Array.from(table.tHead.rows || []).forEach((row) => {
            Array.from(row.cells || []).forEach((cell, idx) => {
                if(!cell.classList || !cell.classList.contains('pm-col-num')) return;
                formatCell(cell, headerRow.cells[idx] || cell);
            });
        });

        const state = managedTableState.get(table) || null;
        const bodyRows = state
            ? getDataRows(state)
            : Array.from(table.tBodies[0]?.rows || []).filter((row) => {
                const tag = row && row.parentNode ? String(row.parentNode.tagName || '').toUpperCase() : '';
                return tag === 'TBODY';
            });
        bodyRows.forEach((row) => {
            Array.from(row.cells || []).forEach((cell, idx) => {
                formatCell(cell, headerRow.cells[idx]);
            });
        });
    }

    function applyNumericColumnLayoutForTable(table){
        applyNumericColumnAlignForTable(table);
        applyNumericColumnDisplayFormatForTable(table);
    }

    function enhanceAllTableNumericAlign(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('table').forEach((table) => applyNumericColumnLayoutForTable(table));
    }

    function measureManagedHeaderMinWidthPx(th){
        if(!th) return 0;
        const label = extractHeaderLabelText(th);
        const sortPad = th.querySelector('.transit-sort-ind, .pm-sortable') ? 18 : 8;
        return Math.ceil(String(label || '').trim().length * 14 + 24 + sortPad);
    }

    /** 按单元格内真实控件（universal-select、日期、状态段等）估算列最小宽度，避免表头被压成竖排 */
    function measureManagedCellContentMinWidthPx(cell){
        if(!cell) return 0;
        let minW = 0;
        const bump = (w) => {
            minW = Math.max(minW, Math.ceil(Number(w) || 0));
        };

        cell.querySelectorAll('.universal-select-trigger').forEach((el) => {
            const text = String(el.textContent || '').trim() || '请选择';
            const compact = el.classList.contains('universal-select-trigger--compact');
            bump(Math.max(compact ? 72 : 96, text.length * (compact ? 7.8 : 9) + (compact ? 38 : 52)));
            if(compact) bump(Math.min(112, minW));
        });
        if(minW > 0) return minW;

        const dateInput = cell.querySelector('input[type="date"], input.app-date-input[type="date"], input.optional-date-input[type="date"]');
        if(dateInput){
            bump(118);
            return minW;
        }
        const dtInput = cell.querySelector('input[type="datetime-local"], input.app-date-input[type="datetime-local"]');
        if(dtInput){
            bump(152);
            return minW;
        }
        const monthInput = cell.querySelector('input[type="month"]');
        if(monthInput){
            bump(108);
            return minW;
        }

        const selectEl = cell.querySelector('select');
        if(selectEl && !cell.querySelector('.universal-select-trigger')){
            let optMax = 0;
            Array.from(selectEl.options || []).forEach((opt) => {
                const t = String(opt.text || opt.label || '').trim();
                if(t) optMax = Math.max(optMax, t.length);
            });
            const selected = selectEl.options && selectEl.selectedIndex >= 0
                ? String(selectEl.options[selectEl.selectedIndex].text || '').trim()
                : '';
            optMax = Math.max(optMax, selected.length, 4);
            bump(Math.max(96, optMax * 8.2 + 44));
            return minW;
        }

        const statusSeg = cell.querySelector('.status-segment, .preview-status');
        if(statusSeg){
            const pills = Math.max(2, statusSeg.querySelectorAll('.status-pill').length || 0);
            bump(Math.max(92, pills * 42 + 20));
            return minW;
        }

        const actions = cell.querySelector('.pm-actions, .preview-doc-actions');
        if(actions){
            const btns = Math.max(1, actions.querySelectorAll('button').length || 0);
            bump(Math.max(100, btns * 58 + 16));
            return minW;
        }

        const textInput = cell.querySelector('input[type="text"], input[type="number"], input:not([type])');
        if(textInput){
            const val = String(textInput.value != null ? textInput.value : textInput.getAttribute('value') || '').trim();
            bump(Math.max(72, val.length * 7.5 + 30));
            return minW;
        }

        if(cell.querySelector('textarea')){
            bump(120);
            return minW;
        }

        if(cell.querySelector('img.thumb, img[data-thumb], .thumb-img, .sj-table-thumb-img, .sf-variant-thumb, .fabric-table-thumb, .order-preview-thumb')){
            bump(72);
        }

        const stackLines = cell.querySelectorAll('.transit-sku-stack-line');
        if(stackLines.length){
            stackLines.forEach((line) => {
                const t = String(line.textContent || '').replace(/\s+/g, ' ').trim();
                if(t) bump(Math.min(220, t.length * 7.5 + 20));
            });
            return minW;
        }

        if(minW === 0){
            const plain = String(cell.innerText || cell.textContent || '').replace(/\s+/g, ' ').trim();
            if(plain) bump(Math.min(280, plain.length * 7.5 + 24));
        }

        return minW;
    }

    /** 按表头 + 表体内容估算列默认宽度（仅用于初始/重置，不限制用户拖窄） */
    function computeManagedColumnContentDefaultWidth(state, columnKey){
        const key = String(columnKey || '').trim();
        if(!state || !key) return 0;

        let width = getPmTableColResizeMin(state);
        const headerRow = getPrimaryHeaderRow(state);
        if(headerRow){
            const th = Array.from(headerRow.cells || []).find((cell) => String(cell.dataset.manageColKey || '').trim() === key);
            if(th) width = Math.max(width, measureManagedHeaderMinWidthPx(th));
        }

        const rows = getDataRows(state).filter((row) => row && row.style.display !== 'none');
        const sampleCount = Math.min(rows.length, 80);
        for(let i = 0; i < sampleCount; i += 1){
            const cell = mapRowByKey(rows[i]).get(key);
            if(!cell) continue;
            width = Math.max(width, measureManagedCellContentMinWidthPx(cell));
        }
        return Math.max(getPmTableColResizeMin(state), Math.min(280, Math.round(width)));
    }

    /** 列宽硬下限：全局最小 px + 图片列等业务最小宽 */
    function getManagedColumnEffectiveMinWidth(state, columnKey, headerCell){
        const key = String(columnKey || '').trim();
        const cell = headerCell || findManagedHeaderCellForKey(state, key);
        const tableMin = getPmTableColResizeMin(state);
        const thumbMin = managedThumbColumnMinWidthPx(state, key, cell);
        return Math.max(tableMin, thumbMin || 0);
    }

    /** 拖拽列宽时的硬下限（含图片列 68px 等） */
    function getManagedColumnResizeMin(state, columnKey){
        if(!state || !columnKey) return getPmTableColResizeMin(state);
        return getManagedColumnEffectiveMinWidth(state, columnKey, findManagedHeaderCellForKey(state, columnKey));
    }

    function clampManagedColumnWidth(state, columnKey, widthPx){
        const key = String(columnKey || '').trim();
        const w = Math.round(Number(widthPx) || 0);
        const headerCell = findManagedHeaderCellForKey(state, key);
        let floor = getManagedColumnEffectiveMinWidth(state, key, headerCell);
        if(activeResizeState
            && activeResizeState.state === state
            && String(activeResizeState.key || '').trim() === key
            && Number.isFinite(activeResizeState.resizeMinPx)){
            floor = Math.max(floor, activeResizeState.resizeMinPx);
        }
        return Math.max(floor, w);
    }

    function applyManagedColPixelWidth(col, widthPx, minWidthPx){
        if(!col) return;
        const minW = Math.max(1, Math.round(Number(minWidthPx) || 0));
        const w = Math.max(minW, Math.round(Number(widthPx) || 0));
        col.style.width = `${w}px`;
        col.style.minWidth = `${minW}px`;
        col.style.maxWidth = '';
    }

    function parseThStyleWidthPx(th){
        if(!th) return 0;
        const w = parseInt(th.style.width, 10) || 0;
        if(w > 0) return w;
        const minW = parseInt(th.style.minWidth, 10) || 0;
        if(minW > 0) return minW;
        const attrW = parseInt(th.getAttribute('data-pm-default-width') || th.dataset.pmDefaultWidth || '', 10) || 0;
        return attrW > 0 ? attrW : 0;
    }

    function setManagedColHiddenState(col, hidden){
        if(!col) return;
        if(hidden){
            col.setAttribute('data-pm-col-hidden', '1');
            try { col.setAttribute('width', '0'); } catch (_eAttr) {}
            col.style.setProperty('visibility', 'hidden', 'important');
            col.style.setProperty('width', '0px', 'important');
            col.style.setProperty('min-width', '0px', 'important');
            col.style.setProperty('max-width', '0px', 'important');
            col.style.setProperty('padding', '0', 'important');
            col.style.setProperty('border-width', '0', 'important');
            return;
        }
        col.removeAttribute('data-pm-col-hidden');
        try { col.removeAttribute('width'); } catch (_eAttr2) {}
        col.style.removeProperty('visibility');
        col.style.removeProperty('width');
        col.style.removeProperty('min-width');
        col.style.removeProperty('max-width');
        col.style.removeProperty('padding');
        col.style.removeProperty('border-width');
    }

    function setManagedCellHiddenState(cell, hidden){
        if(!cell) return;
        if(hidden){
            cell.setAttribute('data-pm-col-hidden-cell', '1');
            try {
                cell.style.setProperty('width', '0px', 'important');
                cell.style.setProperty('min-width', '0px', 'important');
                cell.style.setProperty('max-width', '0px', 'important');
                cell.style.setProperty('padding', '0', 'important');
                cell.style.setProperty('border-width', '0', 'important');
            } catch (_e) {}
            return;
        }
        cell.removeAttribute('data-pm-col-hidden-cell');
        clearManagedCellInlineColumnSize(cell);
        try {
            cell.style.removeProperty('width');
            cell.style.removeProperty('min-width');
            cell.style.removeProperty('max-width');
            cell.style.removeProperty('padding');
            cell.style.removeProperty('border-width');
        } catch (_e2) {}
    }

    function isManagedThumbColumnKey(state, columnKey, headerCell){
        const key = String(columnKey || '').trim();
        if(key === '图片') return true;
        const cell = headerCell || null;
        if(cell && cell.classList){
            if(cell.classList.contains('sj-th-thumb') || cell.classList.contains('sf-th-thumb')) return true;
        }
        return false;
    }

    function managedThumbColumnMinWidthPx(state, columnKey, headerCell){
        void state;
        return isManagedThumbColumnKey(state, columnKey, headerCell) ? 68 : 0;
    }

    /**
     * 托管表统一用 colgroup 驱动列宽（table-layout:fixed）。
     * 无 colgroup 时表体在 thead 隐藏后仅靠 tbody 计宽，会与分离表头错位。
     */
    function ensureManagedTableColgroup(state){
        if(!state || !state.table) return;
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!headerRow || !headerRow.cells || !headerRow.cells.length) return;

        const colCount = headerRow.cells.length;
        let colgroup = state.table.querySelector('colgroup');
        const created = !colgroup;
        if(!colgroup){
            colgroup = document.createElement('colgroup');
            const anchor = state.table.querySelector('thead, tbody, tfoot');
            if(anchor) state.table.insertBefore(colgroup, anchor);
            else state.table.insertBefore(colgroup, state.table.firstChild);
            if(created) state.templateColumnWidths = {};
        }

        let cols = Array.from(colgroup.children || [])
            .filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        while(cols.length < colCount){
            colgroup.appendChild(document.createElement('col'));
            cols = Array.from(colgroup.children || [])
                .filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        }
        while(cols.length > colCount){
            colgroup.removeChild(cols[cols.length - 1]);
            cols.pop();
        }

        Array.from(headerRow.cells || []).forEach((cell, idx) => {
            const col = cols[idx];
            if(!col) return;
            const key = String(cell.dataset.manageColKey || '').trim();
            if(key) col.dataset.manageColKey = key;
            const fromTh = parseThStyleWidthPx(cell);
            if(fromTh > 0 && !col.dataset.pmDefaultWidth){
                col.dataset.pmDefaultWidth = String(fromTh);
            }
            if(isManagedColumnSlotHidden(state, key, cell)){
                setManagedColHiddenState(col, true);
                return;
            }
            setManagedColHiddenState(col, false);
            if(!parseColWidthPx(col.style.width)){
                const persisted = key ? Number((state.columnWidths || {})[key]) : 0;
                let w = (Number.isFinite(persisted) && persisted > 0) ? persisted : (fromTh || 80);
                if(key === '__sj_agg__') w = Math.min(28, Math.max(20, Math.round(w) || 24));
                const colMin = getManagedColumnEffectiveMinWidth(state, key, cell);
                if(colMin > 0) w = Math.max(colMin, Math.round(w) || colMin);
                applyManagedColPixelWidth(col, w, colMin);
            }
        });
        syncManagedTableTotalWidth(state);
    }

    function resolveManagedColgroupColsForKey(state, columnKey){
        const key = String(columnKey || '').trim();
        if(!state || !state.table || !key) return [];
        const colgroup = state.table.querySelector('colgroup');
        if(!colgroup) return [];
        const cols = Array.from(colgroup.children || [])
            .filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        const keyed = cols.filter(col => String(col.dataset.manageColKey || '').trim() === key);
        if(keyed.length) return keyed;
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!headerRow) return [];
        const idx = Array.from(headerRow.cells || []).findIndex((cell) => String(cell.dataset.manageColKey || '').trim() === key);
        if(idx < 0 || idx >= cols.length) return [];
        return [cols[idx]];
    }

    function applyManagedColumnWidthToCells(state, columnKey, widthPx){
        const key = String(columnKey || '').trim();
        const w = Math.max(1, Math.round(Number(widthPx) || 0));
        if(!state || !key) return;
        const tables = [state.table];
        if(state.headerTable) tables.push(state.headerTable);
        tables.forEach((table) => {
            if(!table) return;
            Array.from(table.rows || []).forEach((row) => {
                if((row.cells || []).length !== state.headerCount) return;
                Array.from(row.cells || []).forEach((cell) => {
                    if(String(cell.dataset.manageColKey || '').trim() !== key) return;
                    cell.style.width = `${w}px`;
                    cell.style.minWidth = '';
                    cell.style.maxWidth = '';
                });
            });
        });
    }

    function parseColWidthPx(raw){
        const m = String(raw || '').match(/^([\d.]+)px$/i);
        return m ? Math.max(0, Math.round(parseFloat(m[1]))) : 0;
    }

    /** 首次托管时快照模板列宽（data-pm-default-width 或尚未被改写的 col.style.width） */
    function ensureTemplateColumnWidths(state){
        if(!state || !state.table) return;
        if(state.templateColumnWidths && Object.keys(state.templateColumnWidths).length) return;
        const colgroup = state.table.querySelector('colgroup');
        if(!colgroup) return;
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        const cols = Array.from(colgroup.children || []).filter((node) => node && String(node.tagName || '').toUpperCase() === 'COL');
        const map = {};
        cols.forEach((col, idx) => {
            let key = String(col.dataset.manageColKey || '').trim();
            if(!key && headerRow && headerRow.cells && headerRow.cells[idx]){
                key = String(headerRow.cells[idx].dataset.manageColKey || '').trim();
            }
            const w = parseColWidthPx(col.dataset.pmDefaultWidth)
                || parseColWidthPx(col.getAttribute('data-pm-default-width'))
                || parseColWidthPx(col.style.width)
                || parseColWidthPx(col.getAttribute('width'));
            if(key && w > 0) map[key] = w;
        });
        if(Object.keys(map).length) state.templateColumnWidths = map;
    }

    /** 读取模板列宽作为「重置列宽」默认值；绝不使用已被 applyColumnWidths 改写过的 col.style.width */
    function readManagedColgroupWidthPx(state, columnKey){
        if(!state || !columnKey) return 0;
        const key = String(columnKey || '').trim();
        ensureTemplateColumnWidths(state);
        const tpl = state.templateColumnWidths && state.templateColumnWidths[key];
        if(tpl > 0) return tpl;

        if(!state.table) return 0;
        const colgroup = state.table.querySelector('colgroup');
        if(!colgroup) return 0;
        const cols = Array.from(colgroup.children || []).filter((node) => node && String(node.tagName || '').toUpperCase() === 'COL');
        let col = cols.find((node) => String(node.dataset.manageColKey || '').trim() === key);
        if(!col && state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0]){
            const idx = Array.from(state.table.tHead.rows[0].cells || []).findIndex((cell) => String(cell.dataset.manageColKey || '').trim() === key);
            if(idx >= 0 && cols[idx]) col = cols[idx];
        }
        if(!col) return 0;
        return parseColWidthPx(col.dataset.pmDefaultWidth) || parseColWidthPx(col.getAttribute('data-pm-default-width')) || 0;
    }

    function inferDefaultWidthFromHeaderCell(cell){
        if(!cell) return 0;
        if(cell.querySelector('input[type="checkbox"]')) return 54;
        const cls = String(cell.className || '');
        if(/transit-col-date|transit-col-expected|transit-col-factory-ship|transit-col-arrival|transit-col-warehouse-exp/.test(cls)) return 112;
        if(/transit-col-forwarder/.test(cls)) return 88;
        if(/transit-col-warehouse/.test(cls)) return 112;
        if(/transit-col-status|transit-col-doc|transit-col-qty-consistent|transit-col-financial/.test(cls)) return 96;
        if(/transit-col-qty-checked/.test(cls)) return 128;
        if(/transit-col-edit/.test(cls)) return 120;
        if(/transit-col-remark/.test(cls)) return 140;
        if(/transit-col-bill|transit-col-shipping|transit-col-vessel|transit-col-port-/.test(cls)) return 120;
        if(/transit-col-inbound|transit-col-box/.test(cls)) return 96;
        if(/transit-col-factory|transit-col-region/.test(cls)) return 96;
        if(/transit-col-created|transit-col-updated/.test(cls)) return 108;
        if(/\bsj-th-thumb\b|\bsf-th-thumb\b/.test(cls)) return 68;
        return 0;
    }

    function computeDefaultColumnWidth(state, meta){
        if(!meta || !meta.cell) return 80;
        const key = String(meta.key || '').trim();
        if(meta.cell.querySelector('input[type="checkbox"]')) return 54;

        const colW = readManagedColgroupWidthPx(state, key);
        if(colW > 0) return colW;

        const thW = parseInt(meta.cell.style.width, 10) || 0;
        if(thW > 0) return thW;

        const dataW = parseInt(meta.cell.dataset.pmDefaultWidth, 10) || 0;
        if(dataW > 0) return dataW;

        const headerWidth = measureManagedHeaderMinWidthPx(meta.cell);
        const typeHint = inferDefaultWidthFromHeaderCell(meta.cell);
        const labelLen = String(meta.label || '').trim().length;
        const textWidth = Math.ceil(Math.min(labelLen, 14) * 14 + 28);
        const contentDefault = state && key ? computeManagedColumnContentDefaultWidth(state, key) : 0;
        const merged = Math.max(headerWidth, typeHint, textWidth, contentDefault);
        return Math.max(48, Math.min(280, merged));
    }

    function canonicalManagedColumnOrderFromMeta(headerMeta){
        return (Array.isArray(headerMeta) ? headerMeta : [])
            .slice()
            .sort((a, b) => Number(a.origin) - Number(b.origin))
            .map((meta) => String(meta.key || '').trim())
            .filter(Boolean);
    }

    function enforceColumnSequenceAfter(order, anchorKey, followKeys){
        const orderArr = Array.isArray(order) ? order.slice() : [];
        const anchor = String(anchorKey || '').trim();
        const follow = (Array.isArray(followKeys) ? followKeys : []).map((k) => String(k || '').trim()).filter(Boolean);
        if(!anchor || !follow.length) return orderArr;
        const followSet = new Set(follow);
        const presentFollow = follow.filter((k) => orderArr.includes(k));
        if(!presentFollow.length) return orderArr;
        const without = orderArr.filter((k) => !followSet.has(k));
        let anchorIdx = without.indexOf(anchor);
        if(anchorIdx < 0){
            return without.concat(presentFollow);
        }
        return without.slice(0, anchorIdx + 1).concat(presentFollow, without.slice(anchorIdx + 1));
    }

    function buildManagedPersistedColumnKeyResolver(headerMeta, validKeys){
        const validSet = new Set(validKeys);
        const originToKey = new Map((Array.isArray(headerMeta) ? headerMeta : []).map(meta => [String(meta.origin), String(meta.key || '').trim()]));
        const labelToKeys = new Map();
        (Array.isArray(headerMeta) ? headerMeta : []).forEach((meta) => {
            const label = String(meta.label || '').trim();
            const key = String(meta.key || '').trim();
            if(!label || !key || !validSet.has(key)) return;
            if(!labelToKeys.has(label)) labelToKeys.set(label, []);
            labelToKeys.get(label).push({ origin: Number(meta.origin), key });
        });
        labelToKeys.forEach((items, label) => {
            items.sort((a, b) => (Number.isFinite(a.origin) ? a.origin : 0) - (Number.isFinite(b.origin) ? b.origin : 0));
            labelToKeys.set(label, items.map(item => item.key));
        });

        function resolvePersistedColumnKeys(raw){
            const token = String(raw || '').trim();
            if(!token) return [];
            if(validSet.has(token)) return [token];
            const fromOrigin = originToKey.get(token);
            if(fromOrigin && validSet.has(fromOrigin)) return [fromOrigin];
            if(token === '操作' && validSet.has('操作类型') && validSet.has('行操作')){
                return ['操作类型', '行操作'];
            }
            if(token === '操作' && validSet.has('操作类型')){
                return ['操作类型'];
            }
            const fromLabel = labelToKeys.get(token);
            if(fromLabel && fromLabel.length) return fromLabel.slice();
            return [];
        }

        function expandLegacyPersistedColumnKeys(rawList){
            const out = [];
            const seen = new Set();
            (Array.isArray(rawList) ? rawList : []).forEach((raw) => {
                resolvePersistedColumnKeys(raw).forEach((key) => {
                    if(!key || seen.has(key)) return;
                    seen.add(key);
                    out.push(key);
                });
            });
            return out;
        }

        return { expandLegacyPersistedColumnKeys };
    }

    function readPersistedColumns(table, headerMeta){
        const validKeys = (Array.isArray(headerMeta) ? headerMeta : []).map(meta => String(meta.key || '').trim()).filter(Boolean);
        const { expandLegacyPersistedColumnKeys } = buildManagedPersistedColumnKeyResolver(headerMeta, validKeys);
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'visible-columns'));
            if(!raw) return new Set(validKeys);
            const arr = JSON.parse(raw);
            const migrated = expandLegacyPersistedColumnKeys(Array.isArray(arr) ? arr : []);
            return new Set(migrated.length ? migrated : validKeys);
        } catch (_) {
            return new Set(validKeys);
        }
    }

    function readPersistedOrder(table, headerMeta){
        const validKeys = (Array.isArray(headerMeta) ? headerMeta : []).map(meta => String(meta.key || '').trim()).filter(Boolean);
        const { expandLegacyPersistedColumnKeys } = buildManagedPersistedColumnKeyResolver(headerMeta, validKeys);
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'column-order'));
            if(!raw) return normalizeManagedTableColumnOrder(canonicalManagedColumnOrderFromMeta(headerMeta), validKeys, headerMeta);
            const arr = JSON.parse(raw);
            const inOrder = expandLegacyPersistedColumnKeys(Array.isArray(arr) ? arr : []);
            validKeys.forEach(v => {
                if(!inOrder.includes(v)) inOrder.push(v);
            });
            const normalized = normalizeManagedTableColumnOrder(inOrder, validKeys, headerMeta);
            if(JSON.stringify(normalized) !== JSON.stringify(inOrder)){
                try {
                    localStorage.setItem(makeStorageKey(table, 'column-order'), JSON.stringify(normalized));
                } catch (_e) {
                }
            }
            return normalized;
        } catch (_) {
            return normalizeManagedTableColumnOrder(canonicalManagedColumnOrderFromMeta(headerMeta), validKeys, headerMeta);
        }
    }

    function persistColumns(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'visible-columns'), JSON.stringify(Array.from(state.visibleColumns.values())));
        } catch (_) {}
    }

    function persistColumnOrder(state){
        if(!state || !state.table) return;
        try {
            const headerMeta = getHeaderMeta(state.table);
            const validKeys = headerMeta.map(meta => String(meta.key || '').trim()).filter(Boolean);
            state.columnOrder = normalizeManagedTableColumnOrder(state.columnOrder || [], validKeys, headerMeta);
            localStorage.setItem(makeStorageKey(state.table, 'column-order'), JSON.stringify(state.columnOrder.slice()));
        } catch (_) {}
    }

    function readPersistedPinned(table, headerMeta){
        const validKeys = (Array.isArray(headerMeta) ? headerMeta : []).map(meta => String(meta.key || '').trim()).filter(Boolean);
        const legacyKeyMap = new Map((Array.isArray(headerMeta) ? headerMeta : []).map(meta => [String(meta.origin), String(meta.key || '').trim()]));
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'pinned-columns'));
            if(!raw) return new Set();
            const arr = JSON.parse(raw);
            const valid = Array.isArray(arr)
                ? arr.map(v => {
                    const key = String(v || '').trim();
                    if(validKeys.includes(key)) return key;
                    return legacyKeyMap.get(key) || '';
                }).filter(key => !!key && validKeys.includes(key))
                : [];
            return new Set(valid);
        } catch (_) {
            return new Set();
        }
    }

    /** 仅锁定布局锚点列（复选框、汇总展开列等）参与冻结，忽略误存的其它列 */
    function resolvePinnedColumnsForTable(table, headerMeta, lockedColumns){
        const lockedSet = new Set(
            (lockedColumns instanceof Set ? Array.from(lockedColumns) : (Array.isArray(lockedColumns) ? lockedColumns : []))
                .map(k => String(k || '').trim())
                .filter(Boolean)
        );
        if(String(table && table.dataset && table.dataset.pmFrozenLeadOnly || '') === '1'){
            return lockedSet;
        }
        const merged = new Set(lockedSet);
        readPersistedPinned(table, headerMeta).forEach(k => merged.add(String(k || '').trim()));
        return merged;
    }

    function tableSkipsClientPagination(state){
        return !!(state && state.table && String(state.table.dataset.pmSkipClientPagination || '') === '1');
    }

    function persistPinnedColumns(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'pinned-columns'), JSON.stringify(Array.from(state.pinnedColumns || []).slice()));
        } catch (_) {}
    }

    function readPersistedPageSize(table){
        try {
            const raw = Number(localStorage.getItem(makeStorageKey(table, 'page-size')) || '50');
            return PAGE_SIZE_OPTIONS.includes(raw) ? raw : 50;
        } catch (_) {
            return 50;
        }
    }

    function persistPageSize(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'page-size'), String(state.pageSize));
        } catch (_) {}
    }

    function readPersistedColumnWidths(table){
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'column-widths'));
            let data = raw ? JSON.parse(raw) : {};
            if(!data || typeof data !== 'object') data = {};
            if(table && isPmMonthColWidthSyncTable(table)){
                try {
                    const sw = localStorage.getItem(makePmMonthGroupWidthStorageKey(table));
                    const gw = Number(sw);
                    if(Number.isFinite(gw) && gw >= 36){
                        data[PM_MONTH_COL_GROUP_WIDTH_KEY] = Math.round(gw);
                    }
                } catch (_e) {
                }
            }
            return data;
        } catch (_) {
            return {};
        }
    }

    function getPmMetricColKeyForWidthSync(table){
        return String(table && table.dataset && table.dataset.pmMetricColKey || 'sf_metric_col').trim();
    }

    function isPmMonthColWidthSyncTable(table){
        return !!(table && String(table.dataset.pmMonthColWidthSync || '') === '1');
    }

    function isPmMonthColKeyForWidthSync(table, key){
        const k = String(key || '').trim();
        if(!k || k === getPmMetricColKeyForWidthSync(table)) return false;
        return /^m_\d+$/.test(k);
    }

    function collectPmMonthColKeysForWidthSync(state){
        if(!state || !state.table || !isPmMonthColWidthSyncTable(state.table)) return [];
        const table = state.table;
        return (state.headers || [])
            .map(h => String(h && h.key || '').trim())
            .filter(k => isPmMonthColKeyForWidthSync(table, k));
    }

    function resolvePmMonthGroupWidthFromPersisted(table, persistedWidths, monthKeys, resolvedWidths){
        let w = Number(persistedWidths && persistedWidths[PM_MONTH_COL_GROUP_WIDTH_KEY]);
        if(!Number.isFinite(w) || w < 36){
            const nums = Object.keys(persistedWidths || {})
                .filter(k => /^m_\d+$/.test(String(k || '').trim()))
                .map(k => Number(persistedWidths[k]))
                .filter(n => Number.isFinite(n) && n >= 36);
            if(nums.length) w = Math.max.apply(null, nums);
        }
        if(!Number.isFinite(w) || w < 36){
            const fromResolved = (monthKeys || []).map(k => Number((resolvedWidths || {})[k])).filter(n => Number.isFinite(n) && n >= 36);
            if(fromResolved.length) w = Math.max.apply(null, fromResolved);
        }
        if(!Number.isFinite(w) || w < 36) w = 72;
        return Math.round(w);
    }

    function persistColumnWidths(state){
        try {
            const raw = Object.assign({}, state.columnWidths || {});
            if(state && state.table && isPmMonthColWidthSyncTable(state.table)){
                let monthKeys = collectPmMonthColKeysForWidthSync(state);
                if(!monthKeys.length){
                    monthKeys = Object.keys(raw).filter(k => isPmMonthColKeyForWidthSync(state.table, k));
                }
                const nums = monthKeys.map(k => Number(raw[k])).filter(n => Number.isFinite(n) && n >= 36);
                let gw = nums.length ? Math.max.apply(null, nums) : Number(raw[PM_MONTH_COL_GROUP_WIDTH_KEY]);
                if(Number.isFinite(gw) && gw >= 36){
                    gw = Math.round(gw);
                    raw[PM_MONTH_COL_GROUP_WIDTH_KEY] = gw;
                    monthKeys.forEach((k) => {
                        raw[k] = gw;
                    });
                    try {
                        localStorage.setItem(makePmMonthGroupWidthStorageKey(state.table), String(gw));
                    } catch (_e2) {
                    }
                }
            }
            localStorage.setItem(makeStorageKey(state.table, 'column-widths'), JSON.stringify(raw));
        } catch (_) {}
    }

    function isPlaceholderRow(row, headerCount){
        if(!row) return false;
        if(row.cells.length !== 1) return false;
        const onlyCell = row.cells[0];
        return Number(onlyCell.colSpan || 1) >= Math.max(headerCount, 2);
    }

    function isGroupedAggregateRow(row){
        if(window.SitjoyGroupedAggregate && typeof window.SitjoyGroupedAggregate.isGroupRow === 'function'){
            return window.SitjoyGroupedAggregate.isGroupRow(row);
        }
        if(!row || !row.classList) return false;
        if(row.classList.contains('perf-group-parent-row')) return true;
        if(row.classList.contains('group-row')) return true;
        for(let i = 0; i < row.classList.length; i++){
            const cls = row.classList[i];
            if(cls && cls.endsWith('-group-row')) return true;
        }
        return false;
    }

    function isAggregateChildRowVisible(row){
        if(window.SitjoyGroupedAggregate && typeof window.SitjoyGroupedAggregate.isAggregateChildRowVisible === 'function'){
            return window.SitjoyGroupedAggregate.isAggregateChildRowVisible(row);
        }
        if(!row) return false;
        if(String(row.dataset.pmFilterHidden || '0') === '1') return false;
        if(row.style && row.style.display === 'none') return false;
        if(row.classList){
            for(let i = 0; i < row.classList.length; i++){
                const cls = row.classList[i];
                if(cls && cls.endsWith('-row-hidden')) return false;
            }
        }
        return true;
    }

    function syncGroupedAggregateRowsAfterFilter(state){
        if(!state) return;
        if(window.SitjoyGroupedAggregate && typeof window.SitjoyGroupedAggregate.syncManagedTableGroupRows === 'function'){
            window.SitjoyGroupedAggregate.syncManagedTableGroupRows(state);
            return;
        }
        const tbody = state.tbody || (state.table && state.table.tBodies && state.table.tBodies[0]);
        if(!tbody) return;
        const bodyRows = Array.from(tbody.rows || []);
        if(!bodyRows.some(row => isGroupedAggregateRow(row))) return;
        let i = 0;
        while(i < bodyRows.length){
            const row = bodyRows[i];
            if(!isGroupedAggregateRow(row)){
                i++;
                continue;
            }
            const children = [];
            let j = i + 1;
            while(j < bodyRows.length && !isGroupedAggregateRow(bodyRows[j])){
                children.push(bodyRows[j]);
                j++;
            }
            const inScope = window.SitjoyGroupedAggregate && typeof window.SitjoyGroupedAggregate.isAggregateChildRowInFilterScope === 'function'
                ? children.some(child => window.SitjoyGroupedAggregate.isAggregateChildRowInFilterScope(child))
                : children.some(child => {
                    if(String(child.dataset.pmFilterHidden || '0') === '1') return false;
                    if(child.style && child.style.display === 'none') return false;
                    return true;
                });
            row.style.display = inScope ? '' : 'none';
            row.dataset.pmFilterHidden = inScope ? '0' : '1';
            i = j;
        }
    }

    function getDataRows(state){
        const rows = Array.from(state.tbody.rows || []);
        if(rows.length === 1 && isPlaceholderRow(rows[0], state.headerCount)) return [];
        return rows.filter(row => !isGroupedAggregateRow(row));
    }

    function resolveManagedColumnKey(label, fallbackIndex){
        const text = String(label || '').trim();
        if(text) return text;
        return `字段${Number(fallbackIndex) + 1}`;
    }

    function isEditableDomTarget(target){
        if(!target || !target.closest) return false;
        return !!target.closest('input, textarea, select, button, a, [contenteditable="true"], .universal-select-dropdown, .status-pill');
    }

    function clearGridSelectionClasses(table){
        if(!table || !table.querySelectorAll) return;
        table.querySelectorAll('td.pm-grid-cell-selected, td.pm-grid-cell-anchor, .pm-grid-detail-selected, .pm-grid-detail-anchor').forEach(cell => {
            cell.classList.remove('pm-grid-cell-selected', 'pm-grid-cell-anchor');
            cell.classList.remove('pm-grid-detail-selected', 'pm-grid-detail-anchor');
        });
        table.classList.remove('is-grid-selecting');
        if(activeGridSelection && activeGridSelection.paintedCells){
            activeGridSelection.paintedCells.clear();
        }
    }

    function clearTransitSkuGridPaintNodes(nodes){
        (nodes || []).forEach((node) => {
            if(!node || !node.classList) return;
            node.classList.remove('pm-grid-detail-selected', 'pm-grid-detail-anchor');
        });
    }

    let gridSelectionPaintScheduled = false;
    function schedulePaintGridSelection(){
        if(gridSelectionPaintScheduled) return;
        gridSelectionPaintScheduled = true;
        window.requestAnimationFrame(() => {
            gridSelectionPaintScheduled = false;
            paintGridSelection();
        });
    }

    function transitSkuGridPaintSignature(skuSel, selection){
        if(!skuSel || !skuSel.anchor || !skuSel.current || !selection || !selection.rowSlots) return '';
        const a = skuSel.anchor;
        const c = skuSel.current;
        return [
            a.tr, a.sc, a.lr,
            c.tr, c.sc, c.lr,
            selection.sc1, selection.sc2,
            selection.rowSlots.length,
            selection.rowSlots[0] ? `${selection.rowSlots[0].tr}:${selection.rowSlots[0].lr}` : '',
            selection.rowSlots.length > 1
                ? `${selection.rowSlots[selection.rowSlots.length - 1].tr}:${selection.rowSlots[selection.rowSlots.length - 1].lr}`
                : ''
        ].join('|');
    }

    function clearGridSelection(){
        if(!activeGridSelection) return;
        const dragState = activeGridSelection.state;
        clearTransitSkuGridPaintNodes(activeGridSelection.skuPaintedNodes);
        clearGridSelectionClasses(activeGridSelection.state && activeGridSelection.state.table);
        if(dragState) endGridDragVisibleRowCache(dragState);
        activeGridSelection = null;
        notifySitjoyGridSelectionChange();
    }

    function getVisibleRows(state){
        if(state && state._gridDragVisibleRows) return state._gridDragVisibleRows;
        return getDataRows(state).filter(row => row && row.style.display !== 'none');
    }

    function beginGridDragVisibleRowCache(state){
        if(!state) return;
        const rows = getDataRows(state).filter(row => row && row.style.display !== 'none');
        rows.forEach((row, idx) => {
            row.dataset.pmGridRowIndex = String(idx);
        });
        state._gridDragVisibleRows = rows;
    }

    function endGridDragVisibleRowCache(state){
        if(!state) return;
        (state._gridDragVisibleRows || []).forEach((row) => {
            if(row && row.dataset) delete row.dataset.pmGridRowIndex;
        });
        state._gridDragVisibleRows = null;
    }

    function gridDragRectSignature(anchor, current){
        if(!anchor || !current) return '';
        return [
            Math.min(anchor.row, current.row),
            Math.max(anchor.row, current.row),
            Math.min(anchor.col, current.col),
            Math.max(anchor.col, current.col)
        ].join('|');
    }

    function updateGridDragRectSelection(state, anchor, currentCoord){
        if(!state || !anchor || !currentCoord) return;
        const selection = ensureGridSelectionState(state);
        const sig = gridDragRectSignature(anchor, currentCoord);
        if(sig && sig === selection.lastPaintedRectSig) return;
        selection.lastPaintedRectSig = sig;
        selection.dragCurrentCoord = currentCoord;
        selection.selectedCells = new Set(getRectCells(state, anchor, currentCoord));
        selection.anchorCoord = anchor;
        selection.transitSkuGrid = null;
        selection.detailSelections = new Map();
        selection.detailDragging = null;
        schedulePaintGridSelection();
    }

    function paintNormalGridCellsIncremental(state, selection){
        if(!state || !selection) return;
        const newSet = selection.selectedCells || new Set();
        const prevPainted = selection.paintedCells || new Set();
        const anchorCell = getCellByCoord(state, selection.anchorCoord);

        prevPainted.forEach(cell => {
            if(!cell || !cell.isConnected) return;
            if(newSet.has(cell)) return;
            cell.classList.remove('pm-grid-cell-selected', 'pm-grid-cell-anchor');
        });

        newSet.forEach(cell => {
            if(!cell || !cell.isConnected) return;
            cell.classList.add('pm-grid-cell-selected');
            if(cell === anchorCell) cell.classList.add('pm-grid-cell-anchor');
            else cell.classList.remove('pm-grid-cell-anchor');
        });

        selection.paintedCells = new Set(Array.from(newSet).filter(cell => cell && cell.isConnected));
        if(newSet.size > 0) state.table.classList.add('is-grid-selecting');
        else state.table.classList.remove('is-grid-selecting');
    }

    function getVisibleCellsInRow(row){
        return Array.from(row.cells || []).filter(cell => {
            if(!cell || cell.classList.contains('pm-table-hide-col')) return false;
            if(cell.style.display === 'none') return false;
            return true;
        });
    }

    function isTransitDetailCell(cell){
        return !!(cell && cell.querySelector && cell.querySelector('[data-transit-detail-list="1"]'));
    }

    function isTransitSkuStackCell(cell){
        return !!(cell && cell.querySelector && cell.querySelector('.transit-sku-stack'));
    }

    function isTransitSubcellCell(cell){
        return isTransitDetailCell(cell) || isTransitSkuStackCell(cell);
    }

    function extractTransitSkuStackLineText(line, cell){
        if(!line) return '';
        const colorDot = line.querySelector('.transit-color-dot');
        if(colorDot){
            const chipColor = String(colorDot.style.backgroundColor || '').trim();
            if(chipColor) return chipColor;
            if(typeof window.getComputedStyle === 'function'){
                const computedColor = String(window.getComputedStyle(colorDot).backgroundColor || '').trim();
                if(computedColor && computedColor.toLowerCase() !== 'rgba(0, 0, 0, 0)' && computedColor.toLowerCase() !== 'transparent'){
                    return computedColor;
                }
            }
            return '●';
        }
        const skuText = line.querySelector('.transit-detail-sku-text');
        if(skuText) return String(skuText.textContent || '').replace(/\s+/g, ' ').trim();
        return String(line.textContent || '').replace(/\s+/g, ' ').trim();
    }

    function getTransitSkuStackLines(cell){
        if(!isTransitSkuStackCell(cell)) return [];
        return Array.from(cell.querySelectorAll('.transit-sku-stack-line')).map((line) => extractTransitSkuStackLineText(line, cell));
    }

    function getTransitSkuStackLineCoord(target, cell){
        if(!target || !cell || !isTransitSkuStackCell(cell)) return null;
        const line = target.closest('.transit-sku-stack-line');
        if(!line || !cell.contains(line)) return null;
        const lines = Array.from(cell.querySelectorAll('.transit-sku-stack-line'));
        const row = lines.indexOf(line);
        if(row < 0) return null;
        return { row, col: 0 };
    }

    const TRANSIT_SKU_GRID_COL_KEYS = [
        'SKU详情-颜色',
        'SKU详情-SKU',
        'SKU详情-发货数量',
        'SKU详情-上架数量'
    ];

    function getTransitSkuGridColIndex(cell){
        if(!cell) return -1;
        const key = String(cell.dataset.manageColKey || '').trim();
        let idx = TRANSIT_SKU_GRID_COL_KEYS.indexOf(key);
        if(idx >= 0) return idx;
        if(cell.classList.contains('transit-col-sku-color')) return 0;
        if(cell.classList.contains('transit-col-sku-qty')) return 2;
        if(cell.classList.contains('transit-col-sku-listed')) return 3;
        if(cell.classList.contains('transit-col-sku')) return 1;
        return -1;
    }

    function getTransitSkuCellInTableRow(row, skuColIndex){
        if(!row || skuColIndex < 0 || skuColIndex >= TRANSIT_SKU_GRID_COL_KEYS.length) return null;
        const cell = mapRowByKey(row).get(TRANSIT_SKU_GRID_COL_KEYS[skuColIndex]);
        return cell && isTransitSkuStackCell(cell) ? cell : null;
    }

    function getTransitSkuGridCoord(state, target){
        if(!state || !target || !target.closest) return null;
        const cell = target.closest('td');
        if(!cell || !state.tbody.contains(cell) || !isTransitSkuStackCell(cell)) return null;
        const sc = getTransitSkuGridColIndex(cell);
        if(sc < 0) return null;
        const trEl = cell.parentElement;
        if(!trEl) return null;
        const tr = getVisibleRows(state).indexOf(trEl);
        if(tr < 0) return null;
        const line = target.closest('.transit-sku-stack-line');
        if(!line || !cell.contains(line)) return null;
        const lr = Array.from(cell.querySelectorAll('.transit-sku-stack-line')).indexOf(line);
        if(lr < 0) return null;
        return { tr, sc, lr };
    }

    /** 将在途记录多行 SKU 压平为连续行号，跨记录框选按「起点→终点」而非每条记录重复同一 lr 序列 */
    function buildTransitSkuFlatRowIndex(state){
        const entries = [];
        getVisibleRows(state).forEach((row, tr) => {
            void row;
            const lineCount = getTransitSkuStackLineCountForRow(state, tr);
            for(let lr = 0; lr < lineCount; lr += 1){
                entries.push({ tr, lr });
            }
        });
        return entries;
    }

    function transitSkuFlatIndexFromCoord(state, coord){
        if(!coord) return -1;
        const entries = buildTransitSkuFlatRowIndex(state);
        return entries.findIndex((e) => e.tr === coord.tr && e.lr === coord.lr);
    }

    function resolveTransitSkuGridSelection(state, anchor, current){
        if(!state || !anchor || !current) return null;
        const entries = buildTransitSkuFlatRowIndex(state);
        if(!entries.length) return null;
        const ia = transitSkuFlatIndexFromCoord(state, anchor);
        const ib = transitSkuFlatIndexFromCoord(state, current);
        if(ia < 0 || ib < 0) return null;
        const flatMin = Math.min(ia, ib);
        const flatMax = Math.max(ia, ib);
        return {
            sc1: Math.min(Number(anchor.sc), Number(current.sc)),
            sc2: Math.max(Number(anchor.sc), Number(current.sc)),
            rowSlots: entries.slice(flatMin, flatMax + 1)
        };
    }

    function collectTransitSkuGridCellsFromSelection(state, selection){
        const cells = new Set();
        if(!state || !selection || !selection.rowSlots) return cells;
        selection.rowSlots.forEach((slot) => {
            const row = getVisibleRows(state)[slot.tr];
            if(!row) return;
            for(let sc = selection.sc1; sc <= selection.sc2; sc += 1){
                const cell = getTransitSkuCellInTableRow(row, sc);
                if(cell) cells.add(cell);
            }
        });
        return cells;
    }

    function getTransitSkuStackLineCountForRow(state, tableRowIndex){
        const row = getVisibleRows(state)[tableRowIndex];
        if(!row) return 0;
        let max = 0;
        for(let sc = 0; sc < TRANSIT_SKU_GRID_COL_KEYS.length; sc += 1){
            const cell = getTransitSkuCellInTableRow(row, sc);
            if(cell) max = Math.max(max, cell.querySelectorAll('.transit-sku-stack-line').length);
        }
        return max;
    }

    function getTransitSkuGridLineNode(state, tableRowIndex, skuColIndex, lineIndex){
        const row = getVisibleRows(state)[tableRowIndex];
        if(!row) return null;
        const cell = getTransitSkuCellInTableRow(row, skuColIndex);
        if(!cell) return null;
        const lines = cell.querySelectorAll('.transit-sku-stack-line');
        return lines[lineIndex] || null;
    }

    function getTransitSkuGridValue(state, tableRowIndex, skuColIndex, lineIndex){
        const row = getVisibleRows(state)[tableRowIndex];
        const cell = row ? getTransitSkuCellInTableRow(row, skuColIndex) : null;
        const node = getTransitSkuGridLineNode(state, tableRowIndex, skuColIndex, lineIndex);
        return node && cell ? extractTransitSkuStackLineText(node, cell) : '';
    }

    function copyTransitSkuGridSelectionToClipboard(state){
        const skuSel = activeGridSelection && activeGridSelection.transitSkuGrid;
        if(!state || !skuSel || !skuSel.anchor || !skuSel.current) return false;
        const selection = resolveTransitSkuGridSelection(state, skuSel.anchor, skuSel.current);
        if(!selection || !selection.rowSlots.length) return false;

        const lines = [];
        selection.rowSlots.forEach((slot) => {
            const cols = [];
            for(let sc = selection.sc1; sc <= selection.sc2; sc += 1){
                cols.push(getTransitSkuGridValue(state, slot.tr, sc, slot.lr));
            }
            lines.push(cols.join('\t'));
        });
        const text = lines.join('\n');
        if(!text) return false;

        if(navigator.clipboard && navigator.clipboard.writeText){
            navigator.clipboard.writeText(text).then(() => {
                if(window.showAppToast) window.showAppToast('已复制选中区域', false, 1200);
            }).catch(() => {});
            return true;
        }

        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.left = '-10000px';
        area.style.top = '-10000px';
        document.body.appendChild(area);
        area.focus();
        area.select();
        try {
            document.execCommand('copy');
            if(window.showAppToast) window.showAppToast('已复制选中区域', false, 1200);
        } catch (_) {}
        document.body.removeChild(area);
        return true;
    }

    function getTransitSubcellCoord(target, cell){
        const stackCoord = getTransitSkuStackLineCoord(target, cell);
        if(stackCoord) return stackCoord;
        return getTransitDetailNodeCoord(target, cell);
    }

    function getTransitSubcellNodesByRect(cell, rect){
        if(!cell || !rect) return [];
        if(isTransitSkuStackCell(cell)){
            const lines = Array.from(cell.querySelectorAll('.transit-sku-stack-line'));
            const out = [];
            for(let r = rect.r1; r <= rect.r2; r += 1){
                if(lines[r]) out.push(lines[r]);
            }
            return out;
        }
        return getTransitDetailNodesByRect(cell, rect);
    }

    function getTransitDetailValueMatrix(cell){
        if(!isTransitDetailCell(cell)) return [];
        const list = cell.querySelector('[data-transit-detail-list="1"]');
        if(!list) return [];
        const rows = Array.from(list.querySelectorAll('[data-transit-detail-row="1"]'));
        return rows.map((row) => {
            const color = row.querySelector('.transit-color-dot') ? '●' : String((row.querySelector('.transit-detail-color-col') || {}).textContent || '').replace(/\s+/g, ' ').trim();
            const sku = String((row.querySelector('.transit-detail-sku-text') || row.querySelector('.transit-detail-sku-col') || {}).textContent || '').replace(/\s+/g, ' ').trim();
            const shipped = String((row.querySelector('.transit-detail-qty-col') || {}).textContent || '').replace(/\s+/g, ' ').trim();
            const listed = String((row.querySelector('.transit-detail-listed-col') || {}).textContent || '').replace(/\s+/g, ' ').trim();
            return [color, sku, shipped, listed];
        });
    }

    function getTransitDetailNodeCoord(target, cell){
        if(!target || !cell || !cell.contains(target)) return null;
        const rowNode = target.closest('[data-transit-detail-row="1"]');
        if(!rowNode || !cell.contains(rowNode)) return null;
        const rowNodes = Array.from(cell.querySelectorAll('[data-transit-detail-row="1"]'));
        const row = rowNodes.indexOf(rowNode);
        if(row < 0) return null;
        let col = -1;
        if(target.closest('.transit-detail-color-col')) col = 0;
        else if(target.closest('.transit-detail-sku-col, .transit-detail-sku-text')) col = 1;
        else if(target.closest('.transit-detail-qty-col')) col = 2;
        else if(target.closest('.transit-detail-listed-col')) col = 3;
        if(col < 0) return null;
        return { row, col };
    }

    function normalizeTransitDetailRect(a, b){
        if(!a || !b) return null;
        return {
            r1: Math.min(Number(a.row), Number(b.row)),
            r2: Math.max(Number(a.row), Number(b.row)),
            c1: Math.min(Number(a.col), Number(b.col)),
            c2: Math.max(Number(a.col), Number(b.col))
        };
    }

    function getTransitDetailNodesByRect(cell, rect){
        if(!cell || !rect) return [];
        const rows = Array.from(cell.querySelectorAll('[data-transit-detail-row="1"]'));
        const out = [];
        for(let r = rect.r1; r <= rect.r2; r += 1){
            const row = rows[r];
            if(!row) continue;
            for(let c = rect.c1; c <= rect.c2; c += 1){
                let node = null;
                if(c === 0) node = row.querySelector('.transit-detail-color-col');
                else if(c === 1) node = row.querySelector('.transit-detail-sku-col') || row.querySelector('.transit-detail-sku-text');
                else if(c === 2) node = row.querySelector('.transit-detail-qty-col');
                else if(c === 3) node = row.querySelector('.transit-detail-listed-col');
                if(node) out.push(node);
            }
        }
        return out;
    }

    function getCellCoord(state, cell){
        if(!state || !cell) return null;
        const row = cell.parentElement;
        if(row && row.dataset && row.dataset.pmGridRowIndex != null){
            const r = Number(row.dataset.pmGridRowIndex);
            if(Number.isFinite(r)){
                const cells = getVisibleCellsInRow(row);
                const c = cells.indexOf(cell);
                if(c >= 0) return { row: r, col: c };
            }
        }
        const rows = getVisibleRows(state);
        for(let r = 0; r < rows.length; r += 1){
            const cells = getVisibleCellsInRow(rows[r]);
            const c = cells.indexOf(cell);
            if(c >= 0) return { row: r, col: c };
        }
        return null;
    }

    function getCellByCoord(state, coord){
        if(!state || !coord) return null;
        const rows = getVisibleRows(state);
        if(coord.row < 0 || coord.row >= rows.length) return null;
        const cells = getVisibleCellsInRow(rows[coord.row]);
        if(coord.col < 0 || coord.col >= cells.length) return null;
        return cells[coord.col] || null;
    }

    function getRectCells(state, a, b){
        if(!state || !a || !b) return [];
        const r1 = Math.min(a.row, b.row);
        const r2 = Math.max(a.row, b.row);
        const c1 = Math.min(a.col, b.col);
        const c2 = Math.max(a.col, b.col);
        const rows = getVisibleRows(state);
        const out = [];
        for(let r = r1; r <= r2; r += 1){
            const row = rows[r];
            if(!row) continue;
            const cells = getVisibleCellsInRow(row);
            for(let c = c1; c <= c2; c += 1){
                if(cells[c]) out.push(cells[c]);
            }
        }
        return out;
    }

    function notifySitjoyGridSelectionChange(){
        if(activeGridSelection && (activeGridSelection.dragging || activeGridSelection.detailDragging)) return;
        let cells = (activeGridSelection && activeGridSelection.selectedCells)
            ? Array.from(activeGridSelection.selectedCells).filter(cell => cell && cell.isConnected)
            : [];
        let extractCellText = (td) => extractCellClipboardText(td);

        /* 在途 SKU 跨行框选：按堆叠行统计，勿把整格多行数字拼成一个大数 */
        if(activeGridSelection
            && activeGridSelection.transitSkuGrid
            && activeGridSelection.skuPaintedNodes
            && activeGridSelection.skuPaintedNodes.length){
            cells = activeGridSelection.skuPaintedNodes.filter((line) => line
                && line.isConnected
                && (line.classList.contains('pm-grid-detail-selected')
                    || line.classList.contains('pm-grid-detail-anchor')));
            extractCellText = (line) => {
                const td = line.closest ? line.closest('td') : null;
                return td ? extractTransitSkuStackLineText(line, td) : '';
            };
        }

        const detail = {
            cells,
            extractCellText
        };
        window.__sitjoyPendingGridSelection = detail;
        if(window.SitjoyCellSelectionStats && typeof window.SitjoyCellSelectionStats.apply === 'function'){
            window.SitjoyCellSelectionStats.apply(detail);
        }
        document.dispatchEvent(new CustomEvent('sitjoy:grid-selection-change', { detail }));
    }

    function paintGridSelection(){
        if(!activeGridSelection || !activeGridSelection.state) return;
        const state = activeGridSelection.state;

        const skuSel = activeGridSelection.transitSkuGrid;
        if(skuSel && skuSel.anchor && skuSel.current){
            const selection = resolveTransitSkuGridSelection(state, skuSel.anchor, skuSel.current);
            if(selection && selection.rowSlots.length){
                const sig = transitSkuGridPaintSignature(skuSel, selection);
                if(sig && sig === activeGridSelection.skuGridPaintSig){
                    return;
                }
                activeGridSelection.skuGridPaintSig = sig;

                clearTransitSkuGridPaintNodes(activeGridSelection.skuPaintedNodes);
                activeGridSelection.skuPaintedNodes = [];
                state.table.querySelectorAll('td.pm-grid-cell-selected, td.pm-grid-cell-anchor').forEach((cell) => {
                    cell.classList.remove('pm-grid-cell-selected', 'pm-grid-cell-anchor');
                });

                activeGridSelection.selectedCells = collectTransitSkuGridCellsFromSelection(state, selection);
                const anchor = skuSel.anchor;
                selection.rowSlots.forEach((slot) => {
                    for(let sc = selection.sc1; sc <= selection.sc2; sc += 1){
                        const node = getTransitSkuGridLineNode(state, slot.tr, sc, slot.lr);
                        if(!node) continue;
                        const isAnchor = anchor.tr === slot.tr && anchor.sc === sc && anchor.lr === slot.lr;
                        node.classList.add(isAnchor ? 'pm-grid-detail-anchor' : 'pm-grid-detail-selected');
                        activeGridSelection.skuPaintedNodes.push(node);
                    }
                });
                state.table.classList.add('is-grid-selecting');
                notifySitjoyGridSelectionChange();
                return;
            }
        }
        activeGridSelection.skuGridPaintSig = '';
        activeGridSelection.skuPaintedNodes = [];

        const hasDetailSelections = !!(activeGridSelection.detailSelections && activeGridSelection.detailSelections.size);
        if(hasDetailSelections){
            clearGridSelectionClasses(state.table);
        }

        paintNormalGridCellsIncremental(state, activeGridSelection);
        if(hasDetailSelections){
            (activeGridSelection.detailSelections || new Map()).forEach((detailSel, cell) => {
            if(!cell || !cell.isConnected || !detailSel || !detailSel.anchor || !detailSel.current) return;
            const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
            const nodes = getTransitSubcellNodesByRect(cell, rect);
            nodes.forEach(node => node.classList.add('pm-grid-detail-selected'));
            const anchorNodes = getTransitSubcellNodesByRect(cell, normalizeTransitDetailRect(detailSel.anchor, detailSel.anchor));
            if(anchorNodes[0]) anchorNodes[0].classList.add('pm-grid-detail-anchor');
            });
        }
        if(activeGridSelection.selectedCells.size > 0){
            state.table.classList.add('is-grid-selecting');
        }
        notifySitjoyGridSelectionChange();
    }

    function ensureGridSelectionState(state){
        if(activeGridSelection && activeGridSelection.state === state) return activeGridSelection;
        clearGridSelection();
        activeGridSelection = {
            state,
            selectedCells: new Set(),
            anchorCoord: null,
            dragging: false,
            dragAnchor: null,
            dragCurrentCoord: null,
            lastPaintedRectSig: '',
            paintedCells: new Set(),
            detailSelections: new Map(),
            detailDragging: null,
            transitSkuGrid: null,
            skuPaintedNodes: [],
            skuGridPaintSig: ''
        };
        return activeGridSelection;
    }

    function selectCellsForState(state, cells, anchorCoord){
        const selection = ensureGridSelectionState(state);
        selection.selectedCells = new Set((cells || []).filter(Boolean));
        selection.anchorCoord = anchorCoord || null;
        selection.transitSkuGrid = null;
        if(selection.selectedCells.size !== 1){
            selection.detailSelections = new Map();
            selection.detailDragging = null;
        }
        paintGridSelection();
    }

    function toggleCellForState(state, cell, anchorCoord){
        const selection = ensureGridSelectionState(state);
        if(selection.selectedCells.has(cell)) selection.selectedCells.delete(cell);
        else selection.selectedCells.add(cell);
        selection.anchorCoord = anchorCoord || selection.anchorCoord;
        selection.transitSkuGrid = null;
        if(selection.selectedCells.size !== 1){
            selection.detailSelections = new Map();
            selection.detailDragging = null;
        }
        paintGridSelection();
    }

    function extractCellClipboardText(cell){
        if(!cell) return '';

        const explicitExport = String(cell.getAttribute('data-export-value') || cell.dataset.exportValue || '').trim();
        if(explicitExport) return explicitExport;

        const textInput = cell.querySelector('input:not([type="checkbox"]):not([type="hidden"]), textarea');
        if(textInput){
            const value = String(textInput.value || '').trim();
            if(value) return value;
        }

        const select = cell.querySelector('select');
        if(select){
            const option = select.options && select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
            const value = option ? String(option.textContent || option.value || '').trim() : String(select.value || '').trim();
            if(value) return value;
        }

        const stackLines = getTransitSkuStackLines(cell);
        if(stackLines.length){
            const detailSel = activeGridSelection
                && activeGridSelection.detailSelections
                ? activeGridSelection.detailSelections.get(cell)
                : null;
            if(detailSel && detailSel.anchor && detailSel.current){
                const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
                const parts = [];
                for(let r = rect.r1; r <= rect.r2; r += 1){
                    parts.push(String(stackLines[r] || ''));
                }
                return parts.join('\n');
            }
            return stackLines.join('\n');
        }

        const transitDetailRows = getTransitDetailValueMatrix(cell);
        if(transitDetailRows.length){
            return transitDetailRows.map(row => row.join('\t')).join('\n');
        }

        // Prefer status value in table cells (copy current state only, not all button labels).
        const activeStatus = cell.querySelector('.status-pill.is-active');
        if(activeStatus){
            return String(activeStatus.textContent || '').replace(/\s+/g, ' ').trim();
        }

        const segment = cell.querySelector('.status-segment');
        if(segment){
            const value = String(segment.getAttribute('data-value') || '').trim();
            if(value){
                let matched = null;
                segment.querySelectorAll('.status-pill').forEach(btn => {
                    if(matched) return;
                    if(String(btn.getAttribute('data-value') || '') === value){
                        matched = btn;
                    }
                });
                if(matched){
                    return String(matched.textContent || '').replace(/\s+/g, ' ').trim();
                }
            }
        }

        const colorChip = cell.querySelector('.sku-color-chip, .transit-color-dot, [data-color-chip]');
        if(colorChip){
            const chipColor = String(
                colorChip.getAttribute('data-color')
                || colorChip.dataset.color
                || colorChip.style.backgroundColor
                || ''
            ).trim();
            if(chipColor) return chipColor;
            if(typeof window.getComputedStyle === 'function'){
                const computedColor = String(window.getComputedStyle(colorChip).backgroundColor || '').trim();
                if(computedColor && computedColor.toLowerCase() !== 'rgba(0, 0, 0, 0)' && computedColor.toLowerCase() !== 'transparent'){
                    return computedColor;
                }
            }
        }

        return String((cell.innerText || cell.textContent || ''))
            .replace(/\r/g, '')
            .replace(/\n+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function copyGridSelectionToClipboard(){
        if(!activeGridSelection || !activeGridSelection.state) return false;
        const state = activeGridSelection.state;
        if(activeGridSelection.transitSkuGrid){
            return copyTransitSkuGridSelectionToClipboard(state);
        }
        if(!activeGridSelection.selectedCells.size) return false;
        const coords = [];
        activeGridSelection.selectedCells.forEach(cell => {
            const coord = getCellCoord(state, cell);
            if(coord) coords.push(coord);
        });
        if(!coords.length) return false;

        const minRow = Math.min.apply(null, coords.map(x => x.row));
        const maxRow = Math.max.apply(null, coords.map(x => x.row));
        const minCol = Math.min.apply(null, coords.map(x => x.col));
        const maxCol = Math.max.apply(null, coords.map(x => x.col));
        const selectedKey = new Set(coords.map(x => `${x.row}:${x.col}`));

        const lines = [];
        for(let r = minRow; r <= maxRow; r += 1){
            let rowExpand = 1;
            for(let c = minCol; c <= maxCol; c += 1){
                const key = `${r}:${c}`;
                if(!selectedKey.has(key)) continue;
                const cell = getCellByCoord(state, { row: r, col: c });
                if(!cell || !isTransitSubcellCell(cell)) continue;
                const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
                if(isTransitSkuStackCell(cell)){
                    const stackLines = getTransitSkuStackLines(cell);
                    if(!stackLines.length) continue;
                    if(detailSel && detailSel.anchor && detailSel.current){
                        const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
                        rowExpand = Math.max(rowExpand, rect.r2 - rect.r1 + 1);
                    } else {
                        rowExpand = Math.max(rowExpand, stackLines.length);
                    }
                    continue;
                }
                const detailMatrix = getTransitDetailValueMatrix(cell);
                if(!detailMatrix.length) continue;
                if(detailSel && detailSel.anchor && detailSel.current){
                    const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
                    rowExpand = Math.max(rowExpand, rect.r2 - rect.r1 + 1);
                } else {
                    rowExpand = Math.max(rowExpand, detailMatrix.length);
                }
            }

            for(let sub = 0; sub < rowExpand; sub += 1){
                const cols = [];
                for(let c = minCol; c <= maxCol; c += 1){
                    const key = `${r}:${c}`;
                    if(!selectedKey.has(key)){
                        cols.push('');
                        continue;
                    }
                    const cell = getCellByCoord(state, { row: r, col: c });
                    if(!cell){
                        cols.push('');
                        continue;
                    }

                    if(isTransitSkuStackCell(cell)){
                        const stackLines = getTransitSkuStackLines(cell);
                        const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
                        if(detailSel && detailSel.anchor && detailSel.current){
                            const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
                            const targetRow = rect.r1 + sub;
                            if(targetRow >= rect.r1 && targetRow <= rect.r2){
                                cols.push(String(stackLines[targetRow] || ''));
                            }
                        } else {
                            cols.push(String(stackLines[sub] || ''));
                        }
                        continue;
                    }

                    if(isTransitDetailCell(cell)){
                        const matrix = getTransitDetailValueMatrix(cell);
                        const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
                        if(detailSel && detailSel.anchor && detailSel.current){
                            const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
                            const targetRow = rect.r1 + sub;
                            const rowValues = matrix[targetRow] || [];
                            for(let dc = rect.c1; dc <= rect.c2; dc += 1){
                                cols.push(String(rowValues[dc] || ''));
                            }
                            continue;
                        }
                        const rowValues = matrix[sub] || [];
                        cols.push(String(rowValues[0] || ''));
                        cols.push(String(rowValues[1] || ''));
                        cols.push(String(rowValues[2] || ''));
                        cols.push(String(rowValues[3] || ''));
                        continue;
                    }

                    const text = sub === 0 ? extractCellClipboardText(cell) : '';
                    cols.push(text);
                }
                lines.push(cols.join('\t'));
            }
        }
        const text = lines.join('\n');
        if(!text) return false;

        if(navigator.clipboard && navigator.clipboard.writeText){
            navigator.clipboard.writeText(text).then(() => {
                if(window.showAppToast) window.showAppToast('已复制选中区域', false, 1200);
            }).catch(() => {});
            return true;
        }

        const area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.left = '-10000px';
        area.style.top = '-10000px';
        document.body.appendChild(area);
        area.focus();
        area.select();
        try {
            document.execCommand('copy');
            if(window.showAppToast) window.showAppToast('已复制选中区域', false, 1200);
        } catch (_) {}
        document.body.removeChild(area);
        return true;
    }

    function parseClipboardMatrix(text){
        const raw = String(text || '').replace(/\r/g, '');
        if(!raw) return [];
        const rows = raw.split('\n').filter(line => line.length > 0);
        return rows.map(line => line.split('\t'));
    }

    function getEditableFieldFromCell(cell){
        if(!cell || !cell.querySelector) return null;
        const candidate = cell.querySelector('input:not([type="checkbox"]):not([type="hidden"]):not([disabled]):not([readonly]), textarea:not([disabled]):not([readonly]), select:not([disabled]):not([readonly])');
        return candidate || null;
    }

    function setFieldValueByPaste(field, raw){
        if(!field) return;
        const value = String(raw === null || raw === undefined ? '' : raw).trim();
        if(field instanceof HTMLInputElement){
            const type = String(field.type || '').toLowerCase();
            if(type === 'number'){
                const cleaned = value.replace(/,/g, '');
                const num = Number(cleaned);
                field.value = (!Number.isNaN(num) && cleaned !== '') ? String(num) : '';
            } else if(type === 'date'){
                const parsed = parseDateText(value);
                field.value = parsed ? formatDateParts(parsed) : '';
            } else if(type === 'datetime-local'){
                const stamp = Date.parse(value);
                if(!Number.isNaN(stamp)){
                    const d = new Date(stamp);
                    const yyyy = d.getFullYear();
                    const mm = String(d.getMonth() + 1).padStart(2, '0');
                    const dd = String(d.getDate()).padStart(2, '0');
                    const hh = String(d.getHours()).padStart(2, '0');
                    const mi = String(d.getMinutes()).padStart(2, '0');
                    field.value = `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
                } else {
                    field.value = '';
                }
            } else {
                field.value = value;
            }
        } else if(field instanceof HTMLTextAreaElement){
            field.value = value;
        } else if(field instanceof HTMLSelectElement){
            const options = Array.from(field.options || []);
            const hit = options.find(opt => String(opt.value || '').trim() === value) || options.find(opt => String(opt.textContent || '').trim() === value);
            if(hit) field.value = String(hit.value || '');
            else field.value = value;
        } else {
            return;
        }

        field.dispatchEvent(new Event('input', { bubbles: true }));
        field.dispatchEvent(new Event('change', { bubbles: true }));
    }

    /** 框选/单选单元格后按 Delete：清空格内可编辑输入（与矩阵粘贴同一套字段识别） */
    function clearEditableFieldsInActiveGridSelection(){
        if(!activeGridSelection || !activeGridSelection.state || !activeGridSelection.selectedCells.size) return false;
        let applied = 0;
        activeGridSelection.selectedCells.forEach(cell => {
            if(!cell || !cell.isConnected) return;
            const field = getEditableFieldFromCell(cell);
            if(field){
                setFieldValueByPaste(field, '');
                applied += 1;
            }
        });
        return applied > 0;
    }

    function applyMatrixPasteToActiveSelection(state, matrix){
        if(!state || !Array.isArray(matrix) || !matrix.length) return false;
        if(!activeGridSelection || activeGridSelection.state !== state || !activeGridSelection.selectedCells.size) return false;

        const coords = [];
        activeGridSelection.selectedCells.forEach(cell => {
            const coord = getCellCoord(state, cell);
            if(coord) coords.push(coord);
        });
        if(!coords.length) return false;

        const rowMin = Math.min.apply(null, coords.map(x => x.row));
        const rowMax = Math.max.apply(null, coords.map(x => x.row));
        const colMin = Math.min.apply(null, coords.map(x => x.col));
        const colMax = Math.max.apply(null, coords.map(x => x.col));
        const selected = new Set(coords.map(x => `${x.row}:${x.col}`));

        let applied = 0;
        for(let r = rowMin; r <= rowMax; r += 1){
            for(let c = colMin; c <= colMax; c += 1){
                if(!selected.has(`${r}:${c}`)) continue;
                const cell = getCellByCoord(state, { row: r, col: c });
                const field = getEditableFieldFromCell(cell);
                if(!field) continue;
                const v = matrix[(r - rowMin) % matrix.length] || [''];
                const text = v[(c - colMin) % v.length] || '';
                setFieldValueByPaste(field, text);
                applied += 1;
            }
        }
        return applied > 0;
    }

    function applyMatrixPasteFromField(state, startField, matrix){
        if(!state || !startField || !Array.isArray(matrix) || !matrix.length) return false;
        const startCell = startField.closest('td');
        if(!startCell) return false;
        const startCoord = getCellCoord(state, startCell);
        if(!startCoord) return false;

        let applied = 0;
        for(let r = 0; r < matrix.length; r += 1){
            const rowVals = matrix[r] || [''];
            for(let c = 0; c < rowVals.length; c += 1){
                const cell = getCellByCoord(state, { row: startCoord.row + r, col: startCoord.col + c });
                const field = getEditableFieldFromCell(cell);
                if(!field) continue;
                setFieldValueByPaste(field, rowVals[c] || '');
                applied += 1;
            }
        }
        return applied > 0;
    }

    function getManagedStateByElement(el){
        if(!el || !el.closest) return null;
        const table = el.closest('table.is-managed-table');
        if(!table) return null;
        return managedTableState.get(table) || null;
    }

    function getManagedStateFromSelection(){
        if(!activeGridSelection || !activeGridSelection.state) return null;
        return activeGridSelection.state;
    }

    function hasActiveManagedSelection(state){
        return !!(state && activeGridSelection && activeGridSelection.state === state && (
            (activeGridSelection.selectedCells && activeGridSelection.selectedCells.size > 0)
            || (activeGridSelection.transitSkuGrid && activeGridSelection.transitSkuGrid.anchor)
        ));
    }

    function bindGridSelection(state){
        if(!state || !state.tbody || state.tbody.dataset.gridSelectBound === '1') return;
        state.tbody.dataset.gridSelectBound = '1';

        state.tbody.addEventListener('mousedown', (event) => {
            if(event.button !== 0) return;
            const cell = event.target && event.target.closest ? event.target.closest('td') : null;
            if(!cell || !state.tbody.contains(cell)) return;
            if(cell.classList.contains('pm-table-hide-col')) return;
            const manageColKey = String(cell.dataset.manageColKey || '').trim();
            if(manageColKey.endsWith('_chk__')) return;
            if(event.target && event.target.closest && event.target.closest('input[type="checkbox"]')) return;
            if(isEditableDomTarget(event.target) && event.target !== cell) return;

            const activeEl = document.activeElement;
            if(
                activeEl &&
                activeEl instanceof HTMLElement &&
                activeEl !== event.target &&
                activeEl !== cell &&
                activeEl.closest &&
                activeEl.closest('table.is-managed-table')
            ){
                if(activeEl.matches('input, textarea, select')){
                    try { activeEl.blur(); } catch (_) {}
                }
            }

            const coord = getCellCoord(state, cell);
            if(!coord) return;

            event.preventDefault();
            const selection = ensureGridSelectionState(state);

            const skuGridCoord = getTransitSkuGridCoord(state, event.target);
            if(skuGridCoord){
                beginGridDragVisibleRowCache(state);
                if(event.shiftKey && selection.transitSkuGrid && selection.transitSkuGrid.anchor){
                    selection.transitSkuGrid.current = skuGridCoord;
                    selection.detailSelections = new Map();
                    selection.detailDragging = null;
                    selection.dragging = false;
                    selection.dragAnchor = null;
                    paintGridSelection();
                    return;
                }
                selection.transitSkuGrid = { anchor: skuGridCoord, current: skuGridCoord };
                selection.detailSelections = new Map();
                selection.detailDragging = { mode: 'transitSkuGrid' };
                selection.dragging = false;
                selection.dragAnchor = null;
                selection.anchorCoord = coord;
                paintGridSelection();
                return;
            }

            const detailCoord = isTransitDetailCell(cell) ? getTransitSubcellCoord(event.target, cell) : null;
            if(detailCoord){
                beginGridDragVisibleRowCache(state);
                selection.transitSkuGrid = null;
                selectCellsForState(state, [cell], coord);
                selection.detailSelections = new Map();
                selection.detailSelections.set(cell, { anchor: detailCoord, current: detailCoord });
                selection.detailDragging = { cell, anchor: detailCoord };
                selection.dragging = false;
                selection.dragAnchor = null;
                paintGridSelection();
                return;
            }

            if(event.shiftKey && selection.anchorCoord){
                selectCellsForState(state, getRectCells(state, selection.anchorCoord, coord), selection.anchorCoord);
                return;
            }

            if(event.ctrlKey || event.metaKey){
                toggleCellForState(state, cell, coord);
                return;
            }

            selectCellsForState(state, [cell], coord);
            selection.detailSelections = new Map();
            selection.detailDragging = null;
            if(activeGridSelection){
                beginGridDragVisibleRowCache(state);
                activeGridSelection.dragging = true;
                activeGridSelection.dragAnchor = coord;
                activeGridSelection.lastPaintedRectSig = gridDragRectSignature(coord, coord);
            }
        });
    }

    function mapRowByOrigin(row){
        const map = new Map();
        Array.from(row.cells || []).forEach((cell, idx) => {
            if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
            map.set(Number(cell.dataset.manageColOrigin), cell);
        });
        return map;
    }

    function invalidatePmRowCellKeyMap(row){
        if(row) row._pmCellKeyMap = null;
    }

    function invalidatePmRowCellKeyMapsInTbody(tbody){
        if(!tbody || !tbody.rows) return;
        Array.from(tbody.rows || []).forEach(invalidatePmRowCellKeyMap);
    }

    function mapRowByKey(row){
        const cached = row && row._pmCellKeyMap;
        if(cached && cached.size > 0) return cached;
        const out = new Map();
        Array.from(row.cells || []).forEach((cell, idx) => {
            const key = String(cell.dataset.manageColKey || '').trim() || `字段${idx + 1}`;
            if(!cell.dataset.manageColKey) cell.dataset.manageColKey = key;
            if(!out.has(key)) out.set(key, cell);
        });
        if(row){
            row._pmCellKeyMap = out.size > 0 ? out : null;
        }
        return out;
    }

    function buildManagedOriginToKeyMap(state, headerMeta){
        const originToKey = new Map();
        const mainHeadRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(mainHeadRow){
            Array.from(mainHeadRow.cells || []).forEach((cell, idx) => {
                if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
                const origin = Number(cell.dataset.manageColOrigin);
                const key = String(cell.dataset.manageColKey || '').trim();
                if(Number.isFinite(origin) && key) originToKey.set(origin, key);
            });
        }
        (Array.isArray(headerMeta) ? headerMeta : []).forEach((meta, idx) => {
            const origin = Number(meta && meta.origin);
            const key = String(meta && meta.key || '').trim();
            if(Number.isFinite(origin) && key) originToKey.set(origin, key);
            else if(!originToKey.has(idx) && key) originToKey.set(idx, key);
        });
        return originToKey;
    }

    function ensureManagedColumnKeys(state, headerMeta){
        if(!state || !state.table || !Array.isArray(headerMeta) || !headerMeta.length) return;
        const originToKey = buildManagedOriginToKeyMap(state, headerMeta);
        const colCount = headerMeta.length;

        const stampHeadRowByDom = (row) => {
            if(!row || (row.cells || []).length !== colCount) return;
            Array.from(row.cells || []).forEach((cell, idx) => {
                const meta = headerMeta[idx];
                const key = meta && String(meta.key || '').trim();
                if(key) cell.dataset.manageColKey = key;
            });
        };

        const stampBodyRowByOrigin = (row) => {
            if(!row || (row.cells || []).length !== colCount) return;
            const headerRow = getPrimaryHeaderRow(state);
            Array.from(row.cells || []).forEach((cell, idx) => {
                const headerCell = headerRow && headerRow.cells && headerRow.cells[idx];
                const keyFromHeader = headerCell ? String(headerCell.dataset.manageColKey || '').trim() : '';
                const key = keyFromHeader
                    || String(cell.dataset.manageColKey || '').trim()
                    || originToKey.get(idx)
                    || (headerMeta[idx] && String(headerMeta[idx].key || '').trim())
                    || `字段${idx + 1}`;
                cell.dataset.manageColKey = key;
                if(headerCell && headerCell.dataset.manageColOrigin){
                    cell.dataset.manageColOrigin = headerCell.dataset.manageColOrigin;
                } else {
                    cell.dataset.manageColOrigin = String(idx);
                }
            });
        };

        const mainHeadRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(mainHeadRow) stampHeadRowByDom(mainHeadRow);
        const detachedHeadRow = state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows && state.headerTable.tHead.rows[0];
        if(detachedHeadRow && detachedHeadRow !== mainHeadRow) stampHeadRowByDom(detachedHeadRow);

        Array.from(state.table.rows || []).forEach((row) => {
            if(row.parentNode && String(row.parentNode.tagName || '').toUpperCase() === 'THEAD') return;
            stampBodyRowByOrigin(row);
            invalidatePmRowCellKeyMap(row);
        });
    }

    function getPrimaryHeaderRow(state){
        if(managedTableUsesDetachedHeader(state) && state && state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows && state.headerTable.tHead.rows[0]){
            return state.headerTable.tHead.rows[0];
        }
        if(state && state.table && state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0]){
            return state.table.tHead.rows[0];
        }
        return null;
    }

    function syncDetachedHeader(state){
        if(!managedTableUsesDetachedHeader(state)) return;
        if(!state || !state.headerTable || !state.table || !state.table.tHead || !state.table.tHead.rows.length) return;
        const srcHead = state.table.tHead;

        // Keep detached header width model identical to source table (especially when colgroup is used).
        state.headerTable.querySelectorAll('colgroup').forEach(node => node.remove());
        const srcColgroup = state.table.querySelector('colgroup');
        if(srcColgroup){
            state.headerTable.insertBefore(srcColgroup.cloneNode(true), state.headerTable.firstChild || null);
        }

        let dstHead = state.headerTable.tHead;
        if(!dstHead){
            dstHead = document.createElement('thead');
            state.headerTable.appendChild(dstHead);
        }
        dstHead.innerHTML = '';

        Array.from(srcHead.rows || []).forEach((srcRow) => {
            if(!srcRow) return;
            const cloned = srcRow.cloneNode(true);
            cloned.querySelectorAll('.pm-col-resizer').forEach(node => node.remove());
            cloned.querySelectorAll('[data-sort-bound]').forEach(node => node.removeAttribute('data-sort-bound'));
            dstHead.appendChild(cloned);
        });

        srcHead.classList.add('pm-managed-hidden-head');
    }

    function applyColumnOrder(state){
        syncManagedColgroupOrder(state);
        const expected = state.headerCount;
        if(!expected || !Array.isArray(state.columnOrder) || !state.columnOrder.length) return;
        const tables = [state.table];
        if(state.headerTable) tables.push(state.headerTable);
        tables.forEach((table) => {
            if(!table) return;
            Array.from(table.rows || []).forEach((row) => {
                const cells = Array.from(row.cells || []);
                if(cells.length !== expected) return;
                const currentOrder = cells.map((cell) => String(cell.dataset.manageColKey || '').trim());
                if(currentOrder.length === state.columnOrder.length && currentOrder.every((v, i) => v === state.columnOrder[i])) {
                    return;
                }
                const byKey = mapRowByKey(row);
                const used = new Set();
                const ordered = [];
                state.columnOrder.forEach((key) => {
                    const cell = byKey.get(String(key || '').trim());
                    if(cell && !used.has(cell)){
                        ordered.push(cell);
                        used.add(cell);
                    }
                });
                cells.forEach((cell) => {
                    if(!used.has(cell)) ordered.push(cell);
                });
                if(ordered.length !== expected) return;
                ordered.forEach((cell) => row.appendChild(cell));
            });
        });
    }

    function findManagedHeaderCellForKey(state, columnKey){
        const key = String(columnKey || '').trim();
        if(!key || !state || !state.table) return null;
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!headerRow) return null;
        return Array.from(headerRow.cells || []).find((cell) => String(cell.dataset.manageColKey || '').trim() === key) || null;
    }

    function readManagedColumnLayoutWidthPx(state, columnKey){
        const key = String(columnKey || '').trim();
        if(!key || !state) return 0;
        const cols = resolveManagedColgroupColsForKey(state, key);
        if(cols.length){
            let sum = 0;
            cols.forEach((col) => {
                if(String(col.getAttribute('data-pm-col-hidden') || '') === '1') return;
                sum += parseColWidthPx(col.style.width) || 0;
            });
            if(sum > 0) return sum;
        }
        const w = Number((state.columnWidths || {})[key]);
        if(Number.isFinite(w) && w > 0) return w;
        const dw = Number((state.defaultColumnWidths || {})[key]);
        if(Number.isFinite(dw) && dw > 0) return dw;
        const meta = (state.headers || []).find(h => String(h.key || '').trim() === key);
        const headerCell = findManagedHeaderCellForKey(state, key);
        const thumbMin = managedThumbColumnMinWidthPx(state, key, headerCell);
        if(thumbMin > 0) return thumbMin;
        return computeDefaultColumnWidth(state, meta);
    }

    function pinnedLayoutSigForState(state){
        const visible = state.visibleColumns || new Set();
        const pinnedAll = new Set();
        if(state.lockedColumns && state.lockedColumns.size){
            state.lockedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        if(state.pinnedColumns && state.pinnedColumns.size){
            state.pinnedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        const pinnedOrder = (state.columnOrder || []).filter(k => {
            const key = String(k || '').trim();
            if(!key || !pinnedAll.has(key) || !visible.has(key)) return false;
            return !isManagedColumnSlotHidden(state, key, findManagedHeaderCellForKey(state, key));
        });
        return pinnedOrder.map(k => `${k}:${readManagedColumnLayoutWidthPx(state, k)}`).join('|');
    }

    function pinnedLayoutNeedsUpdateAfterResize(state, resizedKey){
        const key = String(resizedKey || '').trim();
        if(!key || !state) return false;
        const visible = state.visibleColumns || new Set();
        const pinnedAll = new Set();
        if(state.lockedColumns && state.lockedColumns.size){
            state.lockedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        if(state.pinnedColumns && state.pinnedColumns.size){
            state.pinnedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        const pinnedOrder = (state.columnOrder || []).filter(k => {
            const kk = String(k || '').trim();
            if(!kk || !pinnedAll.has(kk) || !visible.has(kk)) return false;
            return !isManagedColumnSlotHidden(state, kk, findManagedHeaderCellForKey(state, kk));
        });
        if(!pinnedOrder.length) return false;
        const idx = pinnedOrder.indexOf(key);
        return idx >= 0;
    }

    function applyPinnedColumns(state, options){
        if(!state || !state.table) return;
        const sig = pinnedLayoutSigForState(state);
        const force = !!(options && options.force);
        if(!force && state.pinnedLayoutSig === sig) return;
        state.pinnedLayoutSig = sig;

        const visible = state.visibleColumns || new Set();
        const pinnedAll = new Set();
        if(state.lockedColumns && state.lockedColumns.size){
            state.lockedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        if(state.pinnedColumns && state.pinnedColumns.size){
            state.pinnedColumns.forEach(k => pinnedAll.add(String(k || '').trim()));
        }
        const pinnedOrder = (state.columnOrder || []).filter(k => {
            const key = String(k || '').trim();
            if(!key || !pinnedAll.has(key) || !visible.has(key)) return false;
            return !isManagedColumnSlotHidden(state, key, findManagedHeaderCellForKey(state, key));
        });

        const clearSticky = (t) => {
            if(!t) return;
            Array.from(t.rows || []).forEach(row => {
                Array.from(row.cells || []).forEach(cell => {
                    if(!cell || !cell.classList || !cell.classList.contains('pm-table-pinned-cell')) return;
                    cell.classList.remove('pm-table-pinned-cell');
                    try {
                        cell.style.position = '';
                        cell.style.left = '';
                        cell.style.zIndex = '';
                    } catch (_) {}
                });
            });
        };

        if(!pinnedOrder.length){
            state.pinnedLayoutSig = '';
            clearSticky(state.table);
            if(state.headerTable) clearSticky(state.headerTable);
            return;
        }

        const widthByKey = (key) => readManagedColumnLayoutWidthPx(state, key);

        const leftByKey = new Map();
        let acc = 0;
        pinnedOrder.forEach((k) => {
            leftByKey.set(String(k || '').trim(), acc);
            acc += Math.max(0, widthByKey(k));
        });

        const pinnedKeySet = new Set(pinnedOrder);
        const applyTo = (t) => {
            if(!t) return;
            Array.from(t.rows || []).forEach(row => {
                Array.from(row.cells || []).forEach(cell => {
                    const key = String((cell && cell.dataset && cell.dataset.manageColKey) ? cell.dataset.manageColKey : '').trim();
                    if(!key) return;
                    const isPinned = pinnedKeySet.has(key);
                    const wasPinned = !!(cell.classList && cell.classList.contains('pm-table-pinned-cell'));
                    if(!isPinned && !wasPinned) return;
                    if(!isPinned || isManagedColumnSlotHidden(state, key)){
                        if(cell.classList && cell.classList.contains('pm-table-pinned-cell')){
                            cell.classList.remove('pm-table-pinned-cell');
                            try {
                                cell.style.position = '';
                                cell.style.left = '';
                                cell.style.zIndex = '';
                            } catch (_) {}
                        }
                        return;
                    }
                    cell.classList && cell.classList.add('pm-table-pinned-cell');
                    try {
                        cell.style.position = 'sticky';
                        cell.style.left = `${leftByKey.get(key) || 0}px`;
                        const isTh = String(cell.tagName || '').toUpperCase() === 'TH';
                        cell.style.zIndex = isTh ? '35' : '18';
                    } catch (_) {}
                });
            });
        };

        applyTo(state.table);
        if(state.headerTable) applyTo(state.headerTable);
    }

    function syncManagedColgroupOrder(state){
        if(!state || !state.table || !state.table.tHead || !state.table.tHead.rows || !state.table.tHead.rows.length) return;
        const colgroup = state.table.querySelector('colgroup');
        if(!colgroup) return;
        const cols = Array.from(colgroup.children || []).filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        if(!cols.length) return;

        const headerRow = state.table.tHead.rows[0];
        if(!headerRow || !headerRow.cells || !headerRow.cells.length) return;

        const segments = [];
        let cursor = 0;
        Array.from(headerRow.cells || []).forEach((cell, idx) => {
            const span = Math.max(1, Number(cell.colSpan || 1) || 1);
            const key = String(cell.dataset.manageColKey || '').trim() || `字段${idx + 1}`;
            const segmentCols = cols.slice(cursor, cursor + span);
            if(segmentCols.length === span){
                segmentCols.forEach(col => {
                    col.dataset.manageColKey = key;
                    col.dataset.manageColSpan = String(span);
                });
                segments.push({ key, cols: segmentCols });
            }
            cursor += span;
        });

        if(!segments.length) return;

        const orderedCols = [];
        const usedIndexes = new Set();
        state.columnOrder.forEach((key) => {
            const targetKey = String(key || '').trim();
            if(!targetKey) return;
            const segIdx = segments.findIndex((seg, idx) => !usedIndexes.has(idx) && seg.key === targetKey);
            if(segIdx < 0) return;
            usedIndexes.add(segIdx);
            orderedCols.push(...segments[segIdx].cols);
        });

        segments.forEach((seg, idx) => {
            if(usedIndexes.has(idx)) return;
            orderedCols.push(...seg.cols);
        });

        if(orderedCols.length !== cols.length) return;
        const sameOrder = cols.every((col, idx) => col === orderedCols[idx]);
        if(sameOrder) return;
        orderedCols.forEach(col => colgroup.appendChild(col));
    }

    function isManagedColumnSlotHidden(state, columnKey){
        const key = String(columnKey || '').trim();
        if(!key || !state) return false;
        const visible = state.visibleColumns || new Set();
        if(!visible.has(key)) return true;
        if(key === '__sj_agg__'){
            const host = state.table && state.table.closest
                ? state.table.closest('.sj-sales-table-host, .sj-wip-table-host')
                : null;
            if(host && host.classList.contains('sj-aggregate-active')) return false;
            if(host && !host.classList.contains('sj-aggregate-active')) return true;
        }
        return false;
    }

    /** 隐藏列：colgroup + 单元格用 visibility:collapse，保持列索引与分离表头一致 */
    function syncManagedColgroupSlotVisibility(state){
        if(!state || !state.table) return;
        ensureManagedTableColgroup(state);
        const colgroup = state.table.querySelector('colgroup');
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!colgroup || !headerRow) return;

        const cols = Array.from(colgroup.children || [])
            .filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        const widths = state.columnWidths || {};

        Array.from(headerRow.cells || []).forEach((cell, idx) => {
            const col = cols[idx];
            if(!col) return;
            const key = String(cell.dataset.manageColKey || col.dataset.manageColKey || '').trim();
            if(key) col.dataset.manageColKey = key;

            if(isManagedColumnSlotHidden(state, key, cell)){
                setManagedColHiddenState(col, true);
                return;
            }

            setManagedColHiddenState(col, false);
            col.style.maxWidth = '';

            let w = Number(widths[key]);
            if(!Number.isFinite(w) || w <= 0){
                w = readManagedColgroupWidthPx(state, key) || parseThStyleWidthPx(cell) || inferDefaultWidthFromHeaderCell(cell) || 80;
            }
            if(key === '__sj_agg__'){
                w = Math.min(28, Math.max(20, Math.round(w) || 24));
            }
            const colMin = getManagedColumnEffectiveMinWidth(state, key, cell);
            w = clampManagedColumnWidth(state, key, w);
            applyManagedColPixelWidth(col, w, colMin);
        });

        syncManagedHeaderColgroupFromMainTable(state);
        syncManagedTableTotalWidth(state);
    }

    function sumManagedColgroupVisibleWidthPx(state){
        if(!state || !state.table) return 0;
        const colgroup = state.table.querySelector('colgroup');
        if(!colgroup) return 0;
        let sum = 0;
        Array.from(colgroup.children || []).forEach((node) => {
            if(!node || String(node.tagName || '').toUpperCase() !== 'COL') return;
            if(String(node.getAttribute('data-pm-col-hidden') || '') === '1') return;
            sum += parseColWidthPx(node.style.width) || 0;
        });
        return sum;
    }

    function syncManagedTableTotalWidth(state){
        if(!state || !state.table) return;
        const sum = sumManagedColgroupVisibleWidthPx(state);
        if(sum < 1) {
            const tables = [state.table];
            if(state.headerTable) tables.push(state.headerTable);
            tables.forEach((table) => {
                if(!table) return;
                try {
                    table.style.removeProperty('--pm-managed-table-width');
                    table.style.removeProperty('width');
                    table.style.removeProperty('min-width');
                    table.style.removeProperty('max-width');
                    table.removeAttribute('data-pm-col-width-sum');
                } catch (_e) {
                }
            });
            return;
        }
        const px = `${sum}px`;
        const tables = [state.table];
        if(state.headerTable) tables.push(state.headerTable);
        tables.forEach((table) => {
            if(!table) return;
            try {
                table.style.setProperty('--pm-managed-table-width', px);
                table.style.setProperty('width', px, 'important');
                table.style.setProperty('min-width', px, 'important');
                table.style.setProperty('max-width', px, 'important');
                table.setAttribute('data-pm-col-width-sum', '1');
            } catch (_e) {
            }
        });
    }

    function isGroupedAggregateTableRow(row){
        if(!row) return false;
        if(window.SitjoyGroupedAggregate && typeof window.SitjoyGroupedAggregate.isGroupRow === 'function'){
            return window.SitjoyGroupedAggregate.isGroupRow(row);
        }
        return false;
    }

    /** 以表头列索引为准判断隐藏（不依赖 tbody 上可能缺失/漂移的 manageColKey） */
    function managedColumnHiddenAtIndex(state, headerCells, idx){
        const headerCell = headerCells[idx];
        if(!headerCell) return true;
        const key = String(headerCell.dataset.manageColKey || '').trim();
        return isManagedColumnSlotHidden(state, key, headerCell);
    }

    function countGroupedAggregateMiddleColspan(state, headerCells, options){
        const total = headerCells.length;
        if(total < 3) return 1;
        const excludeLast = !!(options && options.excludeTrailingAction);
        const end = excludeLast ? total - 1 : total;
        // colspan 须覆盖全部列槽（含 visibility:collapse 的隐藏列），否则分组行尾列会错位
        return Math.max(1, end - 2);
    }

    function groupedAggregateMiddleHasVisibleSlot(state, headerCells, options){
        const total = headerCells.length;
        if(total < 3) return true;
        const excludeLast = !!(options && options.excludeTrailingAction);
        const end = excludeLast ? total - 1 : total;
        for(let i = 2; i < end; i += 1){
            if(!managedColumnHiddenAtIndex(state, headerCells, i)) return true;
        }
        return false;
    }

    function groupedAggregateRowHasActionsCell(cells){
        return cells.some((cell) => {
            if(!cell || !cell.classList) return false;
            if(cell.classList.contains('sj-group-row-actions-cell')) return true;
            return String(cell.dataset.manageColKey || '').trim() === '__sj_group_actions__';
        });
    }

    function stampManagedCellColumnKey(cell, headerCell){
        if(!cell || !headerCell) return;
        const key = String(headerCell.dataset.manageColKey || '').trim();
        if(key && String(cell.dataset.manageColKey || '').trim() !== key){
            cell.dataset.manageColKey = key;
        }
    }

    function applyManagedRowColumnVisibilityByIndex(row, state, headerCells){
        const cells = Array.from(row.cells || []);
        if(cells.length !== headerCells.length) return false;
        cells.forEach((cell, idx) => {
            const headerCell = headerCells[idx];
            stampManagedCellColumnKey(cell, headerCell);
            const hide = managedColumnHiddenAtIndex(state, headerCells, idx);
            cell.classList.toggle('pm-table-hide-col', hide);
            setManagedCellHiddenState(cell, hide);
        });
        return true;
    }

    /** 父体/分组行：复选+收起+colspan 中间区+操作列，随可见列更新 colspan 与隐藏状态 */
    function syncGroupedAggregateRowColumnLayout(state, headerCells){
        if(!state || !state.table || !headerCells || !headerCells.length) return;
        const tbody = state.tbody || (state.table.tBodies && state.table.tBodies[0]);
        if(!tbody || !tbody.rows || !tbody.rows.length) return;
        const lastIdx = headerCells.length - 1;

        Array.from(tbody.rows || []).forEach((row) => {
            if(!isGroupedAggregateTableRow(row)) return;
            const cells = Array.from(row.cells || []);
            if(!cells.length) return;
            if(applyManagedRowColumnVisibilityByIndex(row, state, headerCells)) return;

            const hasActionsCell = groupedAggregateRowHasActionsCell(cells);
            const middleSpan = countGroupedAggregateMiddleColspan(state, headerCells, {
                excludeTrailingAction: hasActionsCell,
            });
            const middleVisible = groupedAggregateMiddleHasVisibleSlot(state, headerCells, {
                excludeTrailingAction: hasActionsCell,
            });

            const toggleGroupedCellHide = (cell, hide) => {
                if(!cell) return;
                cell.classList.toggle('pm-table-hide-col', hide);
                setManagedCellHiddenState(cell, hide);
            };
            if(cells[0] && headerCells[0]){
                stampManagedCellColumnKey(cells[0], headerCells[0]);
                toggleGroupedCellHide(cells[0], managedColumnHiddenAtIndex(state, headerCells, 0));
            }
            if(cells[1] && headerCells[1]){
                stampManagedCellColumnKey(cells[1], headerCells[1]);
                toggleGroupedCellHide(cells[1], managedColumnHiddenAtIndex(state, headerCells, 1));
            }
            const middleCell = cells.find((cell) => Number(cell.colSpan || 1) > 1) || null;
            const actionsCell = cells.find((cell) => {
                if(!cell || !cell.classList) return false;
                if(cell.classList.contains('sj-group-row-actions-cell')) return true;
                return String(cell.dataset.manageColKey || '').trim() === '__sj_group_actions__';
            }) || null;
            if(middleCell){
                middleCell.colSpan = middleSpan;
                toggleGroupedCellHide(middleCell, !middleVisible);
            }
            if(actionsCell && headerCells[lastIdx]){
                stampManagedCellColumnKey(actionsCell, headerCells[lastIdx]);
                toggleGroupedCellHide(actionsCell, managedColumnHiddenAtIndex(state, headerCells, lastIdx));
            }
        });
    }

    function getManagedBodyHeaderCells(state){
        const row = state && state.table && state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        return row ? Array.from(row.cells || []) : [];
    }

    function getManagedDetachedHeaderCells(state){
        const row = state && state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows && state.headerTable.tHead.rows[0];
        if(row) return Array.from(row.cells || []);
        return getManagedBodyHeaderCells(state);
    }

    function syncManagedColumnVisibilitySlots(state){
        if(!state || !state.table) return;
        if(Array.isArray(state.columnOrder) && state.columnOrder.length){
            applyColumnOrder(state);
            syncManagedColgroupOrder(state);
        }
        const bodyHeaderCells = getManagedBodyHeaderCells(state);
        if(!bodyHeaderCells.length) return;
        state.headerCount = bodyHeaderCells.length;

        Array.from(state.table.rows || []).forEach((row) => {
            applyManagedRowColumnVisibilityByIndex(row, state, bodyHeaderCells);
        });
        if(state.headerTable){
            const detachedHeaderCells = getManagedDetachedHeaderCells(state);
            Array.from(state.headerTable.rows || []).forEach((row) => {
                applyManagedRowColumnVisibilityByIndex(row, state, detachedHeaderCells);
            });
            syncGroupedAggregateRowColumnLayout(state, bodyHeaderCells);
        } else {
            syncGroupedAggregateRowColumnLayout(state, bodyHeaderCells);
        }
        syncManagedColgroupSlotVisibility(state);
        if(state.headerTable){
            syncManagedHeaderColgroupFromMainTable(state);
        }
        applyPinnedColumns(state);
    }

    /** 字段显示勾选变更：仅同步可见性/冻结，避免全量重算列宽 */
    function applyColumnVisibilityChange(state){
        applyColumnVisibility(state);
        applyPinnedColumns(state, { force: true });
        syncManagedTableTotalWidth(state);
        syncTopScroll(state);
        if(!state || !state.headerTable) return;
        window.requestAnimationFrame(() => {
            if(!state || !state.table) return;
            syncManagedColumnVisibilitySlots(state);
            syncManagedTableTotalWidth(state);
            syncTopScroll(state);
        });
    }

    function applyColumnVisibility(state){
        const headerMeta = getHeaderMeta(state.table);
        if(headerMeta.length){
            state.headerCount = headerMeta.length;
            ensureManagedColumnKeys(state, headerMeta);
        }
        if(Array.isArray(state.columnOrder) && state.columnOrder.length){
            applyColumnOrder(state);
            syncManagedColgroupOrder(state);
        }
        syncManagedColumnVisibilitySlots(state);
        if(!state.light && state.headerTable){
            syncDetachedHeader(state);
            const bodyHeaderCells = getManagedBodyHeaderCells(state);
            if(bodyHeaderCells.length){
                const detachedHeaderCells = getManagedDetachedHeaderCells(state);
                Array.from(state.headerTable.rows || []).forEach((row) => {
                    applyManagedRowColumnVisibilityByIndex(row, state, detachedHeaderCells);
                });
                syncManagedHeaderColgroupFromMainTable(state);
                syncGroupedAggregateRowColumnLayout(state, bodyHeaderCells);
            }
            ensureResizeHandles(state);
        }
    }

    function syncManagedHeaderColgroupFromMainTable(state){
        if(!state || !state.table || !state.headerTable) return;
        const srcColgroup = state.table.querySelector('colgroup');
        const dstColgroup = state.headerTable.querySelector('colgroup');
        if(!srcColgroup || !dstColgroup) return;
        const srcCols = Array.from(srcColgroup.children || []).filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        const dstCols = Array.from(dstColgroup.children || []).filter(node => node && String(node.tagName || '').toUpperCase() === 'COL');
        if(!srcCols.length || srcCols.length !== dstCols.length) return;
        for(let i = 0; i < srcCols.length; i += 1){
            const s = srcCols[i];
            const d = dstCols[i];
            d.style.width = s.style.width;
            d.style.minWidth = s.style.minWidth;
            d.style.maxWidth = s.style.maxWidth;
            d.style.visibility = s.style.visibility;
            const k = String(s.dataset.manageColKey || '').trim();
            if(k) d.dataset.manageColKey = k;
            const span = String(s.dataset.manageColSpan || '').trim();
            if(span) d.dataset.manageColSpan = span;
            if(s.getAttribute('data-pm-col-hidden') === '1'){
                d.setAttribute('data-pm-col-hidden', '1');
            } else {
                d.removeAttribute('data-pm-col-hidden');
            }
        }
    }

    function getPmTableColResizeMin(state){
        const raw = Number(state && state.table && state.table.dataset && state.table.dataset.pmColResizeMin);
        return Number.isFinite(raw) && raw >= 1 ? raw : 36;
    }

    function shouldPmTableLockColWidth(state){
        /* 列宽仅由 colgroup 控制；锁定 td/th 的 min/max 会导致表头与表体错位（表体常含 input 等撑宽元素） */
        return false;
    }

    function clearManagedCellInlineColumnSize(cell){
        if(!cell) return;
        cell.style.width = '';
        cell.style.minWidth = '';
        cell.style.maxWidth = '';
    }

    /** 为各 col 写入 min-width，避免调整其它列时 table 总宽短暂不一致导致列被压窄 */
    function syncManagedColgroupMinWidths(state){
        if(!state || !state.table) return;
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!headerRow) return;
        Array.from(headerRow.cells || []).forEach((cell) => {
            const key = String(cell.dataset.manageColKey || '').trim();
            if(!key || isManagedColumnSlotHidden(state, key, cell)) return;
            const colMin = getManagedColumnEffectiveMinWidth(state, key, cell);
            resolveManagedColgroupColsForKey(state, key).forEach((col) => {
                if(String(col.getAttribute('data-pm-col-hidden') || '') === '1') return;
                const cur = parseColWidthPx(col.style.width) || colMin;
                applyManagedColPixelWidth(col, Math.max(colMin, cur), colMin);
            });
        });
        syncManagedHeaderColgroupFromMainTable(state);
    }

    function scheduleLiveResizeColSync(state){
        if(!state) return;
        /* 总宽须与 colgroup 同步更新，否则 table-layout:fixed 会按比例压窄其它列（如图片列） */
        syncManagedColgroupMinWidths(state);
        syncManagedTableTotalWidth(state);
        if(state.liveResizeSyncScheduled) return;
        state.liveResizeSyncScheduled = true;
        window.requestAnimationFrame(() => {
            state.liveResizeSyncScheduled = false;
            if(!state || !state.table) return;
            syncTopScroll(state);
        });
    }

    function applyColumnWidthToDomForKey(state, columnKey, width, options){
        ensureManagedTableColgroup(state);
        const columnKeyStr = String(columnKey || '').trim();
        const live = !!(options && options.live);
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        const headerCell = headerRow
            ? Array.from(headerRow.cells || []).find((cell) => String(cell.dataset.manageColKey || '').trim() === columnKeyStr)
            : null;
        if(isManagedColumnSlotHidden(state, columnKeyStr, headerCell)){
            const matchedHidden = resolveManagedColgroupColsForKey(state, columnKeyStr);
            matchedHidden.forEach((node) => setManagedColHiddenState(node, true));
            if(live) scheduleLiveResizeColSync(state);
            else {
                syncManagedHeaderColgroupFromMainTable(state);
                syncManagedTableTotalWidth(state);
            }
            return;
        }

        const minColWidth = getManagedColumnEffectiveMinWidth(state, columnKeyStr, headerCell);
        let appliedWidth = clampManagedColumnWidth(state, columnKeyStr, width);
        if(columnKeyStr === '__sj_agg__') appliedWidth = Math.min(28, Math.max(20, appliedWidth));
        const matchedCols = resolveManagedColgroupColsForKey(state, columnKeyStr);

        if(matchedCols.length){
            const spanHint = Math.max(
                1,
                ...matchedCols.map(col => Math.max(1, Number(col.dataset.manageColSpan || 1) || 1))
            );
            const span = Math.max(1, Math.min(spanHint, matchedCols.length));
            const perColWidth = Math.max(minColWidth, Math.round(appliedWidth / span));
            matchedCols.forEach(node => {
                applyManagedColPixelWidth(node, perColWidth, minColWidth);
            });
        } else if(!live) {
            applyManagedColumnWidthToCells(state, columnKey, appliedWidth);
        }

        /* 有 colgroup 时清除 td/th 内联列宽，避免与 col 冲突；拖拽过程中跳过以减轻卡顿 */
        if(matchedCols.length && !live){
            const clearKeyOnCell = (cell) => {
                if(String(cell.dataset.manageColKey || '').trim() !== columnKey) return;
                clearManagedCellInlineColumnSize(cell);
            };
            Array.from(state.table.rows || []).forEach(row => {
                if((row.cells || []).length !== state.headerCount) return;
                Array.from(row.cells).forEach(clearKeyOnCell);
            });
            if(state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows.length){
                const headerRowLive = state.headerTable.tHead.rows[0];
                Array.from(headerRowLive.cells || []).forEach(clearKeyOnCell);
            }
        }

        if(live) scheduleLiveResizeColSync(state);
        else {
            syncManagedHeaderColgroupFromMainTable(state);
            syncManagedTableTotalWidth(state);
        }

        if(!live && columnKey === '__sj_agg__' && state.table && state.table.tBodies && state.table.tBodies[0]){
            state.table.tBodies[0].querySelectorAll('td.sj-agg-toggle-cell').forEach((cell) => {
                clearManagedCellInlineColumnSize(cell);
            });
        }
    }

    function resolveColumnWidthKeysToApply(state, primaryKey){
        const columnKey = String(primaryKey || '').trim();
        if(!columnKey) return [];
        if(!state || !state.table || !isPmMonthColWidthSyncTable(state.table)) return [columnKey];
        if(!isPmMonthColKeyForWidthSync(state.table, columnKey)) return [columnKey];
        const monthKeys = collectPmMonthColKeysForWidthSync(state);
        return monthKeys.length ? monthKeys.slice() : [columnKey];
    }

    function setColumnWidthByKey(state, key, widthPx, options){
        const columnKey = String(key || '').trim();
        const enforceMin = !(options && options.enforceMin === false);
        const width = enforceMin
            ? clampManagedColumnWidth(state, columnKey, widthPx)
            : Math.max(1, Math.round(Number(widthPx) || 0));
        if(!columnKey || columnKey === PM_MONTH_COL_GROUP_WIDTH_KEY) return;
        const keysToApply = resolveColumnWidthKeysToApply(state, columnKey);
        keysToApply.forEach((k) => {
            state.columnWidths[k] = width;
        });
        keysToApply.forEach((k) => {
            applyColumnWidthToDomForKey(state, k, width, options);
        });
    }

    function clearAllManagedCellInlineSizes(state){
        if(!state || !state.table) return;
        const scrub = (cell) => clearManagedCellInlineColumnSize(cell);
        Array.from(state.table.rows || []).forEach((row) => {
            Array.from(row.cells || []).forEach(scrub);
        });
        if(state.headerTable && state.headerTable.tHead){
            Array.from(state.headerTable.tHead.rows || []).forEach((row) => {
                Array.from(row.cells || []).forEach(scrub);
            });
        }
    }

    function applyColumnWidths(state, options){
        ensureManagedTableColgroup(state);
        const enforceMin = !(options && options.enforceMin === false);
        clearAllManagedCellInlineSizes(state);
        const widths = state.columnWidths || {};
        const visible = state.visibleColumns || null;
        let widthsChanged = false;
        Object.keys(widths).forEach(key => {
            if(String(key) === PM_MONTH_COL_GROUP_WIDTH_KEY) return;
            if(visible && !visible.has(String(key || '').trim())) return;
            const prev = Number(widths[key]);
            const next = enforceMin ? clampManagedColumnWidth(state, key, prev) : Math.max(1, Math.round(prev) || 0);
            if(next !== prev) widthsChanged = true;
            setColumnWidthByKey(state, key, next, { enforceMin });
        });
        if(widthsChanged && enforceMin) persistColumnWidths(state);
        syncManagedColgroupSlotVisibility(state);
        syncSjAggToggleColumnCssVar(state);
    }

    /** 拖拽其它列后校正各列不低于业务最小宽（如图片列 68px） */
    function enforceManagedColumnWidthFloors(state){
        if(!state || !state.table) return false;
        ensureManagedTableColgroup(state);
        const headerRow = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!headerRow) return false;
        let changed = false;
        Array.from(headerRow.cells || []).forEach((cell) => {
            const key = String(cell.dataset.manageColKey || '').trim();
            if(!key || isManagedColumnSlotHidden(state, key, cell)) return;
            const colMin = getManagedColumnEffectiveMinWidth(state, key, cell);
            const cols = resolveManagedColgroupColsForKey(state, key);
            if(!cols.length) return;
            let targetW = 0;
            cols.forEach((col) => {
                if(String(col.getAttribute('data-pm-col-hidden') || '') === '1') return;
                targetW += parseColWidthPx(col.style.width) || colMin;
            });
            if(!targetW) targetW = colMin;
            targetW = clampManagedColumnWidth(state, key, targetW);
            const prevStored = Number((state.columnWidths || {})[key]);
            if(!Number.isFinite(prevStored) || prevStored !== targetW){
                state.columnWidths[key] = targetW;
                changed = true;
            }
            const span = Math.max(1, cols.length);
            const perCol = Math.max(colMin, Math.round(targetW / span));
            cols.forEach((col) => {
                const cur = parseColWidthPx(col.style.width) || 0;
                const curMin = parseColWidthPx(col.style.minWidth) || 0;
                if(cur !== perCol || curMin !== colMin) changed = true;
                applyManagedColPixelWidth(col, perCol, colMin);
            });
        });
        if(changed){
            persistColumnWidths(state);
            syncManagedHeaderColgroupFromMainTable(state);
            syncManagedTableTotalWidth(state);
        }
        return changed;
    }

    function ensureResizeHandles(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow || headerRow.cells.length !== state.headerCount) return;

        Array.from(headerRow.cells).forEach(cell => {
            const key = String(cell.dataset.manageColKey || '').trim();
            if(isManagedColumnSlotHidden(state, key, cell)) return;
            if(cell.querySelector('.pm-col-resizer')) return;
            const handle = document.createElement('span');
            handle.className = 'pm-col-resizer';
            handle.addEventListener('mousedown', (event) => {
                event.preventDefault();
                event.stopPropagation();
                const resizeKey = String(cell.dataset.manageColKey || '').trim();
                activeResizeState = {
                    state,
                    key: resizeKey,
                    startX: event.clientX,
                    startWidth: cell.getBoundingClientRect().width,
                    resizeMinPx: getManagedColumnResizeMin(state, resizeKey),
                    handle,
                    hasMoved: false
                };
                handle.classList.add('is-active');
                document.body.style.cursor = 'col-resize';
                document.body.style.userSelect = 'none';
            });
            cell.appendChild(handle);
        });
    }

    function positionAppAnchorPanel(trigger, panel, options){
        if(!trigger || !panel) return;
        const opts = options || {};
        const gap = opts.gap != null ? opts.gap : 8;
        const minMargin = opts.minMargin != null ? opts.minMargin : 8;
        const align = opts.align === 'right' ? 'right' : 'left';
        const allowFlip = opts.allowFlip !== false;
        const measureDisplay = opts.measureDisplay || 'grid';

        panel.style.visibility = 'hidden';
        panel.style.display = measureDisplay;

        const triggerRect = trigger.getBoundingClientRect();
        const panelRect = panel.getBoundingClientRect();
        const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;

        let left = align === 'right' ? (triggerRect.right - panelRect.width) : triggerRect.left;
        let top = triggerRect.bottom + gap;

        if(allowFlip){
            const spaceBelow = viewportHeight - triggerRect.bottom - gap;
            const spaceAbove = triggerRect.top - gap;
            if(panelRect.height > spaceBelow - minMargin && spaceAbove > spaceBelow && spaceAbove >= panelRect.height + minMargin){
                top = triggerRect.top - panelRect.height - gap;
            }
        }

        left = Math.max(minMargin, Math.min(left, viewportWidth - panelRect.width - minMargin));
        top = Math.max(minMargin, Math.min(top, viewportHeight - panelRect.height - minMargin));

        panel.style.left = `${left}px`;
        panel.style.top = `${top}px`;
        panel.style.visibility = 'visible';
    }

    function repositionColumnsPanel(state){
        if(!state || !state.columnPanel.classList.contains('open')) return;
        const alignLeft = state.headerCount <= 5;
        positionAppAnchorPanel(state.columnsTrigger, state.columnPanel, {
            gap: 8,
            align: alignLeft ? 'left' : 'right',
            measureDisplay: 'grid'
        });
    }

    function repositionResetMenu(state){
        if(!state || !state.resetWrap || !state.resetMenu || !state.resetBtn) return;
        if(!state.resetWrap.classList.contains('is-open') && !state.resetMenu.classList.contains('is-open')) return;
        positionAppAnchorPanel(state.resetBtn, state.resetMenu, {
            gap: 6,
            align: 'left',
            measureDisplay: 'grid'
        });
        state.resetMenu.classList.add('is-open');
        state.resetMenu.style.pointerEvents = 'auto';
    }

    function closeColumnsPanel(state){
        if(!state) return;
        state.columnPanel.classList.remove('open');
        state.columnPanel.style.visibility = 'hidden';
        state.columnPanel.style.display = 'none';
        state.columnPanel.style.pointerEvents = 'none';
        state.columnsTrigger.setAttribute('aria-expanded', 'false');
        if(activeColumnsPanelState === state) activeColumnsPanelState = null;
    }

    function openColumnsPanel(state){
        if(activeColumnsPanelState && activeColumnsPanelState !== state) {
            closeColumnsPanel(activeColumnsPanelState);
        }
        closeAllResetMenus();
        state.columnPanel.classList.add('open');
        state.columnPanel.style.pointerEvents = 'auto';
        state.columnsTrigger.setAttribute('aria-expanded', 'true');
        activeColumnsPanelState = state;
        repositionColumnsPanel(state);
    }

    function hideResetMenuPanel(menu){
        if(!menu) return;
        menu.classList.remove('is-open');
        menu.style.visibility = 'hidden';
        menu.style.display = 'none';
        menu.style.pointerEvents = 'none';
    }

    function closeResetMenu(state){
        if(!state || !state.resetWrap) return;
        state.resetWrap.classList.remove('is-open');
        hideResetMenuPanel(state.resetMenu);
        if(activeResetMenuState === state) activeResetMenuState = null;
    }

    function closeAllResetMenus(exceptWrap){
        const keep = exceptWrap && exceptWrap.classList ? exceptWrap : null;
        managedTableState.forEach((state) => {
            if(keep && state.resetWrap === keep) return;
            closeResetMenu(state);
        });
        document.querySelectorAll('.pm-table-reset-group.is-open').forEach((wrap) => {
            if(keep && keep === wrap) return;
            wrap.classList.remove('is-open');
        });
        if(!keep){
            activeResetMenuState = null;
        } else if(activeResetMenuState && activeResetMenuState.resetWrap !== keep){
            activeResetMenuState = null;
        }
    }

    function clearColumnDragIndicator(state){
        if(!state || !state.columnPanel) return;
        state.columnPanel.querySelectorAll('.pm-table-columns-item').forEach(node => {
            node.classList.remove('is-drop-target', 'is-drop-before', 'is-drop-after');
        });
        state.dragPlacementNode = null;
    }

    function setColumnDragIndicator(state, item, before){
        if(!state || !item) return;
        const sameNode = state.dragPlacementNode === item;
        const sameBefore = !!(state.dragPlacement && state.dragPlacement.before) === !!before;
        if(sameNode && sameBefore) return;
        clearColumnDragIndicator(state);
        item.classList.add('is-drop-target');
        item.classList.add(before ? 'is-drop-before' : 'is-drop-after');
        state.dragPlacementNode = item;
    }

    function commitColumnPanelDrag(state, targetKey, before){
        const fromKey = String(state.dragOrigin || '').trim();
        const key = String(targetKey || '').trim();
        if(!fromKey || !key || fromKey === key) return;
        const fromIdx = state.columnOrder.indexOf(fromKey);
        let toIdx = state.columnOrder.indexOf(key);
        if(fromIdx < 0 || toIdx < 0) return;
        toIdx += before ? 0 : 1;
        if(fromIdx < toIdx) toIdx -= 1;
        if(fromIdx === toIdx) return;

        state.columnOrder.splice(fromIdx, 1);
        state.columnOrder.splice(toIdx, 0, fromKey);
        persistColumnOrder(state);

        window.requestAnimationFrame(() => {
            applyColumnOrder(state);
            applyColumnVisibility(state);
            syncDetachedHeader(state);
            applyPinnedColumns(state, { force: true });
            ensureSortableHeaders(state);
            ensureResizeHandles(state);
            refreshSortHeaderUi(state);
            syncTopScroll(state);
            renderColumnPanel(state);
        });
    }

    function renderColumnPanel(state){
        const panel = state.columnPanel;
        panel.innerHTML = '';

        state.columnOrder.forEach((key, orderIdx) => {
            const header = state.headers.find(h => String(h.key || '').trim() === String(key || '').trim());
            if(!header) return;
            const k0 = String(key || '').trim();

            const item = document.createElement('label');
            item.className = 'pm-table-columns-item';
            item.draggable = true;
            item.dataset.columnKey = String(key || '').trim();

            const main = document.createElement('span');
            main.className = 'pm-table-columns-item-main';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            const isLocked = state.lockedColumns.has(String(key || '').trim());
            checkbox.checked = isLocked ? true : state.visibleColumns.has(String(key || '').trim());
            checkbox.disabled = isLocked;
            checkbox.addEventListener('change', () => {
                if(!checkbox.checked && state.visibleColumns.size <= 1){
                    checkbox.checked = true;
                    return;
                }
                if(isLocked){
                    checkbox.checked = true;
                    return;
                }
                if(checkbox.checked) state.visibleColumns.add(String(key || '').trim());
                else state.visibleColumns.delete(String(key || '').trim());
                persistColumns(state);
                applyColumnVisibilityChange(state);
                ensureSortableHeaders(state);
                ensureResizeHandles(state);
                refreshSortHeaderUi(state);
            });

            const text = document.createElement('span');
            text.textContent = header.label;
            if(isLocked) text.title = k0 === '__sj_agg__' ? '该列为汇总收起列，不能隐藏' : '该列为多选/选择列，不能隐藏';
            main.appendChild(checkbox);
            main.appendChild(text);

            const pin = document.createElement('button');
            pin.type = 'button';
            pin.className = 'pm-table-columns-pin';
            const frozenLeadOnly = String(state.table.dataset.pmFrozenLeadOnly || '') === '1';
            const pinnedNow = !!(state.pinnedColumns && state.pinnedColumns.has(k0)) || isLocked;
            pin.textContent = '';
            pin.setAttribute('aria-label', pinnedNow ? '取消冻结' : '冻结到左侧');
            pin.title = isLocked
                ? (k0 === '__sj_agg__' ? '收起列默认冻结' : '复选列默认冻结')
                : (frozenLeadOnly ? '该表仅冻结复选框与展开列' : (pinnedNow ? '点击取消冻结' : '点击冻结到左侧'));
            pin.disabled = isLocked || frozenLeadOnly;
            pin.classList.toggle('is-active', pinnedNow);
            pin.addEventListener('click', (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                const k = String(key || '').trim();
                if(!k || (state.lockedColumns && state.lockedColumns.has(k))) return;
                if(frozenLeadOnly) return;
                state.pinnedColumns = state.pinnedColumns || new Set();
                const willPin = !state.pinnedColumns.has(k);
                if(willPin){
                    state.pinnedColumns.add(k);
                    // move into pinned region end
                    const pinnedAll = new Set();
                    (state.lockedColumns || new Set()).forEach(v => pinnedAll.add(String(v || '').trim()));
                    (state.pinnedColumns || new Set()).forEach(v => pinnedAll.add(String(v || '').trim()));
                    const pinnedOrder = (state.columnOrder || []).filter(x => pinnedAll.has(String(x || '').trim()) && String(x || '').trim() !== k);
                    const toIdx = pinnedOrder.length;
                    const fromIdx = state.columnOrder.indexOf(k);
                    if(fromIdx >= 0){
                        state.columnOrder.splice(fromIdx, 1);
                        state.columnOrder.splice(Math.min(Math.max(0, toIdx), state.columnOrder.length), 0, k);
                        persistColumnOrder(state);
                    }
                } else {
                    state.pinnedColumns.delete(k);
                }
                (state.lockedColumns || new Set()).forEach(v => state.pinnedColumns.add(String(v || '').trim()));
                persistPinnedColumns(state);
                window.requestAnimationFrame(() => {
                    applyColumnOrder(state);
                    applyColumnVisibility(state);
                    syncDetachedHeader(state);
                    applyPinnedColumns(state, { force: true });
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    syncTopScroll(state);
                    renderColumnPanel(state);
                });
            });

            const drag = document.createElement('span');
            drag.className = 'pm-table-columns-item-drag';
            drag.textContent = '⋮⋮';

            item.appendChild(main);
            item.appendChild(pin);
            item.appendChild(drag);

            item.addEventListener('dragstart', () => {
                state.dragOrigin = String(key || '').trim();
                state.dragPlacement = null;
                state.dragPlacementNode = null;
                item.classList.add('is-dragging');
            });
            item.addEventListener('dragend', () => {
                state.dragOrigin = null;
                state.dragPlacement = null;
                clearColumnDragIndicator(state);
                panel.querySelectorAll('.pm-table-columns-item').forEach(node => node.classList.remove('is-dragging'));
            });
            item.addEventListener('dragover', (event) => {
                event.preventDefault();
                if(event.dataTransfer) event.dataTransfer.dropEffect = 'move';
                const rect = item.getBoundingClientRect();
                const before = event.clientY < (rect.top + rect.height / 2);
                state.dragPlacement = { key: String(key || '').trim(), before };
                setColumnDragIndicator(state, item, before);
            });
            item.addEventListener('drop', (event) => {
                event.preventDefault();
                const placement = state.dragPlacement && state.dragPlacement.key === String(key || '').trim() ? state.dragPlacement : { key: String(key || '').trim(), before: false };
                commitColumnPanelDrag(state, String(key || '').trim(), placement.before);
            });

            panel.appendChild(item);
            if(orderIdx === state.columnOrder.length - 1){
                item.classList.remove('is-drop-target');
            }
        });
    }

    function applyPagination(state){
        if(!state || !state.info || !state.pageCurrent || !state.prevBtn || !state.nextBtn) return;
        const allRows = getDataRows(state);
        if(tableSkipsClientPagination(state)){
            allRows.forEach((row) => {
                if(String(row.dataset.pmFilterHidden || '0') === '1') row.style.display = 'none';
                else row.style.display = '';
            });
            return;
        }
        const rows = allRows.filter(row => String(row.dataset.pmFilterHidden || '0') !== '1');
        const isServerManaged = String(state.table.dataset.serverPaginationMode || '').toLowerCase() === 'server'
            || state.table.dataset.serverPaginationMode === '1';
        const serverTotal = Number(state.table.dataset.serverTotalRows || '0');
        const serverPageSize = Math.max(1, Number(state.table.dataset.serverPageSize || state.pageSize || '50') || 50);
        const serverCurrentPage = Math.max(1, Number(state.table.dataset.serverCurrentPage || state.currentPage || '1') || 1);
        const total = isServerManaged && Number.isFinite(serverTotal) ? Math.max(0, serverTotal) : rows.length;
        if(!total){
            state.currentPage = 1;
            state.info.textContent = '共 0 条';
            state.pageCurrent.textContent = '1 / 1';
            state.prevBtn.disabled = true;
            state.nextBtn.disabled = true;
            allRows.forEach((row) => {
                row.style.display = 'none';
            });
            clearManagedBatchCheckboxesOnHiddenRows(state);
            syncGroupedAggregateRowsAfterFilter(state);
            return;
        }

        if(isServerManaged){
            state.pageSize = serverPageSize;
            state.currentPage = serverCurrentPage;
            const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
            state.currentPage = Math.max(1, Math.min(state.currentPage, totalPages));
            if(state.pageSizeSelect && String(state.pageSizeSelect.value || '') !== String(state.pageSize)){
                state.pageSizeSelect.value = String(state.pageSize);
            }
            rows.forEach((row) => {
                row.style.display = '';
            });
            allRows.forEach((row) => {
                if(String(row.dataset.pmFilterHidden || '0') === '1') row.style.display = 'none';
            });
            const start = Math.min((state.currentPage - 1) * state.pageSize + 1, total);
            const end = Math.min(state.currentPage * state.pageSize, total);
            state.info.textContent = `显示 ${start}-${end} / 共 ${total} 条`;
            state.pageCurrent.textContent = `${state.currentPage} / ${totalPages}`;
            state.prevBtn.disabled = state.currentPage <= 1;
            state.nextBtn.disabled = state.currentPage >= totalPages;
            clearManagedBatchCheckboxesOnHiddenRows(state);
            syncGroupedAggregateRowsAfterFilter(state);
            return;
        }

        const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
        state.currentPage = Math.max(1, Math.min(state.currentPage, totalPages));
        const start = (state.currentPage - 1) * state.pageSize;
        const end = Math.min(start + state.pageSize, total);

        allRows.forEach((row) => {
            row.style.display = 'none';
        });
        rows.forEach((row, idx) => {
            row.style.display = (idx >= start && idx < end) ? '' : 'none';
        });

        state.info.textContent = `显示 ${start + 1}-${end} / 共 ${total} 条`;
        state.pageCurrent.textContent = `${state.currentPage} / ${totalPages}`;
        state.prevBtn.disabled = state.currentPage <= 1;
        state.nextBtn.disabled = state.currentPage >= totalPages;
        clearManagedBatchCheckboxesOnHiddenRows(state);
        syncGroupedAggregateRowsAfterFilter(state);
    }

    function isMultiSelectColumn(headerCell, label){
        if(!headerCell) return false;
        if(headerCell.querySelector('input[type="checkbox"]')) return true;
        const t = String(label || '').trim();
        if(!t) return false;
        return /多选|选择|勾选/.test(t);
    }

    /** 复选列或业务声明的列（如汇总三角列），冻结窗格中不可取消 */
    function isLockedLayoutColumn(headerCell, label){
        if(!headerCell) return false;
        if(headerCell.classList && headerCell.classList.contains('sj-agg-toggle-col')) return true;
        if(String(headerCell.dataset && headerCell.dataset.manageColKey || '').trim() === '__sj_agg__') return true;
        if(isMultiSelectColumn(headerCell, label)) return true;
        return String(headerCell.dataset && headerCell.dataset.manageColLocked || '').trim() === '1';
    }

    /** 汇总展开列、表头全选列：托管表不在表头展示列排序箭头与列筛选入口 */
    function isManagedTableNoSortNoFilterHeaderCell(headerCell){
        if(!headerCell) return false;
        if(headerCell.classList && headerCell.classList.contains('sj-agg-toggle-col')) return true;
        if(String(headerCell.dataset && headerCell.dataset.manageColKey || '').trim() === '__sj_agg__') return true;
        if(headerCell.querySelector('input[type="checkbox"]')) return true;
        return false;
    }

    /** 汇总收起列、全选列等必须固定在表格最前，且不受持久化顺序漂移影响 */
    function canonicalLayoutLeadKeysFromMeta(headerMeta, validKeySet){
        const unique = new Set();
        (Array.isArray(headerMeta) ? headerMeta : []).forEach((meta) => {
            const k = String(meta && meta.key || '').trim();
            if(!k || !validKeySet.has(k)) return;
            if(!isLockedLayoutColumn(meta.cell, meta.label)) return;
            unique.add(k);
        });
        const isLeadCheckboxKey = (k) => {
            const kk = String(k || '').trim();
            if(!kk || kk === '__sj_agg__') return false;
            const meta = (Array.isArray(headerMeta) ? headerMeta : []).find(m => String(m && m.key || '').trim() === kk);
            return !!(meta && meta.cell && meta.cell.querySelector('input[type="checkbox"]'));
        };
        return [...unique].sort((a, b) => {
            const ra = isLeadCheckboxKey(a) ? 0 : (a === '__sj_agg__' ? 1 : 2);
            const rb = isLeadCheckboxKey(b) ? 0 : (b === '__sj_agg__' ? 1 : 2);
            if(ra !== rb) return ra - rb;
            return String(a).localeCompare(String(b), 'en');
        });
    }

    /**
     * 将持久化列顺序与当前表头字段对齐：布局锚点列（收起三角、复选框等）始终排在最前，
     * 其余列保持持久化中的相对顺序，未出现的键按 validKeysArray 顺序补全。
     * 解决：持久化顺序把锚点列挤到末尾后 applyColumnOrder 污染 thead，导致重置时读 DOM 仍错位。
     */
    function normalizeManagedTableColumnOrder(persistedKeys, validKeysArray, headerMeta){
        const validKeys = (Array.isArray(validKeysArray) ? validKeysArray : []).map((k) => String(k || '').trim()).filter(Boolean);
        const validSet = new Set(validKeys);
        const seen = new Set();
        const persistUnique = [];
        (Array.isArray(persistedKeys) ? persistedKeys : []).forEach((k) => {
            const kk = String(k || '').trim();
            if(!validSet.has(kk) || seen.has(kk)) return;
            seen.add(kk);
            persistUnique.push(kk);
        });
        const leadKeys = canonicalLayoutLeadKeysFromMeta(headerMeta, validSet);
        const leadSet = new Set(leadKeys);
        const out = leadKeys.slice();
        persistUnique.forEach((k) => {
            if(!leadSet.has(k) && !out.includes(k)) out.push(k);
        });
        validKeys.forEach((k) => {
            if(!out.includes(k)) out.push(k);
        });
        const table = headerMeta && headerMeta[0] && headerMeta[0].cell && headerMeta[0].cell.closest
            ? headerMeta[0].cell.closest('table')
            : null;
        const seqHint = table ? String(table.dataset.pmColumnSequenceAfter || '').trim() : '';
        if(seqHint){
            const splitAt = seqHint.indexOf(':');
            if(splitAt > 0){
                const anchor = seqHint.slice(0, splitAt).trim();
                const follow = seqHint.slice(splitAt + 1).split(',').map((k) => k.trim()).filter(Boolean);
                return enforceColumnSequenceAfter(out, anchor, follow);
            }
        }
        return out;
    }

    /** 父体/分组行等需与表头「收起」列同宽：优先用持久化列宽，避免 display:none 时测到 0 宽污染 CSS 变量 */
    function syncSjAggToggleColumnCssVar(state){
        if(!state || !state.table || state.light) return;
        const hr = state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        if(!hr) return;
        let th = null;
        Array.from(hr.cells || []).forEach((cell) => {
            if(String(cell.dataset.manageColKey || '').trim() === '__sj_agg__') th = cell;
        });
        if(!th) th = hr.querySelector('th.sj-agg-toggle-col');
        if(!th) return;

        const stored = Number((state.columnWidths || {})['__sj_agg__']);
        let w = 0;
        if(Number.isFinite(stored) && stored > 0){
            w = Math.round(stored);
        } else {
            let cs = null;
            try {
                cs = window.getComputedStyle(th);
            } catch (_e) {
                cs = null;
            }
            if(!cs || cs.display === 'none' || cs.visibility === 'hidden'){
                try {
                    state.table.style.removeProperty('--sj-agg-toggle-w');
                } catch (_e2) {
                }
                return;
            }
            w = Math.max(1, Math.round(th.getBoundingClientRect().width || 0));
        }
        if(th.classList && th.classList.contains('sj-agg-toggle-col') && w > 0){
            w = Math.min(w, 28);
        }
        try {
            state.table.style.setProperty('--sj-agg-toggle-w', `${w}px`);
        } catch (_e) {
        }
    }

    function readManagedCellDisplayText(cell){
        if(!cell) return '';

        const explicitDisplay = String(
            cell.getAttribute('data-display-value')
            || cell.dataset.displayValue
            || cell.getAttribute('data-display-text')
            || cell.dataset.displayText
            || ''
        ).trim();
        if(explicitDisplay) return explicitDisplay;

        const input = cell.querySelector('input:not([type="hidden"])');
        if(input){
            const type = String(input.type || '').toLowerCase();
            if(type === 'checkbox' || type === 'radio') return input.checked ? '是' : '否';
            return String(input.value || '').trim();
        }

        const select = cell.querySelector('select');
        if(select){
            const option = select.options && select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
            return String(option ? (option.textContent || option.value || '') : (select.value || '')).trim();
        }

        const textarea = cell.querySelector('textarea');
        if(textarea) return String(textarea.value || '').trim();

        const activePill = cell.querySelector('.status-pill.is-active');
        if(activePill){
            return String(activePill.textContent || activePill.getAttribute('data-value') || '').trim();
        }

        const segment = cell.querySelector('.status-segment');
        if(segment){
            const value = String(segment.getAttribute('data-value') || segment.dataset.value || '').trim();
            if(value){
                const matched = Array.from(segment.querySelectorAll('.status-pill')).find(btn => String(btn.getAttribute('data-value') || btn.dataset.value || '') === value);
                if(matched) return String(matched.textContent || '').trim();
                return value;
            }
        }

        const pressedButton = cell.querySelector('button[aria-pressed="true"]');
        if(pressedButton){
            return String(pressedButton.textContent || pressedButton.getAttribute('data-value') || '').trim();
        }

        return String(cell.textContent || '').replace(/[↕↑↓▲▼▴▾]/g, ' ').replace(/\s+/g, ' ').trim();
    }

    function readCellFilterText(cell){
        return readManagedCellDisplayText(cell);
    }

    function getRowCellMap(row){
        if(!row || !row.cells) return null;
        if(row._pmCellKeyMap && row._pmCellKeyMap.size > 0) return row._pmCellKeyMap;
        const map = new Map();
        Array.from(row.cells || []).forEach((cell) => {
            const key = String(cell.dataset.manageColKey || '').trim();
            if(key && !map.has(key)) map.set(key, cell);
        });
        row._pmCellKeyMap = map.size > 0 ? map : null;
        return map;
    }

    function getRowCellByKey(row, columnKey){
        if(!row || !row.cells) return null;
        const key = String(columnKey || '').trim();
        if(!key) return null;
        const map = getRowCellMap(row);
        if(map && map.has(key)) return map.get(key);
        for(const cell of Array.from(row.cells || [])){
            if(String(cell.dataset.manageColKey || '').trim() === key) return cell;
        }
        return null;
    }

    /** 行是否通过列筛选；excludeColumnKey 为当前正在编辑的列时跳过该列条件（用于联动可选项） */
    function rowPassesManagedColumnFilters(row, filters, excludeColumnKey){
        if(!row || !filters || typeof filters !== 'object') return true;
        const skipKey = String(excludeColumnKey || '').trim();
        for(const key of Object.keys(filters)){
            const colKey = String(key || '').trim();
            if(!colKey || colKey === skipKey) continue;
            const filter = filters[key] || {};
            const query = String(filter.query || '').trim();
            const exact = !!filter.exact;
            const selected = Array.isArray(filter.selected) ? filter.selected.map(v => String(v)) : [];
            if(!query && !selected.length) continue;
            const cell = getRowCellByKey(row, colKey);
            const value = String(readCellFilterText(cell) || '');
            if(selected.length && !selected.includes(value)) return false;
            if(query){
                if(exact){
                    if(value !== query) return false;
                } else if(!value.toLowerCase().includes(query.toLowerCase())) {
                    return false;
                }
            }
        }
        return true;
    }

    function columnFilterScopeSignature(filters, excludeColumnKey){
        const skipKey = String(excludeColumnKey || '').trim();
        return Object.keys(filters || {}).sort().map((key) => {
            const colKey = String(key || '').trim();
            if(!colKey || colKey === skipKey) return '';
            const filter = filters[key] || {};
            const query = String(filter.query || '').trim();
            const selected = Array.isArray(filter.selected) ? filter.selected.slice().sort().join('\x1f') : '';
            if(!query && !selected) return '';
            return `${colKey}\x1e${query}\x1e${filter.exact ? 1 : 0}\x1e${selected}`;
        }).filter(Boolean).join('\x1d');
    }

    function collectManagedColumnFilterOptions(state, columnKey, query, exact, limit, filtersSnapshot){
        const rows = getDataRows(state);
        const filters = (filtersSnapshot && typeof filtersSnapshot === 'object') ? filtersSnapshot : {};
        const excludeKey = String(columnKey || '').trim();
        const q = String(query || '').trim().toLowerCase();
        const isExact = !!exact;
        const counts = new Map();
        rows.forEach(row => {
            if(!rowPassesManagedColumnFilters(row, filters, excludeKey)) return;
            const cell = getRowCellByKey(row, columnKey);
            const value = readCellFilterText(cell);
            const text = String(value === null || value === undefined ? '' : value).trim();
            if(q){
                if(isExact){
                    if(text !== String(query || '').trim()) return;
                } else if(!text.toLowerCase().includes(q)) {
                    return;
                }
            }
            counts.set(text, (counts.get(text) || 0) + 1);
        });
        return Array.from(counts.entries())
            .map(([value, count]) => ({ value, label: value === '' ? '[空]' : value, count }))
            .sort((a, b) => {
                if((b.count || 0) !== (a.count || 0)) return (b.count || 0) - (a.count || 0);
                return String(a.label || '').localeCompare(String(b.label || ''), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
            })
            .slice(0, Math.max(1, Number(limit || 120) || 120));
    }

    function snapshotHasActiveColumnFilters(snapshot){
        if(!snapshot || typeof snapshot !== 'object') return false;
        return Object.keys(snapshot).some(key => isColumnFilterActive(snapshot[key]));
    }

    function reapplyManagedColumnFiltersFromHandle(state){
        if(!state || !state.table) return;
        if(String(state.table.dataset.pmLightNoColumnFilter || '') === '1') return;
        const handle = state.columnFilterHandle
            || (state.table ? (columnFilterRegistry.get(state.table) || null) : null);
        if(!handle || typeof handle.getFilters !== 'function') return;
        const snapshot = handle.getFilters();
        if(!snapshotHasActiveColumnFilters(snapshot)) return;
        applyManagedColumnFilters(state, snapshot);
    }

    function pruneInvalidColumnFilterSelections(state){
        const handle = state.columnFilterHandle
            || (state.table ? (columnFilterRegistry.get(state.table) || null) : null);
        if(!handle || !handle.filters || typeof handle.filters.forEach !== 'function') return;
        const snapshot = columnFilterStateSnapshot(handle);
        handle.filters.forEach((filterState, colKey) => {
            if(!filterState || !Array.isArray(filterState.selected) || !filterState.selected.length) return;
            const opts = collectManagedColumnFilterOptions(state, colKey, '', false, 10000, snapshot);
            const allowed = new Set(opts.map((item) => String(item.value)));
            filterState.selected = filterState.selected.filter((v) => allowed.has(String(v)));
        });
    }

    function applyManagedColumnFilters(state, snapshot){
        const filters = snapshot || {};
        const rows = getDataRows(state);
        rows.forEach(row => {
            invalidatePmRowCellKeyMap(row);
            const pass = rowPassesManagedColumnFilters(row, filters, null);
            row.dataset.pmFilterHidden = pass ? '0' : '1';
        });
        const handle = state.columnFilterHandle
            || (state.table ? (columnFilterRegistry.get(state.table) || null) : null);
        if(handle && handle.optionCache && typeof handle.optionCache.clear === 'function'){
            handle.optionCache.clear();
        }
        pruneInvalidColumnFilterSelections(state);
        state.currentPage = 1;
        applyPagination(state);
        syncGroupedAggregateRowsAfterFilter(state);
        syncManagedBatchBar(state);
        if(state.table && !tableSkipsFilterPersist(state.table)){
            persistManagedColumnFilters(state.table, filters);
        }
        if(handle && typeof handle.refreshButtons === 'function'){
            handle.refreshButtons();
        }
    }

    function restoreManagedColumnFiltersFromStorageIfNeeded(state){
        if(!state || !state.table || tableSkipsFilterPersist(state.table)) return;
        if(String(state.table.dataset.pmLightNoColumnFilter || '') === '1') return;
        const handle = state.columnFilterHandle
            || (state.table ? (columnFilterRegistry.get(state.table) || null) : null);
        if(!handle || typeof handle.getFilters !== 'function' || typeof handle.setFilters !== 'function') return;
        const current = handle.getFilters();
        if(snapshotHasActiveColumnFilters(current)) return;
        const saved = readPersistedColumnFilters(state.table);
        if(!snapshotHasActiveColumnFilters(saved)) return;
        handle.setFilters(saved);
    }

    function clearAllManagedTableFilters(state){
        if(!state || !state.table) return;
        closeColumnFilterPopup();
        const handle = state.columnFilterHandle
            || (state.table ? (columnFilterRegistry.get(state.table) || null) : null);
        if(handle && typeof handle.setFilters === 'function'){
            handle.setFilters({});
        }
        applyManagedColumnFilters(state, {});
        clearPersistedFiltersForTable(state.table);
        const provider = resolveTableFilterProvider(state.table);
        if(provider && typeof provider.clear === 'function'){
            try { provider.clear(); } catch (_) {}
        } else if(provider && typeof provider.apply === 'function'){
            try { provider.apply({}, { source: 'clear' }); } catch (_) {}
        }
        state.table.dispatchEvent(new CustomEvent('pm-clear-page-filters', {
            bubbles: true,
            detail: { table: state.table }
        }));
        if(typeof showAppToast === 'function'){
            showAppToast('筛选已清除', false, 1200);
        }
    }

    function ensureManagedTableColumnFilter(state){
        if(!state || !state.table || !state.table.tHead || !state.table.tHead.rows || !state.table.tHead.rows.length) return;
        const serverPagination = String(state.table.dataset.serverPaginationMode || '').toLowerCase() === 'server'
            || state.table.dataset.serverPaginationMode === '1';
        const allowColumnFilterWithServer = String(state.table.dataset.allowManagedColumnFilterWithServer || '').trim() === '1';
        if(serverPagination && !allowColumnFilterWithServer) return;
        if(String(state.table.dataset.pmLightNoColumnFilter || '') === '1') return;
        if(!window.SitjoyColumnFilter || typeof window.SitjoyColumnFilter.attach !== 'function') return;

        const headerCells = Array.from(state.table.tHead.rows[0].cells || []);
        const columns = headerCells.map((cell, index) => {
            const label = extractHeaderLabelText(cell);
            const key = String(cell.dataset.manageColKey || label || `字段${index + 1}`).trim();
            const resolvedLabel = label || (key === '__sj_agg__' ? '展开收起' : `字段${index + 1}`);
            return { index, key, label: resolvedLabel };
        }).filter(item => {
            const label = String(item.label || '').trim();
            if(!label) return false;
            if(/操作|详情|动作/.test(label)) return false;
            const cell = headerCells[item.index];
            if(isManagedTableNoSortNoFilterHeaderCell(cell)) return false;
            return true;
        });
        if(!columns.length) return;

        if(state.columnFilterHandle){
            state.columnFilterHandle.refreshButtons();
            return;
        }

        state.columnFilterHandle = window.SitjoyColumnFilter.attach(state.table, {
            columns,
            limit: 120,
            fetchOptions: ({ columnKey, query, exact, limit, filters }) => collectManagedColumnFilterOptions(state, columnKey, query, exact, limit, filters),
            onApply: (filters) => applyManagedColumnFilters(state, filters),
            onReset: (filters) => applyManagedColumnFilters(state, filters)
        });
    }

    function ensureRowSortOrigin(state){
        const rows = Array.from(state.tbody.rows || []);
        rows.forEach((row, idx) => {
            if((row.cells || []).length !== state.headerCount) return;
            if(!row.dataset.sortOrigin) row.dataset.sortOrigin = String(idx);
        });
    }

    function normalizeComparableValue(raw){
        const text = String(raw === null || raw === undefined ? '' : raw).trim();
        if(!text) return '';

        const lowered = text.toLowerCase();
        if(/^(是|已|启用|开启|正常|有效|true|yes|on|active)$/i.test(lowered)) return 1;
        if(/^(否|未|禁用|关闭|异常|无效|false|no|off|inactive)$/i.test(lowered)) return 0;

        const plainNumeric = text.replace(/,/g, '').replace(/%$/, '');
        const numeric = Number(plainNumeric);
        if(plainNumeric && !Number.isNaN(numeric) && /^-?\d+(\.\d+)?$/.test(plainNumeric)) return numeric;

        const dateOnly = parseDateText(text);
        if(dateOnly){
            return Date.UTC(dateOnly.year, dateOnly.month - 1, dateOnly.day);
        }

        const stamp = Date.parse(text);
        if(!Number.isNaN(stamp) && /\d{4}[-/.]\d{1,2}[-/.]\d{1,2}/.test(text)) return stamp;

        return lowered;
    }

    function readControlComparableValue(cell){
        if(!cell || !cell.querySelectorAll) return null;
        const explicit = String(cell.getAttribute('data-sort-value') || cell.dataset.sortValue || '').trim();
        if(explicit) return normalizeComparableValue(explicit);

        const explicitExport = String(cell.getAttribute('data-export-value') || cell.dataset.exportValue || '').trim();
        if(explicitExport) return normalizeComparableValue(explicitExport);

        const input = cell.querySelector('input:not([type="hidden"])');
        if(input){
            const type = String(input.type || '').toLowerCase();
            if(type === 'checkbox' || type === 'radio') return input.checked ? 1 : 0;
            if(type === 'date' || type === 'datetime-local'){
                const parsed = parseDateText(input.value || '');
                if(parsed) return Date.UTC(parsed.year, parsed.month - 1, parsed.day);
            }
            const value = String(input.value || '').trim();
            if(value) return normalizeComparableValue(value);
        }

        const select = cell.querySelector('select');
        if(select){
            const option = select.options && select.selectedIndex >= 0 ? select.options[select.selectedIndex] : null;
            const selectedText = option ? String(option.textContent || option.value || '').trim() : String(select.value || '').trim();
            if(selectedText) return normalizeComparableValue(selectedText);
        }

        const textarea = cell.querySelector('textarea');
        if(textarea){
            const value = String(textarea.value || '').trim();
            if(value) return normalizeComparableValue(value);
        }

        const activePill = cell.querySelector('.status-pill.is-active');
        if(activePill){
            const pillValue = String(activePill.getAttribute('data-value') || activePill.textContent || '').trim();
            if(pillValue) return normalizeComparableValue(pillValue);
        }

        const pressedButton = cell.querySelector('button[aria-pressed="true"]');
        if(pressedButton){
            const pressedValue = String(pressedButton.getAttribute('data-value') || pressedButton.textContent || '').trim();
            if(pressedValue) return normalizeComparableValue(pressedValue);
        }

        const colorChip = cell.querySelector('.sku-color-chip, .transit-color-dot, [data-color-chip]');
        if(colorChip){
            const colorText = String(
                colorChip.getAttribute('data-color')
                || colorChip.dataset.color
                || colorChip.style.backgroundColor
                || ''
            ).trim();
            if(colorText) return normalizeComparableValue(colorText);
            if(typeof window.getComputedStyle === 'function'){
                const computedColor = String(window.getComputedStyle(colorChip).backgroundColor || '').trim();
                if(computedColor && computedColor.toLowerCase() !== 'rgba(0, 0, 0, 0)' && computedColor.toLowerCase() !== 'transparent'){
                    return normalizeComparableValue(computedColor);
                }
            }
        }

        return null;
    }

    function readCellComparableValue(cell){
        if(!cell) return '';
        const controlValue = readControlComparableValue(cell);
        if(controlValue !== null && controlValue !== undefined && controlValue !== '') return controlValue;
        return normalizeComparableValue(String(cell.textContent || '').replace(/[↕↑↓▲▼▴▾]/g, ' ').replace(/\s+/g, ' ').trim());
    }

    const columnFilterRegistry = new WeakMap();
    let activeColumnFilterState = null;
    let activeColumnFilterRequestId = 0;

    function resolveColumnFilterTable(tableOrSelector){
        if(!tableOrSelector) return null;
        if(typeof tableOrSelector === 'string') return document.querySelector(tableOrSelector);
        return tableOrSelector;
    }

    function normalizeColumnFilterValue(item){
        if(item === null || item === undefined) return null;
        if(typeof item === 'string' || typeof item === 'number' || typeof item === 'boolean'){
            const text = String(item).trim();
            if(text === '') return { value: '', label: '[空]', count: 0 };
            return { value: text, label: text, count: 0 };
        }
        const rawValue = (item.value ?? item.id ?? item.key);
        const value = String(rawValue === null || rawValue === undefined ? '' : rawValue).trim();
        const label = String(item.label ?? item.text ?? item.name ?? item.title ?? (value === '' ? '[空]' : value)).trim() || (value === '' ? '[空]' : value);
        const count = Number(item.count ?? item.total ?? 0) || 0;
        return { value, label, count };
    }

    function createColumnFilterPopup(){
        let popup = document.getElementById('pmColumnFilterPopup');
        if(popup) return popup;
        popup = document.createElement('div');
        popup.id = 'pmColumnFilterPopup';
        popup.className = 'pm-column-filter-pop';
        popup.innerHTML = `
            <div class="pm-column-filter-title" data-role="title">列筛选</div>
            <div class="pm-column-filter-row">
                <input type="text" class="inline-input" data-role="query" placeholder="输入筛选关键词（模糊匹配）">
            </div>
            <div class="pm-column-filter-row">
                <label class="pm-column-filter-option" style="padding:0;">
                    <input type="checkbox" data-role="exact">精确匹配
                </label>
            </div>
            <div class="pm-column-filter-status" data-role="status"></div>
            <div class="pm-column-filter-options" data-role="options"></div>
            <div class="pm-column-filter-actions">
                <button type="button" class="btn-secondary" data-role="reset">重置</button>
                <button type="button" class="btn-primary" data-role="apply">应用</button>
            </div>
        `;
        document.body.appendChild(popup);
        return popup;
    }

    function closeColumnFilterPopup(){
        if(activeColumnFilterState && activeColumnFilterState.popup){
            activeColumnFilterState.popup.classList.remove('open');
        }
        activeColumnFilterState = null;
    }

    function columnFilterStateSnapshot(handle){
        const snapshot = {};
        handle.filters.forEach((value, key) => {
            snapshot[String(key)] = {
                query: String(value.query || ''),
                exact: !!value.exact,
                selected: Array.isArray(value.selected) ? value.selected.slice() : []
            };
        });
        return snapshot;
    }

    function isColumnFilterActive(filterState){
        return !!(filterState && ((String(filterState.query || '').trim()) || (Array.isArray(filterState.selected) && filterState.selected.length)));
    }

    function syncColumnFilterButtons(handle){
        if(!handle || !handle.table) return;
        const state = managedTableState.get(handle.table) || null;
        const hostTables = [handle.table];
        if(state && state.headerTable) hostTables.push(state.headerTable);
        hostTables.forEach(host => {
            host.querySelectorAll('.pm-column-filter-btn[data-column-key]').forEach(btn => {
                const key = String(btn.dataset.columnKey || '').trim();
                btn.classList.toggle('has-filter', isColumnFilterActive(handle.filters.get(key)));
            });
        });
    }

    function renderColumnFilterOptions(handle, columnKey, items){
        const popup = handle.popup || createColumnFilterPopup();
        const optionsEl = popup.querySelector('[data-role="options"]');
        const statusEl = popup.querySelector('[data-role="status"]');
        const state = handle.filters.get(columnKey) || { query: '', exact: false, selected: [] };
        const selectedSet = new Set(Array.isArray(state.selected) ? state.selected.map(v => String(v)) : []);
        const normalized = [];
        const seen = new Set();

        (Array.isArray(items) ? items : []).forEach(item => {
            const normalizedItem = normalizeColumnFilterValue(item);
            if(!normalizedItem) return;
            if(seen.has(normalizedItem.value)) return;
            seen.add(normalizedItem.value);
            normalized.push(normalizedItem);
        });

        const popupSearchQuery = String(state.query || '').trim();
        selectedSet.forEach(value => {
            if(seen.has(value)) return;
            if(!popupSearchQuery) return;
            seen.add(value);
            normalized.unshift({ value, label: value === '' ? '[空]' : value, count: 0 });
        });

        const selectAllId = `pmColumnFilterSelectAll_${String(columnKey || '').replace(/[^a-zA-Z0-9_\-\u4e00-\u9fa5]/g, '_')}`;
        const allSelected = normalized.length > 0 && normalized.every(item => selectedSet.has(item.value));
        const someSelected = normalized.some(item => selectedSet.has(item.value));
        statusEl.innerHTML = normalized.length ? `
            <label class="pm-column-filter-selectall" for="${selectAllId}">
                <input type="checkbox" id="${selectAllId}" data-role="select-all" ${allSelected ? 'checked' : ''} ${normalized.length ? '' : 'disabled'}>
                <span>显示 ${normalized.length} 项</span>
            </label>
        ` : '<span>暂无可选项</span>';
        const selectAllEl = statusEl.querySelector('[data-role="select-all"]');
        if(selectAllEl){
            selectAllEl.indeterminate = !allSelected && someSelected;
            selectAllEl.disabled = !normalized.length;
        }
        optionsEl.innerHTML = normalized.length ? normalized.map(item => {
            const checked = selectedSet.has(item.value) ? 'checked' : '';
            const countText = item.count > 0 ? ` <span style="color:var(--morandi-slate);">(${item.count})</span>` : '';
            const escapedValue = String(item.value).replace(/"/g, '&quot;');
            return `<label class="pm-column-filter-option" data-option-value="${escapedValue}"><span class="pm-column-filter-option-main"><input type="checkbox" data-value="${escapedValue}" ${checked}><span class="pm-column-filter-option-text">${String(item.label || item.value || '').replace(/</g, '&lt;').replace(/>/g, '&gt;')}${countText}</span></span><button type="button" class="pm-column-filter-only-btn" data-action="only" data-value="${escapedValue}">仅筛选此项</button></label>`;
        }).join('') : '<div class="pm-column-filter-option" style="opacity:.7;">暂无可选项</div>';

        if(selectAllEl){
            selectAllEl.checked = allSelected;
            selectAllEl.indeterminate = !allSelected && someSelected;
        }
    }

    function getColumnFilterFetchKey(columnKey, query, exact, limit, filtersSnapshot){
        const scope = columnFilterScopeSignature(filtersSnapshot || {}, columnKey);
        return `${String(columnKey || '').trim().toLowerCase()}|${String(query || '').trim().toLowerCase()}|${exact ? 1 : 0}|${Number(limit) || 0}|${scope}`;
    }

    function attachColumnFilter(tableOrSelector, config){
        const table = resolveColumnFilterTable(tableOrSelector);
        if(!table || !table.tHead || !table.tHead.rows || !table.tHead.rows.length) return null;
        if(table.dataset.columnFilterAttached === '1'){
            const existing = columnFilterRegistry.get(table);
            if(existing){
                existing.refreshButtons();
                return existing;
            }
        }

        const state = {
            table,
            config: config || {},
            popup: createColumnFilterPopup(),
            filters: new Map(),
            optionCache: new Map(),
            requestId: 0,
            activeColumn: null,
            timer: null,
        };

        function getColumnConfig(columnKey){
            const columns = Array.isArray(state.config.columns) ? state.config.columns : [];
            const key = String(columnKey || '').trim();
            return columns.find(item => String(item.key || item.index || '').trim() === key || Number(item.index) === Number(key)) || null;
        }

        function loadOptions(columnKey, force){
            const columnConfig = getColumnConfig(columnKey);
            if(!columnConfig || typeof state.config.fetchOptions !== 'function') return Promise.resolve([]);
            const filterState = state.filters.get(columnKey) || { query: '', exact: false, selected: [] };
            const query = String(filterState.query || '').trim();
            const exact = !!filterState.exact;
            const limit = Number(columnConfig.limit || state.config.limit || 120) || 120;
            const filtersSnapshot = columnFilterStateSnapshot(state);
            const cacheKey = getColumnFilterFetchKey(columnKey, query, exact, limit, filtersSnapshot);
            if(!force && state.optionCache.has(cacheKey)){
                renderColumnFilterOptions(state, columnKey, state.optionCache.get(cacheKey));
                return Promise.resolve(state.optionCache.get(cacheKey));
            }

            const requestId = ++state.requestId;
            const popup = state.popup;
            const statusEl = popup.querySelector('[data-role="status"]');
            const optionsEl = popup.querySelector('[data-role="options"]');
            if(statusEl) statusEl.textContent = '加载筛选项...';
            if(optionsEl) optionsEl.innerHTML = '<div class="pm-column-filter-option" style="opacity:.7;">加载中...</div>';

            return Promise.resolve(state.config.fetchOptions({
                table,
                column: columnConfig,
                columnKey,
                columnIndex: columnConfig.index,
                query,
                exact,
                limit,
                filters: columnFilterStateSnapshot(state)
            })).then(result => {
                if(requestId !== state.requestId) return [];
                const values = Array.isArray(result) ? result : (result && Array.isArray(result.values) ? result.values : []);
                state.optionCache.set(cacheKey, values);
                renderColumnFilterOptions(state, columnKey, values);
                return values;
            }).catch(err => {
                if(requestId !== state.requestId) return [];
                if(statusEl) statusEl.textContent = err && err.message ? err.message : '加载筛选项失败';
                if(optionsEl) optionsEl.innerHTML = '<div class="pm-column-filter-option" style="opacity:.7;">加载失败</div>';
                return [];
            });
        }

        function applyFilters(){
            state.optionCache.clear();
            if(typeof state.config.onApply === 'function'){
                state.config.onApply(columnFilterStateSnapshot(state), state);
            }
            state.popup.classList.remove('open');
            state.activeColumn = null;
            activeColumnFilterState = null;
            syncColumnFilterButtons(state);
        }

        function syncSelectAllState(){
            const statusEl = popup.querySelector('[data-role="status"]');
            const selectAllEl = statusEl ? statusEl.querySelector('[data-role="select-all"]') : null;
            if(!selectAllEl) return;
            const optionCheckboxes = Array.from(popup.querySelectorAll('.pm-column-filter-options input[type="checkbox"][data-value]'));
            const checkedCount = optionCheckboxes.filter(input => !!input.checked).length;
            const total = optionCheckboxes.length;
            selectAllEl.checked = total > 0 && checkedCount === total;
            selectAllEl.indeterminate = checkedCount > 0 && checkedCount < total;
            selectAllEl.disabled = total === 0;
        }

        function resetFilter(columnKey){
            state.optionCache.clear();
            state.filters.set(columnKey, { query: '', exact: false, selected: [] });
            if(typeof state.config.onReset === 'function'){
                state.config.onReset(columnFilterStateSnapshot(state), state);
            } else if(typeof state.config.onApply === 'function'){
                state.config.onApply(columnFilterStateSnapshot(state), state);
            }
            state.popup.classList.remove('open');
            state.activeColumn = null;
            activeColumnFilterState = null;
            syncColumnFilterButtons(state);
        }

        function open(columnKey, button){
            const columnConfig = getColumnConfig(columnKey);
            if(!columnConfig) return;
            const filterState = state.filters.get(columnKey) || { query: '', exact: false, selected: [] };
            state.filters.set(columnKey, filterState);
            state.activeColumn = columnKey;
            activeColumnFilterState = state;

            const popup = state.popup;
            popup.querySelector('[data-role="title"]').textContent = `${columnConfig.label || '列'}筛选`;
            popup.querySelector('[data-role="query"]').value = String(filterState.query || '');
            popup.querySelector('[data-role="exact"]').checked = !!filterState.exact;
            popup.classList.add('open');

            const rect = button.getBoundingClientRect();
            const popupWidth = Math.max(220, popup.offsetWidth || 0);
            const left = Math.min(window.innerWidth - popupWidth - 10, Math.max(10, rect.left));
            popup.style.top = `${Math.max(10, rect.bottom + 6)}px`;
            popup.style.left = `${Math.max(10, left)}px`;

            // Show current selected values immediately so reopening always reflects checked state.
            const selectedPreview = Array.isArray(filterState.selected)
                ? filterState.selected.map(v => {
                    const raw = (v === null || v === undefined) ? '' : String(v);
                    const text = String(raw).trim();
                    return { value: text, label: text === '' ? '[空]' : text, count: 0 };
                })
                : [];
            renderColumnFilterOptions(state, columnKey, selectedPreview);

            loadOptions(columnKey, false);
        }

        function refreshButtons(){
            const managed = managedTableState.get(table) || null;
            const hosts = [table];
            if(managed && managed.headerTable) hosts.push(managed.headerTable);
            hosts.forEach(host => {
                const headerRow = host.tHead && host.tHead.rows ? host.tHead.rows[0] : null;
                if(!headerRow) return;
                Array.from(headerRow.cells || []).forEach((cell, idx) => {
                    const headerKey = String(cell.dataset.manageColKey || '').trim() || String(idx);
                    const columnConfig = getColumnConfig(headerKey);
                    const existingBtn = cell.querySelector('.pm-column-filter-btn');
                    if(!columnConfig){
                        cell.classList.remove('pm-column-filter-th');
                        if(existingBtn) existingBtn.remove();
                        return;
                    }
                    cell.classList.add('pm-column-filter-th');
                    let btn = existingBtn;
                    if(!btn){
                        btn = document.createElement('button');
                        btn.type = 'button';
                        btn.className = 'pm-column-filter-btn';
                        btn.title = '列筛选';
                        cell.appendChild(btn);
                    }
                    btn.dataset.columnIndex = String(idx);
                    btn.dataset.columnKey = String(columnConfig.key || '').trim() || headerKey;
                    btn.classList.toggle('has-filter', isColumnFilterActive(state.filters.get(String(btn.dataset.columnKey || '').trim())));
                });
            });
        }

        const popup = state.popup;
        popup.addEventListener('click', (event) => event.stopPropagation());
        popup.querySelector('[data-role="apply"]').addEventListener('click', () => applyFilters());
        popup.querySelector('[data-role="reset"]').addEventListener('click', () => {
            if(state.activeColumn == null) return;
            resetFilter(state.activeColumn);
        });
        popup.querySelector('[data-role="query"]').addEventListener('input', () => {
            if(state.activeColumn == null) return;
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            filterState.query = String(popup.querySelector('[data-role="query"]').value || '').trim();
            state.filters.set(state.activeColumn, filterState);
            if(state.timer) window.clearTimeout(state.timer);
            state.timer = window.setTimeout(() => loadOptions(state.activeColumn, false), 160);
        });
        popup.querySelector('[data-role="exact"]').addEventListener('change', () => {
            if(state.activeColumn == null) return;
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            filterState.exact = !!popup.querySelector('[data-role="exact"]').checked;
            state.filters.set(state.activeColumn, filterState);
            if(state.timer) window.clearTimeout(state.timer);
            state.timer = window.setTimeout(() => loadOptions(state.activeColumn, false), 160);
        });
        popup.querySelector('[data-role="options"]').addEventListener('change', (event) => {
            const target = event.target;
            if(!target || !target.matches('input[type="checkbox"][data-value]')) return;
            if(state.activeColumn == null) return;
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            const selected = new Set(Array.isArray(filterState.selected) ? filterState.selected.map(v => String(v)) : []);
            const value = String(target.dataset.value || '');
            if(target.checked) selected.add(value); else selected.delete(value);
            filterState.selected = Array.from(selected.values());
            state.filters.set(state.activeColumn, filterState);
            syncSelectAllState();
        });
        popup.querySelector('[data-role="options"]').addEventListener('click', (event) => {
            const button = event.target && event.target.closest ? event.target.closest('.pm-column-filter-only-btn[data-action="only"]') : null;
            if(!button) return;
            if(state.activeColumn == null) return;
            event.preventDefault();
            event.stopPropagation();
            const rawOnly = button.getAttribute('data-value');
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            // data-value="" 表示筛「空」；不能用 truthy 判断否则会变成未选任何项
            filterState.selected = rawOnly !== null ? [String(rawOnly)] : [];
            state.filters.set(state.activeColumn, filterState);
            applyFilters();
        });
        popup.querySelector('[data-role="status"]').addEventListener('change', (event) => {
            const target = event.target;
            if(!target || !target.matches('[data-role="select-all"]')) return;
            if(state.activeColumn == null) return;
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            const options = Array.from(popup.querySelectorAll('.pm-column-filter-options input[type="checkbox"][data-value]'));
            options.forEach(input => { input.checked = !!target.checked; });
            filterState.selected = target.checked
                ? Array.from(new Set(options.map(input => {
                    const r = input.getAttribute('data-value');
                    return r === null ? '' : String(r);
                })))
                : [];
            state.filters.set(state.activeColumn, filterState);
            syncSelectAllState();
        });

        const clickHandler = (event) => {
            if(Date.now() < suppressSortUntil) return;
            if(event.target && event.target.closest && event.target.closest('.pm-col-resizer')) return;
            const button = event.target && event.target.closest ? event.target.closest('.pm-column-filter-btn[data-column-key]') : null;
            const managed = managedTableState.get(table) || null;
            const inMainTable = !!(button && table.contains(button));
            const inHeadClone = !!(button && managed && managed.headerTable && managed.headerTable.contains(button));
            if(button && (inMainTable || inHeadClone)){
                event.preventDefault();
                event.stopPropagation();
                const columnKey = String(button.dataset.columnKey || '').trim() || String(button.dataset.columnIndex || 0);
                if(activeColumnFilterState === state && state.activeColumn === columnKey && popup.classList.contains('open')){
                    closeColumnFilterPopup();
                    return;
                }
                open(columnKey, button);
                return;
            }
            const eventInsideManagedHead = !!(managed && managed.headerTable && managed.headerTable.contains(event.target));
            if(activeColumnFilterState === state && popup.classList.contains('open') && !popup.contains(event.target) && !table.contains(event.target) && !eventInsideManagedHead){
                closeColumnFilterPopup();
            }
        };
        document.addEventListener('click', clickHandler);

        const keyHandler = (event) => {
            if(activeColumnFilterState !== state) return;
            if(event.key === 'Escape'){
                closeColumnFilterPopup();
            }
            if(event.key === 'Enter' && popup.classList.contains('open')){
                const applyBtn = popup.querySelector('[data-role="apply"]');
                if(applyBtn){
                    event.preventDefault();
                    applyBtn.click();
                }
            }
        };
        document.addEventListener('keydown', keyHandler);

        const handle = {
            table,
            refreshButtons,
            syncButtons: refreshButtons,
            getFilters: () => columnFilterStateSnapshot(state),
            setFilters: (snapshot) => {
                state.filters = new Map();
                Object.entries(snapshot || {}).forEach(([key, value]) => {
                    const colKey = String(key || '').trim();
                    if(!colKey) return;
                    state.filters.set(colKey, {
                        query: String(value && value.query ? value.query : ''),
                        exact: !!(value && value.exact),
                        selected: Array.isArray(value && value.selected) ? value.selected.slice() : []
                    });
                });
                refreshButtons();
            },
            close: closeColumnFilterPopup,
            destroy: () => {
                document.removeEventListener('click', clickHandler);
                document.removeEventListener('keydown', keyHandler);
                if(table.dataset) table.dataset.columnFilterAttached = '0';
                columnFilterRegistry.delete(table);
                if(activeColumnFilterState === state) closeColumnFilterPopup();
            }
        };

        table.dataset.columnFilterAttached = '1';
        columnFilterRegistry.set(table, handle);
        refreshButtons();
        return handle;
    }

    function resolveBodyTableFromHeaderTh(th){
        if(!th || !th.closest) return null;
        const table = th.closest('table');
        if(!table) return null;
        if(managedTableState.has(table)) return table;
        if(table.classList && table.classList.contains('pm-managed-head-table')){
            let found = null;
            managedTableState.forEach((state) => {
                if(found) return;
                if(state && state.headerTable === table) found = state.table || null;
            });
            return found;
        }
        return null;
    }

    /** 表体/布局轻量同步：不重算列宽配置、不克隆分离表头 */
    function syncManagedTableBodyLayout(state){
        if(!state || !state.table) return;
        const headerMeta = getHeaderMeta(state.table);
        if(!headerMeta.length) return;
        state.headerCount = headerMeta.length;
        ensureManagedColumnKeys(state, headerMeta);
        syncManagedColumnVisibilitySlots(state);
        applyNumericColumnLayoutForTable(state.table);
        syncSjAggToggleColumnCssVar(state);
        syncTopScroll(state);
        reapplyManagedColumnFiltersFromHandle(state);
    }

    function finishManagedTableBodyUpdate(state){
        if(!state || !state.table) return;
        if(state.table.tBodies && state.table.tBodies[0]){
            state.tbody = state.table.tBodies[0];
        }
        syncManagedTableBodyLayout(state);
        ensureRowSortOrigin(state);
        if(managedSortStackHasEntries(state) || state.sortApplied || tableBodyHasGroupedAggregateRows(state)){
            applySort(state);
        }
        refreshSortHeaderUi(state);
        applyPagination(state);
        syncManagedBatchBar(state);
    }

    function beginManagedTableBodyUpdate(table){
        const t = typeof table === 'string' ? document.querySelector(table) : table;
        if(!t) return;
        const state = managedTableState.get(t);
        if(!state) return;
        state.bodyUpdateDepth = (state.bodyUpdateDepth || 0) + 1;
        if(state.table && state.table.tBodies && state.table.tBodies[0]){
            state.tbody = state.table.tBodies[0];
        }
        if(state.bodyUpdateDepth === 1){
            state.suppressManagedRefresh = true;
            invalidatePmRowCellKeyMapsInTbody(state.tbody);
            if(state.observer && state.tbody){
                try { state.observer.disconnect(); } catch(_e){}
            }
        }
    }

    function endManagedTableBodyUpdate(table){
        const t = typeof table === 'string' ? document.querySelector(table) : table;
        if(!t) return;
        const state = managedTableState.get(t);
        if(!state) return;
        const depth = Number(state.bodyUpdateDepth || 0);
        if(depth <= 0){
            if(state.suppressManagedRefresh){
                state.bodyUpdateDepth = 0;
                finishManagedTableBodyUpdate(state);
                state.suppressManagedRefresh = false;
                if(state.observer && state.tbody){
                    try {
                        state.observer.observe(state.tbody, { childList: true, subtree: false });
                    } catch(_e){}
                }
            }
            return;
        }
        state.bodyUpdateDepth = depth - 1;
        if(state.bodyUpdateDepth > 0) return;
        finishManagedTableBodyUpdate(state);
        state.suppressManagedRefresh = false;
        if(state.observer && state.tbody){
            try {
                state.observer.observe(state.tbody, { childList: true, subtree: false });
            } catch(_e){}
        }
    }

    /** 表体重绘后轻量同步列宽/分离表头，不重置 headerSignature（避免反复全量解析列宽） */
    function syncManagedTableLayout(table){
        const t = typeof table === 'string' ? document.querySelector(table) : table;
        if(!t) return;
        const state = managedTableState.get(t);
        if(!state) return;
        finishManagedTableBodyUpdate(state);
    }

    function invalidateManagedTableLayout(table){
        const t = typeof table === 'string' ? document.querySelector(table) : table;
        if(!t) return;
        const state = managedTableState.get(t);
        if(!state) return;
        let sigChanged = false;
        try{
            // 月份等宽同步表由页面在重绘 thead 前写入稳定的 sjManageLayoutSig；此处若再刷 Date.now()
            // 会导致 headerSignature 每次变化，反复走列宽全量解析并写回 storage，覆盖用户拖拽宽度。
            if(!isPmMonthColWidthSyncTable(t)){
                const preSet = String(t.dataset.sjManageLayoutSig || '').trim();
                if(!preSet){
                    t.dataset.sjManageLayoutSig = String(Date.now());
                    sigChanged = true;
                } else {
                    const prevLayoutSig = String(state.lastManageLayoutSig || '');
                    if(preSet !== prevLayoutSig){
                        state.lastManageLayoutSig = preSet;
                        sigChanged = true;
                    }
                }
            } else {
                sigChanged = true;
            }
        } catch(_e){
            sigChanged = true;
        }
        if(sigChanged) state.headerSignature = '';
        refreshManagedTable(state);
    }

    window.SitjoyManagedPmTable = Object.assign({}, window.SitjoyManagedPmTable || {}, {
        resolveBodyTableFromHeaderTh,
        invalidateLayout: invalidateManagedTableLayout,
        syncLayout: syncManagedTableLayout,
        beginBodyUpdate: beginManagedTableBodyUpdate,
        endBodyUpdate: endManagedTableBodyUpdate,
        syncBatchBar(tableOrSelector){
            const table = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            const state = table ? (managedTableState.get(table) || null) : null;
            if(state) syncManagedBatchBar(state);
        },
        /** 当前可见行中已勾选的 id（列筛选 / 客户端分页隐藏行不计入） */
        getSelectedIds(tableOrSelector){
            const table = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            const state = table ? (managedTableState.get(table) || null) : null;
            if(!state) return [];
            return getManagedSelectedIds(state);
        },
        syncSelectAllMasters(tableOrSelector){
            const table = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            if(table) syncPmTableSelectAllMasters(table);
        },
        /** 全选/取消全选当前可见行（列筛选隐藏行、分页隐藏行不计入，除非表声明 data-pm-skip-client-pagination="1"） */
        toggleSelectAll(tableOrSelector, checked){
            const table = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            if(table) togglePmTableSelectAll(table, checked);
        },
        /** 表体 DOM 重绘后按当前列筛选状态重新隐藏行（一般由 refreshManagedTable 自动调用） */
        reapplyColumnFilters(tableOrSelector){
            const t = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            if(!t) return;
            const state = managedTableState.get(t);
            if(state) reapplyManagedColumnFiltersFromHandle(state);
        },
        clearAllFilters(tableOrSelector){
            const t = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            if(!t) return;
            const state = managedTableState.get(t);
            if(state) clearAllManagedTableFilters(state);
        },
        clearSort(tableOrSelector){
            const t = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            if(!t) return;
            const state = managedTableState.get(t);
            if(state) clearManagedTableSort(state);
        },
        getState(tableOrSelector){
            const t = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
            return t ? (managedTableState.get(t) || null) : null;
        },
        getSortStack(tableOrSelector){
            const state = this.getState(tableOrSelector);
            return state ? normalizeManagedSortStack(state.sortStack).slice() : [];
        },
        whenReady(tableOrSelector, callback, options){
            const opts = options || {};
            const maxAttempts = Math.max(1, Number(opts.maxAttempts || 120) || 120);
            let attempt = 0;
            const tick = () => {
                const t = typeof tableOrSelector === 'string' ? document.querySelector(tableOrSelector) : tableOrSelector;
                const state = t ? (managedTableState.get(t) || null) : null;
                if(state && state.tbody && typeof callback === 'function'){
                    try { callback(state, t); } catch(err) {
                        console.warn('SitjoyManagedPmTable.whenReady callback failed', err);
                    }
                    return;
                }
                attempt += 1;
                if(attempt >= maxAttempts){
                    if(typeof callback === 'function'){
                        try { callback(null, t); } catch(err) {
                            console.warn('SitjoyManagedPmTable.whenReady callback failed', err);
                        }
                    }
                    return;
                }
                requestAnimationFrame(tick);
            };
            tick();
        },
        setSortStack(tableOrSelector, stack, options){
            const opts = options || {};
            const state = this.getState(tableOrSelector);
            if(!state) return;
            state.sortStack = normalizeManagedSortStack(stack);
            syncLegacySortFieldsFromStack(state);
            state._sortKeyToManageColKey = null;
            if(!opts.skipPersist && state.table && !tableSkipsFilterPersist(state.table)){
                persistManagedSortStack(state.table, state.sortStack);
            }
            refreshSortHeaderUi(state);
            if(!opts.skipApply){
                applySort(state);
                applyPagination(state);
                syncManagedBatchBar(state);
            }
            if(!opts.skipDispatch) dispatchManagedTableSortChange(state);
        },
        syncSortUi(tableOrSelector){
            const state = this.getState(tableOrSelector);
            if(state) refreshSortHeaderUi(state);
        },
        handleHeaderSortClick(th, stateOrTable){
            const state = stateOrTable && stateOrTable.table ? stateOrTable : this.getState(stateOrTable);
            if(!state || !th) return false;
            const manageKey = String(th.dataset.manageColKey || '').trim();
            const sortKey = resolveSortColumnKeyFromHeaderCell(th);
            if(!sortKey || (manageKey && state.lockedColumns.has(manageKey))) return false;
            toggleManagedSortStackEntry(state, sortKey);
            refreshSortHeaderUi(state);
            applySort(state);
            applyPagination(state);
            syncManagedBatchBar(state);
            dispatchManagedTableSortChange(state);
            return true;
        },
        /** 对 root 下尚未托管的 table.pm-table 执行 createManagedTable（如弹窗内动态插入的表） */
        enhance(root){
            enhanceManagedTables(root && root.querySelectorAll ? root : document);
        },
        /** 按列 key / 表头文案 / 单元格内容启发式，为数值列加 pm-col-num 并统一小数格式 */
        applyNumericAlign(tableOrRoot){
            if(!tableOrRoot) return;
            if(tableOrRoot.tagName === 'TABLE') applyNumericColumnLayoutForTable(tableOrRoot);
            else enhanceAllTableNumericAlign(tableOrRoot);
        },
        formatNumber: formatSitjoyNumber
    });

    window.formatSitjoyNumber = formatSitjoyNumber;

    window.SitjoyColumnFilter = {
        attach: attachColumnFilter,
        close: closeColumnFilterPopup,
        rowPassesFilters: rowPassesManagedColumnFilters,
        columnFilterScopeSignature,
        collectOptionsFromTableState: collectManagedColumnFilterOptions,
        refresh(tableOrSelector){
            const table = resolveColumnFilterTable(tableOrSelector);
            if(!table) return null;
            const handle = columnFilterRegistry.get(table) || null;
            if(handle) handle.refreshButtons();
            return handle;
        },
        reapply(tableOrSelector){
            const table = resolveColumnFilterTable(tableOrSelector);
            if(!table) return;
            const state = managedTableState.get(table);
            if(state) reapplyManagedColumnFiltersFromHandle(state);
        },
        get(tableOrSelector){
            const table = resolveColumnFilterTable(tableOrSelector);
            return table ? (columnFilterRegistry.get(table) || null) : null;
        }
    };

    function resolveCheckboxSelectionId(checkbox, idx){
        if(!checkbox) return '';
        const row = checkbox.closest('tr');
        const raw = String(
            checkbox.getAttribute('data-id')
            || checkbox.dataset.id
            || checkbox.value
            || (row && (row.getAttribute('data-id') || row.dataset.id))
            || ''
        ).trim();
        if(raw) return raw;
        return `__row_${idx + 1}`;
    }

    /** 列筛选 / 客户端分页隐藏的行不应参与批量勾选统计与全选逻辑 */
    function isManagedTableRowVisibleForSelection(row){
        if(!row || String(row.tagName || '').toUpperCase() !== 'TR') return false;
        if(String(row.dataset.pmFilterHidden || '0') === '1') return false;
        if(row.style && row.style.display === 'none') return false;
        return true;
    }

    function isManagedRowBatchCheckboxInput(cb){
        if(!cb || cb.disabled || !cb.closest('tr')) return false;
        if(cb.classList.contains('switch-input')) return false;
        return cb.hasAttribute('data-id') || cb.classList.contains('row-check') || cb.name === 'row-check' || /select|check/i.test(String(cb.className || ''));
    }

    function clearManagedBatchCheckboxesOnHiddenRows(state){
        if(!state || !state.tbody) return;
        let cleared = false;
        Array.from(state.tbody.rows || []).forEach(row => {
            if(isManagedTableRowVisibleForSelection(row)) return;
            row.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                if(!isManagedRowBatchCheckboxInput(cb)) return;
                if(!cb.checked) return;
                cb.checked = false;
                cleared = true;
                try{
                    cb.dispatchEvent(new Event('change', { bubbles: true }));
                } catch(_e){}
            });
        });
        if(cleared) syncManagedBatchBarAsync(state);
    }

    function getManagedSelectionCheckboxes(state){
        if(!state || !state.tbody) return [];
        const rows = Array.from(state.tbody.rows || []);
        const fromLockedColumns = [];

        if(state.lockedColumns && state.lockedColumns.size){
            rows.forEach(row => {
                if(!isManagedTableRowVisibleForSelection(row)) return;
                const byKey = mapRowByKey(row);
                state.lockedColumns.forEach(key => {
                    const cell = byKey.get(String(key || '').trim());
                    if(!cell) return;
                    const cb = cell.querySelector('input[type="checkbox"]');
                    if(cb && !fromLockedColumns.includes(cb)) fromLockedColumns.push(cb);
                });
            });
        }

        if(fromLockedColumns.length) return fromLockedColumns;

        return Array.from(state.tbody.querySelectorAll('input[type="checkbox"]')).filter(cb => {
            if(cb.disabled) return false;
            const row = cb.closest('tr');
            if(!row || !isManagedTableRowVisibleForSelection(row)) return false;
            if(cb.classList.contains('switch-input')) return false;
            return isManagedRowBatchCheckboxInput(cb);
        });
    }

    function getManagedSelectedIds(state){
        const set = new Set();
        getManagedSelectionCheckboxes(state).forEach((cb, idx) => {
            if(!cb.checked) return;
            const id = resolveCheckboxSelectionId(cb, idx);
            if(id) set.add(id);
        });
        return Array.from(set.values());
    }

    function getManagedSelectedRowEntries(state){
        const entries = [];
        getManagedSelectionCheckboxes(state).forEach((cb, idx) => {
            if(!cb.checked) return;
            const row = cb.closest('tr');
            if(!row) return;
            entries.push({ id: resolveCheckboxSelectionId(cb, idx), row, checkbox: cb });
        });
        return entries;
    }

    const pmRowCheckAnchorByTbody = new WeakMap();

    function resolvePmBatchCheckboxTable(el){
        if(!el) return null;
        const tableId = String(el.getAttribute && el.getAttribute('data-table-id') || '').trim();
        if(tableId){
            const byId = document.getElementById(tableId);
            if(byId) return byId;
        }
        const cell = el.closest ? el.closest('th,td') : null;
        if(cell){
            const fromTh = resolveBodyTableFromHeaderTh(cell);
            if(fromTh) return fromTh;
        }
        const table = el.closest ? el.closest('table') : null;
        if(table && table.classList && table.classList.contains('pm-managed-head-table')){
            let found = null;
            managedTableState.forEach((state) => {
                if(found) return;
                if(state && state.headerTable === table) found = state.table || null;
            });
            if(found) return found;
        }
        return table;
    }

    function getPmTableVisibleBatchCheckboxes(tableOrTbody){
        const root = tableOrTbody || null;
        if(!root) return [];
        const tbody = String(root.tagName || '').toUpperCase() === 'TBODY'
            ? root
            : (root.tBodies && root.tBodies[0] ? root.tBodies[0] : null);
        if(!tbody) return [];
        return Array.from(tbody.querySelectorAll('input[type="checkbox"]')).filter(cb => {
            if(!isManagedRowBatchCheckboxInput(cb)) return false;
            const row = cb.closest('tr');
            return isManagedTableRowVisibleForSelection(row);
        });
    }

    function getPmTableSelectAllInputs(table){
        if(!table || !table.id) return [];
        const id = String(table.id).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
        return Array.from(document.querySelectorAll(`input.pm-table-select-all[data-table-id="${id}"]`));
    }

    function syncPmTableSelectAllMasters(table){
        if(!table) return;
        const masters = getPmTableSelectAllInputs(table);
        if(!masters.length) return;
        const rows = getPmTableVisibleBatchCheckboxes(table);
        if(!rows.length){
            masters.forEach(master => {
                master.checked = false;
                master.indeterminate = false;
            });
            return;
        }
        const checkedCount = rows.filter(cb => cb.checked).length;
        const allChecked = checkedCount === rows.length;
        const partial = checkedCount > 0 && checkedCount < rows.length;
        masters.forEach(master => {
            master.checked = allChecked;
            master.indeterminate = partial;
        });
    }

    function togglePmTableSelectAll(table, checked){
        if(!table) return;
        getPmTableVisibleBatchCheckboxes(table).forEach(cb => {
            const next = !!checked;
            if(cb.checked === next) return;
            cb.checked = next;
            try {
                cb.dispatchEvent(new Event('change', { bubbles: true }));
            } catch(_e){}
        });
        syncPmTableSelectAllMasters(table);
        const state = managedTableState.get(table);
        if(state) syncManagedBatchBarAsync(state);
    }

    function initPmTableBatchCheckboxSelection(){
        if(initPmTableBatchCheckboxSelection._on) return;
        initPmTableBatchCheckboxSelection._on = true;

        document.addEventListener('change', (event) => {
            const target = event.target;
            if(!target || !(target instanceof HTMLInputElement) || target.type !== 'checkbox') return;
            if(target.classList.contains('pm-table-select-all')){
                const table = resolvePmBatchCheckboxTable(target);
                if(table) togglePmTableSelectAll(table, target.checked);
                return;
            }
            if(isManagedRowBatchCheckboxInput(target)){
                const table = target.closest('table');
                if(table) syncPmTableSelectAllMasters(table);
            }
        }, false);

        document.addEventListener('mousedown', (event) => {
            if(!event || event.button !== 0) return;
            const target = event.target;
            if(!target || !(target instanceof HTMLInputElement) || target.type !== 'checkbox') return;
            if(!isManagedRowBatchCheckboxInput(target)) return;
            if(!event.shiftKey) return;
            const row = target.closest('tr');
            const tbody = row ? row.parentElement : null;
            if(!tbody || String(tbody.tagName || '').toUpperCase() !== 'TBODY') return;
            if(!isManagedTableRowVisibleForSelection(row)) return;
            const boxes = getPmTableVisibleBatchCheckboxes(tbody);
            const idx = boxes.indexOf(target);
            if(idx < 0) return;
            const anchor = pmRowCheckAnchorByTbody.get(tbody);
            if(anchor == null || anchor === idx) return;
            event.preventDefault();
            event.stopPropagation();
            const lo = Math.min(anchor, idx);
            const hi = Math.max(anchor, idx);
            const targetChecked = !target.checked;
            for(let i = lo; i <= hi; i += 1){
                const cb = boxes[i];
                if(!cb || cb.checked === targetChecked) continue;
                cb.checked = targetChecked;
                try {
                    cb.dispatchEvent(new Event('change', { bubbles: true }));
                } catch(_e){}
            }
            pmRowCheckAnchorByTbody.set(tbody, idx);
            const table = tbody.closest('table');
            if(table){
                syncPmTableSelectAllMasters(table);
                const state = managedTableState.get(table);
                if(state) syncManagedBatchBarAsync(state);
            }
        }, true);

        document.addEventListener('click', (event) => {
            if(!event || event.shiftKey) return;
            const target = event.target;
            if(!target || !(target instanceof HTMLInputElement) || target.type !== 'checkbox') return;
            if(!isManagedRowBatchCheckboxInput(target)) return;
            const tbody = target.closest('tbody');
            if(!tbody) return;
            const boxes = getPmTableVisibleBatchCheckboxes(tbody);
            const idx = boxes.indexOf(target);
            if(idx >= 0) pmRowCheckAnchorByTbody.set(tbody, idx);
        }, false);
    }

    function csvEscape(value){
        const text = String(value === null || value === undefined ? '' : value);
        if(/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
        return text;
    }

    function readCellExportText(cell){
        if(!cell) return '';
        const explicit = String(cell.getAttribute('data-export-value') || cell.dataset.exportValue || '').trim();
        if(explicit) return explicit;
        return extractCellClipboardText(cell);
    }

    function exportManagedRowsToCsv(state, rows){
        if(!state || !state.table || !Array.isArray(rows) || !rows.length) return false;
        const exportKeys = (state.columnOrder || []).filter(key => {
            const columnKey = String(key || '').trim();
            if(state.lockedColumns && state.lockedColumns.has(columnKey)) return false;
            return state.visibleColumns ? state.visibleColumns.has(columnKey) : true;
        });
        if(!exportKeys.length) return false;

        const headerMap = new Map((state.headers || []).map(h => [String(h.key || '').trim(), String(h.label || '').trim()]));
        const lines = [];
        lines.push(exportKeys.map(key => csvEscape(headerMap.get(String(key || '').trim()) || String(key || '字段'))).join(','));

        rows.forEach(row => {
            const byKey = mapRowByKey(row);
            const line = exportKeys.map(key => {
                const cell = byKey.get(String(key || '').trim());
                const raw = cell ? String(readCellExportText(cell) || '').replace(/[↕↑↓▲▼▴▾]/g, ' ').replace(/\s+/g, ' ').trim() : '';
                return csvEscape(raw);
            }).join(',');
            lines.push(line);
        });

        const csv = lines.join('\r\n');
        const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        const date = new Date();
        const yyyy = date.getFullYear();
        const mm = String(date.getMonth() + 1).padStart(2, '0');
        const dd = String(date.getDate()).padStart(2, '0');
        const tableName = (state.table.id || state.table.dataset.manageKey || 'table').replace(/[^a-zA-Z0-9_-]+/g, '_');
        link.href = url;
        link.download = `${tableName}_selected_${yyyy}${mm}${dd}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        return true;
    }

    function findRowDeleteButton(row){
        if(!row || !row.querySelectorAll) return null;
        const buttons = Array.from(row.querySelectorAll('button, a'));
        const primary = buttons.find(btn => btn.classList.contains('btn-danger') || btn.getAttribute('data-action') === 'delete');
        if(primary) return primary;
        return buttons.find(btn => /删除/.test(String(btn.textContent || '').trim())) || null;
    }

    function withSilentConfirm(task){
        if(typeof task !== 'function') return;
        const originalConfirm = window.confirm;
        window.confirm = function(){ return true; };
        try {
            task();
        } finally {
            window.confirm = originalConfirm;
        }
    }

    function defaultManagedTableBatchDownload(ids, table, state){
        const entries = getManagedSelectedRowEntries(state).filter(item => ids.includes(item.id));
        const rows = entries.map(item => item.row);
        if(!rows.length){
            showAppToast('未找到可下载的勾选行。', true);
            return;
        }
        if(exportManagedRowsToCsv(state, rows)){
            showAppToast(`已导出 ${rows.length} 条勾选数据。`, false);
            return;
        }
        showAppToast('批量下载失败：未能生成导出内容。', true);
    }

    function defaultManagedTableBatchDelete(ids, table, state){
        const entries = getManagedSelectedRowEntries(state).filter(item => ids.includes(item.id));
        const buttons = entries.map(item => findRowDeleteButton(item.row)).filter(Boolean);
        if(!buttons.length){
            showAppToast('当前页面未找到可触发的删除按钮，请在表格上配置 data-batch-delete-handler。', true);
            return;
        }

        buttons.forEach((btn, idx) => {
            window.setTimeout(() => {
                withSilentConfirm(() => {
                    if(btn && typeof btn.click === 'function') btn.click();
                });
            }, idx * 120);
        });
        showAppToast(`已触发 ${buttons.length} 条删除操作。`, false);
    }

    function ensureBatchConfirmModal(){
        let modal = document.getElementById('pm-batch-delete-modal');
        if(modal && document.body.contains(modal)) return modal;

        modal = document.createElement('div');
        modal.id = 'pm-batch-delete-modal';
        modal.className = 'pm-modal pm-batch-delete-modal';
        modal.innerHTML = [
            '<div class="pm-modal-content pm-batch-delete-content">',
            '  <h3>批量删除确认</h3>',
            '  <p class="pm-batch-delete-desc"></p>',
            '  <label class="pm-batch-delete-ack">',
            '    <input type="checkbox" class="pm-batch-delete-ack-input">',
            '    <span>我已阅读并确认操作后果。</span>',
            '  </label>',
            '  <div class="pm-actions pm-batch-delete-actions">',
            '    <button type="button" class="btn-secondary" data-action="cancel">取消</button>',
            '    <button type="button" class="btn-danger" data-action="confirm" disabled>二次确认删除</button>',
            '  </div>',
            '</div>'
        ].join('');
        document.body.appendChild(modal);

        const ack = modal.querySelector('.pm-batch-delete-ack-input');
        const confirmBtn = modal.querySelector('[data-action="confirm"]');
        const cancelBtn = modal.querySelector('[data-action="cancel"]');

        if(ack && confirmBtn){
            ack.addEventListener('change', () => {
                confirmBtn.disabled = !ack.checked;
            });
        }
        if(cancelBtn){
            cancelBtn.addEventListener('click', () => closeBatchConfirmModal());
        }
        if(confirmBtn){
            confirmBtn.addEventListener('click', () => {
                if(!activeBatchConfirmState || !ack || !ack.checked) return;
                const current = activeBatchConfirmState;
                closeBatchConfirmModal();
                current.onConfirm();
            });
        }
        let batchBackdropArmed = false;
        const onBatchBackdropDown = (event) => { batchBackdropArmed = (event.target === modal); };
        const onBatchBackdropUp = (event) => {
            if(batchBackdropArmed && event.target === modal) closeBatchConfirmModal();
            batchBackdropArmed = false;
        };
        const onBatchBackdropReset = () => { batchBackdropArmed = false; };
        modal.addEventListener('pointerdown', onBatchBackdropDown);
        modal.addEventListener('pointerup', onBatchBackdropUp);
        modal.addEventListener('pointerleave', onBatchBackdropReset);
        modal.addEventListener('pointercancel', onBatchBackdropReset);
        return modal;
    }

    function closeBatchConfirmModal(){
        const modal = document.getElementById('pm-batch-delete-modal');
        if(!modal) return;
        modal.classList.remove('active');
        activeBatchConfirmState = null;
        syncModalScrollLock();
    }

    function openBatchConfirmModal(count, onConfirm){
        const modal = ensureBatchConfirmModal();
        if(!modal) return;
        const ack = modal.querySelector('.pm-batch-delete-ack-input');
        const confirmBtn = modal.querySelector('[data-action="confirm"]');
        const desc = modal.querySelector('.pm-batch-delete-desc');

        if(desc){
            desc.textContent = `即将删除 ${count} 条已勾选记录，该操作通常不可恢复。`;
        }
        if(ack){
            ack.checked = false;
        }
        if(confirmBtn){
            confirmBtn.disabled = true;
        }

        activeBatchConfirmState = { onConfirm };
        modal.classList.add('active');
        syncModalScrollLock();
    }

    function emitManagedBulkEvent(state, eventName, ids){
        const detail = {
            table: state ? state.table : null,
            tableId: state && state.table ? (state.table.id || state.table.dataset.manageKey || '') : '',
            ids: Array.isArray(ids) ? ids.slice() : [],
            handled: false
        };
        const ev = new CustomEvent(eventName, { detail, bubbles: true });
        document.dispatchEvent(ev);
        return detail;
    }

    function runManagedBatchAction(state, action, ids){
        if(!state || !state.table || !Array.isArray(ids) || !ids.length) return;
        const fnKey = action === 'download' ? 'batchDownloadHandler' : 'batchDeleteHandler';
        const fnName = String(state.table.dataset[fnKey] || '').trim();
        const configuredHandler = (fnName && typeof window[fnName] === 'function') ? window[fnName] : null;
        const globalHook = action === 'download' ? window.onManagedTableBatchDownload : window.onManagedTableBatchDelete;

        // Execute exactly one callback channel to avoid duplicate side effects.
        const selectedHandler = configuredHandler || (typeof globalHook === 'function' ? globalHook : null);
        let handled = false;

        if(selectedHandler){
            try {
                selectedHandler(ids.slice(), state.table, state);
                handled = true;
            } catch (err) {
                showAppToast(`批量${action === 'download' ? '下载' : '删除'}执行失败: ${err && err.message ? err.message : err}`, true);
                return;
            }
        }

        if(!handled){
            const detail = emitManagedBulkEvent(state, action === 'download' ? 'pm:table-batch-download' : 'pm:table-batch-delete', ids);
            if(detail.handled) handled = true;
        }

        if(!handled){
            showAppToast(`批量${action === 'download' ? '下载' : '删除'}未执行，请为该页面配置 data-batch-${action}-handler 或全局回调。`, true);
        }
    }

    function ensureManagedBatchBarHost(state){
        if(!state || !state.toolbar) return null;
        let host = state.toolbar.querySelector('.pm-managed-batch-host');
        if(host) return host;
        host = document.createElement('div');
        host.className = 'pm-managed-batch-host';
        const right = state.toolbar.querySelector('.pm-table-toolbar-right');
        if(right && right.parentNode === state.toolbar){
            state.toolbar.insertBefore(host, right);
        } else {
            state.toolbar.appendChild(host);
        }
        return host;
    }

    function ensureManagedBatchBar(state){
        if(!state || !state.wrap) return null;
        if(state.batchBar && document.body.contains(state.batchBar)) return state.batchBar;

        const bar = document.createElement('div');
        bar.className = 'pm-batch-float-bar';
        const isOrderProductExtras = state.table && String(state.table.dataset.orderProductBatchExtras || '') === '1';
        bar.innerHTML = [
            '<span class="pm-batch-float-count">已勾选 0 条</span>',
            isOrderProductExtras ? '<button type="button" class="btn-secondary" data-action="shipping-plan-batch">批量替换发货方案</button>' : '',
            '<button type="button" class="btn-secondary" data-action="download">批量下载数据</button>',
            '<button type="button" class="btn-danger" data-action="delete">批量删除</button>'
        ].join('');
        // 默认右下角浮动；仅当表上声明 data-batch-bar-embedded="1" 时嵌入工具栏（避免与「每页/共几条」抢位）
        const useEmbedded = state.table && String(state.table.dataset.batchBarEmbedded || '').trim() === '1';
        const host = (useEmbedded && state.toolbar) ? ensureManagedBatchBarHost(state) : null;
        if(host){
            host.appendChild(bar);
            bar.classList.add('pm-batch-float-bar--embedded');
        } else {
            document.body.appendChild(bar);
            const tid = state.table && state.table.id ? String(state.table.id).trim() : '';
            if(tid){
                bar.dataset.pmTableId = tid;
            }
        }

        const downloadBtn = bar.querySelector('[data-action="download"]');
        const deleteBtn = bar.querySelector('[data-action="delete"]');
        const shipPlanBatchBtn = bar.querySelector('[data-action="shipping-plan-batch"]');

        if(shipPlanBatchBtn){
            shipPlanBatchBtn.addEventListener('click', () => {
                const ids = getManagedSelectedIds(state);
                if(!ids.length) return;
                try {
                    document.dispatchEvent(new CustomEvent('sitjoy:order-product-batch-shipping-plan-verify', {
                        bubbles: true,
                        detail: { ids: ids.slice(), table: state.table }
                    }));
                } catch(_err){
                }
            });
        }

        if(downloadBtn){
            downloadBtn.addEventListener('click', () => {
                const ids = getManagedSelectedIds(state);
                if(!ids.length) return;
                runManagedBatchAction(state, 'download', ids);
            });
        }

        if(deleteBtn){
            deleteBtn.addEventListener('click', () => {
                const ids = getManagedSelectedIds(state);
                if(!ids.length) return;
                openBatchConfirmModal(ids.length, () => {
                    runManagedBatchAction(state, 'delete', ids);
                });
            });
        }

        state.batchBar = bar;
        return bar;
    }

    function getPreviewSaveBarOffset(){
        let maxHeight = 0;
        document.querySelectorAll('.preview-savebar').forEach((bar) => {
            const style = window.getComputedStyle(bar);
            if(style.display === 'none' || style.visibility === 'hidden') return;
            const rect = bar.getBoundingClientRect();
            if(!rect || rect.height <= 0) return;
            maxHeight = Math.max(maxHeight, Math.ceil(rect.height) + 18);
        });
        return maxHeight;
    }

    function positionManagedBatchBar(state){
        if(!state || !state.batchBar) return;
        if(state.batchBar.classList.contains('pm-batch-float-bar--embedded')) return;
        const baseBottom = 18;
        const extraBottom = getPreviewSaveBarOffset();
        state.batchBar.style.bottom = `${baseBottom + extraBottom}px`;
    }

    function syncManagedBatchBarAsync(state){
        if(!state) return;
        if(state.batchSyncTimer){
            window.clearTimeout(state.batchSyncTimer);
            state.batchSyncTimer = 0;
        }
        state.batchSyncTimer = window.setTimeout(() => {
            state.batchSyncTimer = 0;
            syncManagedBatchBar(state);
        }, 30);
    }

    function syncManagedBatchBar(state){
        if(!state || !state.tbody || state.light) return;
        const checkboxList = getManagedSelectionCheckboxes(state);
        if(!checkboxList.length){
            if(state.batchBar) state.batchBar.classList.remove('active');
            return;
        }

        const ids = getManagedSelectedIds(state);
        const bar = ensureManagedBatchBar(state);
        if(!bar) return;
        const countEl = bar.querySelector('.pm-batch-float-count');
        if(countEl){
            countEl.textContent = `已勾选 ${ids.length} 条`;
        }
        bar.classList.toggle('active', ids.length > 0);
        positionManagedBatchBar(state);
        if(state.table && String(state.table.dataset.orderProductBatchExtras || '') === '1'){
            try {
                document.dispatchEvent(new CustomEvent('sitjoy:order-product-batch-toolbar-sync', { bubbles: true }));
            } catch(_e){
            }
        }
    }

    function ensureManagedBatchHandlers(state){
        if(!state || !state.table || state.light) return;
        const hasCheckbox = getManagedSelectionCheckboxes(state).length > 0;
        if(!hasCheckbox) return;
        if(!String(state.table.dataset.batchDownloadHandler || '').trim()){
            state.table.dataset.batchDownloadHandler = 'onManagedTableBatchDownload';
        }
        if(!String(state.table.dataset.batchDeleteHandler || '').trim()){
            state.table.dataset.batchDeleteHandler = 'onManagedTableBatchDelete';
        }
    }

    function resolveSortColumnKeyFromHeaderCell(cell){
        if(!cell) return '';
        const sortKey = String(cell.getAttribute('data-sort-key') || '').trim();
        if(sortKey) return sortKey;
        return String(cell.dataset.manageColKey || '').trim();
    }

    function buildSortKeyToManageColKeyMap(state){
        const map = new Map();
        const headerRow = state ? getPrimaryHeaderRow(state) : null;
        const fallbackRow = state && state.table && state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0];
        [headerRow, fallbackRow].filter(Boolean).forEach((row) => {
            Array.from(row.cells || []).forEach((cell) => {
                const manageKey = String(cell.dataset.manageColKey || '').trim();
                const sortKey = String(cell.getAttribute('data-sort-key') || '').trim();
                if(manageKey) map.set(manageKey, manageKey);
                if(sortKey) map.set(sortKey, manageKey || sortKey);
            });
        });
        return map;
    }

    function getRowCellForSortKey(row, state, sortKey){
        if(!row) return null;
        const key = String(sortKey || '').trim();
        if(!key) return null;
        const cellMap = mapRowByKey(row);
        if(cellMap.has(key)) return cellMap.get(key);
        if(state){
            if(!state._sortKeyToManageColKey) state._sortKeyToManageColKey = buildSortKeyToManageColKeyMap(state);
            const manageKey = state._sortKeyToManageColKey.get(key);
            if(manageKey && cellMap.has(manageKey)) return cellMap.get(manageKey);
            if(manageKey){
                for(const cell of Array.from(row.cells || [])){
                    if(String(cell.dataset.manageColKey || '').trim() === manageKey) return cell;
                }
            }
        }
        for(const cell of Array.from(row.cells || [])){
            if(String(cell.getAttribute('data-sort-key') || '').trim() === key) return cell;
        }
        return getRowCellByKey(row, key);
    }

    function tableBodyHasGroupedAggregateRows(state){
        const tbody = state && (state.tbody || (state.table && state.table.tBodies && state.table.tBodies[0]));
        if(!tbody || !tbody.rows) return false;
        return Array.from(tbody.rows || []).some((row) => isGroupedAggregateRow(row));
    }

    function appendGroupedAggregateSort(state, stack){
        const tbody = state && (state.tbody || (state.table && state.table.tBodies && state.table.tBodies[0]));
        if(!tbody) return;
        const bodyRows = Array.from(tbody.rows || []);
        const normalizedStack = normalizeManagedSortStack(stack);
        const cmp = normalizedStack.length
            ? (a, b) => compareRowsForManagedSortStack(a, b, normalizedStack, state)
            : (a, b) => Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0');
        const docFrag = document.createDocumentFragment();
        let i = 0;
        while(i < bodyRows.length){
            const row = bodyRows[i];
            if(!isGroupedAggregateRow(row)){
                const flat = [];
                while(i < bodyRows.length && !isGroupedAggregateRow(bodyRows[i])){
                    flat.push(bodyRows[i]);
                    i++;
                }
                flat.sort(cmp);
                flat.forEach((child) => docFrag.appendChild(child));
                continue;
            }
            const groupRow = row;
            const children = [];
            i++;
            while(i < bodyRows.length && !isGroupedAggregateRow(bodyRows[i])){
                children.push(bodyRows[i]);
                i++;
            }
            children.sort(cmp);
            docFrag.appendChild(groupRow);
            children.forEach((child) => docFrag.appendChild(child));
        }
        tbody.appendChild(docFrag);
    }

    function dispatchManagedTableSortChange(state){
        if(!state || !state.table) return;
        try {
            state.table.dispatchEvent(new CustomEvent('pm-managed-sort-change', {
                bubbles: true,
                detail: {
                    table: state.table,
                    stack: normalizeManagedSortStack(state.sortStack).slice()
                }
            }));
        } catch (_e) {}
    }
    function applySort(state){
        const stack = normalizeManagedSortStack(state && state.sortStack);
        state.sortStack = stack;
        syncLegacySortFieldsFromStack(state);
        if(state) state._sortKeyToManageColKey = null;
        const rows = getDataRows(state);
        if(!rows.length) return;

        if(tableBodyHasGroupedAggregateRows(state)){
            appendGroupedAggregateSort(state, stack);
            state.sortApplied = stack.length > 0;
            syncGroupedAggregateRowsAfterFilter(state);
            return;
        }

        if(!stack.length){
            if(!state.sortApplied) return;
            rows.sort((a, b) => Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0'));
            const sortedOrigins = rows.map(r => Number(r.dataset.sortOrigin || '0'));
            const sameOrder = Array.from(state.tbody.rows || []).every((r, idx) => Number(r.dataset.sortOrigin || '0') === sortedOrigins[idx]);
            if(!sameOrder) rows.forEach(row => state.tbody.appendChild(row));
            state.sortApplied = false;
            return;
        }

        rows.sort((a, b) => compareRowsForManagedSortStack(a, b, stack, state));

        const sortedOrigins = rows.map(r => Number(r.dataset.sortOrigin || '0'));
        const sameOrder = Array.from(state.tbody.rows || []).every((r, idx) => Number(r.dataset.sortOrigin || '0') === sortedOrigins[idx]);
        if(!sameOrder) rows.forEach(row => state.tbody.appendChild(row));
        state.sortApplied = true;
    }

    function compareRowsForManagedSortStack(a, b, stack, state){
        for(let i = 0; i < stack.length; i++){
            const entry = stack[i];
            const key = String(entry.key || '').trim();
            if(!key) continue;
            const dir = entry.dir === 'asc' ? 'asc' : 'desc';
            const aCell = getRowCellForSortKey(a, state, key);
            const bCell = getRowCellForSortKey(b, state, key);
            const av = readCellComparableValue(aCell);
            const bv = readCellComparableValue(bCell);
            let cmp = 0;
            if(typeof av === 'number' && typeof bv === 'number'){
                cmp = av - bv;
            } else if(av === bv){
                cmp = 0;
            } else {
                cmp = String(av).localeCompare(String(bv), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
            }
            if(cmp !== 0) return dir === 'asc' ? cmp : -cmp;
        }
        return Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0');
    }

    function toggleManagedSortStackEntry(state, origin){
        const key = String(origin || '').trim();
        if(!key) return;
        const stack = normalizeManagedSortStack(state.sortStack);
        const idx = stack.findIndex(item => item.key === key);
        if(idx < 0){
            stack.push({ key, dir: 'desc' });
        } else if(stack[idx].dir === 'desc'){
            stack[idx].dir = 'asc';
        } else {
            stack.splice(idx, 1);
        }
        state.sortStack = stack;
        syncLegacySortFieldsFromStack(state);
        if(state) state._sortKeyToManageColKey = null;
        if(state.table && !tableSkipsFilterPersist(state.table)){
            persistManagedSortStack(state.table, stack);
        }
    }

    function restoreManagedSortStackFromStorageIfNeeded(state){
        if(!state || !state.table || tableSkipsFilterPersist(state.table)) return;
        if(managedSortStackHasEntries(state)) return;
        const saved = readPersistedSortStack(state.table);
        if(!saved.length) return;
        state.sortStack = saved;
        syncLegacySortFieldsFromStack(state);
    }

    function clearManagedTableSort(state){
        if(!state || !state.table) return;
        state.sortStack = [];
        syncLegacySortFieldsFromStack(state);
        clearPersistedSortStack(state.table);
        refreshSortHeaderUi(state);
        applySort(state);
        applyPagination(state);
        dispatchManagedTableSortChange(state);
        if(typeof showAppToast === 'function'){
            showAppToast('排序已清除', false, 1200);
        }
    }

    function refreshSortHeaderUi(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow) return;
        const stack = normalizeManagedSortStack(state && state.sortStack);
        const stackMap = new Map(stack.map((item, idx) => [item.key, { dir: item.dir, order: idx + 1 }]));
        Array.from(headerRow.cells || []).forEach(cell => {
            const origin = String(cell.dataset.manageColKey || '').trim();
            if(cell.dataset.disableSort === '1') return;
            cell.classList.remove('pm-sortable', 'pm-sort-asc', 'pm-sort-desc');
            cell.removeAttribute('data-sort-order');
            if(isManagedTableNoSortNoFilterHeaderCell(cell)) return;
            if(state.lockedColumns.has(origin)) return;
            cell.classList.add('pm-sortable');
            const sortKey = String(cell.getAttribute('data-sort-key') || '').trim();
            const active = stackMap.get(sortKey) || stackMap.get(origin);
            if(!active) return;
            if(active.dir === 'asc') cell.classList.add('pm-sort-asc');
            else cell.classList.add('pm-sort-desc');
            cell.dataset.sortOrder = String(active.order);
        });
    }

    function ensureSortableHeaders(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow) return;
        Array.from(headerRow.cells).forEach(cell => {
            if(cell.dataset.sortBound === '1') return;
            if(cell.dataset.disableSort === '1' || isManagedTableNoSortNoFilterHeaderCell(cell)){
                cell.dataset.sortBound = '1';
                return;
            }
            cell.dataset.sortBound = '1';
            cell.addEventListener('click', (event) => {
                if(Date.now() < suppressSortUntil) return;
                if(event.target.closest('.pm-col-resizer')) return;
                if(event.target.closest('input, button, select, textarea, label, a')) return;
                if(cell.querySelector('input[type="checkbox"]')) return;
                const manageKey = String(cell.dataset.manageColKey || '').trim();
                const sortKey = resolveSortColumnKeyFromHeaderCell(cell);
                if(state.lockedColumns.has(manageKey)) return;
                toggleManagedSortStackEntry(state, sortKey);
                refreshSortHeaderUi(state);
                applySort(state);
                applyPagination(state);
                syncManagedBatchBar(state);
                dispatchManagedTableSortChange(state);
            });
        });
    }

    function syncTopScroll(state){
        if(!state.topScroll || !state.topScrollInner || !state.wrap) return;
        let headerWidth = sumManagedColgroupVisibleWidthPx(state);
        if(headerWidth < 1){
            const headerRow = getPrimaryHeaderRow(state);
            if(headerRow){
                Array.from(headerRow.cells || []).forEach(cell => {
                    const key = String(cell.dataset.manageColKey || '').trim();
                    if(isManagedColumnSlotHidden(state, key)) return;
                    const styled = parseFloat(cell.style.width || '0') || 0;
                    const measured = Math.ceil(cell.getBoundingClientRect().width || 0);
                    headerWidth += Math.max(styled, measured, 36);
                });
            }
        }
        const width = Math.max(state.table.scrollWidth, state.wrap.scrollWidth, headerWidth, state.wrap.clientWidth);
        const scrollbarWidth = Math.max(0, state.wrap.offsetWidth - state.wrap.clientWidth);
        if(state.headWrap) state.headWrap.style.paddingRight = `${scrollbarWidth}px`;
        state.topScroll.style.paddingRight = `${scrollbarWidth}px`;
        state.topScrollInner.style.width = `${width}px`;
        const shouldShow = width > (state.wrap.clientWidth + 1) || state.wrap.scrollWidth > (state.wrap.clientWidth + 1);
        state.topScroll.style.display = shouldShow ? '' : 'none';
        state.topScroll.scrollLeft = state.wrap.scrollLeft;
        if(state.headWrap) state.headWrap.scrollLeft = state.wrap.scrollLeft;
    }

    function refreshManagedTable(state){
        if(state && state.suppressManagedRefresh) return;
        if(activeGridSelection && activeGridSelection.state === state){
            const hasDetached = Array.from(activeGridSelection.selectedCells || []).some(cell => !cell || !cell.isConnected);
            if(hasDetached) clearGridSelection();
        }

        if(state.isRefreshing){
            state.needRefresh = true;
            return;
        }
        state.isRefreshing = true;

        const headerMeta = getHeaderMeta(state.table);
        const headerCount = headerMeta.length;
        if(!headerCount) {
            state.isRefreshing = false;
            return;
        }

        state.headerCount = headerCount;
        ensureManagedColumnKeys(state, headerMeta);
        ensureManagedTableColgroup(state);

        const validKeys = headerMeta.map(meta => String(meta.key || '').trim()).filter(Boolean);
        const layoutSig = String(state.table && state.table.dataset && state.table.dataset.sjManageLayoutSig ? state.table.dataset.sjManageLayoutSig : '');
        const headerSignature = headerMeta
            .slice()
            .sort((a, b) => String(a.key || '').localeCompare(String(b.key || ''), 'zh-Hans-CN', { sensitivity: 'base' }))
            .map(meta => String(meta.key || '').trim())
            .join('|') + '|__layout__|' + layoutSig;

        const headerStructureChanged = headerSignature !== state.headerSignature;

        if(headerStructureChanged){
            state.headerSignature = headerSignature;
            state.headerCount = headerCount;
            state.headers = headerMeta.map(meta => ({ origin: meta.origin, key: meta.key, label: meta.label }));
            state.visibleColumns = readPersistedColumns(state.table, headerMeta);
            state.columnOrder = readPersistedOrder(state.table, headerMeta);
            const persistedWidths = readPersistedColumnWidths(state.table);
            state.defaultColumnWidths = {};
            headerMeta.forEach(meta => {
                const key = String(meta.key || '').trim();
                const compact = computeDefaultColumnWidth(state, meta);
                state.defaultColumnWidths[key] = compact;
            });
            const resolvedWidths = {};
            headerMeta.forEach(meta => {
                const key = String(meta.key || '').trim();
                const legacyKey = String(meta.origin);
                const compact = state.defaultColumnWidths[key] || computeDefaultColumnWidth(state, meta);
                const stored = persistedWidths[key];
                const legacy = persistedWidths[legacyKey];
                const hasStored = Number.isFinite(Number(stored ?? legacy)) && Number(stored ?? legacy) > 0;
                const width = Number(stored ?? legacy ?? compact);
                const raw = Number.isFinite(width) && width > 0 ? width : compact;
                /* 已保存宽度尊重用户拖窄；仅保证不低于绝对最小列宽 */
                resolvedWidths[key] = hasStored
                    ? Math.max(getPmTableColResizeMin(state), Math.round(raw))
                    : raw;
            });
            if(isPmMonthColWidthSyncTable(state.table)){
                const monthKeys = validKeys.filter(k => isPmMonthColKeyForWidthSync(state.table, k));
                if(monthKeys.length){
                    const gw = resolvePmMonthGroupWidthFromPersisted(state.table, persistedWidths, monthKeys, resolvedWidths);
                    monthKeys.forEach(k => {
                        resolvedWidths[k] = gw;
                    });
                    resolvedWidths[PM_MONTH_COL_GROUP_WIDTH_KEY] = gw;
                }
            }
            state.columnWidths = resolvedWidths;
            try {
                localStorage.setItem(makeStorageKey(state.table, 'column-widths'), JSON.stringify(state.columnWidths || {}));
            } catch (_) {
            }
            state.lockedColumns = new Set(
                headerMeta
                    .filter(meta => isLockedLayoutColumn(meta.cell, meta.label))
                    .map(meta => String(meta.key || '').trim())
            );
            state.lockedColumns.forEach(key => state.visibleColumns.add(String(key || '').trim()));
            state.pinnedColumns = resolvePinnedColumnsForTable(state.table, headerMeta, state.lockedColumns);
            persistPinnedColumns(state);
            if(String(state.table.dataset.pmDefaultPinnedFirst || '') === '1' && validKeys[0]){
                let hasStoredPins = false;
                try{
                    hasStoredPins = localStorage.getItem(makeStorageKey(state.table, 'pinned-columns')) != null;
                } catch(_e){
                }
                if(!hasStoredPins){
                    state.pinnedColumns.add(validKeys[0]);
                    persistPinnedColumns(state);
                }
            }
            if(!state.light){
                state.columnsWrap.style.display = headerCount >= 2 ? '' : 'none';
                renderColumnPanel(state);
            }
        }

        const lockedNow = new Set(
            headerMeta
                .filter(meta => isLockedLayoutColumn(meta.cell, meta.label))
                .map(meta => String(meta.key || '').trim())
                .filter(Boolean)
        );
        state.lockedColumns = lockedNow;
        let lockedVisChanged = false;
        lockedNow.forEach(key => {
            if(!state.visibleColumns.has(key)){
                state.visibleColumns.add(key);
                lockedVisChanged = true;
            }
        });
        if(lockedVisChanged && !headerStructureChanged && !state.light){
            applyColumnVisibility(state);
        }

        if(!headerStructureChanged && state.pinnedColumns){
            const nextPins = resolvePinnedColumnsForTable(state.table, headerMeta, lockedNow);
            const cur = Array.from(state.pinnedColumns.values()).sort().join('|');
            const nxt = Array.from(nextPins.values()).sort().join('|');
            if(cur !== nxt){
                state.pinnedColumns = nextPins;
                persistPinnedColumns(state);
                applyPinnedColumns(state, { force: true });
            }
        }

        validKeys.forEach(key => {
            if(!state.columnOrder.includes(key)) state.columnOrder.push(key);
        });
        state.columnOrder = normalizeManagedTableColumnOrder(state.columnOrder || [], validKeys, headerMeta);

        ensureRowSortOrigin(state);
        ensureManagedBatchHandlers(state);
        if(!state.light){
            if(headerStructureChanged){
                applyColumnOrder(state);
                applyColumnVisibility(state);
                applyColumnWidths(state);
                applyPinnedColumns(state);
            } else {
                syncManagedTableBodyLayout(state);
            }
        } else if(String(state.table.dataset.pmLightStickyLayout || '') === '1'){
            if(headerStructureChanged){
                applyColumnOrder(state);
                applyColumnVisibility(state);
                applyColumnWidths(state);
                applyPinnedColumns(state);
            } else {
                syncManagedTableBodyLayout(state);
            }
        }
        ensureSortableHeaders(state);
        restoreManagedSortStackFromStorageIfNeeded(state);
        refreshSortHeaderUi(state);
        if(managedSortStackHasEntries(state)) {
            applySort(state);
        }
        if(!state.light){
            if(headerStructureChanged) ensureResizeHandles(state);
            applyPagination(state);
            syncManagedBatchBar(state);
            syncTopScroll(state);
            if(activeColumnsPanelState === state) repositionColumnsPanel(state);
            if(activeResetMenuState === state) repositionResetMenu(state);
        } else if(state.light && String(state.table.dataset.pmLightStickyLayout || '') === '1'
            && String(state.table.dataset.pmLightAllowColResize || '') === '1'){
            if(headerStructureChanged) ensureResizeHandles(state);
        }
        ensureManagedTableColumnFilter(state);
        restoreManagedColumnFiltersFromStorageIfNeeded(state);
        reapplyManagedColumnFiltersFromHandle(state);
        applyNumericColumnLayoutForTable(state.table);

        state.isRefreshing = false;
        if(state.needRefresh){
            state.needRefresh = false;
            window.requestAnimationFrame(() => refreshManagedTable(state));
        }
    }

    function createManagedTable(table, index){
        if(managedTableState.has(table) || !shouldManageTable(table)) return;

        const manageMode = String(table.dataset.tableManageMode || '').trim().toLowerCase();
        const isLightTable = manageMode === 'light';

        if(!table.id) table.dataset.manageKey = `managed-${index + 1}`;
        table.classList.add('is-managed-table');
        table.classList.add('pm-table');

        let wrap = table.parentElement;
        let headWrap = null;
        let headTable = null;
        let toolbar = null;
        let topScroll = null;
        let topScrollInner = null;

        if(!isLightTable){
            if(!wrap || !wrap.classList.contains('pm-table-wrap')){
                wrap = document.createElement('div');
                wrap.className = 'pm-table-wrap';
                table.parentNode.insertBefore(wrap, table);
                wrap.appendChild(table);
            }
            const useDetachedHeader = managedTableUsesDetachedHeader(table);
            wrap.classList.add('is-managed-wrap', 'pm-managed-body-wrap');
            wrap.classList.toggle('pm-uses-detached-header', useDetachedHeader);
            if(table.tHead){
                if(useDetachedHeader){
                    table.tHead.classList.add('pm-managed-hidden-head');
                } else {
                    table.tHead.classList.remove('pm-managed-hidden-head');
                }
            }

            if(useDetachedHeader){
                headWrap = document.createElement('div');
                headWrap.className = 'pm-table-wrap pm-managed-head-wrap is-managed-wrap';
                headTable = document.createElement('table');
                headTable.className = `${table.className} pm-managed-head-table`;
                headTable.setAttribute('data-disable-table-manage', '1');
                headWrap.appendChild(headTable);
            }

            toolbar = document.createElement('div');
            toolbar.className = 'pm-table-toolbar';
            toolbar.innerHTML = `
                <div class="pm-table-toolbar-left">
                    <label>每页</label>
                    <select class="pm-table-page-size" data-universal-compact="1" data-universal-no-search="1"></select>
                    <span class="pm-table-info"></span>
                </div>
                <div class="pm-table-toolbar-right">
                    <button type="button" class="pm-table-clear-filters btn-secondary" title="清除列筛选与页面筛选记忆">清除筛选</button>
                    <button type="button" class="pm-table-clear-sort btn-secondary" title="清除多级列排序">清除排序</button>
                    <div class="pm-table-reset-group">
                        <button type="button" class="pm-table-columns-reset btn-secondary" title="重置列宽、字段排序、字段显示">重置</button>
                        <div class="pm-table-reset-menu" aria-label="重置菜单">
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="width">重置列宽</button>
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="order">重置字段排序</button>
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="visibility">重置字段显示</button>
                        </div>
                    </div>
                    <div class="pm-table-columns">
                        <button type="button" class="pm-table-columns-trigger btn-secondary" aria-expanded="false">字段显示与冻结窗格</button>
                        <div class="pm-table-columns-panel"></div>
                    </div>
                    <div class="pm-table-pager">
                        <button type="button" class="pm-table-prev btn-secondary">上一页</button>
                        <span class="pm-table-pager-current">1 / 1</span>
                        <button type="button" class="pm-table-next btn-secondary">下一页</button>
                    </div>
                </div>
            `;
            wrap.parentNode.insertBefore(toolbar, wrap);

            topScroll = document.createElement('div');
            topScroll.className = 'pm-table-top-scroll';
            topScrollInner = document.createElement('div');
            topScrollInner.className = 'pm-table-top-scroll-inner';
            topScroll.appendChild(topScrollInner);
            if(headWrap) wrap.parentNode.insertBefore(headWrap, wrap);
            wrap.parentNode.insertBefore(topScroll, wrap);
        }

        const state = {
            table,
            tbody: table.tBodies[0],
            wrap,
            headWrap,
            headerTable: headTable,
            detachedHeader: !isLightTable && managedTableUsesDetachedHeader(table),
            toolbar,
            topScroll,
            topScrollInner,
            light: isLightTable,
            pageSizeSelect: toolbar ? toolbar.querySelector('.pm-table-page-size') : null,
            info: toolbar ? toolbar.querySelector('.pm-table-info') : null,
            prevBtn: toolbar ? toolbar.querySelector('.pm-table-prev') : null,
            nextBtn: toolbar ? toolbar.querySelector('.pm-table-next') : null,
            pageCurrent: toolbar ? toolbar.querySelector('.pm-table-pager-current') : null,
            columnsWrap: toolbar ? toolbar.querySelector('.pm-table-columns') : null,
            columnsTrigger: toolbar ? toolbar.querySelector('.pm-table-columns-trigger') : null,
            columnPanel: toolbar ? toolbar.querySelector('.pm-table-columns-panel') : null,
            resetBtn: toolbar ? toolbar.querySelector('.pm-table-columns-reset') : null,
            clearFiltersBtn: toolbar ? toolbar.querySelector('.pm-table-clear-filters') : null,
            clearSortBtn: toolbar ? toolbar.querySelector('.pm-table-clear-sort') : null,
            resetWrap: toolbar ? toolbar.querySelector('.pm-table-reset-group') : null,
            resetMenu: toolbar ? toolbar.querySelector('.pm-table-reset-menu') : null,
            pageSize: readPersistedPageSize(table),
            currentPage: 1,
            headerSignature: '',
            headerCount: 0,
            headers: [],
            visibleColumns: new Set(),
            lockedColumns: new Set(),
            pinnedColumns: new Set(),
            columnOrder: [],
            columnWidths: {},
            defaultColumnWidths: {},
            templateColumnWidths: {},
            dragOrigin: null,
            dragPlacement: null,
            sortStack: [],
            sortOrigin: null,
            sortDir: null,
            sortApplied: false,
            isRefreshing: false,
            needRefresh: false,
            refreshScheduled: false,
            bodyUpdateDepth: 0,
            suppressManagedRefresh: false,
            batchBar: null,
            columnFilterHandle: null
        };
        managedTableState.set(table, state);

        if(!isLightTable && state.columnPanel && state.columnPanel.parentNode !== document.body){
            document.body.appendChild(state.columnPanel);
        }
        if(!isLightTable && state.resetMenu && state.resetMenu.parentNode !== document.body){
            document.body.appendChild(state.resetMenu);
        }

        if(!isLightTable){
            if(String(table.dataset.pmSkipClientPagination || '') === '1'){
                const pagerLeft = toolbar.querySelector('.pm-table-toolbar-left');
                const pagerRight = toolbar.querySelector('.pm-table-pager');
                if(pagerLeft) pagerLeft.style.display = 'none';
                if(pagerRight) pagerRight.style.display = 'none';
            }
            PAGE_SIZE_OPTIONS.forEach(size => {
                const option = document.createElement('option');
                option.value = String(size);
                option.textContent = String(size);
                if(size === state.pageSize) option.selected = true;
                state.pageSizeSelect.appendChild(option);
            });

            enhanceSingleSelect(state.pageSizeSelect);

            state.pageSizeSelect.addEventListener('change', () => {
                state.pageSize = Number(state.pageSizeSelect.value || '50');
                state.currentPage = 1;
                persistPageSize(state);
                applyPagination(state);
            });

            state.prevBtn.addEventListener('click', () => {
                if(state.currentPage <= 1) return;
                state.currentPage -= 1;
                applyPagination(state);
            });

            state.nextBtn.addEventListener('click', () => {
                state.currentPage += 1;
                applyPagination(state);
            });

            state.columnsTrigger.addEventListener('click', (event) => {
                event.stopPropagation();
                if(state.columnPanel.classList.contains('open')) closeColumnsPanel(state);
                else openColumnsPanel(state);
            });

            if(state.clearFiltersBtn){
                state.clearFiltersBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    closeAllResetMenus(null);
                    if(activeColumnsPanelState) closeColumnsPanel(activeColumnsPanelState);
                    clearAllManagedTableFilters(state);
                });
            }

            if(state.clearSortBtn){
                state.clearSortBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    closeAllResetMenus(null);
                    if(activeColumnsPanelState) closeColumnsPanel(activeColumnsPanelState);
                    clearManagedTableSort(state);
                });
            }

            if(state.resetBtn && state.resetWrap){
                state.resetBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const nextOpen = !state.resetWrap.classList.contains('is-open');
                    closeAllResetMenus(nextOpen ? state.resetWrap : null);
                    if(nextOpen && activeColumnsPanelState) closeColumnsPanel(activeColumnsPanelState);
                    state.resetWrap.classList.toggle('is-open', nextOpen);
                    if(nextOpen){
                        activeResetMenuState = state;
                        repositionResetMenu(state);
                    } else {
                        hideResetMenuPanel(state.resetMenu);
                        if(activeResetMenuState === state){
                            activeResetMenuState = null;
                        }
                    }
                });
            }

            const onResetMenuItemClick = (event) => {
                const target = event.target && event.target.closest ? event.target.closest('.pm-table-reset-item[data-reset-mode]') : null;
                if(!target) return;
                event.preventDefault();
                const mode = String(target.dataset.resetMode || '').trim();
                if(!mode) return;

                const refreshLayout = () => {
                    applyColumnOrder(state);
                    applyColumnVisibility(state);
                    syncDetachedHeader(state);
                    applyColumnWidths(state);
                    applyPinnedColumns(state);
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    applySort(state);
                    applyPagination(state);
                    syncTopScroll(state);
                    renderColumnPanel(state);
                };

                if(mode === 'width'){
                    try { localStorage.removeItem(makeStorageKey(state.table, 'column-widths')); } catch (_) {}
                    state.templateColumnWidths = {};
                    ensureTemplateColumnWidths(state);
                    const headerMetaNow = getHeaderMeta(state.table);
                    state.defaultColumnWidths = {};
                    headerMetaNow.forEach((meta) => {
                        const k = String(meta.key || '').trim();
                        if(!k) return;
                        state.defaultColumnWidths[k] = computeDefaultColumnWidth(state, meta);
                    });
                    state.columnWidths = Object.assign({}, state.defaultColumnWidths || {});
                    persistColumnWidths(state);
                    applyColumnWidths(state, { enforceMin: false });
                    try {
                        state.table.dispatchEvent(new CustomEvent('pm-reset-column-widths', { bubbles: true }));
                    } catch (_e) {
                    }
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    applySort(state);
                    applyPagination(state);
                    syncTopScroll(state);
                    showAppToast('列宽已重置', false, 1200);
                    closeResetMenu(state);
                    return;
                }

                if(mode === 'order'){
                    const doReset = async () => {
                        // Reset order always clears custom freeze-pane to avoid subtle sticky offset bugs.
                        const locked = new Set();
                        (state.lockedColumns || new Set()).forEach(k => locked.add(String(k || '').trim()));
                        const pinnedNow = state.pinnedColumns || new Set();
                        const hasCustomPinned = Array.from(pinnedNow.values()).some(k => k && !locked.has(String(k || '').trim()));

                        if(hasCustomPinned){
                            const msg = '重置字段排序会取消对「冻结窗格」的保存（仅保留收起列、复选列等布局锚点的默认冻结）。\n\n是否继续重置？';
                            let ok = true;
                            if(window.showAppConfirmAsync){
                                const res = await window.showAppConfirmAsync({
                                    title: '确认重置字段排序',
                                    message: msg,
                                    confirmText: '继续重置',
                                    cancelText: '取消'
                                }).catch(() => false);
                                ok = (res === true) || (res && res.id === 'confirm');
                            } else {
                                ok = window.confirm(msg.replace(/\n\n/g, '\n'));
                            }
                            if(!ok){
                                closeResetMenu(state);
                                return;
                            }
                        }

                        const orderKey = makeStorageKey(state.table, 'column-order');
                        let previousOrder = [];
                        try {
                            const rawPrev = localStorage.getItem(orderKey);
                            if(rawPrev){
                                const parsed = JSON.parse(rawPrev);
                                if(Array.isArray(parsed)) previousOrder = parsed;
                            }
                        } catch (_e) {}

                        try { localStorage.removeItem(orderKey); } catch (_) {}
                        try { localStorage.removeItem(makeStorageKey(state.table, 'pinned-columns')); } catch (_) {}
                        state.pinnedColumns = new Set();
                        locked.forEach(k => state.pinnedColumns.add(String(k || '').trim()));
                        persistPinnedColumns(state);

                        const headerMetaNow = getHeaderMeta(state.table);
                        const validKeysNow = headerMetaNow.map(m => String(m.key || '').trim()).filter(Boolean);
                        const hintOrder = canonicalManagedColumnOrderFromMeta(headerMetaNow);
                        state.columnOrder = normalizeManagedTableColumnOrder(hintOrder, validKeysNow, headerMetaNow);
                        persistColumnOrder(state);
                        refreshLayout();
                        showAppToast('字段排序已重置', false, 1200);
                        closeResetMenu(state);
                    };

                    // fire-and-forget async
                    doReset();
                    return;
                }

                if(mode === 'visibility'){
                    const allVisible = new Set((state.headers || []).map(h => String(h.key || '').trim()).filter(Boolean));
                    state.lockedColumns.forEach(key => allVisible.add(String(key || '').trim()));
                    state.visibleColumns = allVisible;
                    persistColumns(state);
                    applyColumnVisibility(state);
                    syncDetachedHeader(state);
                    // Reset pins to locked columns only
                    state.pinnedColumns = new Set();
                    state.lockedColumns.forEach(key => state.pinnedColumns.add(String(key || '').trim()));
                    persistPinnedColumns(state);
                    applyPinnedColumns(state);
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    applySort(state);
                    applyPagination(state);
                    syncTopScroll(state);
                    renderColumnPanel(state);
                    showAppToast('字段显示已重置', false, 1200);
                    closeResetMenu(state);
                }
            };
            if(state.resetMenu) state.resetMenu.addEventListener('click', onResetMenuItemClick);

            state.wrap.addEventListener('scroll', () => {
                if(state.headWrap && Math.abs(state.headWrap.scrollLeft - state.wrap.scrollLeft) > 1){
                    state.headWrap.scrollLeft = state.wrap.scrollLeft;
                }
                if(state.topScroll && Math.abs(state.topScroll.scrollLeft - state.wrap.scrollLeft) > 1){
                    state.topScroll.scrollLeft = state.wrap.scrollLeft;
                }
            });

            if(state.headWrap){
                state.headWrap.addEventListener('scroll', () => {
                    if(Math.abs(state.wrap.scrollLeft - state.headWrap.scrollLeft) > 1){
                        state.wrap.scrollLeft = state.headWrap.scrollLeft;
                    }
                    if(state.topScroll && Math.abs(state.topScroll.scrollLeft - state.headWrap.scrollLeft) > 1){
                        state.topScroll.scrollLeft = state.headWrap.scrollLeft;
                    }
                });
            }

            state.topScroll.addEventListener('scroll', () => {
                if(Math.abs(state.wrap.scrollLeft - state.topScroll.scrollLeft) > 1){
                    state.wrap.scrollLeft = state.topScroll.scrollLeft;
                }
                if(state.headWrap && Math.abs(state.headWrap.scrollLeft - state.topScroll.scrollLeft) > 1){
                    state.headWrap.scrollLeft = state.topScroll.scrollLeft;
                }
            });

            // When users interact with checkbox controls in the cloned header,
            // forward the change to the original table header control that page scripts bind to.
            if(state.headerTable){
            state.headerTable.addEventListener('change', (event) => {
                const target = event.target;
                if(!target || !(target instanceof HTMLInputElement)) return;
                if(target.type !== 'checkbox') return;

                const cell = target.closest('th,td');
                const row = cell ? cell.parentElement : null;
                if(!cell || !row || !row.parentElement) return;

                const rowIndex = Array.from(row.parentElement.children).indexOf(row);
                const colIndex = Array.from(row.children).indexOf(cell);
                if(rowIndex < 0 || colIndex < 0) return;

                const sourceHead = state.table.tHead;
                const sourceRow = sourceHead && sourceHead.rows ? sourceHead.rows[rowIndex] : null;
                const sourceCell = sourceRow && sourceRow.cells ? sourceRow.cells[colIndex] : null;
                if(!sourceCell) return;

                const sourceCheckbox = sourceCell.querySelector('input[type="checkbox"]');
                if(!sourceCheckbox || sourceCheckbox === target) return;
                sourceCheckbox.checked = target.checked;
                if(sourceCheckbox.classList.contains('pm-table-select-all')){
                    const bodyTable = resolvePmBatchCheckboxTable(sourceCheckbox) || state.table;
                    if(bodyTable){
                        togglePmTableSelectAll(bodyTable, !!target.checked);
                        event.stopPropagation();
                        return;
                    }
                }
                sourceCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
                syncManagedBatchBarAsync(state);
            });
            }

            state.table.addEventListener('change', (event) => {
                const target = event.target;
                if(!target || !(target instanceof HTMLInputElement)) return;
                if(target.type !== 'checkbox') return;
                syncManagedBatchBarAsync(state);
                if(isManagedRowBatchCheckboxInput(target)){
                    syncPmTableSelectAllMasters(state.table);
                }
            });

            state.table.addEventListener('click', (event) => {
                const target = event.target;
                if(!target || !(target instanceof HTMLInputElement)) return;
                if(target.type !== 'checkbox') return;
                syncManagedBatchBarAsync(state);
            });
        }

        const scheduleRefresh = () => {
            if(state.suppressManagedRefresh) return;
            if(state.refreshScheduled) return;
            state.refreshScheduled = true;
            window.requestAnimationFrame(() => {
                state.refreshScheduled = false;
                refreshManagedTable(state);
            });
        };

        const observer = new MutationObserver(() => scheduleRefresh());
        observer.observe(state.tbody, { childList: true, subtree: false });
        state.observer = observer;

        bindGridSelection(state);

        ensureTemplateColumnWidths(state);
        refreshManagedTable(state);
    }

    function enhanceManagedTables(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('table').forEach((table, index) => createManagedTable(table, index));
        enhanceAllTableNumericAlign(scope);
    }

    function repositionManagedBatchBars(){
        managedTableState.forEach((state) => {
            if(!state || !state.batchBar || !state.batchBar.classList.contains('active')) return;
            positionManagedBatchBar(state);
        });
    }

    function parseDateTimeTextValue(value){
        const raw = String(value || '').trim();
        if(!raw) return null;
        const t = raw.replace('T', ' ').slice(0, 16);
        const m = t.match(/^(\d{4})-(\d{2})-(\d{2})[ ](\d{2}):(\d{2})$/);
        if(!m) return null;
        const year = Number(m[1]);
        const month = Number(m[2]);
        const day = Number(m[3]);
        const hour = Number(m[4]);
        const minute = Number(m[5]);
        if(!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day) || !Number.isFinite(hour) || !Number.isFinite(minute)) return null;
        if(month < 1 || month > 12 || day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
        const dt = new Date(year, month - 1, day, hour, minute, 0, 0);
        if(dt.getFullYear() !== year || (dt.getMonth() + 1) !== month || dt.getDate() !== day) return null;
        return { year, month, day, hour, minute };
    }

    function formatDateTimePartsText(parts){
        if(!parts) return '';
        const y = String(parts.year || '').padStart(4, '0');
        const m = String(parts.month || '').padStart(2, '0');
        const d = String(parts.day || '').padStart(2, '0');
        const hh = String(parts.hour || '').padStart(2, '0');
        const mm = String(parts.minute || '').padStart(2, '0');
        return `${y}-${m}-${d} ${hh}:${mm}`;
    }

    function maskDateTimeTextInput(input){
        if(!input) return;
        const digits = String(input.value || '').replace(/[^\d]/g, '').slice(0, 12);
        const y = digits.slice(0, 4);
        const mo = digits.slice(4, 6);
        const d = digits.slice(6, 8);
        const hh = digits.slice(8, 10);
        const mm = digits.slice(10, 12);
        let out = '';
        if(y) out += y;
        if(digits.length > 4) out += '-' + mo;
        else if(digits.length === 4) out += '-';
        if(digits.length > 6) out += '-' + d;
        else if(digits.length === 6) out += '-';
        if(digits.length > 8) out += ' ' + hh;
        else if(digits.length === 8) out += ' ';
        if(digits.length > 10) out += ':' + mm;
        else if(digits.length === 10) out += ':';
        input.value = out;
        try { input.setSelectionRange(out.length, out.length); } catch(_) {}
    }

    function initOptionalDateInputs(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('input.optional-field[type="date"], input.optional-field[type="datetime-local"], input[data-optional-date="1"], input.app-datetime-text-input, input[data-optional-datetime="1"]').forEach(input => {
            if(input.dataset.optionalDateEnhanced === '1') return;
            input.dataset.optionalDateEnhanced = '1';
            input.classList.add('optional-date-input');

            const syncValueClass = () => {
                const hasValue = String(input.value || '').trim().length > 0;
                input.classList.toggle('has-value', hasValue);
            };
            syncValueClass();

            input.addEventListener('change', syncValueClass);
            input.addEventListener('input', syncValueClass);
            input.addEventListener('blur', syncValueClass);

            const inputType = String(input.type || '').toLowerCase();
            if(inputType === 'datetime-local'){
                input.classList.add('app-datetime-input');
                input.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    openDateTimePickerForInput(input, input);
                });
                input.addEventListener('focus', () => openDateTimePickerForInput(input, input));
                input.addEventListener('keydown', (event) => {
                    if(event.key === 'ArrowDown' || event.key === 'Enter'){
                        event.preventDefault();
                        openDateTimePickerForInput(input, input);
                    }
                    if(event.key === 'Escape'){
                        closeDateTimePicker();
                    }
                });
                return;
            }

            const isDateTimeText = input.classList && input.classList.contains('app-datetime-text-input');
            if(isDateTimeText){
                input.classList.add('app-date-input');
                input.classList.add('app-datetime-input');
                input.addEventListener('input', () => {
                    maskDateTimeTextInput(input);
                    syncValueClass();
                });
                input.addEventListener('blur', () => {
                    const parsed = parseDateTimeTextValue(input.value || '');
                    if(!parsed && String(input.value || '').trim()){
                        input.classList.add('app-date-invalid');
                    } else {
                        input.classList.remove('app-date-invalid');
                        if(parsed) input.value = formatDateTimePartsText(parsed);
                    }
                    syncValueClass();
                });
                input.addEventListener('keydown', (event) => {
                    if(event.key === 'ArrowDown' || event.key === 'Enter'){
                        event.preventDefault();
                        openDateTimePickerForInput(input, input);
                    }
                    if(event.key === 'Escape'){
                        closeDateTimePicker();
                    }
                });
                input.addEventListener('click', () => openDateTimePickerForInput(input, input));
                return;
            }

            input.addEventListener('click', () => {
                if(typeof input.showPicker === 'function'){
                    try { input.showPicker(); } catch(_) {}
                }
            });
        });
    }

    function normalizeResetButtons(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.pm-table-columns-reset').forEach((btn) => {
            if(String(btn.textContent || '').trim() !== '重置'){
                btn.textContent = '重置';
            }
            btn.setAttribute('title', '重置列宽、字段排序、字段显示');
        });
    }

    function parseDateText(value){
        const raw = String(value || '').trim();
        if(!raw) return null;
        const normalized = raw.replace(/[./\\]/g, '-');
        const match = normalized.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
        if(!match) return null;
        const year = Number(match[1]);
        const month = Number(match[2]);
        const day = Number(match[3]);
        if(!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) return null;
        if(month < 1 || month > 12 || day < 1 || day > 31) return null;
        const date = new Date(year, month - 1, day);
        if(date.getFullYear() !== year || (date.getMonth() + 1) !== month || date.getDate() !== day) return null;
        return { year, month, day };
    }

    function formatDateParts(parts){
        if(!parts) return '';
        const year = String(parts.year || '').padStart(4, '0');
        const month = String(parts.month || '').padStart(2, '0');
        const day = String(parts.day || '').padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    function todayDateParts(){
        const d = new Date();
        return { year: d.getFullYear(), month: d.getMonth() + 1, day: d.getDate() };
    }

    function normalizeDateInputValue(input){
        if(!input) return '';
        const text = String(input.value || '').trim();
        if(!text){
            input.value = '';
            input.classList.remove('app-date-invalid');
            input.classList.remove('has-value');
            return '';
        }
        const parsed = parseDateText(text);
        if(!parsed){
            input.classList.add('app-date-invalid');
            input.value = '';
            input.classList.remove('has-value');
            return '';
        }
        const normalized = formatDateParts(parsed);
        const changed = normalized !== input.value;
        input.value = normalized;
        input.classList.remove('app-date-invalid');
        input.classList.add('has-value');
        if(changed){
            input.dispatchEvent(new Event('input', { bubbles: true }));
            input.dispatchEvent(new Event('change', { bubbles: true }));
        }
        return normalized;
    }

    function ensureDatePicker(){
        if(activeDatePickerState && activeDatePickerState.panel && document.body.contains(activeDatePickerState.panel)) return activeDatePickerState;

        const panel = document.createElement('div');
        panel.className = 'app-date-picker';
        panel.style.display = 'none';
        panel.innerHTML = [
            '<div class="app-date-picker-head">',
            '  <button type="button" class="app-date-nav" data-nav="prev" aria-label="上个月">‹</button>',
            '  <div class="app-date-title"></div>',
            '  <button type="button" class="app-date-nav" data-nav="next" aria-label="下个月">›</button>',
            '</div>',
            '<div class="app-date-week">',
            '  <span>一</span><span>二</span><span>三</span><span>四</span><span>五</span><span>六</span><span>日</span>',
            '</div>',
            '<div class="app-date-grid"></div>',
            '<div class="app-date-actions">',
            '  <button type="button" class="btn-secondary" data-action="today">今天</button>',
            '  <button type="button" class="btn-secondary" data-action="clear">清空</button>',
            '</div>'
        ].join('');
        document.body.appendChild(panel);

        const state = {
            panel,
            title: panel.querySelector('.app-date-title'),
            grid: panel.querySelector('.app-date-grid'),
            input: null,
            viewYear: 0,
            viewMonth: 0
        };

        const setDateToInput = (parts) => {
            if(!state.input) return;
            const value = parts ? formatDateParts(parts) : '';
            state.input.value = value;
            state.input.classList.toggle('has-value', !!value);
            state.input.classList.remove('app-date-invalid');
            state.input.dispatchEvent(new Event('input', { bubbles: true }));
            state.input.dispatchEvent(new Event('change', { bubbles: true }));
            closeDatePicker();
            state.input.focus();
        };

        panel.querySelectorAll('.app-date-nav').forEach(btn => {
            btn.addEventListener('click', () => {
                const nav = btn.getAttribute('data-nav');
                if(nav === 'prev'){
                    state.viewMonth -= 1;
                    if(state.viewMonth < 1){
                        state.viewMonth = 12;
                        state.viewYear -= 1;
                    }
                } else {
                    state.viewMonth += 1;
                    if(state.viewMonth > 12){
                        state.viewMonth = 1;
                        state.viewYear += 1;
                    }
                }
                renderDatePicker();
            });
        });

        panel.querySelectorAll('[data-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.getAttribute('data-action');
                if(action === 'today') setDateToInput(todayDateParts());
                if(action === 'clear') setDateToInput(null);
            });
        });

        state.grid.addEventListener('click', (e) => {
            const dayBtn = e.target.closest('.app-date-day');
            if(!dayBtn || dayBtn.disabled) return;
            const y = Number(dayBtn.getAttribute('data-year') || '0');
            const m = Number(dayBtn.getAttribute('data-month') || '0');
            const d = Number(dayBtn.getAttribute('data-day') || '0');
            if(!y || !m || !d) return;
            setDateToInput({ year: y, month: m, day: d });
        });

        activeDatePickerState = state;
        return state;
    }

    function parseDateTimeLocalValue(text){
        const raw = String(text || '').trim();
        const m = raw.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/);
        if(!m) return null;
        const year = Number(m[1]);
        const month = Number(m[2]);
        const day = Number(m[3]);
        const hour = Number(m[4]);
        const minute = Number(m[5]);
        if(!Number.isFinite(year) || month < 1 || month > 12 || day < 1 || day > 31) return null;
        if(!Number.isFinite(hour) || hour < 0 || hour > 23 || !Number.isFinite(minute) || minute < 0 || minute > 59) return null;
        const d = new Date(year, month - 1, day);
        if(d.getFullYear() !== year || (d.getMonth() + 1) !== month || d.getDate() !== day) return null;
        return { year, month, day, hour, minute };
    }

    function formatDateTimeLocalParts(parts){
        if(!parts) return '';
        const y = String(parts.year).padStart(4, '0');
        const mo = String(parts.month).padStart(2, '0');
        const d = String(parts.day).padStart(2, '0');
        const h = String(parts.hour).padStart(2, '0');
        const mi = String(parts.minute).padStart(2, '0');
        return `${y}-${mo}-${d}T${h}:${mi}`;
    }

    function positionFloatingNearAnchor(anchor, panel){
        if(!anchor || !panel) return;
        const rect = anchor.getBoundingClientRect();
        const viewportW = window.innerWidth || document.documentElement.clientWidth || 0;
        const viewportH = window.innerHeight || document.documentElement.clientHeight || 0;
        panel.style.visibility = 'hidden';
        panel.style.display = 'block';
        const panelRect = panel.getBoundingClientRect();
        let left = rect.left;
        if(left + panelRect.width > viewportW - 8){
            left = viewportW - panelRect.width - 8;
        }
        left = Math.max(8, left);
        let top = rect.bottom + 8;
        if(top + panelRect.height > viewportH - 8){
            top = rect.top - panelRect.height - 8;
        }
        top = Math.max(8, top);
        panel.style.left = `${left}px`;
        panel.style.top = `${top}px`;
        panel.style.visibility = 'visible';
    }

    function ensureDateTimePicker(){
        if(activeDateTimePickerState && activeDateTimePickerState.panel && document.body.contains(activeDateTimePickerState.panel)){
            return activeDateTimePickerState;
        }
        const panel = document.createElement('div');
        panel.className = 'app-date-picker app-datetime-picker';
        panel.style.display = 'none';
        panel.setAttribute('role', 'dialog');
        panel.innerHTML = [
            '<div class="app-date-picker-head">',
            '  <button type="button" class="app-date-nav" data-dt-nav="prev" aria-label="上个月">‹</button>',
            '  <div class="app-date-title app-dt-title"></div>',
            '  <button type="button" class="app-date-nav" data-dt-nav="next" aria-label="下个月">›</button>',
            '</div>',
            '<div class="app-date-week">',
            '  <span>一</span><span>二</span><span>三</span><span>四</span><span>五</span><span>六</span><span>日</span>',
            '</div>',
            '<div class="app-date-grid app-dt-grid"></div>',
            '<div class="app-datetime-time-row">',
            '  <span class="app-datetime-time-label">时间</span>',
            '  <select class="inline-input app-dt-hour" aria-label="小时"></select>',
            '  <span class="app-datetime-sep">:</span>',
            '  <select class="inline-input app-dt-minute" aria-label="分钟"></select>',
            '</div>',
            '<div class="app-date-actions app-datetime-actions">',
            '  <button type="button" class="btn-secondary" data-dt-action="now">此刻</button>',
            '  <button type="button" class="btn-secondary" data-dt-action="clear">清空</button>',
            '  <button type="button" class="btn-primary" data-dt-action="ok">确定</button>',
            '</div>'
        ].join('');
        document.body.appendChild(panel);
        // Clicks inside the panel replace the day grid (innerHTML), which detaches the
        // original target before the event bubbles to document. A document-level "outside"
        // handler would then see a detached target and wrongly close the picker — stop
        // propagation at the panel so in-panel clicks never reach document.
        panel.addEventListener('click', (e) => { e.stopPropagation(); });
        const hourSel = panel.querySelector('.app-dt-hour');
        const minSel = panel.querySelector('.app-dt-minute');
        for(let i = 0; i < 24; i += 1){
            const o = document.createElement('option');
            const v = String(i).padStart(2, '0');
            o.value = v;
            o.textContent = v;
            hourSel.appendChild(o);
        }
        for(let i = 0; i < 60; i += 1){
            const o = document.createElement('option');
            const v = String(i).padStart(2, '0');
            o.value = v;
            o.textContent = v;
            minSel.appendChild(o);
        }
        const state = {
            panel,
            anchor: null,
            input: null,
            title: panel.querySelector('.app-dt-title'),
            grid: panel.querySelector('.app-dt-grid'),
            hourSel,
            minSel,
            viewYear: 0,
            viewMonth: 0,
            pending: null
        };
        const reposition = () => positionFloatingNearAnchor(state.anchor, state.panel);

        panel.querySelectorAll('[data-dt-nav]').forEach(btn => {
            btn.addEventListener('click', () => {
                const nav = btn.getAttribute('data-dt-nav');
                if(nav === 'prev'){
                    state.viewMonth -= 1;
                    if(state.viewMonth < 1){
                        state.viewMonth = 12;
                        state.viewYear -= 1;
                    }
                } else {
                    state.viewMonth += 1;
                    if(state.viewMonth > 12){
                        state.viewMonth = 1;
                        state.viewYear += 1;
                    }
                }
                renderDateTimePickerCalendar();
            });
        });

        panel.querySelectorAll('[data-dt-action]').forEach(btn => {
            btn.addEventListener('click', () => {
                const action = btn.getAttribute('data-dt-action');
                if(action === 'clear'){
                    commitDateTimePickerValue('');
                    return;
                }
                if(action === 'now'){
                    const now = new Date();
                    state.viewYear = now.getFullYear();
                    state.viewMonth = now.getMonth() + 1;
                    state.hourSel.value = String(now.getHours()).padStart(2, '0');
                    state.minSel.value = String(now.getMinutes()).padStart(2, '0');
                    state.pending = {
                        year: state.viewYear,
                        month: state.viewMonth,
                        day: now.getDate(),
                        hour: Number(state.hourSel.value) || 0,
                        minute: Number(state.minSel.value) || 0
                    };
                    renderDateTimePickerCalendar();
                    commitDateTimePickerValue(formatDateTimeLocalParts(state.pending));
                    return;
                }
                if(action === 'ok'){
                    if(!state.pending) return;
                    const h = Number(state.hourSel.value) || 0;
                    const mi = Number(state.minSel.value) || 0;
                    const full = {
                        year: state.pending.year,
                        month: state.pending.month,
                        day: state.pending.day,
                        hour: h,
                        minute: mi
                    };
                    commitDateTimePickerValue(formatDateTimeLocalParts(full));
                }
            });
        });

        state.grid.addEventListener('click', (e) => {
            const dayBtn = e.target.closest('.app-date-day');
            if(!dayBtn || dayBtn.disabled) return;
            const y = Number(dayBtn.getAttribute('data-year') || '0');
            const m = Number(dayBtn.getAttribute('data-month') || '0');
            const d = Number(dayBtn.getAttribute('data-day') || '0');
            if(!y || !m || !d) return;
            state.pending = {
                year: y,
                month: m,
                day: d,
                hour: Number(state.hourSel.value) || 0,
                minute: Number(state.minSel.value) || 0
            };
            renderDateTimePickerCalendar();
        });

        state.hourSel.addEventListener('change', () => {
            if(state.pending){
                state.pending.hour = Number(state.hourSel.value) || 0;
            }
        });
        state.minSel.addEventListener('change', () => {
            if(state.pending){
                state.pending.minute = Number(state.minSel.value) || 0;
            }
        });

        function renderDateTimePickerCalendar(){
            const year = state.viewYear;
            const month = state.viewMonth;
            state.title.textContent = `${year}年${String(month).padStart(2, '0')}月`;
            const selectedParts = state.pending;
            const today = todayDateParts();
            const firstDay = new Date(year, month - 1, 1);
            const totalDays = new Date(year, month, 0).getDate();
            const lead = (firstDay.getDay() + 6) % 7;
            const html = [];
            for(let i = 0; i < lead; i += 1){
                html.push('<span class="app-date-blank"></span>');
            }
            for(let day = 1; day <= totalDays; day += 1){
                const isToday = today.year === year && today.month === month && today.day === day;
                const isSelected = selectedParts && selectedParts.year === year && selectedParts.month === month && selectedParts.day === day;
                html.push(`<button type="button" class="app-date-day ${isToday ? 'is-today' : ''} ${isSelected ? 'is-selected' : ''}" data-year="${year}" data-month="${month}" data-day="${day}">${day}</button>`);
            }
            state.grid.innerHTML = html.join('');
            reposition();
        }

        function commitDateTimePickerValue(value){
            if(!state.input) return;
            const inp = state.input;
            const raw = String(value || '').trim();
            const inputType = String(inp.type || '').toLowerCase();
            const v = (inputType === 'datetime-local')
                ? raw
                : formatDateTimePartsText(parseDateTimeLocalValue(raw) || parseDateTimeTextValue(raw));
            inp.value = String(v || '').trim();
            if(inp.classList && inp.classList.toggle){
                inp.classList.toggle('has-value', !!inp.value);
            }
            if(inp.classList && inp.classList.remove){
                inp.classList.remove('app-date-invalid');
            }
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            inp.dispatchEvent(new Event('change', { bubbles: true }));
            closeDateTimePicker();
            try { inp.focus(); } catch(_) {}
        }

        state.renderDateTimePickerCalendar = renderDateTimePickerCalendar;
        state.commitDateTimePickerValue = commitDateTimePickerValue;
        state.reposition = reposition;
        activeDateTimePickerState = state;
        return state;
    }

    function closeDateTimePicker(){
        if(!activeDateTimePickerState || !activeDateTimePickerState.panel) return;
        activeDateTimePickerState.panel.classList.remove('open');
        activeDateTimePickerState.panel.style.display = 'none';
        activeDateTimePickerState.input = null;
        activeDateTimePickerState.anchor = null;
    }

    function openDateTimePickerForInput(input, anchorEl){
        if(!input || input.disabled) return;
        const state = ensureDateTimePicker();
        state.input = input;
        state.anchor = anchorEl || input;
        const inputType = String(input.type || '').toLowerCase();
        const parsed = (inputType === 'datetime-local')
            ? parseDateTimeLocalValue(input.value || '')
            : parseDateTimeTextValue(input.value || '');
        const now = new Date();
        const base = parsed || {
            year: now.getFullYear(),
            month: now.getMonth() + 1,
            day: now.getDate(),
            hour: now.getHours(),
            minute: now.getMinutes()
        };
        state.viewYear = base.year;
        state.viewMonth = base.month;
        state.hourSel.value = String(base.hour).padStart(2, '0');
        state.minSel.value = String(base.minute).padStart(2, '0');
        state.pending = {
            year: base.year,
            month: base.month,
            day: base.day,
            hour: base.hour,
            minute: base.minute
        };
        state.renderDateTimePickerCalendar();
        state.panel.style.display = 'block';
        state.panel.classList.add('open');
        state.reposition();
    }

    function closeDatePicker(){
        if(!activeDatePickerState || !activeDatePickerState.panel) return;
        activeDatePickerState.panel.classList.remove('open');
        activeDatePickerState.panel.style.display = 'none';
        activeDatePickerState.input = null;
    }

    function positionDatePicker(input, state){
        if(!input || !state || !state.panel) return;
        const rect = input.getBoundingClientRect();
        const panel = state.panel;
        const viewportW = window.innerWidth || document.documentElement.clientWidth || 0;
        const viewportH = window.innerHeight || document.documentElement.clientHeight || 0;

        panel.style.visibility = 'hidden';
        panel.style.display = 'block';
        const panelRect = panel.getBoundingClientRect();

        let left = rect.left;
        if(left + panelRect.width > viewportW - 8){
            left = viewportW - panelRect.width - 8;
        }
        left = Math.max(8, left);

        let top = rect.bottom + 8;
        if(top + panelRect.height > viewportH - 8){
            top = rect.top - panelRect.height - 8;
        }
        top = Math.max(8, top);

        panel.style.left = `${left}px`;
        panel.style.top = `${top}px`;
        panel.style.visibility = 'visible';
    }

    function renderDatePicker(){
        const state = activeDatePickerState;
        if(!state || !state.input || !state.grid) return;

        const year = state.viewYear;
        const month = state.viewMonth;
        state.title.textContent = `${year}年${String(month).padStart(2, '0')}月`;

        const selected = parseDateText(state.input.value || '');
        const today = todayDateParts();
        const firstDay = new Date(year, month - 1, 1);
        const totalDays = new Date(year, month, 0).getDate();
        const lead = (firstDay.getDay() + 6) % 7;

        const html = [];
        for(let i = 0; i < lead; i += 1){
            html.push('<span class="app-date-blank"></span>');
        }
        for(let day = 1; day <= totalDays; day += 1){
            const isToday = today.year === year && today.month === month && today.day === day;
            const isSelected = selected && selected.year === year && selected.month === month && selected.day === day;
            html.push(`<button type="button" class="app-date-day ${isToday ? 'is-today' : ''} ${isSelected ? 'is-selected' : ''}" data-year="${year}" data-month="${month}" data-day="${day}">${day}</button>`);
        }
        state.grid.innerHTML = html.join('');
        positionDatePicker(state.input, state);
    }

    function openDatePicker(input){
        if(!input || input.disabled || input.readOnly) return;
        const state = ensureDatePicker();
        state.input = input;

        const parsed = parseDateText(input.value || '');
        const base = parsed || todayDateParts();
        state.viewYear = base.year;
        state.viewMonth = base.month;

        renderDatePicker();
        state.panel.style.display = 'block';
        state.panel.classList.add('open');
    }

    function enhanceCustomDateInputs(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('input[type="date"]').forEach(input => {
            if(input.dataset.customDateEnhanced === '1') return;
            input.dataset.customDateEnhanced = '1';
            input.dataset.nativeDateType = 'date';
            input.type = 'text';
            input.classList.add('app-date-input');
            input.autocomplete = 'off';
            input.placeholder = input.getAttribute('placeholder') || 'YYYY-MM-DD';
            input.inputMode = 'numeric';

            input.addEventListener('focus', () => openDatePicker(input));
            input.addEventListener('click', () => openDatePicker(input));
            input.addEventListener('keydown', (event) => {
                if(event.key === 'ArrowDown' || event.key === 'Enter'){
                    event.preventDefault();
                    openDatePicker(input);
                }
                if(event.key === 'Escape'){
                    closeDatePicker();
                }
            });
            input.addEventListener('beforeinput', (event) => {
                if(!event || event.inputType !== 'insertText') return;
                const text = String(event.data || '');
                if(!/^[0-9-]+$/.test(text)){
                    event.preventDefault();
                }
            });
            input.addEventListener('blur', () => {
                window.setTimeout(() => {
                    if(activeDatePickerState && activeDatePickerState.panel && activeDatePickerState.panel.contains(document.activeElement)) return;
                    normalizeDateInputValue(input);
                }, 40);
            });
            input.addEventListener('input', () => {
                input.value = String(input.value || '').replace(/[^0-9-]/g, '').slice(0, 10);
                input.classList.toggle('has-value', !!String(input.value || '').trim());
            });

            normalizeDateInputValue(input);
        });
    }

    window.openDateTimePicker = openDateTimePickerForInput;
    window.closeDateTimePicker = closeDateTimePicker;

    window.initUniversalSingleSelects = initUniversalSingleSelects;
    window.bindPmModalBackdropClose = bindPmModalBackdropClose;
    initPmModalBackdropAutoBind();
    window.refreshUniversalSingleSelect = refreshUniversalSingleSelect;
    window.refreshAllUniversalSingleSelects = function(){
        initUniversalSingleSelects(document);
        universalSelectState.forEach((state, select) => {
            renderDropdownOptions(select, state);
            syncTriggerFromSelect(select, state);
        });
        enhanceCustomDateInputs(document);
        initOptionalDateInputs(document);
    };
    window.showAppResultPanel = showAppResultPanel;
    window.showAppSaveResult = showAppSaveResult;
    window.showAppUploadProgress = showAppUploadProgress;
    window.hideAppUploadProgress = hideAppUploadProgress;
    window.uploadBatchImportFile = uploadBatchImportFile;
    window.handleBatchImportResponse = handleBatchImportResponse;

    function isAuthAdmin(authData){
        if(!authData) return false;
        if(Number(authData.id || 0) === 1) return true;
        const value = authData.is_admin;
        if(value === true || value === 1) return true;
        if(value === false || value === 0 || value == null) return false;
        const num = Number(value);
        if(!Number.isNaN(num)) return num === 1;
        return String(value).trim() === '1';
    }

    function applyHeaderPermissions(authData){
        const permissions = authData && authData.page_permissions ? authData.page_permissions : null;
        if(!permissions) return;
        const adminUser = isAuthAdmin(authData);

        document.querySelectorAll('[data-page-key]').forEach(link => {
            const key = String(link.dataset.pageKey || '');
            if(!key) return;
            const allowed = adminUser || !!permissions[key];
            const item = link.closest('li');
            if(item){
                item.style.display = allowed ? '' : 'none';
            }
        });

        document.querySelectorAll('.sitjoy-sidebar-group').forEach(group => {
            const visibleChildren = Array.from(group.querySelectorAll(':scope .sitjoy-sidebar-sub > li')).filter(li => li.style.display !== 'none');
            if(!visibleChildren.length){
                group.style.display = 'none';
                return;
            }
            group.style.display = '';
        });
    }

    const SITJOY_TABS_STORAGE_KEY = 'sitjoy_nav_tabs_v1';
    const SITJOY_SIDEBAR_COLLAPSED_KEY = 'sitjoy_sidebar_collapsed_v1';
    const SITJOY_HEADER_CACHE_KEY = 'sitjoy_header_html_v1';
    const SITJOY_PAGE_CONTENT_SELECTORS = ['.container', '.home-container', '.pm-layout-root', '.go-play-layout-root', '.mj-layout-root'];
    const SITJOY_SHELL_SKIP_SCRIPT_RE = /header\.js|sitjoy_cell_selection_stats\.js/i;

    let sitjoyHeaderHtmlCache = null;
    let sitjoyNavInFlight = null;
    let sitjoyNavToken = 0;
    const sitjoyPageHtmlCache = new Map();
    const SITJOY_PAGE_CACHE_MAX = 16;

    function normalizeNavPath(path){
        const raw = String(path || '/').split('?')[0].split('#')[0] || '/';
        if(raw.length > 1 && raw.endsWith('/')) return raw.slice(0, -1);
        return raw || '/';
    }

    function buildNavLinkIndex(){
        const map = new Map();
        document.querySelectorAll('.sitjoy-sidebar-nav a[href]').forEach(a => {
            const href = normalizeNavPath(a.getAttribute('href'));
            if(!href) return;
            map.set(href, {
                href,
                label: (a.textContent || '').trim() || href,
                pageKey: String(a.dataset.pageKey || '').trim()
            });
        });
        return map;
    }

    function resolvePageInfoFromPath(path, navIndex){
        const normalized = normalizeNavPath(path);
        const index = navIndex || buildNavLinkIndex();
        if(index.has(normalized)) return Object.assign({ id: normalized }, index.get(normalized));

        let best = null;
        index.forEach((info, href) => {
            if(href === '/') return;
            if(normalized === href || normalized.startsWith(href + '/')){
                if(!best || href.length > best.href.length) best = Object.assign({ id: href }, info);
            }
        });
        if(best) return best;

        const title = (document.title || '').replace(/\s*-\s*SITJOY\s*$/i, '').trim();
        return {
            id: normalized,
            href: normalized,
            label: title || normalized,
            pageKey: ''
        };
    }

    function loadSitjoyTabsState(){
        try {
            const raw = localStorage.getItem(SITJOY_TABS_STORAGE_KEY);
            if(!raw) return { tabs: [] };
            const parsed = JSON.parse(raw);
            if(!parsed || !Array.isArray(parsed.tabs)) return { tabs: [] };
            return { tabs: parsed.tabs.filter(t => t && t.href) };
        } catch (e) {
            return { tabs: [] };
        }
    }

    function saveSitjoyTabsState(state){
        try {
            localStorage.setItem(SITJOY_TABS_STORAGE_KEY, JSON.stringify({ tabs: state.tabs || [] }));
        } catch (e) { /* ignore */ }
    }

    function ensureDefaultPinnedTabs(state){
        const tabs = state.tabs.slice();
        const hasHome = tabs.some(t => normalizeNavPath(t.href) === '/');
        if(!hasHome){
            tabs.unshift({ href: '/', label: '首页', pageKey: 'home', pinned: true });
        }
        state.tabs = tabs;
        return state;
    }

    function upsertCurrentTab(state, pageInfo){
        const href = normalizeNavPath(pageInfo.href);
        let tabs = state.tabs.slice();
        const existingIdx = tabs.findIndex(t => normalizeNavPath(t.href) === href);
        if(existingIdx >= 0){
            tabs[existingIdx] = Object.assign({}, tabs[existingIdx], pageInfo, { href });
        } else {
            tabs.push(Object.assign({ pinned: false }, pageInfo, { href }));
        }
        state.tabs = tabs;
        return state;
    }

    function refreshSitjoyTabsForCurrentPath(path, doc){
        const host = document.getElementById('sitjoyTopTabs');
        if(!host || host.dataset.sitjoyTabsBound !== '1') return;
        const navIndex = buildNavLinkIndex();
        const normalizedPath = normalizeNavPath(path || location.pathname);
        const pageInfo = resolvePageInfoFromPath(normalizedPath, navIndex);
        if(doc && doc.title){
            const titleLabel = doc.title.replace(/\s*-\s*SITJOY\s*$/i, '').trim();
            if(titleLabel) pageInfo.label = titleLabel;
        }
        let state = ensureDefaultPinnedTabs(loadSitjoyTabsState());
        state = upsertCurrentTab(state, pageInfo);
        saveSitjoyTabsState(state);
        renderSitjoyTabs(state, normalizedPath);
    }

    function updateSitjoyTabsActive(activeHref){
        const host = document.getElementById('sitjoyTopTabs');
        if(!host || host.dataset.sitjoyTabsBound !== '1') return;
        renderSitjoyTabs(ensureDefaultPinnedTabs(loadSitjoyTabsState()), activeHref);
    }

    function collectInlineScriptGlobalNames(code, doc){
        const names = new Set();
        const fnRe = /\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g;
        let match;
        while((match = fnRe.exec(code))) names.add(match[1]);
        doc.querySelectorAll('[onclick]').forEach(el => {
            const attr = el.getAttribute('onclick') || '';
            const callRe = /\b([A-Za-z_$][\w$]*)\s*\(/g;
            while((match = callRe.exec(attr))) names.add(match[1]);
        });
        return names;
    }

    function wrapInlinePageScript(code, doc){
        const globals = collectInlineScriptGlobalNames(code, doc);
        const exportLines = [...globals].map(name => (
            `try{if(typeof ${name}==='function'){window.${name}=${name};}}catch(e){}`
        )).join('\n');
        return `(function(){\n${code}\n${exportLines}\n}).call(window);`;
    }

    function sitjoyExternalScriptLoaded(src){
        if(!src) return false;
        try {
            const abs = new URL(src, location.origin).href;
            return Array.from(document.scripts).some(script => {
                if(!script.src) return false;
                return script.src === abs || script.getAttribute('src') === src;
            });
        } catch (e) {
            return false;
        }
    }

    async function fetchSitjoyPageHtml(href, force){
        const key = normalizeNavPath(href);
        if(force) sitjoyPageHtmlCache.delete(key);
        if(!force && sitjoyPageHtmlCache.has(key)) return sitjoyPageHtmlCache.get(key);
        const fetchUrl = force
            ? `${key}${key.includes('?') ? '&' : '?'}_sitjoy=${Date.now()}`
            : key;
        const resp = await fetch(fetchUrl, {
            credentials: 'include',
            headers: { Accept: 'text/html' }
        });
        if(!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const html = await resp.text();
        sitjoyPageHtmlCache.set(key, html);
        while(sitjoyPageHtmlCache.size > SITJOY_PAGE_CACHE_MAX){
            const oldest = sitjoyPageHtmlCache.keys().next().value;
            sitjoyPageHtmlCache.delete(oldest);
        }
        return html;
    }

    function prefetchSitjoyPage(href){
        const key = normalizeNavPath(href);
        if(!key || sitjoyPageHtmlCache.has(key)) return;
        fetchSitjoyPageHtml(key, false).catch(() => {});
    }

    function shouldUseSitjoySoftNav(ev, anchor){
        if(!anchor || ev.defaultPrevented) return false;
        if(ev.button !== 0) return false;
        if(ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return false;
        if(anchor.target === '_blank') return false;
        const href = anchor.getAttribute('href');
        if(!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return false;
        if(/^https?:\/\//i.test(href) && !href.startsWith(location.origin)) return false;
        return document.body.classList.contains('sitjoy-has-shell');
    }

    function removeSitjoyPageStyles(){
        document.querySelectorAll('style[data-sitjoy-page-style], link[data-sitjoy-page-style]').forEach(el => el.remove());
    }

    function applySitjoyPageStyles(doc){
        removeSitjoyPageStyles();
        doc.querySelectorAll('head style').forEach(oldStyle => {
            const style = document.createElement('style');
            style.dataset.sitjoyPageStyle = '1';
            style.textContent = oldStyle.textContent;
            document.head.appendChild(style);
        });
        doc.querySelectorAll('head link[rel="stylesheet"]').forEach(oldLink => {
            const href = oldLink.getAttribute('href') || '';
            if(!href || href.includes('/static/css/style.css') || href.includes('/static/css/tokens.css') || href.includes('/static/css/theme-engine.css') || href.includes('/static/css/app-shell.css')) return;
            if(document.querySelector(`link[rel="stylesheet"][href="${href}"]`)) return;
            const link = document.createElement('link');
            link.rel = 'stylesheet';
            link.href = href;
            link.dataset.sitjoyPageStyle = '1';
            document.head.appendChild(link);
        });
    }

    function extractSitjoyPageNodes(doc){
        const seen = new Set();
        const nodes = [];
        SITJOY_PAGE_CONTENT_SELECTORS.forEach(sel => {
            doc.querySelectorAll(`body > ${sel}`).forEach(el => {
                if(seen.has(el)) return;
                seen.add(el);
                nodes.push(el);
            });
        });
        doc.querySelectorAll('body > *').forEach(el => {
            if(el.id === 'site-header' || el.tagName === 'SCRIPT' || el.tagName === 'FOOTER') return;
            if(seen.has(el)) return;
            seen.add(el);
            nodes.push(el);
        });
        return nodes;
    }

    function removeSitjoyPageScripts(){
        document.querySelectorAll('script[data-sitjoy-page-script]').forEach(el => el.remove());
    }

    function runCapturedPageInitHandlers(handlers, event, context){
        const epoch = window.__sitjoyNavEpoch;
        handlers.forEach(fn => {
            try {
                const result = fn.call(context, event);
                if(result && typeof result.then === 'function'){
                    result.catch(err => {
                        if(window.__sitjoyNavEpoch !== epoch) return;
                        console.warn('Sitjoy page init handler failed', err);
                    });
                }
            } catch (err) {
                console.warn('Sitjoy page init handler failed', err);
            }
        });
    }

    async function runSitjoyPageScripts(doc, pageBody, href){
        removeSitjoyPageScripts();
        const pendingDomReady = [];
        const pendingLoad = [];
        const origDocAdd = document.addEventListener;
        const origWinAdd = window.addEventListener;

        function capturePageInitListener(type, listener){
            if(typeof listener !== 'function') return;
            if(type === 'DOMContentLoaded') pendingDomReady.push(listener);
            else if(type === 'load') pendingLoad.push(listener);
        }

        document.addEventListener = function(type, listener, options){
            if(type === 'DOMContentLoaded'){
                capturePageInitListener(type, listener);
                return;
            }
            return origDocAdd.call(document, type, listener, options);
        };
        window.addEventListener = function(type, listener, options){
            if(type === 'DOMContentLoaded' || type === 'load'){
                capturePageInitListener(type, listener);
                return;
            }
            return origWinAdd.call(window, type, listener, options);
        };

        try {
            const scriptNodes = [...doc.querySelectorAll('body script')];
            for(const oldScript of scriptNodes){
                const src = oldScript.getAttribute('src') || '';
                if(SITJOY_SHELL_SKIP_SCRIPT_RE.test(src)) continue;
                if(src && sitjoyExternalScriptLoaded(src)) continue;
                const script = document.createElement('script');
                script.dataset.sitjoyPageScript = '1';
                [...oldScript.attributes].forEach(attr => script.setAttribute(attr.name, attr.value));
                if(!src) script.textContent = wrapInlinePageScript(oldScript.textContent, doc);
                document.body.appendChild(script);
                if(src){
                    await new Promise(resolve => {
                        script.addEventListener('load', resolve, { once: true });
                        script.addEventListener('error', resolve, { once: true });
                    });
                }
            }
        } finally {
            document.addEventListener = origDocAdd;
            window.addEventListener = origWinAdd;
        }

        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));

        if(normalizeNavPath(window.__sitjoyActivePath) !== normalizeNavPath(href)) return;
        if(!pageBody || !pageBody.isConnected || !pageBody.firstElementChild) return;

        const domReadyEvent = new Event('DOMContentLoaded', { bubbles: true });
        runCapturedPageInitHandlers(pendingDomReady, domReadyEvent, document);
        const loadEvent = new Event('load');
        runCapturedPageInitHandlers(pendingLoad, loadEvent, window);
        if(typeof window.onload === 'function'){
            const legacyOnload = window.onload;
            window.onload = null;
            runCapturedPageInitHandlers([legacyOnload], loadEvent, window);
        }
    }

    function syncSitjoyBodyClasses(doc){
        const preserve = new Set(['sitjoy-has-shell', 'sitjoy-sidebar-collapsed']);
        const classes = [...doc.body.classList].filter(cls => !preserve.has(cls));
        document.body.className = ['sitjoy-has-shell', ...classes].join(' ');
        try {
            if(localStorage.getItem(SITJOY_SIDEBAR_COLLAPSED_KEY) === '1'){
                document.body.classList.add('sitjoy-sidebar-collapsed');
            }
        } catch (e) { /* ignore */ }
    }

    function enhanceSitjoyPageContent(root){
        const scope = root || document.getElementById('sitjoyPageBody') || document;
        initUniversalSingleSelects(scope);
        enhanceCustomDateInputs(scope);
        initOptionalDateInputs(scope);
        normalizeResetButtons(scope);
        enhanceManagedTables(document);
        bindFloatingHelpDots(document);
        partitionPmCardToolbars(document);
        bridgeLegacyResponseToToast(document);
        initColorSwatchPickers(scope);
        repositionManagedBatchBars();
        syncModalScrollLock();
    }

    async function applySitjoyPageSwap(doc, href){
        const pageBody = document.getElementById('sitjoyPageBody');
        if(!pageBody) throw new Error('Missing #sitjoyPageBody');

        window.__sitjoyNavEpoch = (window.__sitjoyNavEpoch || 0) + 1;
        window.__sitjoyActivePath = normalizeNavPath(href);

        if(doc.title) document.title = doc.title;
        applySitjoyPageStyles(doc);
        syncSitjoyBodyClasses(doc);

        pageBody.replaceChildren();
        extractSitjoyPageNodes(doc).forEach(node => {
            pageBody.appendChild(document.importNode(node, true));
        });

        await runSitjoyPageScripts(doc, pageBody, href);

        refreshSitjoyTabsForCurrentPath(href, doc);
        syncSidebarActiveState();
        window.requestAnimationFrame(() => enhanceSitjoyPageContent(pageBody));
    }

    async function sitjoyNavigateTo(rawHref, options){
        const opts = options || {};
        const href = normalizeNavPath(rawHref);
        const current = normalizeNavPath(location.pathname);
        const force = !!opts.force || href === current;
        const navToken = ++sitjoyNavToken;
        const previousPath = current;

        if(href !== current && !opts.skipHistory){
            history.pushState({ sitjoy: true, path: href }, '', href);
            updateSitjoyTabsActive(href);
        }

        if(sitjoyNavInFlight){
            try { await sitjoyNavInFlight; } catch (e) { /* ignore */ }
        }
        if(navToken !== sitjoyNavToken) return sitjoyNavInFlight;

        sitjoyNavInFlight = (async () => {
            const pageBody = document.getElementById('sitjoyPageBody');
            try {
                if(pageBody) pageBody.classList.add('is-sitjoy-nav-loading');
                const html = await fetchSitjoyPageHtml(href, force);
                if(navToken !== sitjoyNavToken) return;

                const doc = new DOMParser().parseFromString(html, 'text/html');
                await applySitjoyPageSwap(doc, href);
                if(navToken !== sitjoyNavToken) return;
            } catch (err) {
                if(href !== previousPath && !opts.skipHistory){
                    history.replaceState({ sitjoy: true, path: previousPath }, '', previousPath);
                    updateSitjoyTabsActive(previousPath);
                }
                console.warn('Sitjoy soft navigation failed, falling back to full load', err);
                window.location.assign(rawHref);
            } finally {
                if(pageBody) pageBody.classList.remove('is-sitjoy-nav-loading');
                if(navToken === sitjoyNavToken) sitjoyNavInFlight = null;
            }
        })();

        return sitjoyNavInFlight;
    }

    function bindSitjoyPopstate(){
        if(window.__sitjoyPopstateBound) return;
        window.__sitjoyPopstateBound = true;
        window.addEventListener('popstate', () => {
            if(!document.body.classList.contains('sitjoy-has-shell')) return;
            sitjoyNavigateTo(location.pathname, { skipHistory: true });
        });
    }

    let sitjoyTabsDragId = null;

    const SITJOY_TAB_ICON_PIN = '<svg class="sitjoy-tab-pin-icon" viewBox="0 0 16 16" width="9" height="9" aria-hidden="true"><circle cx="8" cy="3.75" r="2.1" fill="currentColor"/><path fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" d="M8 5.85v5.15"/><path fill="none" stroke="currentColor" stroke-width="1.35" stroke-linecap="round" d="M6.25 11h3.5"/></svg>';
    const SITJOY_TAB_ICON_PIN_ACTIVE = '<svg class="sitjoy-tab-pin-icon" viewBox="0 0 16 16" width="9" height="9" aria-hidden="true"><circle cx="8" cy="3.75" r="2.1" fill="currentColor"/><path fill="none" stroke="currentColor" stroke-width="1.45" stroke-linecap="round" d="M8 5.85v5.15"/><path fill="none" stroke="currentColor" stroke-width="1.45" stroke-linecap="round" d="M6.25 11h3.5"/></svg>';

    function renderSitjoyTabs(state, activeHref){
        const host = document.getElementById('sitjoyTopTabs');
        if(!host) return;
        const current = normalizeNavPath(activeHref || location.pathname);
        host.innerHTML = '';
        (state.tabs || []).forEach(tab => {
            const href = normalizeNavPath(tab.href);
            const el = document.createElement('a');
            el.className = 'sitjoy-tab' + (href === current ? ' is-active' : '') + (tab.pinned ? ' is-pinned' : '');
            el.href = href;
            el.dataset.tabHref = href;
            el.draggable = true;
            el.setAttribute('role', 'tab');
            el.setAttribute('aria-selected', href === current ? 'true' : 'false');
            const pinIcon = tab.pinned ? SITJOY_TAB_ICON_PIN_ACTIVE : SITJOY_TAB_ICON_PIN;
            el.innerHTML = `<span class="sitjoy-tab-label">${escapeSitjoyTabHtml(tab.label || href)}</span>
                <span class="sitjoy-tab-actions">
                    <button type="button" class="modal-close sitjoy-tab-pin" title="${tab.pinned ? '取消固定' : '固定到顶栏'}" aria-label="${tab.pinned ? '取消固定' : '固定到顶栏'}">${pinIcon}</button>
                    ${tab.pinned ? '' : `<button type="button" class="modal-close sitjoy-tab-close" title="关闭" aria-label="关闭">×</button>`}
                </span>`;
            host.appendChild(el);
        });
    }

    function escapeSitjoyTabHtml(value){
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function initSitjoyAppTabs(){
        const host = document.getElementById('sitjoyTopTabs');
        if(!host || host.dataset.sitjoyTabsBound === '1') return;
        host.dataset.sitjoyTabsBound = '1';

        const navIndex = buildNavLinkIndex();
        let state = ensureDefaultPinnedTabs(loadSitjoyTabsState());
        const pageInfo = resolvePageInfoFromPath(location.pathname, navIndex);
        state = upsertCurrentTab(state, pageInfo);
        saveSitjoyTabsState(state);
        renderSitjoyTabs(state);
        bindSitjoyPopstate();

        host.addEventListener('click', (ev) => {
            const pinBtn = ev.target.closest('.sitjoy-tab-pin');
            const closeBtn = ev.target.closest('.sitjoy-tab-close');
            const tabEl = ev.target.closest('.sitjoy-tab');
            if(!tabEl) return;
            const href = normalizeNavPath(tabEl.dataset.tabHref);
            if(pinBtn){
                ev.preventDefault();
                ev.stopPropagation();
                state.tabs = state.tabs.map(t => {
                    if(normalizeNavPath(t.href) !== href) return t;
                    return Object.assign({}, t, { pinned: !t.pinned });
                });
                saveSitjoyTabsState(state);
                renderSitjoyTabs(state, location.pathname);
                return;
            }
            if(closeBtn){
                ev.preventDefault();
                ev.stopPropagation();
                state.tabs = state.tabs.filter(t => normalizeNavPath(t.href) !== href);
                saveSitjoyTabsState(state);
                if(href === normalizeNavPath(location.pathname)){
                    const last = state.tabs[state.tabs.length - 1];
                    if(last) sitjoyNavigateTo(last.href);
                    else sitjoyNavigateTo('/');
                    return;
                }
                renderSitjoyTabs(state, location.pathname);
                return;
            }
            if(shouldUseSitjoySoftNav(ev, tabEl)){
                ev.preventDefault();
                ev.stopPropagation();
                sitjoyNavigateTo(href, { force: href === normalizeNavPath(location.pathname) });
            }
        });

        host.addEventListener('pointerenter', (ev) => {
            const tabEl = ev.target.closest('.sitjoy-tab');
            if(!tabEl) return;
            prefetchSitjoyPage(tabEl.dataset.tabHref);
        }, true);

        host.addEventListener('mousedown', (ev) => {
            if(ev.target.closest('.sitjoy-tab-pin, .sitjoy-tab-close')) ev.stopPropagation();
        });

        host.addEventListener('dragstart', (ev) => {
            const tabEl = ev.target.closest('.sitjoy-tab');
            if(!tabEl) return;
            sitjoyTabsDragId = normalizeNavPath(tabEl.dataset.tabHref);
            tabEl.classList.add('is-dragging');
            if(ev.dataTransfer){
                ev.dataTransfer.effectAllowed = 'move';
                ev.dataTransfer.setData('text/plain', sitjoyTabsDragId);
            }
        });

        host.addEventListener('dragend', (ev) => {
            const tabEl = ev.target.closest('.sitjoy-tab');
            if(tabEl) tabEl.classList.remove('is-dragging');
            sitjoyTabsDragId = null;
        });

        host.addEventListener('dragover', (ev) => {
            ev.preventDefault();
            if(ev.dataTransfer) ev.dataTransfer.dropEffect = 'move';
        });

        host.addEventListener('drop', (ev) => {
            ev.preventDefault();
            const targetTab = ev.target.closest('.sitjoy-tab');
            const fromId = sitjoyTabsDragId || (ev.dataTransfer ? ev.dataTransfer.getData('text/plain') : '');
            const toId = targetTab ? normalizeNavPath(targetTab.dataset.tabHref) : '';
            if(!fromId || !toId || fromId === toId) return;
            const tabs = state.tabs.slice();
            const fromIdx = tabs.findIndex(t => normalizeNavPath(t.href) === fromId);
            const toIdx = tabs.findIndex(t => normalizeNavPath(t.href) === toId);
            if(fromIdx < 0 || toIdx < 0) return;
            const [moved] = tabs.splice(fromIdx, 1);
            tabs.splice(toIdx, 0, moved);
            state.tabs = tabs;
            saveSitjoyTabsState(state);
            renderSitjoyTabs(state);
        });
    }

    function syncSidebarActiveState(){
        const path = normalizeNavPath(location.pathname);
        document.querySelectorAll('.sitjoy-sidebar-nav a[href]').forEach(a => {
            const href = normalizeNavPath(a.getAttribute('href'));
            const isActive = href === path || (href !== '/' && path.startsWith(href + '/'));
            a.classList.toggle('active', isActive);
            if(isActive){
                const group = a.closest('.sitjoy-sidebar-group');
                if(group){
                    const details = group.querySelector('.sitjoy-sidebar-details');
                    if(details) details.open = true;
                }
            }
        });
    }

    function initSitjoySidebar(){
        const sidebar = document.getElementById('sitjoySidebar');
        if(!sidebar || sidebar.dataset.sitjoySidebarBound === '1') return;
        sidebar.dataset.sitjoySidebarBound = '1';

        try {
            if(localStorage.getItem(SITJOY_SIDEBAR_COLLAPSED_KEY) === '1'){
                document.body.classList.add('sitjoy-sidebar-collapsed');
            }
        } catch (e) { /* ignore */ }

        document.querySelectorAll('.sitjoy-sidebar-details').forEach(details => {
            if(details.dataset.sitjoyDetailsBound === '1') return;
            details.dataset.sitjoyDetailsBound = '1';
            details.addEventListener('toggle', () => {
                if(!details.open) return;
                const group = details.closest('.sitjoy-sidebar-group');
                if(!group) return;
                group.parentElement.querySelectorAll(':scope > .sitjoy-sidebar-group .sitjoy-sidebar-details[open]').forEach(other => {
                    if(other !== details) other.open = false;
                });
            });
        });

        const collapseBtn = document.getElementById('sitjoySidebarCollapseBtn');
        if(collapseBtn && collapseBtn.dataset.sitjoyCollapseBound !== '1'){
            collapseBtn.dataset.sitjoyCollapseBound = '1';
            collapseBtn.addEventListener('click', () => {
                document.body.classList.toggle('sitjoy-sidebar-collapsed');
                try {
                    localStorage.setItem(SITJOY_SIDEBAR_COLLAPSED_KEY, document.body.classList.contains('sitjoy-sidebar-collapsed') ? '1' : '0');
                } catch (e) { /* ignore */ }
            });
        }

        sidebar.addEventListener('click', (ev) => {
            const link = ev.target.closest('.sitjoy-sidebar a[href]');
            if(!link || !shouldUseSitjoySoftNav(ev, link)) return;
            ev.preventDefault();
            sitjoyNavigateTo(link.getAttribute('href'));
        });

        sidebar.addEventListener('pointerenter', (ev) => {
            const link = ev.target.closest('.sitjoy-sidebar a[href]');
            if(!link) return;
            prefetchSitjoyPage(link.getAttribute('href'));
        }, true);

        syncSidebarActiveState();
    }

    function mountAppShellLayout(){
        const headerHost = document.getElementById('site-header');
        const pageBody = document.getElementById('sitjoyPageBody');
        if(!headerHost || !pageBody || headerHost.dataset.shellMounted === '1') return;

        const moveSelectors = ['.container', '.home-container', '.pm-layout-root', '.go-play-layout-root', '.mj-layout-root'];
        moveSelectors.forEach(sel => {
            document.querySelectorAll(`body > ${sel}`).forEach(el => {
                if(!pageBody.contains(el)) pageBody.appendChild(el);
            });
        });

        document.querySelectorAll('body > footer').forEach(el => el.remove());
        pageBody.querySelectorAll('footer').forEach(el => el.remove());
        document.body.classList.add('sitjoy-has-shell');
        headerHost.dataset.shellMounted = '1';
    }

    function initTopbarUser(authData){
        const el = document.getElementById('sitjoyTopbarUser');
        if(!el) return;
        if(!authData || authData.status === 'error'){
            el.hidden = true;
            el.textContent = '';
            return;
        }
        el.hidden = false;
        const name = authData.display_name || authData.name || authData.username || '用户';
        el.textContent = name;
        el.title = name;
    }

    function initTopbarClock(){
        const el = document.getElementById('sitjoyTopbarClock');
        if(!el || el.dataset.sitjoyClockBound === '1') return;
        el.dataset.sitjoyClockBound = '1';
        function tick(){
            const now = new Date();
            const y = now.getFullYear();
            const m = String(now.getMonth() + 1).padStart(2, '0');
            const d = String(now.getDate()).padStart(2, '0');
            const hh = String(now.getHours()).padStart(2, '0');
            const mm = String(now.getMinutes()).padStart(2, '0');
            el.textContent = `${y}-${m}-${d} ${hh}:${mm}`;
        }
        tick();
        window.setInterval(tick, 30000);
    }

    function initTopbarLogout(){
        const btn = document.getElementById('sitjoyTopbarLogout');
        if(!btn || btn.dataset.sitjoyLogoutBound === '1') return;
        btn.dataset.sitjoyLogoutBound = '1';
        btn.addEventListener('click', async () => {
            try {
                await fetch('/api/auth?action=logout', { method: 'POST', credentials: 'include' });
            } catch (e) { /* ignore */ }
            window.location.href = '/';
        });
    }

    function getCurrentAuthState(forceRefresh){
        if(forceRefresh || !window.__sitjoyAuthStatePromise){
            window.__sitjoyAuthStatePromise = fetch('/api/auth?action=current', { credentials: 'include' })
                .then(r => r.json())
                .catch(() => null);
        }
        return window.__sitjoyAuthStatePromise;
    }

    let sitjoyUsageGuideEscapeInstalled = false;

    function initSitjoyUsageGuide(){
        const tickerBtn = document.getElementById('sitjoyUsageTicker');
        const track = document.getElementById('sitjoyUsageTickerTrack');
        if(!tickerBtn || !track) return;
        if(tickerBtn.dataset.sitjoyUsageBound === '1') return;
        tickerBtn.dataset.sitjoyUsageBound = '1';

        const SHORT_ITEMS = [
            '托管表：在单元格空白处拖选区域；Ctrl/Cmd 点击追加/取消；Shift 点击按矩形扩展选区',
            'Ctrl/Cmd+C 将选中格复制为制表符分隔文本，可直接粘贴到 Excel / 表格',
            '矩阵粘贴：从表格或「多行 × 多列」纯文本复制，在选区或单元格上粘贴可批量填入预览输入',
            '点击表内输入框、下拉会清空格选区，避免粘贴到错误范围',
            'Esc 可关闭列配置浮层、重置菜单、日期弹层并清除格选区',
            '表头「字段显示与冻结窗格」可隐藏列、拖拽列顺序、冻结左侧列；列宽拖曳后会记忆',
            '表头「重置」菜单可分别恢复列宽、字段顺序或字段显示',
            '表底可改每页条数；部分表支持表头漏斗筛选与行勾选批量下载/删除',
            '字段旁「?」为说明；业务页标题旁小圆点可查看本页简介（由副标题生成）',
            '弹窗支持点击遮罩关闭（已绑定时）；全站日期/部分下拉有统一增强控件',
            '图片编辑等场景支持共享弹窗：推荐命名、关联规格/面料、NAS 导入等依页面配置'
        ];

        const DETAIL_SECTIONS = [
            {
                title: '托管表格格选（多数列表页）',
                lines: [
                    '带「每页条数 / 字段显示与冻结窗格」工具栏的表格为托管表：表体与表头横向滚动可同步。',
                    '在单元格的空白区域（避免点在输入框、按钮内部）按住左键拖动，可框选矩形区域。',
                    '先单击锚点单元格后，Shift 再单击另一单元格，可选中两格之间的矩形。',
                    'Ctrl（Windows）或 ⌘（Mac）单击单元格可追加或取消选中，实现不连续多选。',
                    '在途物流等页面的复杂单元格内，若支持子网格，可在格内继续拖选局部明细再复制。'
                ]
            },
            {
                title: '复制为表格（Excel 友好）',
                lines: [
                    '选中一个或多个单元格后，按 Ctrl+C 或 ⌘+C，将按行列输出为制表符分隔（TSV）、换行分行。',
                    '若单元格内有输入框，会优先导出框内值；部分列可用 data-export-value 指定导出文本。',
                    '复制成功后会短暂 toast 提示「已复制选中区域」。'
                ]
            },
            {
                title: '批量粘贴（矩阵粘贴）',
                lines: [
                    '从 Excel 等复制多行多列后，剪贴板为「制表符分列、换行分行」的纯文本时，系统会解析为矩阵。',
                    '若当前有格选区，会按选区左上角对齐粘贴到可见的预览输入/可编辑控件中。',
                    '若仅在单个单元格内粘贴且为「多格矩阵」，会从该格起向右向下铺开；单个值仍走浏览器原生粘贴。',
                    '粘贴成功会 toast「已粘贴到预览输入区域」；进入输入框焦点时会清除格选区以防误操作。'
                ]
            },
            {
                title: '列、分页与筛选',
                lines: [
                    '表头右侧竖条可拖列宽；宽度写入本地存储，下次进入页面保留。',
                    '「字段显示与冻结窗格」中可勾选显示列、拖拽排序；多选列通常锁定不可隐藏。',
                    '「重置」按钮展开菜单，可单独重置列宽、字段顺序或字段显示。',
                    '部分业务表（如工厂在制）表头带漏斗图标，支持列筛选与选项面板。',
                    '表底分页可切换每页条数；上一页 / 下一页浏览。'
                ]
            },
            {
                title: '批量下载与批量删除',
                lines: [
                    '勾选行后，批量下载/删除条默认固定在页面右下角，不挤占表头工具栏与分页区域。',
                    '若某页确需将该条嵌入工具栏，可为表格设置 data-batch-bar-embedded="1"。',
                    '页面可通过 data-batch-delete-handler 等属性接入自定义逻辑；未配置时会有 toast 提示。',
                    '批量删除前会弹出全屏居中确认框，请勾选「我已阅读…」后再二次确认执行。'
                ]
            },
            {
                title: '其它通用交互',
                lines: [
                    '表单字段旁 help-dot（?）悬停或点击可查看说明；首页与业务页 hero 区标题旁圆点可展示简介。',
                    '许多 select 支持搜索过滤输入；日期类输入可使用统一的日期 / 日期时间选择器。',
                    '确认类操作常使用 showAppConfirm / showAppConfirmAsync；上传过程可能有全屏进度提示。',
                    '若某页未接入托管表或不展示某按钮，则以该页实际界面为准。'
                ]
            },
            {
                title: '如何汇报Bug？',
                lines: [
                    '联系『俞杨昆』进行Bug反馈，或添加微信『k2630983959』进行反馈。'
                ]
            }
        ];

        function escapeUsageHtml(s){
            return String(s || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        function ensureUsageModal(){
            let modal = document.getElementById('sitjoyUsageTipsModal');
            if(modal) return modal;
            const sectionsHtml = DETAIL_SECTIONS.map((sec) => {
                const lis = sec.lines.map((t) => `<li>${escapeUsageHtml(t)}</li>`).join('');
                return `<section class="sitjoy-usage-section"><h4 class="sitjoy-usage-section-title">${escapeUsageHtml(sec.title)}</h4><ul class="sitjoy-usage-list">${lis}</ul></section>`;
            }).join('');
            modal = document.createElement('div');
            modal.id = 'sitjoyUsageTipsModal';
            modal.className = 'pm-modal';
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            modal.setAttribute('aria-labelledby', 'sitjoyUsageTipsTitle');
            modal.innerHTML = `
                <div class="pm-modal-content pm-modal-content--wide" style="max-width:720px;">
                    <div class="pm-modal-scroll">
                        <h3 id="sitjoyUsageTipsTitle" style="margin-top:0;" class="label-help">SITJOY 使用提示与隐藏功能<span class="help-dot" data-tip="以下为全站通用能力说明。个别页面若未接入托管表或未展示某按钮，以实际界面为准。"></span></h3>
                        <div class="sitjoy-usage-detail-body">${sectionsHtml}</div>
                    </div>
                    <div class="pm-modal-actions">
                        <button type="button" class="btn-primary" id="sitjoyUsageTipsClose">关闭</button>
                    </div>
                </div>`;
            document.body.appendChild(modal);
            bindFloatingHelpDots(modal);
            modal.querySelector('#sitjoyUsageTipsClose').addEventListener('click', () => closeUsageTipsModal());
            window.setTimeout(() => {
                if(typeof window.bindPmModalBackdropClose === 'function'){
                    try { window.bindPmModalBackdropClose(modal, () => closeUsageTipsModal()); } catch(_e) {}
                }
            }, 0);
            return modal;
        }

        function openUsageTipsModal(){
            const modal = ensureUsageModal();
            modal.classList.add('active');
            if(typeof window.syncModalScrollLock === 'function'){
                try { window.syncModalScrollLock(); } catch(_e) {}
            }
        }

        function closeUsageTipsModal(){
            const modal = document.getElementById('sitjoyUsageTipsModal');
            if(modal) modal.classList.remove('active');
            if(typeof window.syncModalScrollLock === 'function'){
                try { window.syncModalScrollLock(); } catch(_e) {}
            }
        }

        if(window.__sitjoyUsageTickerTimerId){
            clearTimeout(window.__sitjoyUsageTickerTimerId);
            window.__sitjoyUsageTickerTimerId = null;
        }

        function dwellMsForTip(text){
            const len = String(text || '').length;
            return Math.min(26000, Math.max(6000, 4000 + len * 100));
        }

        const lineEl = document.createElement('p');
        lineEl.className = 'sitjoy-usage-ticker-line';
        lineEl.id = 'sitjoyUsageTickerLine';
        lineEl.setAttribute('aria-live', 'polite');
        lineEl.setAttribute('aria-atomic', 'true');
        track.innerHTML = '';
        track.appendChild(lineEl);

        const iconOnlyTicker = track.classList.contains('sitjoy-usage-ticker-track--hidden')
            || track.hasAttribute('hidden')
            || track.closest('[hidden]');

        let tipIndex = 0;
        let tipPaused = false;

        function scheduleNextTip(){
            if(tipPaused) return;
            if(window.__sitjoyUsageTickerTimerId){
                clearTimeout(window.__sitjoyUsageTickerTimerId);
                window.__sitjoyUsageTickerTimerId = null;
            }
            const cur = SHORT_ITEMS[tipIndex % SHORT_ITEMS.length];
            lineEl.textContent = cur;
            if(iconOnlyTicker) tickerBtn.title = `使用提示：${cur}`;
            const wait = dwellMsForTip(cur);
            window.__sitjoyUsageTickerTimerId = window.setTimeout(() => {
                window.__sitjoyUsageTickerTimerId = null;
                if(tipPaused) return;
                tipIndex = (tipIndex + 1) % SHORT_ITEMS.length;
                scheduleNextTip();
            }, wait);
        }

        scheduleNextTip();

        tickerBtn.addEventListener('mouseenter', () => {
            tipPaused = true;
            if(window.__sitjoyUsageTickerTimerId){
                clearTimeout(window.__sitjoyUsageTickerTimerId);
                window.__sitjoyUsageTickerTimerId = null;
            }
        });
        tickerBtn.addEventListener('mouseleave', () => {
            tipPaused = false;
            scheduleNextTip();
        });

        tickerBtn.addEventListener('click', (ev) => {
            ev.preventDefault();
            openUsageTipsModal();
        });

        if(!sitjoyUsageGuideEscapeInstalled){
            sitjoyUsageGuideEscapeInstalled = true;
            document.addEventListener('keydown', (ev) => {
                if(ev.key !== 'Escape') return;
                const modal = document.getElementById('sitjoyUsageTipsModal');
                if(modal && modal.classList.contains('active')){
                    closeUsageTipsModal();
                }
            });
        }
    }

    function initSitjoyNotifications(authData){
        const wrap = document.getElementById('sitjoyNotificationCenter');
        const trigger = document.getElementById('sitjoyNotificationTrigger');
        const panel = document.getElementById('sitjoyNotificationPanel');
        const list = document.getElementById('sitjoyNotificationList');
        const badge = document.getElementById('sitjoyNotificationBadge');
        const markAllBtn = document.getElementById('sitjoyNotificationMarkAll');
        if(!wrap || !trigger || !panel || !list || !badge) return;
        if(!authData || authData.status === 'error'){
            wrap.hidden = true;
            return;
        }
        wrap.hidden = false;

        let panelOpen = false;
        let pollTimer = null;
        let panelPortaled = false;

        function ensureNotificationPanelPortaled(){
            if(panelPortaled || !panel) return;
            if(panel.parentElement !== document.body){
                document.body.appendChild(panel);
            }
            panelPortaled = true;
        }

        function escapeNotificationHtml(value){
            return String(value || '')
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;');
        }

        function formatNotificationTime(value){
            const text = String(value || '').trim();
            if(!text) return '';
            return text.replace('T', ' ').slice(0, 16);
        }

        function setUnreadCount(count){
            const num = Math.max(0, Number(count || 0));
            if(num > 0){
                badge.hidden = false;
                badge.textContent = num > 99 ? '99+' : String(num);
            } else {
                badge.hidden = true;
                badge.textContent = '0';
            }
        }

        function renderNotificationItems(items){
            const rows = Array.isArray(items) ? items : [];
            if(!rows.length){
                list.innerHTML = '<div class="sitjoy-notification-empty">暂无通知</div>';
                return;
            }
            list.innerHTML = rows.map(item => {
                const unread = !Number(item.is_read || 0);
                const linkUrl = String(item.link_url || '').trim();
                const linkLabel = String(item.link_label || '').trim() || '查看详情';
                const linkHtml = linkUrl
                    ? `<a class="sitjoy-notification-item-link" href="${escapeNotificationHtml(linkUrl)}">${escapeNotificationHtml(linkLabel)}</a>`
                    : '<span></span>';
                return `
                    <article class="sitjoy-notification-item${unread ? ' is-unread' : ''}" data-notification-id="${escapeNotificationHtml(item.id)}" data-link-url="${escapeNotificationHtml(linkUrl)}">
                        <div class="sitjoy-notification-item-title">${escapeNotificationHtml(item.title || '通知')}</div>
                        ${item.body ? `<div class="sitjoy-notification-item-body">${escapeNotificationHtml(item.body)}</div>` : ''}
                        <div class="sitjoy-notification-item-meta">
                            <span>${escapeNotificationHtml(formatNotificationTime(item.created_at))}</span>
                            ${linkHtml}
                        </div>
                    </article>
                `;
            }).join('');
        }

        async function fetchUnreadCount(){
            try {
                const resp = await fetch('/api/notification?action=unread_count', { credentials: 'include' });
                const data = await resp.json();
                if(data.status === 'success'){
                    setUnreadCount(data.unread_count);
                }
            } catch (_err) {
            }
        }

        async function loadNotificationList(){
            try {
                const resp = await fetch('/api/notification?page=1&page_size=20', { credentials: 'include' });
                const data = await resp.json();
                if(data.status !== 'success'){
                    list.innerHTML = '<div class="sitjoy-notification-empty">' + escapeNotificationHtml(data.message || '加载失败') + '</div>';
                    return;
                }
                renderNotificationItems(data.items || []);
                setUnreadCount(data.unread_count);
            } catch (_err) {
                list.innerHTML = '<div class="sitjoy-notification-empty">网络错误</div>';
            }
        }

        function positionNotificationPanel(){
            if(!trigger || !panel || panel.hidden) return;
            const rect = trigger.getBoundingClientRect();
            const gap = 8;
            const viewportPad = 12;
            const panelWidth = Math.min(360, Math.max(240, window.innerWidth - viewportPad * 2));
            let left = rect.right - panelWidth;
            left = Math.max(viewportPad, Math.min(left, window.innerWidth - panelWidth - viewportPad));
            let top = rect.bottom + gap;
            const maxHeight = Math.min(420, window.innerHeight - top - viewportPad);
            panel.style.width = panelWidth + 'px';
            panel.style.left = left + 'px';
            panel.style.top = top + 'px';
            panel.style.maxHeight = Math.max(160, maxHeight) + 'px';
        }

        function closeNotificationPanel(){
            panelOpen = false;
            panel.hidden = true;
            panel.classList.remove('is-open');
            trigger.setAttribute('aria-expanded', 'false');
        }

        function openNotificationPanel(){
            ensureNotificationPanelPortaled();
            panelOpen = true;
            panel.hidden = false;
            panel.classList.add('is-open');
            trigger.setAttribute('aria-expanded', 'true');
            positionNotificationPanel();
            loadNotificationList();
        }

        async function markNotificationRead(id){
            if(!id) return;
            try {
                await fetch('/api/notification?action=mark_read', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ id: Number(id) })
                });
            } catch (_err) {
            }
        }

        trigger.addEventListener('click', (ev) => {
            ev.preventDefault();
            ev.stopPropagation();
            if(panelOpen) closeNotificationPanel();
            else openNotificationPanel();
        });

        if(markAllBtn){
            markAllBtn.addEventListener('click', async (ev) => {
                ev.preventDefault();
                ev.stopPropagation();
                try {
                    const resp = await fetch('/api/notification?action=mark_all_read', {
                        method: 'POST',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({})
                    });
                    const data = await resp.json();
                    if(data.status === 'success'){
                        await loadNotificationList();
                        setUnreadCount(0);
                    }
                } catch (_err) {
                }
            });
        }

        list.addEventListener('click', async (ev) => {
            const itemEl = ev.target.closest('.sitjoy-notification-item');
            if(!itemEl) return;
            const id = itemEl.dataset.notificationId;
            const linkUrl = String(itemEl.dataset.linkUrl || '').trim();
            if(id) await markNotificationRead(id);
            if(linkUrl){
                window.location.href = linkUrl;
                return;
            }
            itemEl.classList.remove('is-unread');
            fetchUnreadCount();
        });

        document.addEventListener('click', (ev) => {
            if(!panelOpen) return;
            if(ev.target.closest('#sitjoyNotificationCenter')) return;
            if(ev.target.closest('#sitjoyNotificationPanel')) return;
            closeNotificationPanel();
        });

        document.addEventListener('keydown', (ev) => {
            if(ev.key === 'Escape' && panelOpen) closeNotificationPanel();
        });

        window.addEventListener('resize', () => {
            if(panelOpen) positionNotificationPanel();
        });
        window.addEventListener('scroll', () => {
            if(panelOpen) positionNotificationPanel();
        }, true);

        fetchUnreadCount();
        if(pollTimer) window.clearInterval(pollTimer);
        pollTimer = window.setInterval(fetchUnreadCount, 60000);
        window.refreshSitjoyNotifications = async function(forceList){
            await fetchUnreadCount();
            if(forceList && panelOpen) await loadNotificationList();
        };
    }

    function fetchHeaderHtml(){
        if(sitjoyHeaderHtmlCache) return Promise.resolve(sitjoyHeaderHtmlCache);
        try {
            const cached = sessionStorage.getItem(SITJOY_HEADER_CACHE_KEY);
            if(cached){
                sitjoyHeaderHtmlCache = cached;
                fetch('/static/partials/header.html')
                    .then(r => r.text())
                    .then(html => {
                        sitjoyHeaderHtmlCache = html;
                        try { sessionStorage.setItem(SITJOY_HEADER_CACHE_KEY, html); } catch (e) { /* ignore */ }
                    })
                    .catch(() => {});
                return Promise.resolve(cached);
            }
        } catch (e) { /* ignore */ }
        return fetch('/static/partials/header.html')
            .then(r => r.text())
            .then(html => {
                sitjoyHeaderHtmlCache = html;
                try { sessionStorage.setItem(SITJOY_HEADER_CACHE_KEY, html); } catch (e) { /* ignore */ }
                return html;
            });
    }

    function paintCachedHeaderShell(){
        const el = document.getElementById('site-header');
        if(!el || el.dataset.shellMounted === '1') return false;
        try {
            const cached = sessionStorage.getItem(SITJOY_HEADER_CACHE_KEY) || sitjoyHeaderHtmlCache;
            if(!cached) return false;
            el.innerHTML = cached;
            mountAppShellLayout();
            initSitjoySidebar();
            initSitjoyAppTabs();
            bindSitjoyPopstate();
            return true;
        } catch (e) {
            return false;
        }
    }

    function loadHeader(){
        paintCachedHeaderShell();
        Promise.all([
            fetchHeaderHtml(),
            getCurrentAuthState()
        ])
            .then(([html, authData]) => {
                const el = document.getElementById('site-header');
                if(!el) return;
                const shellReady = el.dataset.shellMounted === '1';
                if(!shellReady){
                    el.innerHTML = html;
                    mountAppShellLayout();
                    initSitjoySidebar();
                    initSitjoyAppTabs();
                    bindSitjoyPopstate();
                }
                applyHeaderPermissions(authData);
                initTopbarUser(authData);
                initTopbarClock();
                initTopbarLogout();
                initSitjoyNotifications(authData);
                initSitjoyUsageGuide();
                if(shellReady){
                    refreshSitjoyTabsForCurrentPath(location.pathname);
                    syncSidebarActiveState();
                }
            })
            .catch(err => console.error('Load header failed', err));
    }

    document.addEventListener('click', (e) => {
        if(!e.target.closest('.universal-select-dropdown') && !e.target.closest('.universal-select-floating-menu')) {
            closeAllDropdowns();
        }
        if(activeDatePickerState && activeDatePickerState.panel && !e.target.closest('.app-date-picker') && !e.target.closest('.app-date-input')) {
            closeDatePicker();
        }
        if(activeDateTimePickerState && activeDateTimePickerState.panel){
            const t = e.target;
            if(!t.closest || (!t.closest('.app-datetime-picker') && !t.closest('.app-datetime-input'))){
                const an = activeDateTimePickerState.anchor;
                const onAnchor = !!(an && (an === t || (an.contains && an.contains(t))));
                if(!onAnchor){
                    closeDateTimePicker();
                }
            }
        }
        if(!e.target.closest('.help-dot') && !e.target.closest('.app-help-floating-tip')) {
            hideHelpDotTooltip();
        }
        if(!e.target.closest('.pm-table-columns') && !e.target.closest('.pm-table-columns-panel')) {
            closeColumnsPanel(activeColumnsPanelState);
        }
        if(!e.target.closest('.pm-table-reset-group') && !e.target.closest('.pm-table-reset-menu')) {
            closeAllResetMenus();
        }
    });

    document.addEventListener('mousedown', (e) => {
        if(!e.target.closest('.pm-table-columns') && !e.target.closest('.pm-table-columns-panel')) {
            closeColumnsPanel(activeColumnsPanelState);
        }
        if(!e.target.closest('.pm-table-reset-group') && !e.target.closest('.pm-table-reset-menu')) {
            closeAllResetMenus();
        }
        // If user enters an input inside a managed table, immediately release any grid selection
        // to avoid paste/copy being applied to the previous selected cell range.
        if(activeGridSelection && isEditableDomTarget(e.target) && e.target.closest('.is-managed-table')) {
            clearGridSelection();
        }
        if(activeGridSelection && !e.target.closest('.is-managed-table')) {
            clearGridSelection();
        }
    });

    document.addEventListener('focusin', (e) => {
        if(activeGridSelection && isEditableDomTarget(e.target) && e.target.closest('.is-managed-table')) {
            clearGridSelection();
        }
    });

    document.addEventListener('keydown', (e) => {
        if((e.ctrlKey || e.metaKey) && String(e.key || '').toLowerCase() === 'c'){
            const hasManagedSelection = !!(activeGridSelection && activeGridSelection.selectedCells && activeGridSelection.selectedCells.size > 0);
            if(isEditableDomTarget(e.target) && !hasManagedSelection) return;
            if(copyGridSelectionToClipboard()){
                e.preventDefault();
                return;
            }
        }
        if(e.key === 'Delete'){
            const hasManagedSelection = !!(activeGridSelection && activeGridSelection.selectedCells && activeGridSelection.selectedCells.size > 0);
            if(!hasManagedSelection) return;
            if(clearEditableFieldsInActiveGridSelection()){
                e.preventDefault();
            }
        }
        if(e.key === 'Escape'){
            closeColumnsPanel(activeColumnsPanelState);
            closeAllResetMenus();
            closeAllDropdowns();
            closeDatePicker();
            closeDateTimePicker();
            closeBatchConfirmModal();
            clearGridSelection();
            hideHelpDotTooltip();
        }
    });

    document.addEventListener('paste', (e) => {
        const target = e.target;
        if(!target || !(target instanceof HTMLElement)) return;
        const field = target.closest('input, textarea, select');
        const state = field ? getManagedStateByElement(field) : getManagedStateFromSelection();
        if(!state) return;

        const text = (e.clipboardData && e.clipboardData.getData) ? e.clipboardData.getData('text/plain') : '';
        const matrix = parseClipboardMatrix(text);
        if(!matrix.length) return;

        // Keep native paste for single-value input paste.
        const isSingle = matrix.length === 1 && (matrix[0] || []).length <= 1;
        const hasSelection = hasActiveManagedSelection(state);
        if(isSingle && !hasSelection) return;

        e.preventDefault();

        let applied = false;
        if(hasSelection){
            applied = applyMatrixPasteToActiveSelection(state, matrix);
        }
        if(!applied && field){
            applied = applyMatrixPasteFromField(state, field, matrix);
        }

        if(applied && window.showAppToast){
            window.showAppToast('已粘贴到预览输入区域', false, 1200);
        }
    });

    document.addEventListener('mousemove', (event) => {
        if(activeResizeState){
            const delta = event.clientX - activeResizeState.startX;
            if(Math.abs(delta) > 2) activeResizeState.hasMoved = true;
            resizePendingWidth = activeResizeState.startWidth + delta;
            if(resizePendingFrame) return;
            const rs = activeResizeState;
            resizePendingFrame = window.requestAnimationFrame(() => {
                resizePendingFrame = null;
                if(!activeResizeState || activeResizeState !== rs) return;
                setColumnWidthByKey(rs.state, rs.key, resizePendingWidth, { live: true });
            });
        }

        if(activeGridSelection && activeGridSelection.detailDragging && activeGridSelection.state){
            const dragInfo = activeGridSelection.detailDragging;
            const state = activeGridSelection.state;

            if(dragInfo.mode === 'transitSkuGrid' && activeGridSelection.transitSkuGrid){
                const el = document.elementFromPoint(event.clientX, event.clientY);
                const g = getTransitSkuGridCoord(state, el);
                if(!g) return;
                activeGridSelection.transitSkuGrid.current = g;
                schedulePaintGridSelection();
                return;
            }

            const cell = dragInfo.cell;
            if(!cell || !cell.isConnected || !state.tbody.contains(cell)) return;
            const el = document.elementFromPoint(event.clientX, event.clientY);
            const hoverCell = el && el.closest ? el.closest('td') : null;
            if(!hoverCell || hoverCell !== cell) return;
            const detailCoord = getTransitSubcellCoord(el, cell);
            if(!detailCoord) return;
            const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
            if(!detailSel) return;
            detailSel.current = detailCoord;
            schedulePaintGridSelection();
            return;
        }

        if(activeGridSelection && activeGridSelection.dragging && activeGridSelection.state){
            const anchor = activeGridSelection.dragAnchor;
            if(!anchor) return;
            const el = document.elementFromPoint(event.clientX, event.clientY);
            const cell = el && el.closest ? el.closest('td') : null;
            const state = activeGridSelection.state;
            if(!cell || !state.tbody.contains(cell) || cell.classList.contains('pm-table-hide-col')) return;
            const coord = getCellCoord(state, cell);
            if(!coord) return;
            updateGridDragRectSelection(state, anchor, coord);
        }
    });

    document.addEventListener('mouseup', () => {
        if(activeResizeState){
            // 松手后 click 常落在表头 th 上而非 resizer，会误触排序；与是否产生位移无关
            const until = Date.now() + 650;
            suppressSortUntil = Math.max(Number(suppressSortUntil) || 0, until);
            if(resizePendingFrame){
                window.cancelAnimationFrame(resizePendingFrame);
                resizePendingFrame = null;
            }
            activeResizeState.handle.classList.remove('is-active');
            const rsState = activeResizeState.state;
            const rsKey = activeResizeState.key;
            const finalWidth = Number.isFinite(Number(resizePendingWidth))
                ? resizePendingWidth
                : (activeResizeState.startWidth || 0);
            resizePendingWidth = null;
            setColumnWidthByKey(rsState, rsKey, finalWidth);
            enforceManagedColumnWidthFloors(rsState);
            persistColumnWidths(rsState);
            if(pinnedLayoutNeedsUpdateAfterResize(rsState, rsKey)){
                applyPinnedColumns(rsState, { force: true });
            }
            syncSjAggToggleColumnCssVar(rsState);
            syncTopScroll(rsState);
            activeResizeState = null;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }

        if(activeGridSelection){
            const dragState = activeGridSelection.state;
            const wasDragging = !!activeGridSelection.dragging;
            const wasDetailDragging = !!activeGridSelection.detailDragging;
            activeGridSelection.dragging = false;
            activeGridSelection.detailDragging = null;
            if(dragState) endGridDragVisibleRowCache(dragState);
            if(wasDragging || wasDetailDragging) notifySitjoyGridSelectionChange();
        }
    });

    window.addEventListener('resize', () => {
        repositionOpenDropdowns();
        if(activeDatePickerState && activeDatePickerState.input) positionDatePicker(activeDatePickerState.input, activeDatePickerState);
        if(activeDateTimePickerState && activeDateTimePickerState.reposition) activeDateTimePickerState.reposition();
        repositionActiveHelpDotTip();
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
        if(activeResetMenuState) repositionResetMenu(activeResetMenuState);
        repositionManagedBatchBars();
    });

    window.addEventListener('focus', () => {
        if(typeof window.refreshTransitDetailSortHeaderUi === 'function'){
            window.refreshTransitDetailSortHeaderUi();
        }
    });

    document.addEventListener('visibilitychange', () => {
        if(!document.hidden) {
            if(typeof window.refreshTransitDetailSortHeaderUi === 'function'){
                window.refreshTransitDetailSortHeaderUi();
            }
        }
    });

    window.addEventListener('scroll', () => {
        repositionOpenDropdowns();
        if(activeDatePickerState && activeDatePickerState.input) positionDatePicker(activeDatePickerState.input, activeDatePickerState);
        if(activeDateTimePickerState && activeDateTimePickerState.reposition) activeDateTimePickerState.reposition();
        repositionActiveHelpDotTip();
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
        if(activeResetMenuState) repositionResetMenu(activeResetMenuState);
        repositionManagedBatchBars();
    }, true);

    function initGlobalTableCheckboxCellToggle(){
        if(initGlobalTableCheckboxCellToggle._on) return;
        initGlobalTableCheckboxCellToggle._on = true;
        document.addEventListener('click', (e) => {
            if(!e || e.button !== 0) return;
            if(!e.target || !e.target.closest) return;
            if(e.target.closest('button, a, select, textarea')) return;
            if(e.target.closest('input[type="checkbox"]')) return;
            if(e.target.closest('label')) return;
            const cell = e.target.closest('td, th');
            if(!cell) return;
            const kids = cell.children;
            const autoSingle = kids && kids.length === 1 && kids[0] && kids[0].matches && kids[0].matches('input[type="checkbox"]');
            const wantsToggle = (cell.classList && cell.classList.contains('sj-toggle-cb-cell')) || !!autoSingle;
            if(!wantsToggle) return;
            const cb = cell.querySelector('input[type="checkbox"]');
            if(!cb || cb.disabled) return;
            cb.checked = !cb.checked;
            try {
                cb.dispatchEvent(new Event('input', { bubbles: true }));
                cb.dispatchEvent(new Event('change', { bubbles: true }));
            } catch(_){}
        }, false);
    }

    const SJ_COLOR_SWATCH_WAND_HTML = '<span class="sj-color-swatch-picker__wand" aria-hidden="true">'
        + '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
        + '<path d="m7 21 3-3m3.5-12.5a2.12 2.12 0 0 1 3 0l2.5 2.5a2.12 2.12 0 0 1 0 3L9 17"/>'
        + '</svg></span>';

    function syncColorSwatchPicker(input){
        if(!input) return;
        const wrap = input.closest('.sj-color-swatch-picker');
        const disk = wrap ? wrap.querySelector('.sj-color-swatch-picker__disk') : null;
        const color = String(input.value || '#cfc7bd').trim() || '#cfc7bd';
        if(disk) disk.style.backgroundColor = color;
        if(wrap) wrap.style.setProperty('--sj-swatch-color', color);
        input.title = color;
        if(wrap) wrap.title = color;
    }

    function wrapColorInputAsSwatchPicker(input){
        if(!input || input.type !== 'color' || input.closest('.sj-color-swatch-picker')) return input;
        const wrap = document.createElement('span');
        wrap.className = 'sj-color-swatch-picker';
        const disk = document.createElement('span');
        disk.className = 'sj-color-swatch-picker__disk';
        wrap.appendChild(disk);
        wrap.insertAdjacentHTML('beforeend', SJ_COLOR_SWATCH_WAND_HTML);
        input.classList.add('sj-color-swatch-picker__input');
        const parent = input.parentNode;
        if(parent){
            parent.insertBefore(wrap, input);
            wrap.appendChild(input);
        }
        syncColorSwatchPicker(input);
        return input;
    }

    function initColorSwatchPickers(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('input[type="color"].sj-color-swatch-picker__input, .sj-color-swatch-picker input[type="color"]').forEach((inp) => {
            if(inp.dataset.sjColorSwatchBound === '1') return;
            inp.dataset.sjColorSwatchBound = '1';
            if(!inp.classList.contains('sj-color-swatch-picker__input')) inp.classList.add('sj-color-swatch-picker__input');
            const wrap = inp.closest('.sj-color-swatch-picker');
            if(wrap && !wrap.querySelector('.sj-color-swatch-picker__disk')){
                const disk = document.createElement('span');
                disk.className = 'sj-color-swatch-picker__disk';
                wrap.insertBefore(disk, inp);
            }
            if(wrap && !wrap.querySelector('.sj-color-swatch-picker__wand')){
                wrap.insertAdjacentHTML('beforeend', SJ_COLOR_SWATCH_WAND_HTML);
            }
            inp.addEventListener('input', () => syncColorSwatchPicker(inp));
            inp.addEventListener('change', () => syncColorSwatchPicker(inp));
            syncColorSwatchPicker(inp);
        });
        scope.querySelectorAll('input[type="color"][data-sj-color-swatch="1"]').forEach((inp) => {
            if(!inp.closest('.sj-color-swatch-picker')) wrapColorInputAsSwatchPicker(inp);
        });
    }

    window.SitjoyColorSwatchPicker = {
        sync: syncColorSwatchPicker,
        init: initColorSwatchPickers,
        wrap: wrapColorInputAsSwatchPicker
    };

    function loadSitjoyCellSelectionStats(){
        if(window.SitjoyCellSelectionStats) return;
        if(document.querySelector('script[data-sj-cell-stats="1"]')) return;
        const script = document.createElement('script');
        script.src = '/static/js/sitjoy_cell_selection_stats.js';
        script.dataset.sjCellStats = '1';
        script.defer = true;
        document.head.appendChild(script);
    }

    const boot = () => {
        loadHeader();
        loadSitjoyCellSelectionStats();
        initGlobalTableCheckboxCellToggle();
        initPmTableBatchCheckboxSelection();
        initUniversalSingleSelects(document);
        enhanceCustomDateInputs(document);
        initOptionalDateInputs(document);
        normalizeResetButtons(document);
        enhanceManagedTables(document);
        bindFloatingHelpDots(document);
        partitionPmCardToolbars(document);
        bridgeLegacyResponseToToast(document);
        initColorSwatchPickers(document);
        startUniversalSelectValueSync();

        window.showAppToast = function(message, isError, duration){
            showAppToast(message, !!isError, duration);
        };
        window.showAppSaveResult = showAppSaveResult;
        window.downloadTemplateWithIds = function(endpoint, ids, fallbackName){
            downloadTemplateWithIds(endpoint, ids, fallbackName).catch(err => {
                const msg = err && err.message ? err.message : '下载失败';
                showAppToast(msg, true, 4200);
            });
        };
        window.showAppConfirm = showAppConfirm;
        window.showAppConfirmAsync = showAppConfirmAsync;
        window.bindFloatingHelpDots = bindFloatingHelpDots;
        window.confirmUnlinkAllBindingsMoveToRecycleAsync = confirmUnlinkAllBindingsMoveToRecycleAsync;

        if(typeof window.onManagedTableBatchDownload !== 'function'){
            window.onManagedTableBatchDownload = function(ids, table, state){
                defaultManagedTableBatchDownload(ids, table, state);
            };
        }

        if(typeof window.onManagedTableBatchDelete !== 'function'){
            window.onManagedTableBatchDelete = function(ids, table, state){
                defaultManagedTableBatchDelete(ids, table, state);
            };
        }

        syncModalScrollLock();

        let bodyEnhanceScheduled = false;
        const bodyObserver = new MutationObserver(() => {
            if(bodyEnhanceScheduled) return;
            bodyEnhanceScheduled = true;
            window.requestAnimationFrame(() => {
                bodyEnhanceScheduled = false;
                enhanceManagedTables(document);
                bindFloatingHelpDots(document);
                partitionPmCardToolbars(document);
                enhanceCustomDateInputs(document);
                initOptionalDateInputs(document);
                normalizeResetButtons(document);
                bridgeLegacyResponseToToast(document);
                syncModalScrollLock();
                repositionManagedBatchBars();
                initColorSwatchPickers(document);
            });
        });
        bodyObserver.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ['class']
        });
    };

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();