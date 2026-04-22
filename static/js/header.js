// 在页面加载时动态注入顶部导航，保持各模板统一
(function(){
    const universalSelectState = new Map();
    const managedTableState = new Map();
    const PAGE_SIZE_OPTIONS = [20, 50, 100, 300, 500, 1000];
    const responseToastState = new WeakMap();
    let toastStack = null;
    let activeColumnsPanelState = null;
    let activeResizeState = null;
    let activeHelpDotTooltip = null;
    let activeDatePickerState = null;
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
        state.menu.style.zIndex = '5600';
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
        const stack = ensureToastStack();
        const toast = document.createElement('div');
        toast.className = `app-toast ${isError ? 'error persistent' : 'success'}`;

        const messageEl = document.createElement('div');
        messageEl.className = 'app-toast-message';
        messageEl.textContent = text;
        toast.appendChild(messageEl);

        const actions = document.createElement('div');
        actions.className = 'app-toast-actions';

        const closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'app-toast-btn close';
        closeBtn.setAttribute('aria-label', '关闭提示');
        closeBtn.textContent = '×';
        actions.appendChild(closeBtn);

        const copyBtn = document.createElement('button');
        copyBtn.type = 'button';
        copyBtn.className = 'app-toast-btn copy';
        copyBtn.textContent = '复制';
        actions.appendChild(copyBtn);

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

        if(isError) return;
        const timeout = Number(duration || 2600);
        window.setTimeout(removeToast, Math.max(800, timeout));
    }

    function parseDownloadFilename(contentDisposition, fallbackName){
        const fallback = String(fallbackName || 'template.xlsx');
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
        const filename = parseDownloadFilename(resp.headers.get('content-disposition'), fallbackName || 'template.xlsx');
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        if(a.parentNode) a.parentNode.removeChild(a);
        window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
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
        if(titleEl) titleEl.textContent = title;
        if(msgEl) msgEl.textContent = message;
        if(confirmBtn) confirmBtn.textContent = confirmText;
        if(cancelBtn) cancelBtn.textContent = cancelText;
        if(checkTextEl) checkTextEl.textContent = checkText;
        if(checkRow) checkRow.style.display = requireCheck ? '' : 'none';
        if(checkInput) checkInput.checked = false;

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
            if(confirmBtn) confirmBtn.removeEventListener('click', onConfirm);
            if(cancelBtn) cancelBtn.removeEventListener('click', onCancel);
            if(checkInput) checkInput.removeEventListener('change', updateConfirmState);
            modal.removeEventListener('click', onBackdrop);
            document.removeEventListener('keydown', onEsc);
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

        const onBackdrop = (event) => {
            if(event.target === modal) onCancel();
        };

        const onEsc = (event) => {
            if(event.key === 'Escape') onCancel();
        };

        if(confirmBtn) confirmBtn.addEventListener('click', onConfirm);
        if(cancelBtn) cancelBtn.addEventListener('click', onCancel);
        if(checkInput) checkInput.addEventListener('change', updateConfirmState);
        modal.addEventListener('click', onBackdrop);
        document.addEventListener('keydown', onEsc);

        modal.classList.add('active');
        syncModalScrollLock();
    }

    function showAppConfirmAsync(options){
        return new Promise((resolve) => {
            showAppConfirm(Object.assign({}, (options || {}), {
                onClose: (ok) => resolve(!!ok)
            }));
        });
    }

    function ensureHelpDotTooltip(){
        if(activeHelpDotTooltip && document.body.contains(activeHelpDotTooltip)) return activeHelpDotTooltip;
        const tooltip = document.createElement('div');
        tooltip.className = 'app-help-floating-tip';
        tooltip.style.display = 'none';
        document.body.appendChild(tooltip);
        activeHelpDotTooltip = tooltip;
        return tooltip;
    }

    function hideHelpDotTooltip(){
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

    function showHelpDotTooltip(dot){
        const text = resolveHelpDotTipText(dot);
        if(!text) return;
        const tooltip = ensureHelpDotTooltip();
        tooltip.textContent = text;
        tooltip.style.display = 'block';
        positionHelpDotTooltip(dot, tooltip);
    }

    function bindFloatingHelpDots(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.help-dot').forEach(dot => {
            if(dot.dataset.helpFloatingBound === '1') return;
            dot.dataset.helpFloatingBound = '1';
            dot.classList.add('help-dot--floating');
            dot.addEventListener('mouseenter', () => showHelpDotTooltip(dot));
            dot.addEventListener('mouseleave', hideHelpDotTooltip);
            dot.addEventListener('focus', () => showHelpDotTooltip(dot));
            dot.addEventListener('blur', hideHelpDotTooltip);
        });
    }

    function showAppResultPanel(options){
        const opt = options && typeof options === 'object' ? options : { title: '处理结果', summary: String(options || '') };
        const title = String(opt.title || '处理结果').trim() || '处理结果';
        const summary = String(opt.summary || '').trim();
        const details = Array.isArray(opt.details) ? opt.details : [];
        const isError = !!opt.isError;

        let panel = document.getElementById('app-result-panel');
        if(!panel){
            panel = document.createElement('div');
            panel.id = 'app-result-panel';
            panel.className = 'app-result-panel';
            panel.innerHTML = [
                '<div class="app-result-panel-head">',
                '  <div class="app-result-panel-title"></div>',
                '  <button type="button" class="app-result-panel-close" aria-label="关闭">×</button>',
                '</div>',
                '<div class="app-result-panel-summary"></div>',
                '<ul class="app-result-panel-list"></ul>'
            ].join('');
            document.body.appendChild(panel);
            const closeBtn = panel.querySelector('.app-result-panel-close');
            if(closeBtn){
                closeBtn.addEventListener('click', () => panel.classList.remove('show'));
            }
        }

        panel.classList.toggle('error', isError);
        panel.classList.toggle('success', !isError);
        const titleEl = panel.querySelector('.app-result-panel-title');
        const summaryEl = panel.querySelector('.app-result-panel-summary');
        const listEl = panel.querySelector('.app-result-panel-list');

        if(titleEl) titleEl.textContent = title;
        if(summaryEl) {
            summaryEl.textContent = summary || '';
            summaryEl.style.display = summary ? '' : 'none';
        }
        if(listEl){
            if(details.length){
                listEl.innerHTML = details.map(item => `<li>${String(item || '')}</li>`).join('');
                listEl.style.display = '';
            } else {
                listEl.innerHTML = '';
                listEl.style.display = 'none';
            }
        }

        panel.classList.add('show');
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
    }

    function hideAppUploadProgress(){
        const panel = document.getElementById('app-upload-progress-panel');
        if(panel) panel.classList.remove('show');
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
            const state = { lastSig: '' };
            responseToastState.set(el, state);
            el.style.display = 'none';

            const flushToast = () => {
                const text = String(el.textContent || '').trim();
                if(!text) return;
                const isError = inferErrorFromResponseEl(el);
                const sig = `${isError ? 'e' : 's'}:${text}`;
                if(sig === state.lastSig) return;
                state.lastSig = sig;
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

    function enhanceHeroSections(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('.hero').forEach(hero => {
            const title = hero.querySelector('h2');
            if(!title) return;
            hero.classList.add('is-standard-page-hero');

            let titleRow = hero.querySelector('.hero-title-row');
            if(!titleRow){
                titleRow = document.createElement('div');
                titleRow.className = 'hero-title-row';
                title.parentNode.insertBefore(titleRow, title);
                titleRow.appendChild(title);
            }

            const note = hero.querySelector('p');
            if(!note) return;

            let dot = titleRow.querySelector('.hero-help-dot');
            if(!dot){
                dot = document.createElement('span');
                dot.className = 'help-dot hero-help-dot';
                titleRow.appendChild(dot);
            }
            dot.textContent = '';
            dot.dataset.tip = (note.textContent || '').trim();
            dot.style.display = dot.dataset.tip ? '' : 'none';

            if(!note.dataset.heroNoteObserved){
                note.dataset.heroNoteObserved = '1';
                const observer = new MutationObserver(() => {
                    dot.dataset.tip = (note.textContent || '').trim();
                    dot.style.display = dot.dataset.tip ? '' : 'none';
                });
                observer.observe(note, { childList: true, subtree: true, characterData: true });
            }
        });
    }

    function shouldManageTable(table){
        if(!table || table.tagName !== 'TABLE') return false;
        if(table.dataset.disableTableManage === '1') return false;
        if(!table.tHead || !table.tBodies || !table.tBodies[0]) return false;
        if(!table.tHead.rows.length) return false;
        const firstRow = table.tHead.rows[0];
        if(!firstRow || firstRow.cells.length < 2) return false;
        return true;
    }

    function getHeaderMeta(table){
        if(!table.tHead || !table.tHead.rows.length) return [];
        const cells = Array.from(table.tHead.rows[0].cells || []);
        return cells.map((cell, idx) => {
            if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
            const origin = Number(cell.dataset.manageColOrigin);
            const rawLabel = extractHeaderLabelText(cell);
            const key = String(cell.dataset.manageColKey || rawLabel || `字段${origin + 1}`).trim();
            if(!cell.dataset.manageColKey) cell.dataset.manageColKey = key;
            const fallback = cell.querySelector('input[type="checkbox"]') ? '多选框' : `字段${origin + 1}`;
            return {
                origin,
                key,
                label: rawLabel || fallback,
                cell
            };
        });
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

    function computeDefaultColumnWidth(state, meta){
        if(!meta || !meta.cell) return 80;
        if(meta.cell.querySelector('input[type="checkbox"]')) return 64;

        const inlineW = parseInt(meta.cell.style.width, 10) || 0;
        if(inlineW > 0) return inlineW;

        const rows = getDataRows(state);
        const sampleCount = Math.min(rows.length, 120);
        let maxLen = String(meta.label || '').trim().length;

        for(let i = 0; i < sampleCount; i += 1){
            const row = rows[i];
            if(!row) continue;
            const cell = mapRowByKey(row).get(meta.key);
            if(!cell) continue;
            let len = String(cell.textContent || '').trim().length;
            if(cell.querySelector('img')) len = Math.max(len, 4);
            maxLen = Math.max(maxLen, Math.min(len, 40));
        }

        const headerLen = String(meta.label || '').trim().length;
        const headerWidth = Math.ceil(headerLen * 16 + 34);
        return Math.max(64, Math.min(520, Math.max(headerWidth, Math.ceil(maxLen * 13 + 26))));
    }

    function readPersistedColumns(table, headerMeta){
        const validKeys = (Array.isArray(headerMeta) ? headerMeta : []).map(meta => String(meta.key || '').trim()).filter(Boolean);
        const legacyKeyMap = new Map((Array.isArray(headerMeta) ? headerMeta : []).map(meta => [String(meta.origin), String(meta.key || '').trim()]));
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'visible-columns'));
            if(!raw) return new Set(validKeys);
            const arr = JSON.parse(raw);
            const valid = Array.isArray(arr)
                ? arr.map(v => {
                    const key = String(v || '').trim();
                    if(validKeys.includes(key)) return key;
                    return legacyKeyMap.get(key) || '';
                }).filter(key => !!key && validKeys.includes(key))
                : [];
            return new Set(valid.length ? valid : validKeys);
        } catch (_) {
            return new Set(validKeys);
        }
    }

    function readPersistedOrder(table, headerMeta){
        const validKeys = (Array.isArray(headerMeta) ? headerMeta : []).map(meta => String(meta.key || '').trim()).filter(Boolean);
        const legacyKeyMap = new Map((Array.isArray(headerMeta) ? headerMeta : []).map(meta => [String(meta.origin), String(meta.key || '').trim()]));
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'column-order'));
            if(!raw) return validKeys.slice();
            const arr = JSON.parse(raw);
            const inOrder = Array.isArray(arr)
                ? arr.map(v => {
                    const key = String(v || '').trim();
                    if(validKeys.includes(key)) return key;
                    return legacyKeyMap.get(key) || '';
                }).filter(key => !!key && validKeys.includes(key))
                : [];
            validKeys.forEach(v => {
                if(!inOrder.includes(v)) inOrder.push(v);
            });
            return inOrder;
        } catch (_) {
            return validKeys.slice();
        }
    }

    function persistColumns(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'visible-columns'), JSON.stringify(Array.from(state.visibleColumns.values())));
        } catch (_) {}
    }

    function persistColumnOrder(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'column-order'), JSON.stringify(state.columnOrder.slice()));
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
            const data = raw ? JSON.parse(raw) : {};
            return data && typeof data === 'object' ? data : {};
        } catch (_) {
            return {};
        }
    }

    function persistColumnWidths(state){
        try {
            localStorage.setItem(makeStorageKey(state.table, 'column-widths'), JSON.stringify(state.columnWidths || {}));
        } catch (_) {}
    }

    function isPlaceholderRow(row, headerCount){
        if(!row) return false;
        if(row.cells.length !== 1) return false;
        const onlyCell = row.cells[0];
        return Number(onlyCell.colSpan || 1) >= Math.max(headerCount, 2);
    }

    function getDataRows(state){
        const rows = Array.from(state.tbody.rows || []);
        if(rows.length === 1 && isPlaceholderRow(rows[0], state.headerCount)) return [];
        return rows;
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
    }

    function clearGridSelection(){
        if(!activeGridSelection) return;
        clearGridSelectionClasses(activeGridSelection.state && activeGridSelection.state.table);
        activeGridSelection = null;
    }

    function getVisibleRows(state){
        return getDataRows(state).filter(row => row && row.style.display !== 'none');
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

    function paintGridSelection(){
        if(!activeGridSelection || !activeGridSelection.state) return;
        const state = activeGridSelection.state;
        clearGridSelectionClasses(state.table);
        activeGridSelection.selectedCells.forEach(cell => {
            if(cell && cell.isConnected) cell.classList.add('pm-grid-cell-selected');
        });
        const anchorCell = getCellByCoord(state, activeGridSelection.anchorCoord);
        if(anchorCell) anchorCell.classList.add('pm-grid-cell-anchor');
        (activeGridSelection.detailSelections || new Map()).forEach((detailSel, cell) => {
            if(!cell || !cell.isConnected || !detailSel || !detailSel.anchor || !detailSel.current) return;
            const rect = normalizeTransitDetailRect(detailSel.anchor, detailSel.current);
            const nodes = getTransitDetailNodesByRect(cell, rect);
            nodes.forEach(node => node.classList.add('pm-grid-detail-selected'));
            const anchorNodes = getTransitDetailNodesByRect(cell, normalizeTransitDetailRect(detailSel.anchor, detailSel.anchor));
            if(anchorNodes[0]) anchorNodes[0].classList.add('pm-grid-detail-anchor');
        });
        if(activeGridSelection.selectedCells.size > 0){
            state.table.classList.add('is-grid-selecting');
        }
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
            detailSelections: new Map(),
            detailDragging: null
        };
        return activeGridSelection;
    }

    function selectCellsForState(state, cells, anchorCoord){
        const selection = ensureGridSelectionState(state);
        selection.selectedCells = new Set((cells || []).filter(Boolean));
        selection.anchorCoord = anchorCoord || null;
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
        if(!activeGridSelection || !activeGridSelection.state || !activeGridSelection.selectedCells.size) return false;
        const state = activeGridSelection.state;
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
                if(!cell || !isTransitDetailCell(cell)) continue;
                const detailMatrix = getTransitDetailValueMatrix(cell);
                if(!detailMatrix.length) continue;
                const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
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
        return !!(state && activeGridSelection && activeGridSelection.state === state && activeGridSelection.selectedCells && activeGridSelection.selectedCells.size > 0);
    }

    function bindGridSelection(state){
        if(!state || !state.tbody || state.tbody.dataset.gridSelectBound === '1') return;
        state.tbody.dataset.gridSelectBound = '1';

        state.tbody.addEventListener('mousedown', (event) => {
            if(event.button !== 0) return;
            const cell = event.target && event.target.closest ? event.target.closest('td') : null;
            if(!cell || !state.tbody.contains(cell)) return;
            if(cell.classList.contains('pm-table-hide-col')) return;
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

            const detailCoord = getTransitDetailNodeCoord(event.target, cell);
            if(detailCoord){
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
                activeGridSelection.dragging = true;
                activeGridSelection.dragAnchor = coord;
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

    function mapRowByKey(row){
        const map = new Map();
        Array.from(row.cells || []).forEach((cell, idx) => {
            const key = String(cell.dataset.manageColKey || '').trim() || `字段${idx + 1}`;
            if(!cell.dataset.manageColKey) cell.dataset.manageColKey = key;
            map.set(key, cell);
        });
        return map;
    }

    function ensureManagedColumnKeys(state, headerMeta){
        if(!state || !state.table || !Array.isArray(headerMeta) || !headerMeta.length) return;
        const originToKey = new Map();
        headerMeta.forEach((meta, idx) => {
            const origin = Number(meta && meta.origin);
            const key = String(meta && meta.key || '').trim() || `字段${idx + 1}`;
            if(Number.isFinite(origin)) originToKey.set(origin, key);
        });

        const resolveKeyByCell = (cell, idx) => {
            if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
            const origin = Number(cell.dataset.manageColOrigin);
            if(Number.isFinite(origin) && originToKey.has(origin)) return originToKey.get(origin);
            const fallbackMeta = headerMeta[idx];
            if(fallbackMeta && String(fallbackMeta.key || '').trim()) return String(fallbackMeta.key || '').trim();
            return `字段${idx + 1}`;
        };

        const headerRow = getPrimaryHeaderRow(state);
        if(headerRow && headerRow.cells){
            Array.from(headerRow.cells || []).forEach((cell, idx) => {
                const key = resolveKeyByCell(cell, idx);
                if(String(cell.dataset.manageColKey || '').trim() !== key) cell.dataset.manageColKey = key;
            });
        }

        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== state.headerCount) return;
            Array.from(row.cells || []).forEach((cell, idx) => {
                const key = resolveKeyByCell(cell, idx);
                if(String(cell.dataset.manageColKey || '').trim() !== key) cell.dataset.manageColKey = key;
            });
        });
    }

    function getPrimaryHeaderRow(state){
        if(state && state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows && state.headerTable.tHead.rows[0]){
            return state.headerTable.tHead.rows[0];
        }
        if(state && state.table && state.table.tHead && state.table.tHead.rows && state.table.tHead.rows[0]){
            return state.table.tHead.rows[0];
        }
        return null;
    }

    function syncDetachedHeader(state){
        if(!state || !state.headerTable || !state.table || !state.table.tHead || !state.table.tHead.rows.length) return;
        const srcHead = state.table.tHead;
        const srcRow = srcHead.rows[0];
        if(!srcRow) return;

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

        const cloned = srcRow.cloneNode(true);
        cloned.querySelectorAll('.pm-col-resizer').forEach(node => node.remove());
        cloned.querySelectorAll('[data-sort-bound]').forEach(node => node.removeAttribute('data-sort-bound'));
        dstHead.appendChild(cloned);

        srcHead.classList.add('pm-managed-hidden-head');
    }

    function applyColumnOrder(state){
        syncManagedColgroupOrder(state);
        const expected = state.headerCount;
        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== expected) return;
            const currentOrder = Array.from(row.cells).map(cell => String(cell.dataset.manageColKey || '').trim());
            if(currentOrder.length === state.columnOrder.length && currentOrder.every((v, i) => v === state.columnOrder[i])) {
                return;
            }
            const byKey = mapRowByKey(row);
            state.columnOrder.forEach(key => {
                const cell = byKey.get(String(key || '').trim());
                if(cell) row.appendChild(cell);
            });
        });
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

    function applyColumnVisibility(state){
        const visible = state.visibleColumns;
        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== state.headerCount) return;
            Array.from(row.cells).forEach(cell => {
                const key = String(cell.dataset.manageColKey || '').trim();
                cell.classList.toggle('pm-table-hide-col', !visible.has(key));
            });
        });
    }

    function setColumnWidthByKey(state, key, widthPx){
        const width = Math.max(36, Math.round(Number(widthPx) || 0));
        const columnKey = String(key || '').trim();
        if(!columnKey) return;
        state.columnWidths[columnKey] = width;

        const colgroup = state.table && state.table.querySelector ? state.table.querySelector('colgroup') : null;
        if(colgroup){
            const matchedCols = Array.from(colgroup.children || [])
                .filter(node => node && String(node.tagName || '').toUpperCase() === 'COL')
                .filter(node => String(node.dataset.manageColKey || '').trim() === columnKey);

            // When a header cell spans multiple <col> (colSpan > 1), we persist / resize using the
            // "group width" but must distribute it into each underlying column width. Otherwise the
            // group width is multiplied by the span and causes jumpy resizing + misalignment.
            if(matchedCols.length){
                const spanHint = Math.max(
                    1,
                    ...matchedCols.map(col => Math.max(1, Number(col.dataset.manageColSpan || 1) || 1))
                );
                const span = Math.max(1, Math.min(spanHint, matchedCols.length));
                const perColWidth = Math.max(24, Math.round(width / span));
                matchedCols.forEach(node => {
                    node.style.width = `${perColWidth}px`;
                    node.style.minWidth = `${perColWidth}px`;
                    node.style.maxWidth = `${perColWidth}px`;
                });
            }
        }

        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== state.headerCount) return;
            Array.from(row.cells).forEach(cell => {
                if(String(cell.dataset.manageColKey || '').trim() !== columnKey) return;
                cell.style.width = `${width}px`;
                cell.style.minWidth = `${width}px`;
                cell.style.maxWidth = `${width}px`;
            });
        });

        if(state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows.length){
            const headerRow = state.headerTable.tHead.rows[0];
            Array.from(headerRow.cells || []).forEach(cell => {
                if(String(cell.dataset.manageColKey || '').trim() !== columnKey) return;
                cell.style.width = `${width}px`;
                cell.style.minWidth = `${width}px`;
                cell.style.maxWidth = `${width}px`;
            });
        }
    }

    function applyColumnWidths(state){
        const widths = state.columnWidths || {};
        Object.keys(widths).forEach(key => setColumnWidthByKey(state, key, Number(widths[key])));
    }

    function ensureResizeHandles(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow || headerRow.cells.length !== state.headerCount) return;

        Array.from(headerRow.cells).forEach(cell => {
            if(cell.querySelector('.pm-col-resizer')) return;
            const handle = document.createElement('span');
            handle.className = 'pm-col-resizer';
            handle.addEventListener('mousedown', (event) => {
                event.preventDefault();
                event.stopPropagation();
                const key = String(cell.dataset.manageColKey || '').trim();
                activeResizeState = {
                    state,
                    key,
                    startX: event.clientX,
                    startWidth: cell.getBoundingClientRect().width,
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

    function repositionColumnsPanel(state){
        if(!state || !state.columnPanel.classList.contains('open')) return;
        const triggerRect = state.columnsTrigger.getBoundingClientRect();
        const panel = state.columnPanel;
        panel.style.visibility = 'hidden';
        panel.style.display = 'grid';
        const panelRect = panel.getBoundingClientRect();
        const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
        const alignLeft = state.headerCount <= 5;
        let left = alignLeft ? triggerRect.left : (triggerRect.right - panelRect.width);
        let top = triggerRect.bottom + 8;
        left = Math.max(8, Math.min(left, viewportWidth - panelRect.width - 8));
        top = Math.max(8, Math.min(top, viewportHeight - panelRect.height - 8));
        panel.style.left = `${left}px`;
        panel.style.top = `${top}px`;
        panel.style.visibility = 'visible';
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
        state.columnPanel.classList.add('open');
        state.columnPanel.style.pointerEvents = 'auto';
        state.columnsTrigger.setAttribute('aria-expanded', 'true');
        activeColumnsPanelState = state;
        repositionColumnsPanel(state);
    }

    function closeAllResetMenus(exceptWrap){
        const keep = exceptWrap && exceptWrap.classList ? exceptWrap : null;
        document.querySelectorAll('.pm-table-reset-group.is-open').forEach((wrap) => {
            if(keep && keep === wrap) return;
            wrap.classList.remove('is-open');
        });
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
            applyColumnWidths(state);
            ensureSortableHeaders(state);
            ensureResizeHandles(state);
            refreshSortHeaderUi(state);
            applySort(state);
            applyPagination(state);
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
                applyColumnVisibility(state);
                syncDetachedHeader(state);
                applyColumnWidths(state);
                ensureSortableHeaders(state);
                ensureResizeHandles(state);
                refreshSortHeaderUi(state);
                applySort(state);
                applyPagination(state);
                syncTopScroll(state);
            });

            const text = document.createElement('span');
            text.textContent = header.label;
            if(isLocked) text.title = '该列为多选/选择列，不能隐藏';
            main.appendChild(checkbox);
            main.appendChild(text);

            const drag = document.createElement('span');
            drag.className = 'pm-table-columns-item-drag';
            drag.textContent = '⋮⋮';

            item.appendChild(main);
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
        const allRows = getDataRows(state);
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
    }

    function isMultiSelectColumn(headerCell, label){
        if(!headerCell) return false;
        if(headerCell.querySelector('input[type="checkbox"]')) return true;
        const t = String(label || '').trim();
        if(!t) return false;
        return /多选|选择|勾选/.test(t);
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

    function getRowCellByKey(row, columnKey){
        if(!row || !row.cells) return null;
        const key = String(columnKey || '').trim();
        if(!key) return null;
        return mapRowByKey(row).get(key) || null;
    }

    function collectManagedColumnFilterOptions(state, columnKey, query, exact, limit){
        const rows = getDataRows(state);
        const q = String(query || '').trim().toLowerCase();
        const isExact = !!exact;
        const counts = new Map();
        rows.forEach(row => {
            const cell = getRowCellByKey(row, columnKey);
            const value = readCellFilterText(cell);
            if(!value) return;
            const text = String(value).trim();
            if(!text) return;
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
            .map(([value, count]) => ({ value, label: value, count }))
            .sort((a, b) => {
                if((b.count || 0) !== (a.count || 0)) return (b.count || 0) - (a.count || 0);
                return String(a.label || '').localeCompare(String(b.label || ''), 'zh-Hans-CN', { numeric: true, sensitivity: 'base' });
            })
            .slice(0, Math.max(1, Number(limit || 120) || 120));
    }

    function applyManagedColumnFilters(state, snapshot){
        const filters = snapshot || {};
        const rows = getDataRows(state);
        rows.forEach(row => {
            let pass = true;
            for(const key of Object.keys(filters)){
                const filter = filters[key] || {};
                const query = String(filter.query || '').trim();
                const exact = !!filter.exact;
                const selected = Array.isArray(filter.selected) ? filter.selected.map(v => String(v)) : [];
                if(!query && !selected.length) continue;
                const cell = getRowCellByKey(row, key);
                const value = String(readCellFilterText(cell) || '');
                if(selected.length && !selected.includes(value)){
                    pass = false;
                    break;
                }
                if(query){
                    if(exact){
                        if(value !== query){ pass = false; break; }
                    } else if(!value.toLowerCase().includes(query.toLowerCase())) {
                        pass = false;
                        break;
                    }
                }
            }
            row.dataset.pmFilterHidden = pass ? '0' : '1';
        });
        state.currentPage = 1;
        applyPagination(state);
        syncManagedBatchBar(state);
    }

    function ensureManagedTableColumnFilter(state){
        if(!state || !state.table || !state.table.tHead || !state.table.tHead.rows || !state.table.tHead.rows.length) return;
        if(String(state.table.dataset.serverPaginationMode || '').toLowerCase() === 'server' || state.table.dataset.serverPaginationMode === '1') return;
        if(!window.SitjoyColumnFilter || typeof window.SitjoyColumnFilter.attach !== 'function') return;

        const headerCells = Array.from(state.table.tHead.rows[0].cells || []);
        const columns = headerCells.map((cell, index) => {
            const label = extractHeaderLabelText(cell);
            const key = String(cell.dataset.manageColKey || label || `字段${index + 1}`).trim();
            return { index, key, label: label || `字段${index + 1}` };
        }).filter(item => {
            const label = String(item.label || '').trim();
            if(!label) return false;
            if(/操作|详情|动作/.test(label)) return false;
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
            fetchOptions: ({ columnKey, query, exact, limit }) => collectManagedColumnFilterOptions(state, columnKey, query, exact, limit),
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
            if(!text) return null;
            return { value: text, label: text, count: 0 };
        }
        const value = String(item.value ?? item.id ?? item.key ?? '').trim();
        if(!value) return null;
        const label = String(item.label ?? item.text ?? item.name ?? item.title ?? value).trim() || value;
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

        selectedSet.forEach(value => {
            if(seen.has(value)) return;
            seen.add(value);
            normalized.unshift({ value, label: value, count: 0 });
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

    function getColumnFilterFetchKey(columnKey, query, exact, limit){
        return `${String(columnKey || '').trim().toLowerCase()}|${String(query || '').trim().toLowerCase()}|${exact ? 1 : 0}|${Number(limit) || 0}`;
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
            const cacheKey = getColumnFilterFetchKey(columnKey, query, exact, limit);
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
                ? filterState.selected.map(v => ({ value: String(v || ''), label: String(v || ''), count: 0 })).filter(x => x.value)
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
                    if(!columnConfig) return;
                    cell.classList.add('pm-column-filter-th');
                    let btn = cell.querySelector('.pm-column-filter-btn');
                    if(!btn){
                        btn = document.createElement('button');
                        btn.type = 'button';
                        btn.className = 'pm-column-filter-btn';
                        btn.dataset.columnIndex = String(idx);
                        btn.dataset.columnKey = String(columnConfig.key || '').trim() || headerKey;
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
            const value = String(button.dataset.value || '');
            const filterState = state.filters.get(state.activeColumn) || { query: '', exact: false, selected: [] };
            filterState.selected = value ? [value] : [];
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
            filterState.selected = target.checked ? Array.from(new Set(options.map(input => String(input.dataset.value || '')).filter(Boolean))) : [];
            state.filters.set(state.activeColumn, filterState);
            syncSelectAllState();
        });

        const clickHandler = (event) => {
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
                    const index = Number(key);
                    state.filters.set(index, {
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

    window.SitjoyColumnFilter = {
        attach: attachColumnFilter,
        close: closeColumnFilterPopup,
        refresh(tableOrSelector){
            const table = resolveColumnFilterTable(tableOrSelector);
            if(!table) return null;
            const handle = columnFilterRegistry.get(table) || null;
            if(handle) handle.refreshButtons();
            return handle;
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

    function getManagedSelectionCheckboxes(state){
        if(!state || !state.tbody) return [];
        const rows = Array.from(state.tbody.rows || []);
        const fromLockedColumns = [];

        if(state.lockedColumns && state.lockedColumns.size){
            rows.forEach(row => {
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
            if(!cb.closest('tr')) return false;
            if(cb.classList.contains('switch-input')) return false;
            return cb.hasAttribute('data-id') || cb.classList.contains('row-check') || cb.name === 'row-check' || /select|check/i.test(String(cb.className || ''));
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
        modal.addEventListener('click', (event) => {
            if(event.target === modal) closeBatchConfirmModal();
        });
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

    function ensureManagedBatchBar(state){
        if(!state || !state.wrap) return null;
        if(state.batchBar && document.body.contains(state.batchBar)) return state.batchBar;

        const bar = document.createElement('div');
        bar.className = 'pm-batch-float-bar';
        bar.innerHTML = [
            '<span class="pm-batch-float-count">已勾选 0 条</span>',
            '<button type="button" class="btn-secondary" data-action="download">批量下载数据</button>',
            '<button type="button" class="btn-danger" data-action="delete">批量删除</button>'
        ].join('');
        document.body.appendChild(bar);

        const downloadBtn = bar.querySelector('[data-action="download"]');
        const deleteBtn = bar.querySelector('[data-action="delete"]');

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

    function applySort(state){
        const sortOrigin = String(state.sortOrigin || '').trim();
        const sortDir = state.sortDir;
        const rows = getDataRows(state);
        if(!rows.length) return;

        if(!sortOrigin || !sortDir){
            if(!state.sortApplied) return;
            rows.sort((a, b) => Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0'));
            const sortedOrigins = rows.map(r => Number(r.dataset.sortOrigin || '0'));
            const sameOrder = Array.from(state.tbody.rows || []).every((r, idx) => Number(r.dataset.sortOrigin || '0') === sortedOrigins[idx]);
            if(!sameOrder) rows.forEach(row => state.tbody.appendChild(row));
            state.sortApplied = false;
            return;
        }

        rows.sort((a, b) => {
            const aCell = mapRowByKey(a).get(sortOrigin);
            const bCell = mapRowByKey(b).get(sortOrigin);
            const av = readCellComparableValue(aCell);
            const bv = readCellComparableValue(bCell);
            if(typeof av === 'number' && typeof bv === 'number') return sortDir === 'asc' ? (av - bv) : (bv - av);
            if(av === bv) return Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0');
            return sortDir === 'asc' ? String(av).localeCompare(String(bv), 'zh') : String(bv).localeCompare(String(av), 'zh');
        });

        const sortedOrigins = rows.map(r => Number(r.dataset.sortOrigin || '0'));
        const sameOrder = Array.from(state.tbody.rows || []).every((r, idx) => Number(r.dataset.sortOrigin || '0') === sortedOrigins[idx]);
        if(!sameOrder) rows.forEach(row => state.tbody.appendChild(row));
        state.sortApplied = true;
    }

    function refreshSortHeaderUi(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow) return;
        Array.from(headerRow.cells || []).forEach(cell => {
            if(cell.dataset.disableSort === '1') return;
            const origin = String(cell.dataset.manageColKey || '').trim();
            cell.classList.remove('pm-sortable', 'pm-sort-asc', 'pm-sort-desc');
            if(state.lockedColumns.has(origin)) return;
            cell.classList.add('pm-sortable');
            if(state.sortOrigin !== origin || !state.sortDir) return;
            if(state.sortDir === 'asc') cell.classList.add('pm-sort-asc');
            if(state.sortDir === 'desc') cell.classList.add('pm-sort-desc');
        });
    }

    function ensureSortableHeaders(state){
        const headerRow = getPrimaryHeaderRow(state);
        if(!headerRow) return;
        Array.from(headerRow.cells).forEach(cell => {
            if(cell.dataset.disableSort === '1') return;
            if(cell.dataset.sortBound === '1') return;
            cell.dataset.sortBound = '1';
            cell.addEventListener('click', (event) => {
                if(Date.now() < suppressSortUntil) return;
                if(event.target.closest('.pm-col-resizer')) return;
                if(event.target.closest('input, button, select, textarea, label, a')) return;
                if(cell.querySelector('input[type="checkbox"]')) return;
                const origin = String(cell.dataset.manageColKey || '').trim();
                if(state.lockedColumns.has(origin)) return;
                if(state.sortOrigin !== origin){
                    state.sortOrigin = origin;
                    state.sortDir = 'desc';
                } else if(state.sortDir === 'desc'){
                    state.sortDir = 'asc';
                } else if(state.sortDir === 'asc'){
                    state.sortDir = null;
                } else {
                    state.sortDir = 'desc';
                }
                refreshSortHeaderUi(state);
                applySort(state);
                applyPagination(state);
            });
        });
    }

    function syncTopScroll(state){
        if(!state.topScroll || !state.topScrollInner || !state.wrap) return;
        let headerWidth = 0;
        const headerRow = getPrimaryHeaderRow(state);
        if(headerRow){
            Array.from(headerRow.cells || []).forEach(cell => {
                if(cell.classList.contains('pm-table-hide-col')) return;
                const styled = parseFloat(cell.style.width || '0') || 0;
                const measured = Math.ceil(cell.getBoundingClientRect().width || 0);
                headerWidth += Math.max(styled, measured, 36);
            });
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

        const validKeys = headerMeta.map(meta => String(meta.key || '').trim()).filter(Boolean);
        const headerSignature = headerMeta
            .slice()
            .sort((a, b) => String(a.key || '').localeCompare(String(b.key || ''), 'zh-Hans-CN', { sensitivity: 'base' }))
            .map(meta => `${meta.key}:${meta.label}`)
            .join('|');

        if(headerSignature !== state.headerSignature){
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
                const width = Number(stored ?? legacy ?? compact);
                resolvedWidths[key] = Number.isFinite(width) && width > 0 ? width : compact;
            });
            state.columnWidths = resolvedWidths;
            try {
                localStorage.setItem(makeStorageKey(state.table, 'column-widths'), JSON.stringify(state.columnWidths || {}));
            } catch (_) {
            }
            state.lockedColumns = new Set(
                headerMeta
                    .filter(meta => isMultiSelectColumn(meta.cell, meta.label))
                    .map(meta => String(meta.key || '').trim())
            );
            state.lockedColumns.forEach(key => state.visibleColumns.add(String(key || '').trim()));
            validKeys.forEach(key => {
                if(!state.columnOrder.includes(key)) state.columnOrder.push(key);
            });
            if(!state.light){
                state.columnsWrap.style.display = headerCount >= 2 ? '' : 'none';
                renderColumnPanel(state);
            }
        }

        ensureRowSortOrigin(state);
        ensureManagedBatchHandlers(state);
        if(!state.light){
            applyColumnOrder(state);
            applyColumnVisibility(state);
            syncDetachedHeader(state);
            applyColumnWidths(state);
        }
        ensureSortableHeaders(state);
        refreshSortHeaderUi(state);
        applySort(state);
        if(!state.light){
            ensureResizeHandles(state);
            applyPagination(state);
            syncManagedBatchBar(state);
            syncTopScroll(state);
            if(activeColumnsPanelState === state) repositionColumnsPanel(state);
        }
        ensureManagedTableColumnFilter(state);

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
            wrap.classList.add('is-managed-wrap', 'pm-managed-body-wrap');

            headWrap = document.createElement('div');
            headWrap.className = 'pm-table-wrap pm-managed-head-wrap is-managed-wrap';
            headTable = document.createElement('table');
            headTable.className = `${table.className} pm-managed-head-table`;
            headTable.setAttribute('data-disable-table-manage', '1');
            headWrap.appendChild(headTable);

            toolbar = document.createElement('div');
            toolbar.className = 'pm-table-toolbar';
            toolbar.innerHTML = `
                <div class="pm-table-toolbar-left">
                    <label>每页</label>
                    <select class="pm-table-page-size" data-universal-no-search="1"></select>
                    <span class="pm-table-info"></span>
                </div>
                <div class="pm-table-toolbar-right">
                    <div class="pm-table-reset-group">
                        <button type="button" class="pm-table-columns-reset btn-secondary" title="重置列宽、字段排序、字段显示">重置</button>
                        <div class="pm-table-reset-menu" aria-label="重置菜单">
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="width">重置列宽</button>
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="order">重置字段排序</button>
                            <button type="button" class="pm-table-reset-item btn-secondary" data-reset-mode="visibility">重置字段显示</button>
                        </div>
                    </div>
                    <div class="pm-table-columns">
                        <button type="button" class="pm-table-columns-trigger btn-secondary" aria-expanded="false">字段显示</button>
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
            wrap.parentNode.insertBefore(headWrap, wrap);
            wrap.parentNode.insertBefore(topScroll, wrap);
        }

        const state = {
            table,
            tbody: table.tBodies[0],
            wrap,
            headWrap,
            headerTable: headTable,
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
            resetWrap: toolbar ? toolbar.querySelector('.pm-table-reset-group') : null,
            resetMenu: toolbar ? toolbar.querySelector('.pm-table-reset-menu') : null,
            pageSize: readPersistedPageSize(table),
            currentPage: 1,
            headerSignature: '',
            headerCount: 0,
            headers: [],
            visibleColumns: new Set(),
            lockedColumns: new Set(),
            columnOrder: [],
            columnWidths: {},
            defaultColumnWidths: {},
            dragOrigin: null,
            dragPlacement: null,
            sortOrigin: null,
            sortDir: null,
            sortApplied: false,
            isRefreshing: false,
            needRefresh: false,
            refreshScheduled: false,
            batchBar: null,
            columnFilterHandle: null
        };
        managedTableState.set(table, state);

        if(!isLightTable && state.columnPanel && state.columnPanel.parentNode !== document.body){
            document.body.appendChild(state.columnPanel);
        }

        if(!isLightTable){
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

            if(state.resetBtn && state.resetWrap){
                state.resetBtn.addEventListener('click', (event) => {
                    event.preventDefault();
                    event.stopPropagation();
                    const nextOpen = !state.resetWrap.classList.contains('is-open');
                    closeAllResetMenus(nextOpen ? state.resetWrap : null);
                    state.resetWrap.classList.toggle('is-open', nextOpen);
                });
            }

            state.toolbar.addEventListener('click', (event) => {
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
                    state.columnWidths = Object.assign({}, state.defaultColumnWidths || {});
                    persistColumnWidths(state);
                    applyColumnWidths(state);
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    applySort(state);
                    applyPagination(state);
                    syncTopScroll(state);
                    showAppToast('列宽已重置', false, 1200);
                    if(state.resetWrap) state.resetWrap.classList.remove('is-open');
                    return;
                }

                if(mode === 'order'){
                    try { localStorage.removeItem(makeStorageKey(state.table, 'column-order')); } catch (_) {}
                    state.columnOrder = (state.headers || []).map(h => String(h.key || '').trim()).filter(Boolean);
                    persistColumnOrder(state);
                    refreshLayout();
                    showAppToast('字段排序已重置', false, 1200);
                    if(state.resetWrap) state.resetWrap.classList.remove('is-open');
                    return;
                }

                if(mode === 'visibility'){
                    const allVisible = new Set((state.headers || []).map(h => String(h.key || '').trim()).filter(Boolean));
                    state.lockedColumns.forEach(key => allVisible.add(String(key || '').trim()));
                    state.visibleColumns = allVisible;
                    persistColumns(state);
                    applyColumnVisibility(state);
                    syncDetachedHeader(state);
                    ensureSortableHeaders(state);
                    ensureResizeHandles(state);
                    refreshSortHeaderUi(state);
                    applySort(state);
                    applyPagination(state);
                    syncTopScroll(state);
                    renderColumnPanel(state);
                    showAppToast('字段显示已重置', false, 1200);
                    if(state.resetWrap) state.resetWrap.classList.remove('is-open');
                }
            });

            state.wrap.addEventListener('scroll', () => {
                if(Math.abs(state.headWrap.scrollLeft - state.wrap.scrollLeft) > 1){
                    state.headWrap.scrollLeft = state.wrap.scrollLeft;
                }
                if(Math.abs(state.topScroll.scrollLeft - state.wrap.scrollLeft) > 1){
                    state.topScroll.scrollLeft = state.wrap.scrollLeft;
                }
            });

            state.headWrap.addEventListener('scroll', () => {
                if(Math.abs(state.wrap.scrollLeft - state.headWrap.scrollLeft) > 1){
                    state.wrap.scrollLeft = state.headWrap.scrollLeft;
                }
                if(Math.abs(state.topScroll.scrollLeft - state.headWrap.scrollLeft) > 1){
                    state.topScroll.scrollLeft = state.headWrap.scrollLeft;
                }
            });

            state.topScroll.addEventListener('scroll', () => {
                if(Math.abs(state.wrap.scrollLeft - state.topScroll.scrollLeft) > 1){
                    state.wrap.scrollLeft = state.topScroll.scrollLeft;
                }
                if(Math.abs(state.headWrap.scrollLeft - state.topScroll.scrollLeft) > 1){
                    state.headWrap.scrollLeft = state.topScroll.scrollLeft;
                }
            });

            // When users interact with checkbox controls in the cloned header,
            // forward the change to the original table header control that page scripts bind to.
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
                sourceCheckbox.dispatchEvent(new Event('change', { bubbles: true }));
                syncManagedBatchBarAsync(state);
            });

            state.table.addEventListener('change', (event) => {
                const target = event.target;
                if(!target || !(target instanceof HTMLInputElement)) return;
                if(target.type !== 'checkbox') return;
                syncManagedBatchBarAsync(state);
            });

            state.table.addEventListener('click', (event) => {
                const target = event.target;
                if(!target || !(target instanceof HTMLInputElement)) return;
                if(target.type !== 'checkbox') return;
                syncManagedBatchBarAsync(state);
            });
        }

        const scheduleRefresh = () => {
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

        refreshManagedTable(state);
    }

    function enhanceManagedTables(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('table').forEach((table, index) => createManagedTable(table, index));
    }

    function repositionManagedBatchBars(){
        managedTableState.forEach((state) => {
            if(!state || !state.batchBar || !state.batchBar.classList.contains('active')) return;
            positionManagedBatchBar(state);
        });
    }

    function initOptionalDateInputs(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('input.optional-field[type="date"], input.optional-field[type="datetime-local"], input[data-optional-date="1"]').forEach(input => {
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

    window.initUniversalSingleSelects = initUniversalSingleSelects;
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
    window.showAppUploadProgress = showAppUploadProgress;
    window.hideAppUploadProgress = hideAppUploadProgress;

    function applyHeaderPermissions(authData){
        const permissions = authData && authData.page_permissions ? authData.page_permissions : null;
        if(!permissions) return;

        document.querySelectorAll('[data-page-key]').forEach(link => {
            const key = String(link.dataset.pageKey || '');
            if(!key) return;
            const allowed = !!permissions[key];
            const item = link.closest('li');
            if(item && !item.classList.contains('dropdown')){
                item.style.display = allowed ? '' : 'none';
            }
            if(link.closest('.dropdown-menu')){
                const childItem = link.closest('li');
                if(childItem) childItem.style.display = allowed ? '' : 'none';
            }
        });

        document.querySelectorAll('.nav-item.dropdown').forEach(item => {
            const topLink = item.querySelector(':scope > a');
            const visibleChildren = Array.from(item.querySelectorAll(':scope .dropdown-menu li')).filter(li => li.style.display !== 'none');
            if(!visibleChildren.length){
                item.style.display = 'none';
                return;
            }
            item.style.display = '';
            if(topLink){
                const ownKey = String(topLink.dataset.pageKey || '');
                if(ownKey && !permissions[ownKey]){
                    const firstVisible = visibleChildren[0] && visibleChildren[0].querySelector('a[href]');
                    if(firstVisible) topLink.setAttribute('href', firstVisible.getAttribute('href'));
                }
            }
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

    function loadHeader(){
        Promise.all([
            fetch('/static/partials/header.html').then(r => r.text()),
            getCurrentAuthState()
        ])
            .then(([html, authData]) => {
                const el = document.getElementById('site-header');
                if(!el) return;
                el.innerHTML = html;
                applyHeaderPermissions(authData);

                // 设置当前激活的菜单样式
                const path = location.pathname || '/';
                document.querySelectorAll('.nav-menu a').forEach(a => a.classList.remove('active'));
                if(path === '/' || path === '/index.html'){
                    const elHome = document.querySelector('.nav-home'); if(elHome) elHome.classList.add('active');
                } else if(path.startsWith('/shop-brand-management') || path.startsWith('/amazon-account-health-management')){
                    const elShop = document.querySelector('.nav-shop'); if(elShop) elShop.classList.add('active');
                } else if(path.startsWith('/gallery')){
                    const elG = document.querySelector('.nav-gallery'); if(elG) elG.classList.add('active');
                } else if(path.startsWith('/amazon-ad-management') || path.startsWith('/amazon-ad-subtype-management') || path.startsWith('/amazon-ad-delivery-management') || path.startsWith('/amazon-ad-product-management') || path.startsWith('/amazon-ad-adjustment-management') || path.startsWith('/amazon-ad-keyword-management')){
                    const elAd = document.querySelector('.nav-amazon-ad'); if(elAd) elAd.classList.add('active');
                } else if(path.startsWith('/logistics-factory-management') || path.startsWith('/logistics-forwarder-management') || path.startsWith('/logistics-warehouse-management') || path.startsWith('/logistics-warehouse-inventory-management') || path.startsWith('/logistics-in-transit-management') || path.startsWith('/factory-stock-management') || path.startsWith('/factory-wip-management') || path.startsWith('/logistics-warehouse-dashboard')){
                    const elL = document.querySelector('.nav-logistics'); if(elL) elL.classList.add('active');
                } else if(path.startsWith('/product-management') || path.startsWith('/fabric-management') || path.startsWith('/feature-management') || path.startsWith('/material-management') || path.startsWith('/certification-management') || path.startsWith('/order-product-management')){
                    const elP = document.querySelector('.nav-product'); if(elP) elP.classList.add('active');
                } else if(path.startsWith('/sales-product-management') || path.startsWith('/sales-product-performance-management') || path.startsWith('/sales-order-registration-management') || path.startsWith('/parent-management')){
                    const elS = document.querySelector('.nav-sales'); if(elS) elS.classList.add('active');
                } else if(path.startsWith('/about')){
                    const elA = document.querySelector('.nav-about'); if(elA) elA.classList.add('active');
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
        if(!e.target.closest('.help-dot') && !e.target.closest('.app-help-floating-tip')) {
            hideHelpDotTooltip();
        }
        if(!e.target.closest('.pm-table-columns') && !e.target.closest('.pm-table-columns-panel')) {
            closeColumnsPanel(activeColumnsPanelState);
        }
        if(!e.target.closest('.pm-table-reset-group')) {
            closeAllResetMenus();
        }
    });

    document.addEventListener('mousedown', (e) => {
        if(!e.target.closest('.pm-table-columns') && !e.target.closest('.pm-table-columns-panel')) {
            closeColumnsPanel(activeColumnsPanelState);
        }
        if(!e.target.closest('.pm-table-reset-group')) {
            closeAllResetMenus();
        }
        if(activeGridSelection && !e.target.closest('.is-managed-table')) {
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
        if(e.key === 'Escape'){
            closeColumnsPanel(activeColumnsPanelState);
            closeAllResetMenus();
            closeAllDropdowns();
            closeDatePicker();
            closeBatchConfirmModal();
            clearGridSelection();
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
            const width = activeResizeState.startWidth + delta;
            setColumnWidthByKey(activeResizeState.state, activeResizeState.key, width);
        }

        if(activeGridSelection && activeGridSelection.detailDragging && activeGridSelection.state){
            const dragInfo = activeGridSelection.detailDragging;
            const state = activeGridSelection.state;
            const cell = dragInfo.cell;
            if(!cell || !cell.isConnected || !state.tbody.contains(cell)) return;
            const el = document.elementFromPoint(event.clientX, event.clientY);
            const hoverCell = el && el.closest ? el.closest('td') : null;
            if(!hoverCell || hoverCell !== cell) return;
            const detailCoord = getTransitDetailNodeCoord(el, cell);
            if(!detailCoord) return;
            const detailSel = (activeGridSelection.detailSelections || new Map()).get(cell);
            if(!detailSel) return;
            detailSel.current = detailCoord;
            paintGridSelection();
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
            selectCellsForState(state, getRectCells(state, anchor, coord), anchor);
            activeGridSelection.dragging = true;
            activeGridSelection.dragAnchor = anchor;
        }
    });

    document.addEventListener('mouseup', () => {
        if(activeResizeState){
            if(activeResizeState.hasMoved) suppressSortUntil = Date.now() + 260;
            activeResizeState.handle.classList.remove('is-active');
            persistColumnWidths(activeResizeState.state);
            activeResizeState = null;
            document.body.style.cursor = '';
            document.body.style.userSelect = '';
        }

        if(activeGridSelection){
            activeGridSelection.dragging = false;
            activeGridSelection.detailDragging = null;
        }
    });

    window.addEventListener('resize', () => {
        repositionOpenDropdowns();
        if(activeDatePickerState && activeDatePickerState.input) positionDatePicker(activeDatePickerState.input, activeDatePickerState);
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
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
        hideHelpDotTooltip();
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
        repositionManagedBatchBars();
    }, true);

    const boot = () => {
        loadHeader();
        initUniversalSingleSelects(document);
        enhanceCustomDateInputs(document);
        initOptionalDateInputs(document);
        normalizeResetButtons(document);
        enhanceHeroSections(document);
        enhanceManagedTables(document);
        bindFloatingHelpDots(document);
        bridgeLegacyResponseToToast(document);
        startUniversalSelectValueSync();

        window.showAppToast = function(message, isError, duration){
            showAppToast(message, !!isError, duration);
        };
        window.downloadTemplateWithIds = function(endpoint, ids, fallbackName){
            downloadTemplateWithIds(endpoint, ids, fallbackName).catch(err => {
                const msg = err && err.message ? err.message : '下载失败';
                showAppToast(msg, true, 4200);
            });
        };
        window.showAppConfirm = showAppConfirm;
        window.showAppConfirmAsync = showAppConfirmAsync;

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
                enhanceHeroSections(document);
                enhanceManagedTables(document);
                bindFloatingHelpDots(document);
                enhanceCustomDateInputs(document);
                initOptionalDateInputs(document);
                normalizeResetButtons(document);
                bridgeLegacyResponseToToast(document);
                syncModalScrollLock();
                repositionManagedBatchBars();
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