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

    function showAppToast(message, isError, duration){
        const text = String(message || '').trim();
        if(!text) return;
        const stack = ensureToastStack();
        const toast = document.createElement('div');
        toast.className = `app-toast ${isError ? 'error' : 'success'}`;
        toast.textContent = text;
        stack.appendChild(toast);
        window.requestAnimationFrame(() => toast.classList.add('show'));

        const timeout = Number(duration || 2600);
        window.setTimeout(() => {
            toast.classList.remove('show');
            window.setTimeout(() => {
                if(toast.parentNode) toast.parentNode.removeChild(toast);
            }, 180);
        }, Math.max(800, timeout));
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
                const sig = `${text}|${inferErrorFromResponseEl(el) ? 'e' : 's'}`;
                if(sig === state.lastSig) return;
                state.lastSig = sig;
                showAppToast(text, inferErrorFromResponseEl(el));
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
                dot.textContent = '?';
                titleRow.appendChild(dot);
            }
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
            const rawLabel = (cell.textContent || '').trim();
            const fallback = cell.querySelector('input[type="checkbox"]') ? '多选框' : `字段${origin + 1}`;
            return {
                origin,
                label: rawLabel || fallback,
                cell
            };
        });
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
            const cell = mapRowByOrigin(row).get(meta.origin);
            if(!cell) continue;
            let len = String(cell.textContent || '').trim().length;
            if(cell.querySelector('img')) len = Math.max(len, 4);
            maxLen = Math.max(maxLen, Math.min(len, 40));
        }

        const headerLen = String(meta.label || '').trim().length;
        const headerWidth = Math.ceil(headerLen * 16 + 34);
        return Math.max(64, Math.min(520, Math.max(headerWidth, Math.ceil(maxLen * 13 + 26))));
    }

    function readPersistedColumns(table, validOrigins){
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'visible-columns'));
            if(!raw) return new Set(validOrigins);
            const arr = JSON.parse(raw);
            const valid = Array.isArray(arr) ? arr.map(v => Number(v)).filter(v => validOrigins.includes(v)) : [];
            return new Set(valid.length ? valid : validOrigins);
        } catch (_) {
            return new Set(validOrigins);
        }
    }

    function readPersistedOrder(table, validOrigins){
        try {
            const raw = localStorage.getItem(makeStorageKey(table, 'column-order'));
            if(!raw) return validOrigins.slice();
            const arr = JSON.parse(raw);
            const inOrder = Array.isArray(arr) ? arr.map(v => Number(v)).filter(v => validOrigins.includes(v)) : [];
            validOrigins.forEach(v => {
                if(!inOrder.includes(v)) inOrder.push(v);
            });
            return inOrder;
        } catch (_) {
            return validOrigins.slice();
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

    function mapRowByOrigin(row){
        const map = new Map();
        Array.from(row.cells || []).forEach((cell, idx) => {
            if(!cell.dataset.manageColOrigin) cell.dataset.manageColOrigin = String(idx);
            map.set(Number(cell.dataset.manageColOrigin), cell);
        });
        return map;
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

        let dstHead = state.headerTable.tHead;
        if(!dstHead){
            dstHead = document.createElement('thead');
            state.headerTable.appendChild(dstHead);
        }
        dstHead.innerHTML = '';

        const cloned = srcRow.cloneNode(true);
        cloned.querySelectorAll('.pm-col-resizer').forEach(node => node.remove());
        dstHead.appendChild(cloned);

        srcHead.classList.add('pm-managed-hidden-head');
    }

    function applyColumnOrder(state){
        const expected = state.headerCount;
        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== expected) return;
            const currentOrder = Array.from(row.cells).map(cell => Number(cell.dataset.manageColOrigin || '-1'));
            if(currentOrder.length === state.columnOrder.length && currentOrder.every((v, i) => v === state.columnOrder[i])) {
                return;
            }
            const byOrigin = mapRowByOrigin(row);
            state.columnOrder.forEach(origin => {
                const cell = byOrigin.get(origin);
                if(cell) row.appendChild(cell);
            });
        });
    }

    function applyColumnVisibility(state){
        const visible = state.visibleColumns;
        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== state.headerCount) return;
            Array.from(row.cells).forEach(cell => {
                const origin = Number(cell.dataset.manageColOrigin || '-1');
                cell.classList.toggle('pm-table-hide-col', !visible.has(origin));
            });
        });
    }

    function setColumnWidthByOrigin(state, origin, widthPx){
        const width = Math.max(36, Math.round(Number(widthPx) || 0));
        state.columnWidths[String(origin)] = width;

        Array.from(state.table.rows || []).forEach(row => {
            if((row.cells || []).length !== state.headerCount) return;
            Array.from(row.cells).forEach(cell => {
                if(Number(cell.dataset.manageColOrigin || '-1') !== Number(origin)) return;
                cell.style.width = `${width}px`;
                cell.style.minWidth = `${width}px`;
                cell.style.maxWidth = `${width}px`;
            });
        });

        if(state.headerTable && state.headerTable.tHead && state.headerTable.tHead.rows.length){
            const headerRow = state.headerTable.tHead.rows[0];
            Array.from(headerRow.cells || []).forEach(cell => {
                if(Number(cell.dataset.manageColOrigin || '-1') !== Number(origin)) return;
                cell.style.width = `${width}px`;
                cell.style.minWidth = `${width}px`;
                cell.style.maxWidth = `${width}px`;
            });
        }
    }

    function applyColumnWidths(state){
        const widths = state.columnWidths || {};
        Object.keys(widths).forEach(origin => setColumnWidthByOrigin(state, Number(origin), Number(widths[origin])));
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
                const origin = Number(cell.dataset.manageColOrigin || '0');
                activeResizeState = {
                    state,
                    origin,
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

    function commitColumnPanelDrag(state, targetOrigin, before){
        const fromOrigin = Number(state.dragOrigin);
        const origin = Number(targetOrigin);
        if(!Number.isFinite(fromOrigin) || !Number.isFinite(origin) || fromOrigin === origin) return;
        const fromIdx = state.columnOrder.indexOf(fromOrigin);
        let toIdx = state.columnOrder.indexOf(origin);
        if(fromIdx < 0 || toIdx < 0) return;
        toIdx += before ? 0 : 1;
        if(fromIdx < toIdx) toIdx -= 1;
        if(fromIdx === toIdx) return;

        state.columnOrder.splice(fromIdx, 1);
        state.columnOrder.splice(toIdx, 0, fromOrigin);
        persistColumnOrder(state);

        window.requestAnimationFrame(() => {
            applyColumnOrder(state);
            applyColumnVisibility(state);
            syncDetachedHeader(state);
            applyColumnWidths(state);
            ensureResizeHandles(state);
            refreshSortHeaderUi(state);
            syncTopScroll(state);
            renderColumnPanel(state);
        });
    }

    function renderColumnPanel(state){
        const panel = state.columnPanel;
        panel.innerHTML = '';

        state.columnOrder.forEach((origin, orderIdx) => {
            const header = state.headers.find(h => h.origin === origin);
            if(!header) return;

            const item = document.createElement('label');
            item.className = 'pm-table-columns-item';
            item.draggable = true;
            item.dataset.origin = String(origin);

            const main = document.createElement('span');
            main.className = 'pm-table-columns-item-main';

            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            const isLocked = state.lockedColumns.has(origin);
            checkbox.checked = isLocked ? true : state.visibleColumns.has(origin);
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
                if(checkbox.checked) state.visibleColumns.add(origin);
                else state.visibleColumns.delete(origin);
                persistColumns(state);
                applyColumnVisibility(state);
                syncDetachedHeader(state);
                applyColumnWidths(state);
                ensureResizeHandles(state);
                refreshSortHeaderUi(state);
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
                state.dragOrigin = origin;
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
                state.dragPlacement = { origin, before };
                setColumnDragIndicator(state, item, before);
            });
            item.addEventListener('drop', (event) => {
                event.preventDefault();
                const placement = state.dragPlacement && state.dragPlacement.origin === origin ? state.dragPlacement : { origin, before: false };
                commitColumnPanelDrag(state, origin, placement.before);
            });

            panel.appendChild(item);
            if(orderIdx === state.columnOrder.length - 1){
                item.classList.remove('is-drop-target');
            }
        });
    }

    function applyPagination(state){
        const rows = getDataRows(state);
        const total = rows.length;
        if(!total){
            state.currentPage = 1;
            state.info.textContent = '共 0 条';
            state.pageCurrent.textContent = '1 / 1';
            state.prevBtn.disabled = true;
            state.nextBtn.disabled = true;
            return;
        }

        const totalPages = Math.max(1, Math.ceil(total / state.pageSize));
        state.currentPage = Math.max(1, Math.min(state.currentPage, totalPages));
        const start = (state.currentPage - 1) * state.pageSize;
        const end = Math.min(start + state.pageSize, total);

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

    function ensureRowSortOrigin(state){
        const rows = Array.from(state.tbody.rows || []);
        rows.forEach((row, idx) => {
            if((row.cells || []).length !== state.headerCount) return;
            if(!row.dataset.sortOrigin) row.dataset.sortOrigin = String(idx);
        });
    }

    function readCellComparableValue(cell){
        if(!cell) return '';
        const text = String(cell.textContent || '').trim();
        const normalized = text.replace(/,/g, '');
        const numeric = Number(normalized);
        if(normalized && !Number.isNaN(numeric) && /^-?\d+(\.\d+)?$/.test(normalized)) return numeric;
        return text.toLowerCase();
    }

    function applySort(state){
        const sortOrigin = state.sortOrigin;
        const sortDir = state.sortDir;
        const rows = getDataRows(state);
        if(!rows.length) return;

        if((sortOrigin === null || sortOrigin === undefined) || !sortDir){
            if(!state.sortApplied) return;
            rows.sort((a, b) => Number(a.dataset.sortOrigin || '0') - Number(b.dataset.sortOrigin || '0'));
            const sortedOrigins = rows.map(r => Number(r.dataset.sortOrigin || '0'));
            const sameOrder = Array.from(state.tbody.rows || []).every((r, idx) => Number(r.dataset.sortOrigin || '0') === sortedOrigins[idx]);
            if(!sameOrder) rows.forEach(row => state.tbody.appendChild(row));
            state.sortApplied = false;
            return;
        }

        rows.sort((a, b) => {
            const aCell = mapRowByOrigin(a).get(sortOrigin);
            const bCell = mapRowByOrigin(b).get(sortOrigin);
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
            const origin = Number(cell.dataset.manageColOrigin || '-1');
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
            if(cell.dataset.sortBound === '1') return;
            cell.dataset.sortBound = '1';
            cell.addEventListener('click', (event) => {
                if(Date.now() < suppressSortUntil) return;
                if(event.target.closest('.pm-col-resizer')) return;
                const origin = Number(cell.dataset.manageColOrigin || '-1');
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

        const validOrigins = headerMeta.map(meta => meta.origin);
        const headerSignature = headerMeta
            .slice()
            .sort((a, b) => a.origin - b.origin)
            .map(meta => `${meta.origin}:${meta.label}`)
            .join('|');

        if(headerSignature !== state.headerSignature){
            state.headerSignature = headerSignature;
            state.headerCount = headerCount;
            state.headers = headerMeta.map(meta => ({ origin: meta.origin, label: meta.label }));
            state.visibleColumns = readPersistedColumns(state.table, validOrigins);
            state.columnOrder = readPersistedOrder(state.table, validOrigins);
            state.columnWidths = readPersistedColumnWidths(state.table);
            state.defaultColumnWidths = {};
            headerMeta.forEach(meta => {
                const key = String(meta.origin);
                const compact = computeDefaultColumnWidth(state, meta);
                state.defaultColumnWidths[key] = compact;
                if(state.columnWidths[key]) return;
                state.columnWidths[key] = compact;
            });
            state.lockedColumns = new Set(
                headerMeta
                    .filter(meta => isMultiSelectColumn(meta.cell, meta.label))
                    .map(meta => meta.origin)
            );
            state.lockedColumns.forEach(origin => state.visibleColumns.add(origin));
            state.columnsWrap.style.display = headerCount >= 2 ? '' : 'none';
            renderColumnPanel(state);
        }

        ensureRowSortOrigin(state);
        applyColumnOrder(state);
        applyColumnVisibility(state);
        syncDetachedHeader(state);
        applyColumnWidths(state);
        ensureSortableHeaders(state);
        refreshSortHeaderUi(state);
        applySort(state);
        ensureResizeHandles(state);
        applyPagination(state);
        syncTopScroll(state);
        if(activeColumnsPanelState === state) repositionColumnsPanel(state);

        state.isRefreshing = false;
        if(state.needRefresh){
            state.needRefresh = false;
            window.requestAnimationFrame(() => refreshManagedTable(state));
        }
    }

    function createManagedTable(table, index){
        if(managedTableState.has(table) || !shouldManageTable(table)) return;

        if(!table.id) table.dataset.manageKey = `managed-${index + 1}`;
        table.classList.add('is-managed-table');
        table.classList.add('pm-table');

        let wrap = table.parentElement;
        if(!wrap || !wrap.classList.contains('pm-table-wrap')){
            wrap = document.createElement('div');
            wrap.className = 'pm-table-wrap';
            table.parentNode.insertBefore(wrap, table);
            wrap.appendChild(table);
        }
        wrap.classList.add('is-managed-wrap', 'pm-managed-body-wrap');

        const headWrap = document.createElement('div');
        headWrap.className = 'pm-table-wrap pm-managed-head-wrap is-managed-wrap';
        const headTable = document.createElement('table');
        headTable.className = `${table.className} pm-managed-head-table`;
        headTable.setAttribute('data-disable-table-manage', '1');
        headWrap.appendChild(headTable);

        const toolbar = document.createElement('div');
        toolbar.className = 'pm-table-toolbar';
        toolbar.innerHTML = `
            <div class="pm-table-toolbar-left">
                <label>每页</label>
                <select class="pm-table-page-size" data-universal-no-search="1"></select>
                <span class="pm-table-info"></span>
            </div>
            <div class="pm-table-toolbar-right">
                <button type="button" class="pm-table-columns-reset btn-secondary" title="恢复默认列宽">重置列宽</button>
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

        const topScroll = document.createElement('div');
        topScroll.className = 'pm-table-top-scroll';
        const topScrollInner = document.createElement('div');
        topScrollInner.className = 'pm-table-top-scroll-inner';
        topScroll.appendChild(topScrollInner);
        wrap.parentNode.insertBefore(headWrap, wrap);
        wrap.parentNode.insertBefore(topScroll, wrap);

        const state = {
            table,
            tbody: table.tBodies[0],
            wrap,
            headWrap,
            headerTable: headTable,
            toolbar,
            topScroll,
            topScrollInner,
            pageSizeSelect: toolbar.querySelector('.pm-table-page-size'),
            info: toolbar.querySelector('.pm-table-info'),
            prevBtn: toolbar.querySelector('.pm-table-prev'),
            nextBtn: toolbar.querySelector('.pm-table-next'),
            pageCurrent: toolbar.querySelector('.pm-table-pager-current'),
            columnsWrap: toolbar.querySelector('.pm-table-columns'),
            columnsTrigger: toolbar.querySelector('.pm-table-columns-trigger'),
            columnPanel: toolbar.querySelector('.pm-table-columns-panel'),
            resetBtn: toolbar.querySelector('.pm-table-columns-reset'),
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
            refreshScheduled: false
        };
        managedTableState.set(table, state);

        if(state.columnPanel && state.columnPanel.parentNode !== document.body){
            document.body.appendChild(state.columnPanel);
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

        state.resetBtn.addEventListener('click', () => {
            try { localStorage.removeItem(makeStorageKey(state.table, 'column-widths')); } catch (_) {}
            state.columnWidths = Object.assign({}, state.defaultColumnWidths || {});
            persistColumnWidths(state);
            applyColumnWidths(state);
            syncTopScroll(state);
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

        refreshManagedTable(state);
    }

    function enhanceManagedTables(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('table').forEach((table, index) => createManagedTable(table, index));
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
            input.classList.toggle('has-value', !!text);
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
            input.addEventListener('blur', () => {
                window.setTimeout(() => {
                    if(activeDatePickerState && activeDatePickerState.panel && activeDatePickerState.panel.contains(document.activeElement)) return;
                    normalizeDateInputValue(input);
                }, 40);
            });
            input.addEventListener('input', () => {
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
                } else if(path.startsWith('/sales-product-management') || path.startsWith('/sales-order-registration-management') || path.startsWith('/parent-management')){
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
    });

    document.addEventListener('mousedown', (e) => {
        if(!e.target.closest('.pm-table-columns') && !e.target.closest('.pm-table-columns-panel')) {
            closeColumnsPanel(activeColumnsPanelState);
        }
    });

    document.addEventListener('keydown', (e) => {
        if(e.key === 'Escape'){
            closeColumnsPanel(activeColumnsPanelState);
            closeAllDropdowns();
            closeDatePicker();
        }
    });

    document.addEventListener('mousemove', (event) => {
        if(!activeResizeState) return;
        const delta = event.clientX - activeResizeState.startX;
        if(Math.abs(delta) > 2) activeResizeState.hasMoved = true;
        const width = activeResizeState.startWidth + delta;
        setColumnWidthByOrigin(activeResizeState.state, activeResizeState.origin, width);
    });

    document.addEventListener('mouseup', () => {
        if(!activeResizeState) return;
        if(activeResizeState.hasMoved) suppressSortUntil = Date.now() + 260;
        activeResizeState.handle.classList.remove('is-active');
        persistColumnWidths(activeResizeState.state);
        activeResizeState = null;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
    });

    window.addEventListener('resize', () => {
        repositionOpenDropdowns();
        if(activeDatePickerState && activeDatePickerState.input) positionDatePicker(activeDatePickerState.input, activeDatePickerState);
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
    });

    window.addEventListener('scroll', () => {
        repositionOpenDropdowns();
        if(activeDatePickerState && activeDatePickerState.input) positionDatePicker(activeDatePickerState.input, activeDatePickerState);
        hideHelpDotTooltip();
        if(activeColumnsPanelState) repositionColumnsPanel(activeColumnsPanelState);
    }, true);

    const boot = () => {
        loadHeader();
        initUniversalSingleSelects(document);
        enhanceCustomDateInputs(document);
        initOptionalDateInputs(document);
        enhanceHeroSections(document);
        enhanceManagedTables(document);
        bindFloatingHelpDots(document);
        bridgeLegacyResponseToToast(document);
        startUniversalSelectValueSync();

        window.showAppToast = function(message, isError, duration){
            showAppToast(message, !!isError, duration);
        };

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
                bridgeLegacyResponseToToast(document);
                syncModalScrollLock();
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