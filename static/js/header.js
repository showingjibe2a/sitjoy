// 在页面加载时动态注入顶部导航，保持各模板统一
(function(){
    const universalSelectState = new Map();

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
            state.searchInput.value = '';
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
        const keyword = (state.searchInput.value || '').trim().toLowerCase();
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
    }

    function openDropdown(select, state){
        if(!state || state.trigger.disabled) return;
        closeAllDropdowns();
        renderDropdownOptions(select, state);
        state.wrapper.classList.remove('open-upward');
        const triggerRect = state.trigger.getBoundingClientRect();
        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
        const spaceBelow = viewportHeight - triggerRect.bottom;
        const spaceAbove = triggerRect.top;
        const preferHeight = 280;
        if(spaceBelow < 180 && spaceAbove > spaceBelow && spaceAbove >= 140){
            state.wrapper.classList.add('open-upward');
        }
        const maxHeight = Math.max(120, Math.min(preferHeight, state.wrapper.classList.contains('open-upward') ? (spaceAbove - 20) : (spaceBelow - 20)));
        state.list.style.maxHeight = `${maxHeight}px`;
        state.wrapper.classList.add('expanded');
        window.setTimeout(() => {
            state.wrapper.classList.add('open');
            state.searchInput.focus();
            state.searchInput.select();
        }, 90);
    }

    function closeAllDropdowns(){
        universalSelectState.forEach((state, select) => {
            closeDropdown(select, state);
        });
    }

    function enhanceSingleSelect(select){
        if(!shouldEnhanceSelect(select)) return;

        const wrapper = document.createElement('div');
        wrapper.className = 'feature-category-dropdown universal-select-dropdown';

        const trigger = document.createElement('button');
        trigger.type = 'button';
        trigger.className = 'universal-select-trigger';
        trigger.textContent = '请选择';

        const menu = document.createElement('div');
        menu.className = 'feature-category-menu';

        const searchInput = document.createElement('input');
        searchInput.type = 'text';
        searchInput.className = 'universal-select-search';
        searchInput.placeholder = select.dataset.searchPlaceholder || '搜索';

        const list = document.createElement('div');
        list.className = 'feature-category-list universal-select-list';

        menu.appendChild(searchInput);
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

        searchInput.addEventListener('input', () => renderDropdownOptions(select, state));

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

    function normalizeDateText(raw){
        const digits = String(raw || '').replace(/\D/g, '').slice(0, 8);
        if(!digits) return '';
        if(digits.length <= 4) return digits;
        if(digits.length <= 6) return `${digits.slice(0, 4)}/${digits.slice(4)}`;
        return `${digits.slice(0, 4)}/${digits.slice(4, 6)}/${digits.slice(6, 8)}`;
    }

    function enhanceDateInput(input){
        if(!input || input.dataset.slashDateEnhanced === '1') return;
        input.dataset.slashDateEnhanced = '1';
        const current = input.value || '';
        input.type = 'text';
        input.inputMode = 'numeric';
        input.autocomplete = 'off';
        if(!input.placeholder) input.placeholder = 'yyyy/mm/dd';
        input.value = normalizeDateText(current);
        input.addEventListener('input', () => {
            input.value = normalizeDateText(input.value);
        });
        input.addEventListener('blur', () => {
            input.value = normalizeDateText(input.value);
        });
    }

    function initSlashDateInputs(root){
        const scope = root && root.querySelectorAll ? root : document;
        scope.querySelectorAll('input[type="date"], input[data-date-input="1"]').forEach(enhanceDateInput);
    }

    window.initUniversalSingleSelects = initUniversalSingleSelects;
    window.refreshUniversalSingleSelect = refreshUniversalSingleSelect;
    window.refreshAllUniversalSingleSelects = function(){
        initUniversalSingleSelects(document);
        universalSelectState.forEach((state, select) => {
            renderDropdownOptions(select, state);
            syncTriggerFromSelect(select, state);
        });
    };
    window.initSlashDateInputs = initSlashDateInputs;

    function loadHeader(){
        fetch('/static/partials/header.html')
            .then(r => r.text())
            .then(html => {
                const el = document.getElementById('site-header');
                if(!el) return;
                el.innerHTML = html;

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
                } else if(path.startsWith('/logistics-factory-management') || path.startsWith('/logistics-forwarder-management') || path.startsWith('/logistics-warehouse-management') || path.startsWith('/logistics-warehouse-inventory-management') || path.startsWith('/logistics-in-transit-management')){
                    const elL = document.querySelector('.nav-logistics'); if(elL) elL.classList.add('active');
                } else if(path.startsWith('/product-management') || path.startsWith('/fabric-management') || path.startsWith('/feature-management') || path.startsWith('/material-management') || path.startsWith('/certification-management') || path.startsWith('/order-product-management')){
                    const elP = document.querySelector('.nav-product'); if(elP) elP.classList.add('active');
                } else if(path.startsWith('/sales-product-management') || path.startsWith('/parent-management')){
                    const elS = document.querySelector('.nav-sales'); if(elS) elS.classList.add('active');
                } else if(path.startsWith('/about')){
                    const elA = document.querySelector('.nav-about'); if(elA) elA.classList.add('active');
                }
            })
            .catch(err => console.error('Load header failed', err));
    }

    document.addEventListener('click', (e) => {
        if(!e.target.closest('.universal-select-dropdown')) {
            closeAllDropdowns();
        }
    });

    const boot = () => {
        loadHeader();
        initUniversalSingleSelects(document);
        initSlashDateInputs(document);
        startUniversalSelectValueSync();
    };

    if(document.readyState === 'loading'){
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();