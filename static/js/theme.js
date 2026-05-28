/**
 * SITJOY 组件样式接口（非成品主题包）
 * localStorage: sitjoy_theme_prefs_v2
 */
(function (global) {
    'use strict';

    const STORAGE_KEY = 'sitjoy_theme_prefs_v2';

    const COMPONENT_REGISTRY = [
        { id: 'navbar', dataAttr: 'sjNavbar', label: '顶栏', variants: { default: '默认' } },
        { id: 'card', dataAttr: 'sjCard', label: '卡片', variants: { default: '默认' } },
        { id: 'modal', dataAttr: 'sjModal', label: '弹窗', variants: { default: '默认' } },
        { id: 'profile', dataAttr: 'sjProfile', label: '首页资料卡', variants: { default: '默认' } },
        { id: 'button', dataAttr: 'sjButton', label: '按钮', variants: { default: '默认' } },
        { id: 'table', dataAttr: 'sjTable', label: '表格', variants: { default: '默认' } },
        { id: 'formInput', dataAttr: 'sjFormInput', label: '表单输入', variants: { default: '默认' } },
        {
            id: 'statusSegment',
            dataAttr: 'sjStatusSegment',
            label: '状态分段 status-segment',
            variants: { default: '默认', compact: '紧凑' }
        },
        {
            id: 'dateInput',
            dataAttr: 'sjDateInput',
            label: '日期输入 app-date-input',
            variants: { default: '默认', compact: '紧凑' }
        }
    ];

    function registryById() {
        const map = Object.create(null);
        COMPONENT_REGISTRY.forEach(def => { map[def.id] = def; });
        return map;
    }

    function defaultComponentsState() {
        const o = Object.create(null);
        COMPONENT_REGISTRY.forEach(def => { o[def.id] = 'default'; });
        return o;
    }

    function cloneDefaultPrefs() {
        return { theme: 'default', components: defaultComponentsState() };
    }

    function normalizePrefs(raw) {
        const base = cloneDefaultPrefs();
        if (!raw || typeof raw !== 'object') return base;
        base.theme = 'default';
        const byId = registryById();
        if (raw.components && typeof raw.components === 'object') {
            Object.keys(raw.components).forEach(id => {
                const def = byId[id];
                if (!def) return;
                const val = String(raw.components[id] || 'default');
                base.components[id] = def.variants[val] !== undefined ? val : 'default';
            });
        }
        return base;
    }

    function loadPrefs() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            if (!raw) {
                const legacy = localStorage.getItem('sitjoy_theme_prefs_v1');
                if (legacy) return normalizePrefs(JSON.parse(legacy));
                return cloneDefaultPrefs();
            }
            return normalizePrefs(JSON.parse(raw));
        } catch (e) {
            return cloneDefaultPrefs();
        }
    }

    function savePrefs(prefs) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
        } catch (e) { /* ignore */ }
    }

    function dataAttrToDatasetKey(dataAttr) {
        return dataAttr.charAt(0).toLowerCase() + dataAttr.slice(1);
    }

    function applyPrefs(prefs) {
        const p = normalizePrefs(prefs);
        const root = document.documentElement;
        root.dataset.theme = p.theme || 'default';
        const byId = registryById();
        COMPONENT_REGISTRY.forEach(def => {
            const val = (p.components && p.components[def.id]) || 'default';
            const dsKey = dataAttrToDatasetKey(def.dataAttr);
            if (!val || val === 'default') delete root.dataset[dsKey];
            else root.dataset[dsKey] = val;
        });
        global.__sitjoyThemePrefs = p;
        document.dispatchEvent(new CustomEvent('sitjoy:theme-change', { detail: p }));
        syncModalBody(p);
    }

    function setComponentVariant(componentId, variant) {
        const def = registryById()[componentId];
        if (!def) return;
        const prefs = loadPrefs();
        prefs.components[componentId] = def.variants[variant] !== undefined ? variant : 'default';
        savePrefs(prefs);
        applyPrefs(prefs);
    }

    function registerComponent(def) {
        if (!def || !def.id || !def.dataAttr || !def.label) return false;
        const idx = COMPONENT_REGISTRY.findIndex(d => d.id === def.id);
        const entry = {
            id: def.id,
            dataAttr: def.dataAttr,
            label: def.label,
            variants: Object.assign({ default: '默认' }, def.variants || {})
        };
        if (idx >= 0) COMPONENT_REGISTRY[idx] = entry;
        else COMPONENT_REGISTRY.push(entry);
        const prefs = loadPrefs();
        if (!prefs.components[entry.id]) prefs.components[entry.id] = 'default';
        savePrefs(prefs);
        return true;
    }

    let modalBodyEl = null;

    function buildPanelMarkup() {
        const prefs = loadPrefs();
        const rows = COMPONENT_REGISTRY.map(def => {
            const variantKeys = Object.keys(def.variants);
            const current = (prefs.components && prefs.components[def.id]) || 'default';
            const disabled = variantKeys.length <= 1;
            const options = variantKeys.map(k => {
                const sel = k === current ? ' selected' : '';
                return `<option value="${k}"${sel}>${def.variants[k]}</option>`;
            }).join('');
            return `<div class="sitjoy-theme-panel__row" data-component-id="${def.id}">
                <span class="sitjoy-theme-panel__label">${def.label}</span>
                <select data-component-id="${def.id}"${disabled ? ' disabled' : ''}>${options}</select>
            </div>`;
        }).join('');
        return `<p class="sitjoy-theme-panel__hint">为各组件选择变体；扩展方式见 static/css/STYLE_GUIDE.md。</p>${rows}`;
    }

    function syncModalBody() {
        if (!modalBodyEl) modalBodyEl = document.getElementById('sitjoyThemeModalBody');
        if (!modalBodyEl) return;
        modalBodyEl.innerHTML = buildPanelMarkup();
        modalBodyEl.querySelectorAll('select[data-component-id]').forEach(sel => {
            sel.addEventListener('change', () => {
                setComponentVariant(sel.dataset.componentId, sel.value);
            });
        });
    }

    function getModal() {
        return document.getElementById('sitjoyThemeModal');
    }

    function openModal() {
        const modal = getModal();
        if (!modal) return;
        syncModalBody();
        modal.classList.add('active');
        modal.setAttribute('aria-hidden', 'false');
        const toggle = document.getElementById('homeProfileThemeToggle');
        if (toggle) toggle.setAttribute('aria-expanded', 'true');
    }

    function closeModal() {
        const modal = getModal();
        if (!modal) return;
        modal.classList.remove('active');
        modal.setAttribute('aria-hidden', 'true');
        const toggle = document.getElementById('homeProfileThemeToggle');
        if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }

    function bindModalDismiss() {
        const modal = getModal();
        if (!modal || modal.dataset.sitjoyThemeBound === '1') return;
        modal.dataset.sitjoyThemeBound = '1';
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
        document.addEventListener('keydown', (e) => {
            if (e.key !== 'Escape') return;
            if (modal.classList.contains('active')) closeModal();
        });
    }

    function mountHomeLauncher() {
        const toggle = document.getElementById('homeProfileThemeToggle');
        if (!toggle || toggle.dataset.sitjoyThemeBound === '1') return;
        toggle.dataset.sitjoyThemeBound = '1';
        toggle.addEventListener('click', (e) => {
            e.preventDefault();
            openModal();
        });
        bindModalDismiss();
        modalBodyEl = document.getElementById('sitjoyThemeModalBody');
    }

    /** @deprecated 使用 mountHomeLauncher */
    function mountPanel() {
        mountHomeLauncher();
    }

    function init() {
        const prefs = loadPrefs();
        savePrefs(prefs);
        applyPrefs(prefs);
    }

    global.SitjoyTheme = {
        init,
        loadPrefs,
        savePrefs,
        applyPrefs,
        setComponentVariant,
        registerComponent,
        mountHomeLauncher,
        mountPanel,
        openModal,
        closeModal,
        COMPONENT_REGISTRY,
        registryById
    };

    init();
})(window);
