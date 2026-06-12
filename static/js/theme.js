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
            label: '状态分段',
            variants: { default: '默认', compact: '紧凑' }
        },
        {
            id: 'dateInput',
            dataAttr: 'sjDateInput',
            label: '日期输入',
            variants: { default: '默认', compact: '紧凑' }
        }
    ];

    /** @type {Record<string, { description: string, colors?: Array<{ token: string, label: string, default: string }> }>} */
    const COMPONENT_META = {
        navbar: {
            description: '全站顶部导航栏背景与阴影，影响 logo、菜单与用户信息区域。',
            colors: [{ token: '--sj-variant-navbar-bg', label: '背景色', default: '#ece7df' }]
        },
        card: {
            description: '业务页主内容卡片容器，含圆角、边框与悬停阴影。',
            colors: [
                { token: '--sj-variant-card-bg', label: '背景色', default: '#ece7df' },
                { token: '--sj-variant-card-border', label: '边框色', default: '#cfc7bd' }
            ]
        },
        modal: {
            description: '弹窗面板背景与边框，用于编辑、确认等对话框。',
            colors: [{ token: '--sj-variant-modal-panel-bg', label: '面板背景', default: '#ece7df' }]
        },
        profile: {
            description: '首页个人信息卡片，展示头像、问候语与快捷入口。',
            colors: [
                { token: '--sj-variant-profile-text', label: '文字色', default: '#3e433d' },
                { token: '--sj-variant-profile-border', label: '边框色', default: '#cfc7bd' }
            ]
        },
        button: {
            description: '主要与次要操作按钮，含胶囊形与悬停反馈。',
            colors: [{ token: '--sj-variant-btn-secondary-bg', label: '次要按钮背景', default: '#f3f0ec' }]
        },
        table: {
            description: '数据表格表头、行悬停与斑马纹区域。',
            colors: [{ token: '--sj-variant-table-head-bg', label: '表头背景', default: '#f8f4ee' }]
        },
        formInput: {
            description: '文本框、下拉与可选字段的输入区域样式。',
            colors: [
                { token: '--sj-variant-input-bg', label: '输入背景', default: '#ece7df' },
                { token: '--sj-variant-input-border', label: '输入边框', default: '#cfc7bd' }
            ]
        },
        statusSegment: {
            description: '状态分段切换（status-segment），用于筛选、是/否等选项。',
            colors: [
                { token: '--sj-cmp-status-segment-pill-active-bg', label: '选中项背景', default: '#7fa88b' },
                { token: '--sj-cmp-status-segment-bg', label: '轨道背景', default: '#cfc7bd' }
            ]
        },
        dateInput: {
            description: '日期选择输入框（app-date-input），含日历图标与边框。',
            colors: [{ token: '--sj-cmp-date-input-border', label: '边框色', default: '#cfc7bd' }]
        }
    };

    const ALL_COLOR_TOKENS = (function () {
        const set = new Set();
        Object.keys(COMPONENT_META).forEach(id => {
            const colors = COMPONENT_META[id].colors;
            if (!colors) return;
            colors.forEach(c => set.add(c.token));
        });
        return set;
    })();

    const TOKEN_DEFAULTS = (function () {
        const map = Object.create(null);
        Object.keys(COMPONENT_META).forEach(id => {
            const colors = COMPONENT_META[id].colors;
            if (!colors) return;
            colors.forEach(c => { map[c.token] = c.default; });
        });
        return map;
    })();

    let studioRootEl = null;

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
        return { theme: 'default', components: defaultComponentsState(), customColors: Object.create(null) };
    }

    function isHexColor(val) {
        return typeof val === 'string' && /^#[0-9a-fA-F]{6}$/.test(val);
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
        if (raw.customColors && typeof raw.customColors === 'object') {
            Object.keys(raw.customColors).forEach(token => {
                if (!ALL_COLOR_TOKENS.has(token)) return;
                const val = String(raw.customColors[token] || '').trim();
                if (isHexColor(val)) base.customColors[token] = val.toLowerCase();
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

    function hexToRgb(hex) {
        const h = String(hex || '').replace('#', '');
        if (h.length !== 6) return { r: 207, g: 199, b: 189 };
        return {
            r: parseInt(h.slice(0, 2), 16),
            g: parseInt(h.slice(2, 4), 16),
            b: parseInt(h.slice(4, 6), 16)
        };
    }

    function rgbToHex(r, g, b) {
        const clamp = n => Math.max(0, Math.min(255, Math.round(Number(n) || 0)));
        const to = n => clamp(n).toString(16).padStart(2, '0');
        return `#${to(r)}${to(g)}${to(b)}`;
    }

    function getEffectiveColor(token, prefs) {
        const p = prefs || loadPrefs();
        if (p.customColors && isHexColor(p.customColors[token])) return p.customColors[token];
        return TOKEN_DEFAULTS[token] || '#cfc7bd';
    }

    function applyCustomColors(root, prefs) {
        const p = normalizePrefs(prefs);
        ALL_COLOR_TOKENS.forEach(token => {
            const custom = p.customColors && p.customColors[token];
            if (isHexColor(custom)) root.style.setProperty(token, custom);
            else root.style.removeProperty(token);
        });
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
        applyCustomColors(root, p);
        global.__sitjoyThemePrefs = p;
        document.dispatchEvent(new CustomEvent('sitjoy:theme-change', { detail: p }));
        syncStudioPage(p);
    }

    function setComponentVariant(componentId, variant) {
        const def = registryById()[componentId];
        if (!def) return;
        const prefs = loadPrefs();
        prefs.components[componentId] = def.variants[variant] !== undefined ? variant : 'default';
        savePrefs(prefs);
        applyPrefs(prefs);
    }

    function setCustomColor(token, hex) {
        if (!ALL_COLOR_TOKENS.has(token) || !isHexColor(hex)) return;
        const prefs = loadPrefs();
        prefs.customColors[token] = hex.toLowerCase();
        savePrefs(prefs);
        applyPrefs(prefs);
    }

    function clearCustomColor(token) {
        if (!ALL_COLOR_TOKENS.has(token)) return;
        const prefs = loadPrefs();
        if (prefs.customColors) delete prefs.customColors[token];
        savePrefs(prefs);
        applyPrefs(prefs);
    }

    function resetAllPrefs() {
        const fresh = cloneDefaultPrefs();
        savePrefs(fresh);
        applyPrefs(fresh);
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

    function buildPreviewHtml(componentId) {
        switch (componentId) {
            case 'navbar':
                return `<div class="sitjoy-theme-preview-navbar navbar" aria-hidden="true">
                    <span class="sitjoy-theme-preview-navbar-brand">SITJOY</span>
                    <span class="sitjoy-theme-preview-navbar-links">首页 · 产品 · 小组件</span>
                </div>`;
            case 'card':
                return `<div class="card sitjoy-theme-preview-card" aria-hidden="true">
                    <h4>示例卡片</h4>
                    <p>业务内容区域，含标题与正文。</p>
                </div>`;
            case 'modal':
                return `<div class="sitjoy-theme-preview-modal" aria-hidden="true">
                    <div class="pm-modal-content sitjoy-theme-preview-modal-panel">
                        <div class="modal-header"><h2>示例弹窗</h2></div>
                        <p>确认保存当前设置？</p>
                    </div>
                </div>`;
            case 'profile':
                return `<div class="home-profile-card sitjoy-theme-preview-profile" aria-hidden="true">
                    <div class="home-profile-main">
                        <div class="home-profile-avatar home-profile-avatar--fallback">张</div>
                        <div class="home-profile-text">
                            <span class="home-profile-kicker">上午好 · 示例</span>
                            <h2>员工昵称</h2>
                        </div>
                    </div>
                </div>`;
            case 'button':
                return `<div class="sitjoy-theme-preview-buttons" aria-hidden="true">
                    <button type="button" class="btn-primary btn-small" tabindex="-1">主要</button>
                    <button type="button" class="btn-secondary btn-small" tabindex="-1">次要</button>
                </div>`;
            case 'table':
                return `<div class="pm-table-wrap sitjoy-theme-preview-table-wrap" aria-hidden="true">
                    <table class="pm-table sitjoy-theme-preview-table">
                        <thead><tr><th>列 A</th><th>列 B</th></tr></thead>
                        <tbody><tr><td>示例 1</td><td>100</td></tr><tr><td>示例 2</td><td>200</td></tr></tbody>
                    </table>
                </div>`;
            case 'formInput':
                return `<div class="sitjoy-theme-preview-form" aria-hidden="true">
                    <label>字段名<input type="text" class="optional-field" value="示例文本" tabindex="-1" readonly></label>
                </div>`;
            case 'statusSegment':
                return `<div class="status-segment status-segment--inline sitjoy-theme-preview-segment" aria-hidden="true">
                    <button type="button" class="status-pill is-active" tabindex="-1">启用</button>
                    <button type="button" class="status-pill" tabindex="-1">停用</button>
                </div>`;
            case 'dateInput':
                return `<input type="date" class="app-date-input sitjoy-theme-preview-date" value="2026-06-12" tabindex="-1" aria-hidden="true">`;
            default:
                return `<span class="sitjoy-theme-preview-empty">—</span>`;
        }
    }

    function buildColorRowHtml(componentId, colorDef, prefs) {
        const hex = getEffectiveColor(colorDef.token, prefs);
        const rgb = hexToRgb(hex);
        const idBase = `${componentId}-${colorDef.token.replace(/[^a-z0-9-]/gi, '')}`;
        return `<div class="sitjoy-theme-studio-color-row" data-token="${colorDef.token}">
            <span class="sitjoy-theme-studio-color-label">${colorDef.label}</span>
            <input type="color" id="${idBase}-picker" data-sj-color-swatch="1" value="${hex}" aria-label="${colorDef.label}">
            <span class="sitjoy-theme-studio-rgb" aria-label="${colorDef.label} RGB">
                <input type="number" class="inline-input sitjoy-theme-studio-rgb-input" data-rgb="r" min="0" max="255" value="${rgb.r}" aria-label="R">
                <input type="number" class="inline-input sitjoy-theme-studio-rgb-input" data-rgb="g" min="0" max="255" value="${rgb.g}" aria-label="G">
                <input type="number" class="inline-input sitjoy-theme-studio-rgb-input" data-rgb="b" min="0" max="255" value="${rgb.b}" aria-label="B">
            </span>
            <button type="button" class="btn-secondary btn-small sitjoy-theme-studio-color-reset" data-token="${colorDef.token}">默认</button>
        </div>`;
    }

    function buildStudioRowHtml(def, prefs) {
        const meta = COMPONENT_META[def.id] || { description: '', colors: [] };
        const variantKeys = Object.keys(def.variants);
        const current = (prefs.components && prefs.components[def.id]) || 'default';
        const disabled = variantKeys.length <= 1;
        const options = variantKeys.map(k => {
            const sel = k === current ? ' selected' : '';
            return `<option value="${k}"${sel}>${def.variants[k]}</option>`;
        }).join('');
        const colors = (meta.colors || []).map(c => buildColorRowHtml(def.id, c, prefs)).join('');
        const colorsBlock = colors
            ? `<div class="sitjoy-theme-studio-colors">${colors}</div>`
            : '';
        return `<tr data-component-id="${def.id}">
            <td class="sitjoy-theme-studio-config">
                <h4>${def.label}</h4>
                <p class="sitjoy-theme-studio-desc">${meta.description || ''}</p>
                <div class="sitjoy-theme-studio-field">
                    <label for="sitjoy-variant-${def.id}">样式变体</label>
                    <select id="sitjoy-variant-${def.id}" data-component-id="${def.id}"${disabled ? ' disabled' : ''}>${options}</select>
                </div>
                ${colorsBlock}
            </td>
            <td class="sitjoy-theme-studio-preview">
                <div class="sitjoy-theme-preview" data-preview-id="${def.id}">${buildPreviewHtml(def.id)}</div>
            </td>
        </tr>`;
    }

    function bindColorRow(row) {
        const token = row.dataset.token;
        if (!token) return;
        const picker = row.querySelector('input[type="color"]');
        const rInp = row.querySelector('[data-rgb="r"]');
        const gInp = row.querySelector('[data-rgb="g"]');
        const bInp = row.querySelector('[data-rgb="b"]');
        const resetBtn = row.querySelector('.sitjoy-theme-studio-color-reset');

        function syncRgbFromHex(hex) {
            const rgb = hexToRgb(hex);
            if (rInp) rInp.value = rgb.r;
            if (gInp) gInp.value = rgb.g;
            if (bInp) bInp.value = rgb.b;
        }

        function syncFromRgb() {
            const hex = rgbToHex(rInp && rInp.value, gInp && gInp.value, bInp && bInp.value);
            if (picker) picker.value = hex;
            if (window.SitjoyColorSwatchPicker) window.SitjoyColorSwatchPicker.sync(picker);
            setCustomColor(token, hex);
        }

        if (picker && picker.dataset.sitjoyColorBound !== '1') {
            picker.dataset.sitjoyColorBound = '1';
            picker.addEventListener('input', () => {
                syncRgbFromHex(picker.value);
                setCustomColor(token, picker.value);
            });
        }
        [rInp, gInp, bInp].forEach(inp => {
            if (!inp || inp.dataset.sitjoyRgbBound === '1') return;
            inp.dataset.sitjoyRgbBound = '1';
            inp.addEventListener('change', syncFromRgb);
            inp.addEventListener('input', syncFromRgb);
        });
        if (resetBtn && resetBtn.dataset.sitjoyResetBound !== '1') {
            resetBtn.dataset.sitjoyResetBound = '1';
            resetBtn.addEventListener('click', () => {
                clearCustomColor(token);
                const defHex = TOKEN_DEFAULTS[token] || '#cfc7bd';
                if (picker) picker.value = defHex;
                syncRgbFromHex(defHex);
                if (window.SitjoyColorSwatchPicker) window.SitjoyColorSwatchPicker.sync(picker);
            });
        }
    }

    function bindStudioTable(root) {
        root.querySelectorAll('select[data-component-id]').forEach(sel => {
            if (sel.dataset.sitjoyVariantBound === '1') return;
            sel.dataset.sitjoyVariantBound = '1';
            sel.addEventListener('change', () => {
                setComponentVariant(sel.dataset.componentId, sel.value);
            });
        });
        root.querySelectorAll('.sitjoy-theme-studio-color-row').forEach(bindColorRow);
        const resetAllBtn = root.querySelector('#sitjoyThemeResetAll');
        if (resetAllBtn && resetAllBtn.dataset.sitjoyResetAllBound !== '1') {
            resetAllBtn.dataset.sitjoyResetAllBound = '1';
            resetAllBtn.addEventListener('click', () => {
                if (window.confirm('恢复全部组件为默认样式与配色？')) resetAllPrefs();
            });
        }
        if (window.SitjoyColorSwatchPicker) window.SitjoyColorSwatchPicker.init(root);
    }

    function syncStudioPage(prefs) {
        if (!studioRootEl) return;
        const p = prefs || loadPrefs();
        studioRootEl.querySelectorAll('[data-preview-id]').forEach(el => {
            el.innerHTML = buildPreviewHtml(el.dataset.previewId);
        });
        studioRootEl.querySelectorAll('select[data-component-id]').forEach(sel => {
            const id = sel.dataset.componentId;
            const val = (p.components && p.components[id]) || 'default';
            if (sel.value !== val) sel.value = val;
        });
        studioRootEl.querySelectorAll('.sitjoy-theme-studio-color-row').forEach(row => {
            const token = row.dataset.token;
            if (!token) return;
            const hex = getEffectiveColor(token, p);
            const picker = row.querySelector('input[type="color"]');
            if (picker && picker.value.toLowerCase() !== hex.toLowerCase()) {
                picker.value = hex;
                if (window.SitjoyColorSwatchPicker) window.SitjoyColorSwatchPicker.sync(picker);
            }
            const rgb = hexToRgb(hex);
            const rInp = row.querySelector('[data-rgb="r"]');
            const gInp = row.querySelector('[data-rgb="g"]');
            const bInp = row.querySelector('[data-rgb="b"]');
            if (rInp) rInp.value = rgb.r;
            if (gInp) gInp.value = rgb.g;
            if (bInp) bInp.value = rgb.b;
        });
    }

    function mountStudioPage(containerId) {
        const root = typeof containerId === 'string'
            ? document.getElementById(containerId)
            : containerId;
        if (!root || root.dataset.sitjoyStudioMounted === '1') {
            if (root) syncStudioPage();
            return;
        }
        studioRootEl = root;
        root.dataset.sitjoyStudioMounted = '1';
        const prefs = loadPrefs();
        const rows = COMPONENT_REGISTRY.map(def => buildStudioRowHtml(def, prefs)).join('');
        root.innerHTML = `<div class="sitjoy-theme-studio-toolbar">
            <p class="sitjoy-theme-studio-hint">为各组件选择变体并微调颜色；扩展方式见 static/css/STYLE_GUIDE.md。</p>
            <button type="button" class="btn-secondary btn-small" id="sitjoyThemeResetAll">全部恢复默认</button>
        </div>
        <div class="pm-table-wrap sitjoy-theme-studio-table-wrap">
            <table class="pm-table sitjoy-theme-studio-table">
                <thead>
                    <tr>
                        <th class="sitjoy-theme-studio-th-config">样式配置</th>
                        <th class="sitjoy-theme-studio-th-preview">预览</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>`;
        bindStudioTable(root);
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
        setCustomColor,
        clearCustomColor,
        resetAllPrefs,
        registerComponent,
        mountStudioPage,
        COMPONENT_REGISTRY,
        COMPONENT_META,
        registryById,
        getEffectiveColor
    };

    init();
})(window);
