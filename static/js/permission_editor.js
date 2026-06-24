/** 页面权限编辑器（员工账号管理等） */
window.SitjoyPerm = window.SitjoyPerm || {};

(function () {
    function permUser() {
        return window.__sitjoyPermUser || {};
    }

    function escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function getPagePermissionLabels() {
        return permUser().page_permission_labels || {};
    }

    function getPagePermissionGroups() {
        const groups = permUser().page_permission_groups;
        if (Array.isArray(groups) && groups.length) return groups;
        return [
            { key: 'home', title: '首页', page_keys: ['home'] },
            { key: 'product_management', title: '产品管理', page_keys: ['product_management', 'fabric_management', 'feature_management', 'material_management', 'certification_management', 'order_product_management'] },
            { key: 'logistics_factory_management', title: '物流仓储管理', page_keys: ['logistics_factory_management', 'logistics_warehouse_management', 'logistics_warehouse_inventory_management', 'logistics_in_transit_management', 'factory_stock_management', 'factory_wip_management', 'logistics_warehouse_dashboard'] },
            { key: 'gallery', title: '图片管理', page_keys: ['gallery', 'image_type_management', 'aplus_management'] },
            { key: 'sales_product_management', title: '销售管理', page_keys: ['shop_brand_management', 'amazon_account_health_management', 'sales_product_management', 'sales_product_performance_management', 'sales_forecast_management', 'container_draft_management', 'sales_order_registration_management'] },
            { key: 'amazon_ad_adjustment_management', title: 'Amazon广告管理', page_keys: ['amazon_ad_adjustment_management', 'amazon_ad_adjustment_records_management', 'amazon_ad_keyword_management', 'amazon_ad_management', 'amazon_ad_subtype_management', 'amazon_ad_delivery_management', 'amazon_ad_product_management'] },
            { key: 'system_management', title: '系统管理', page_keys: ['system_employee_management', 'system_audit_log_management', 'system_dingtalk_notify_management'] },
            { key: 'about', title: '关于', page_keys: ['about'] },
            { key: 'widgets', title: '小组件', page_keys: ['widgets_theme', 'widgets_go_play', 'widgets_mahjong'] },
        ];
    }

    function getPermissionGroupPageKeys(group) {
        return Array.isArray(group && group.page_keys) ? group.page_keys.filter(key => key) : [];
    }

    function buildDefaultPagePermissions() {
        const result = {};
        getPagePermissionGroups().forEach(group => {
            getPermissionGroupPageKeys(group).forEach(key => { result[key] = 1; });
        });
        Object.keys(getPagePermissionLabels()).forEach(key => {
            if (!(key in result)) result[key] = 1;
        });
        const denied = window.SITJOY_DENIED_PERMISSION_KEYS || [];
        denied.forEach(key => { result[key] = 0; });
        return result;
    }

    function normalizePagePermissions(value) {
        const labels = getPagePermissionLabels();
        const normalized = buildDefaultPagePermissions();
        if (!value || typeof value !== 'object') return normalized;
        Object.keys(labels).forEach(key => {
            if (key in value) normalized[key] = value[key] ? 1 : 0;
        });
        return normalized;
    }

    function canEditAdminGrant() {
        const u = permUser();
        return Number(u.id || 0) === 1;
    }

    function buildSwitchMarkup(checked, attrs, disabled) {
        return `
            <label class="switch-wrap">
                <input type="checkbox" ${checked ? 'checked' : ''} ${disabled ? 'disabled' : ''} ${attrs || ''}>
                <span class="switch-slider"></span>
            </label>
        `;
    }

    function buildPermissionGroupHtml(group, labels, permissions, options = {}) {
        const pageKeys = getPermissionGroupPageKeys(group);
        const moduleChecked = pageKeys.some(key => !!permissions[key]);
        const compactClass = options.compact ? ' is-compact' : '';
        const pageItems = pageKeys.map(key => `
            <div class="permission-item permission-sub-item${compactClass}" data-module-key="${escapeHtml(group.key || '')}">
                <span class="permission-name">${escapeHtml(labels[key] || key)}</span>
                ${buildSwitchMarkup(!!permissions[key], `data-role="page_permission" data-module-key="${escapeHtml(group.key || '')}" data-page-key="${escapeHtml(key)}"`, !!options.disablePages || !moduleChecked)}
            </div>
        `).join('');
        return `
            <div class="permission-group-card${compactClass}" data-module-key="${escapeHtml(group.key || '')}">
                <div class="permission-group-head">
                    <div class="permission-group-title-wrap">
                        <div class="permission-group-title">${escapeHtml(group.title || group.key || '')}</div>
                        <div class="permission-group-subtitle">${escapeHtml(pageKeys.length ? `${pageKeys.length} 个页面` : '无子页面')}</div>
                    </div>
                    ${buildSwitchMarkup(moduleChecked, `data-role="module_gate" data-module-key="${escapeHtml(group.key || '')}"`, !!options.disablePages)}
                </div>
                <div class="permission-group-pages${options.compact ? ' is-compact' : ''}">
                    ${pageItems}
                </div>
            </div>
        `;
    }

    function buildPermissionEditorHtml(scopeId, payload, options = {}) {
        const labels = getPagePermissionLabels();
        const permissions = normalizePagePermissions((payload && payload.page_permissions) || payload || {});
        const compactClass = options.compact ? ' is-compact' : '';
        const gridClass = options.gridClass ? ` ${options.gridClass}` : '';
        const adminDisabled = !!options.disableAdmin;
        const grantDisabled = !!options.disableGrant || !canEditAdminGrant();
        const groups = getPagePermissionGroups();
        return `
            <div class="permission-block permission-inline-meta" data-permission-editor="${escapeHtml(scopeId)}">
                ${options.hideFlags ? '' : `
                <div class="permission-inline-top">
                    <span class="permission-inline-flag">
                        <span>管理员</span>
                        ${buildSwitchMarkup(!!(payload && payload.is_admin), 'data-role="is_admin"', adminDisabled)}
                    </span>
                    <span class="permission-inline-flag">
                        <span>管理员授权</span>
                        ${buildSwitchMarkup(!!(payload && payload.can_grant_admin), 'data-role="can_grant_admin"', grantDisabled)}
                    </span>
                </div>`}
                <div class="permission-groups${compactClass}${gridClass}">
                    ${groups.map(group => buildPermissionGroupHtml(group, labels, permissions, options)).join('')}
                </div>
            </div>
        `;
    }

    function renderPermissionEditor(target, payload, options = {}) {
        const el = typeof target === 'string' ? document.getElementById(target) : target;
        if (!el) return;
        el.innerHTML = buildPermissionEditorHtml(el.id || 'perm-editor', payload || {}, options);
        syncPermissionEditor(el);
    }

    function collectPermissionEditorState(target) {
        const host = typeof target === 'string' ? document.getElementById(target) : target;
        const editor = host && host.matches && host.matches('[data-permission-editor]') ? host : (host ? host.querySelector('[data-permission-editor]') : null);
        const permissionRoot = editor || host;
        const controlRoot = host || editor;
        const pagePermissions = {};
        if (!permissionRoot) {
            return { is_admin: 0, can_grant_admin: 0, page_permissions: buildDefaultPagePermissions() };
        }
        permissionRoot.querySelectorAll('[data-role="page_permission"]').forEach(input => {
            pagePermissions[input.dataset.pageKey] = input.checked ? 1 : 0;
        });
        const adminInput = controlRoot ? controlRoot.querySelector('[data-role="is_admin"]') : null;
        const grantInput = controlRoot ? controlRoot.querySelector('[data-role="can_grant_admin"]') : null;
        return {
            is_admin: adminInput && adminInput.checked ? 1 : 0,
            can_grant_admin: grantInput && grantInput.checked ? 1 : 0,
            page_permissions: normalizePagePermissions(pagePermissions),
        };
    }

    function syncPermissionEditor(target) {
        const host = typeof target === 'string' ? document.getElementById(target) : target;
        const editor = host && host.matches && host.matches('[data-permission-editor]') ? host : (host ? host.querySelector('[data-permission-editor]') : null);
        const controlRoot = host || editor;
        if (!controlRoot) return;
        const adminInput = controlRoot.querySelector('[data-role="is_admin"]');
        const grantInput = controlRoot.querySelector('[data-role="can_grant_admin"]');
        const groupInputs = Array.from(controlRoot.querySelectorAll('[data-role="module_gate"]'));
        if (grantInput && grantInput.checked && adminInput && !adminInput.checked) adminInput.checked = true;
        if (adminInput && !adminInput.checked && grantInput) grantInput.checked = false;
        if (grantInput) grantInput.disabled = !canEditAdminGrant();
        groupInputs.forEach(input => {
            const groupCard = input.closest('.permission-group-card');
            const children = groupCard ? Array.from(groupCard.querySelectorAll('[data-role="page_permission"]')) : [];
            input.checked = !!input.checked || children.some(child => child.checked);
            children.forEach(child => { child.disabled = !input.checked; });
        });
    }

    function handlePermissionGateToggle(root, gateInput) {
        if (!root || !gateInput) return;
        const moduleKey = gateInput.dataset.moduleKey || '';
        root.querySelectorAll('[data-role="page_permission"][data-module-key="' + moduleKey + '"]').forEach(child => {
            if (!gateInput.checked) child.checked = false;
            child.disabled = !gateInput.checked;
        });
        syncPermissionEditor(root);
    }

    function isAuthAdminUser(user) {
        if (!user) return false;
        if (Number(user.id || 0) === 1) return true;
        const value = user.is_admin;
        if (value === true || value === 1) return true;
        if (value === false || value === 0 || value == null) return false;
        const num = Number(value);
        if (!Number.isNaN(num)) return num === 1;
        return String(value).trim() === '1';
    }

    function hasPageAccess(user, key) {
        if (!user || !key) return false;
        if (isAuthAdminUser(user)) return true;
        const perms = user.page_permissions || {};
        return !!perms[key];
    }

    function initPermContext(user) {
        window.__sitjoyPermUser = user || {};
        window.SITJOY_DENIED_PERMISSION_KEYS = user && Array.isArray(user.denied_permission_keys)
            ? user.denied_permission_keys
            : ['system_employee_management', 'system_audit_log_management', 'system_dingtalk_notify_management'];
    }

    SitjoyPerm.escapeHtml = escapeHtml;
    SitjoyPerm.getPagePermissionLabels = getPagePermissionLabels;
    SitjoyPerm.getPagePermissionGroups = getPagePermissionGroups;
    SitjoyPerm.buildDefaultPagePermissions = buildDefaultPagePermissions;
    SitjoyPerm.normalizePagePermissions = normalizePagePermissions;
    SitjoyPerm.canEditAdminGrant = canEditAdminGrant;
    SitjoyPerm.buildSwitchMarkup = buildSwitchMarkup;
    SitjoyPerm.buildPermissionEditorHtml = buildPermissionEditorHtml;
    SitjoyPerm.renderPermissionEditor = renderPermissionEditor;
    SitjoyPerm.collectPermissionEditorState = collectPermissionEditorState;
    SitjoyPerm.syncPermissionEditor = syncPermissionEditor;
    SitjoyPerm.handlePermissionGateToggle = handlePermissionGateToggle;
    SitjoyPerm.hasPageAccess = hasPageAccess;
    SitjoyPerm.initPermContext = initPermContext;
})();
