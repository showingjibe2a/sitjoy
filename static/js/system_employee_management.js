/**
 * 员工账号管理（系统管理）
 * - 待审批注册、在职员工列表、创建/编辑弹窗
 * - 权限开关、工厂范围、主管关系
 */
(function () {
    const P = () => window.SitjoyPerm;
    let currentUser = null;
    let isAdmin = false;

    // -------------------------------------------------------------------------
    // 权限校验与表单辅助
    // -------------------------------------------------------------------------

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

    function canAccessEmployeePage(user) {
        if (!user) return false;
        if (isAuthAdminUser(user)) return true;
        return P().hasPageAccess(user, 'system_employee_management');
    }

    function showModalHint(elementId, text, isError) {
        const msg = String(text || '').trim();
        if (!msg) {
            resetModalHint(elementId);
            return;
        }
        if (window.showPageStatus) window.showPageStatus(msg, !!isError);
    }

    function resetModalHint(elementId) {
        const el = document.getElementById(elementId);
        if (!el) return;
        el.style.display = 'none';
        el.textContent = '';
    }

    function formatEmployeeOptionLabel(emp) {
        if (!emp) return '';
        const name = String(emp.name || '').trim();
        const username = String(emp.username || '').trim();
        if (name && username) return `${name}（${username}）`;
        return name || username || '';
    }

    function buildEmployeeSupervisorOptions(excludeId, selectedId) {
        const items = Object.values(window.employeeMap || {})
            .filter(emp => Number(emp.id || 0) > 0 && Number(emp.id) !== Number(excludeId || 0))
            .sort((a, b) => {
                const aLabel = formatEmployeeOptionLabel(a);
                const bLabel = formatEmployeeOptionLabel(b);
                return aLabel.localeCompare(bLabel, 'zh-CN') || Number(a.id) - Number(b.id);
            });
        const selected = selectedId ? String(selectedId) : '';
        const options = ['<option value="">无</option>'];
        items.forEach(emp => {
            const id = String(emp.id);
            const label = formatEmployeeOptionLabel(emp) || (`#${id}`);
            options.push(`<option value="${id}"${id === selected ? ' selected' : ''}>${P().escapeHtml(label)}</option>`);
        });
        return options.join('');
    }

    function fillEmployeeSupervisorSelect(selectId, excludeId, selectedId) {
        const select = document.getElementById(selectId);
        if (!select) return;
        select.innerHTML = buildEmployeeSupervisorOptions(excludeId, selectedId);
    }

    async function confirmEmployeeDeletion(employee) {
        if (!employee || !employee.id) {
            alert('未找到用户信息，已取消删除。');
            return { ok: false };
        }
        const username = String(employee.username || '').trim();
        if (!username) {
            alert('目标用户缺少账号名，已取消删除。');
            return { ok: false };
        }
        const firstConfirm = window.showAppConfirmAsync
            ? await window.showAppConfirmAsync({ title: '危险操作确认', message: `危险操作：删除后用户将无法登录。\n\n账号：${username}\n\n是否继续？`, confirmText: '继续删除' })
            : false;
        if (!firstConfirm) return { ok: false };
        const typedUsername = prompt(`请输入账号名以确认删除：\n${username}`);
        if (typedUsername === null) return { ok: false };
        if (String(typedUsername).trim() !== username) {
            alert('账号名不匹配，已取消删除。');
            return { ok: false };
        }
        const typedPhrase = prompt('请输入 DELETE 作为最终确认');
        if (typedPhrase === null) return { ok: false };
        if (String(typedPhrase).trim().toUpperCase() !== 'DELETE') {
            alert('最终确认口令错误，已取消删除。');
            return { ok: false };
        }
        return { ok: true, confirm_username: username, confirm_phrase: 'DELETE' };
    }

    // -------------------------------------------------------------------------
    // 待审批与员工列表加载
    // -------------------------------------------------------------------------

    function loadPendingUsers() {
        if (!isAdmin) {
            const section = document.getElementById('pendingUsersSection');
            if (section) section.style.display = 'none';
            return Promise.resolve([]);
        }
        return fetch('/api/auth?action=pending_users', { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                const section = document.getElementById('pendingUsersSection');
                const tbody = document.querySelector('#pendingUsersTable tbody');
                if (!tbody || !section) return;
                const items = (data.status === 'success') ? (data.items || []) : [];
                window.pendingUserMap = Object.fromEntries(items.map(item => [String(item.id), item]));
                if (items.length === 0) {
                    section.style.display = 'none';
                    return items;
                }
                section.style.display = '';
                tbody.innerHTML = items.map(u => `
                    <tr data-pending-id="${u.id}">
                        <td>${u.username || '-'}</td>
                        <td>${u.name || '-'}</td>
                        <td>${u.phone || '-'}</td>
                        <td>${u.created_at ? new Date(u.created_at).toLocaleDateString('zh-CN') : '-'}</td>
                        <td>${P().buildSwitchMarkup(!!u.is_admin, 'data-role="is_admin"', false)}</td>
                        <td>${P().buildSwitchMarkup(!!u.can_grant_admin, 'data-role="can_grant_admin"', !P().canEditAdminGrant())}</td>
                        <td>${P().buildPermissionEditorHtml('pending-' + u.id, u, { compact: true, hideFlags: true, gridClass: ' permission-inline-grid' })}</td>
                        <td>
                            <div class="pm-actions">
                                <button class="btn-secondary" data-pending-action="approve" data-id="${u.id}">批准</button>
                                <button class="btn-danger" data-pending-action="reject" data-id="${u.id}">拒绝</button>
                            </div>
                        </td>
                    </tr>
                `).join('');
                return items;
            })
            .catch(() => []);
    }

    function loadEmployees() {
        return fetch('/api/employee', { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                const tbody = document.querySelector('#employeeTable tbody');
                if (!tbody) return [];
                if (data.status !== 'success') {
                    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;color:#a33;">${data.message || '加载失败'}</td></tr>`;
                    return [];
                }
                const items = data.items || [];
                window.employeeMap = Object.fromEntries(items.map(item => [String(item.id), item]));
                if (items.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;">暂无账号</td></tr>';
                    return items;
                }
                tbody.innerHTML = items.map(emp => {
                    const displayName = emp.name || '-';
                    const formattedBday = emp.birthday ? new Date(emp.birthday + 'T00:00:00').toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric' }) : '-';
                    const formattedHire = emp.hire_date ? String(emp.hire_date).slice(0, 10) : '-';
                    const jobTitle = (emp.job_title || '').trim() || '-';
                    const isSelf = currentUser && Number(currentUser.id || 0) === Number(emp.id || 0);
                    const canDelete = !isSelf && !Number(emp.is_admin || 0) && !Number(emp.can_grant_admin || 0);
                    return `
                        <tr data-employee-id="${emp.id}">
                            <td>${emp.username || '-'}</td>
                            <td>${displayName}</td>
                            <td>${emp.phone || '-'}</td>
                            <td>${formattedBday}</td>
                            <td>${P().escapeHtml(formattedHire)}</td>
                            <td>${P().escapeHtml(jobTitle)}</td>
                            <td>${P().buildSwitchMarkup(!!emp.is_admin, 'data-role="is_admin"', false)}</td>
                            <td>${P().buildSwitchMarkup(!!emp.can_grant_admin, 'data-role="can_grant_admin"', !P().canEditAdminGrant())}</td>
                            <td>${P().buildPermissionEditorHtml('employee-' + emp.id, emp, { compact: true, hideFlags: true, gridClass: ' permission-inline-grid' })}</td>
                            <td>
                                <div class="pm-actions">
                                    <button type="button" class="btn-secondary btn-small" data-action="edit" data-id="${emp.id}">编辑</button>
                                    <button type="button" class="btn-secondary btn-small" data-action="reset-password" data-id="${emp.id}">重置密码</button>
                                    ${canDelete
                                        ? `<button type="button" class="btn-danger btn-small" data-action="delete" data-id="${emp.id}">删除</button>`
                                        : `<button type="button" class="btn-danger btn-small" disabled title="当前账号或管理员账号不可直接删除">删除</button>`}
                                </div>
                            </td>
                        </tr>
                    `;
                }).join('');
                return items;
            });
    }

    // -------------------------------------------------------------------------
    // 创建 / 编辑弹窗与工厂范围
    // -------------------------------------------------------------------------

    function openEmployeeCreateModal() {
        const modal = document.getElementById('employeeCreateModal');
        const form = document.getElementById('employeeCreateForm');
        if (form) form.reset();
        fillEmployeeSupervisorSelect('employeeCreateDirectSupervisor', 0, '');
        P().renderPermissionEditor('employeeCreatePermissionEditor', {
            is_admin: 0,
            can_grant_admin: 0,
            page_permissions: P().buildDefaultPagePermissions(),
        });
        resetModalHint('employeeCreateHint');
        if (modal) modal.classList.add('active');
    }

    function closeEmployeeCreateModal() {
        const modal = document.getElementById('employeeCreateModal');
        if (modal) modal.classList.remove('active');
    }

    function getEmployeeEditFactoryScopeMode() {
        const select = document.getElementById('employeeEditFactoryScopeMode');
        return (select && select.value === 'custom') ? 'custom' : 'all';
    }

    function getEmployeeEditFactoryScopeIds() {
        if (!Array.isArray(window.employeeEditFactoryScopeSelectedIds)) window.employeeEditFactoryScopeSelectedIds = [];
        return window.employeeEditFactoryScopeSelectedIds;
    }

    function setEmployeeEditFactoryScopeIds(ids) {
        window.employeeEditFactoryScopeSelectedIds = Array.from(new Set((ids || []).map(id => parseInt(id, 10)).filter(id => Number.isFinite(id) && id > 0)));
    }

    function updateEmployeeEditFactoryScopeSelected() {
        const selectedWrap = document.getElementById('employeeEditFactoryScopeSelected');
        const toggleText = document.querySelector('#employeeEditFactoryScopeToggle .feature-category-add-text');
        if (!selectedWrap) return;
        const selectedIds = getEmployeeEditFactoryScopeIds();
        const options = window.employeeEditFactoryScopeOptions || [];
        selectedWrap.innerHTML = '';
        if (selectedIds.length === 0) {
            selectedWrap.innerHTML = '<span class="assignee-empty">未选择工厂</span>';
            if (toggleText) toggleText.textContent = '选择工厂';
            return;
        }
        selectedIds.forEach(id => {
            const option = options.find(item => Number(item.id) === Number(id));
            const displayName = option ? option.factory_name : `工厂${id}`;
            const tag = document.createElement('span');
            tag.className = 'feature-category-chip';
            tag.innerHTML = `<span>${P().escapeHtml(displayName)}</span><button type="button" class="feature-category-remove" data-remove-factory-id="${id}">×</button>`;
            selectedWrap.appendChild(tag);
        });
        if (toggleText) toggleText.textContent = `已选 ${selectedIds.length} 个工厂`;
    }

    function renderEmployeeEditFactoryScopeOptions(keyword = '') {
        const list = document.getElementById('employeeEditFactoryScopeList');
        if (!list) return;
        const selectedIds = new Set(getEmployeeEditFactoryScopeIds().map(id => String(id)));
        const query = String(keyword || '').trim().toLowerCase();
        const options = (window.employeeEditFactoryScopeOptions || []).filter(item => {
            if (selectedIds.has(String(item.id))) return false;
            const name = String(item.factory_name || '').toLowerCase();
            return !query || name.includes(query);
        });
        if (options.length === 0) {
            list.innerHTML = '<div class="feature-category-empty">暂无可选工厂</div>';
            return;
        }
        list.innerHTML = options.map(item => `
            <button type="button" class="feature-category-option" data-factory-id="${item.id}">
                <span>${P().escapeHtml(item.factory_name || `工厂${item.id}`)}</span>
            </button>
        `).join('');
    }

    function syncEmployeeEditFactoryScopeMode() {
        const mode = getEmployeeEditFactoryScopeMode();
        const wrap = document.getElementById('employeeEditFactoryScopeCustomWrap');
        if (wrap) wrap.style.display = mode === 'custom' ? '' : 'none';
    }

    function closeEmployeeEditFactoryScopeDropdown() {
        const dropdown = document.getElementById('employeeEditFactoryScopeDropdown');
        if (!dropdown) return;
        dropdown.classList.remove('open');
        dropdown.classList.remove('expanded');
    }

    async function loadEmployeeEditFactoryScopeOptions() {
        try {
            const resp = await fetch('/api/logistics-factory', { credentials: 'include' });
            const data = await resp.json();
            window.employeeEditFactoryScopeOptions = Array.isArray(data.items) ? data.items : [];
            renderEmployeeEditFactoryScopeOptions((document.getElementById('employeeEditFactoryScopeSearch') || {}).value || '');
            updateEmployeeEditFactoryScopeSelected();
        } catch (err) {
            window.employeeEditFactoryScopeOptions = [];
            renderEmployeeEditFactoryScopeOptions('');
        }
    }

    function openEmployeeEditModal(data) {
        document.getElementById('employeeEditId').value = data.id || '';
        document.getElementById('employeeEditUsername').value = data.username || '';
        document.getElementById('employeeEditName').value = data.name || '';
        document.getElementById('employeeEditBirthday').value = data.birthday || '';
        document.getElementById('employeeEditHireDate').value = (data.hire_date || '').toString().slice(0, 10);
        document.getElementById('employeeEditJobTitle').value = data.job_title || '';
        document.getElementById('employeeEditPhone').value = data.phone || '';
        fillEmployeeSupervisorSelect('employeeEditDirectSupervisor', data.id || 0, data.direct_supervisor_id || '');
        P().renderPermissionEditor('employeeEditPermissionEditor', {
            is_admin: data.is_admin,
            can_grant_admin: data.can_grant_admin,
            page_permissions: data.page_permissions,
        });
        const modeSelect = document.getElementById('employeeEditFactoryScopeMode');
        if (modeSelect) modeSelect.value = data.factory_scope_mode === 'custom' ? 'custom' : 'all';
        setEmployeeEditFactoryScopeIds(data.factory_scope_mode === 'custom' ? (data.factory_scope_ids || []) : []);
        const searchInput = document.getElementById('employeeEditFactoryScopeSearch');
        if (searchInput) searchInput.value = '';
        syncEmployeeEditFactoryScopeMode();
        loadEmployeeEditFactoryScopeOptions();
        resetModalHint('employeeEditHint');
        document.getElementById('employeeEditModal').classList.add('active');
    }

    function closeEmployeeEditModal() {
        document.getElementById('employeeEditModal').classList.remove('active');
    }

    async function resetEmployeePassword(empId) {
        const id = parseInt(empId, 10) || 0;
        if (!id || !isAdmin) return;
        const emp = (window.employeeMap || {})[String(id)] || {};
        const label = emp.username || emp.name || ('#' + id);
        const msg = `确定将账号「${label}」的密码重置为 12345678？\n\n对方下次登录需使用新密码。`;
        const ok = window.showAppConfirmAsync ? await window.showAppConfirmAsync(msg) : window.confirm(msg);
        if (!ok) return;
        try {
            const resp = await fetch('/api/employee', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ action: 'reset_password', id }),
            });
            const data = await resp.json();
            if (data.status === 'success') {
                if (window.showAppToast) window.showAppToast(data.message || '密码已重置', false, 2200);
            } else if (window.showAppToast) {
                window.showAppToast(data.message || '重置失败', true, 0);
            }
        } catch (err) {
            if (window.showAppToast) window.showAppToast('重置失败，请稍后重试', true, 0);
        }
    }

    // -------------------------------------------------------------------------
    // 页面事件绑定与启动
    // -------------------------------------------------------------------------

    function bindEmployeePageEvents() {
        const pendingUsersTable = document.getElementById('pendingUsersTable');
        if (pendingUsersTable) {
            pendingUsersTable.addEventListener('change', e => {
                const row = e.target.closest('tr[data-pending-id]');
                if (!row) return;
                if (e.target.matches('[data-role="module_gate"]')) {
                    P().handlePermissionGateToggle(row, e.target);
                    return;
                }
                P().syncPermissionEditor(row);
            });
            pendingUsersTable.addEventListener('click', e => {
                const action = e.target.dataset.pendingAction;
                const id = e.target.dataset.id;
                if (!action || !id) return;
                const row = e.target.closest('tr[data-pending-id]');
                const permissionState = row ? P().collectPermissionEditorState(row) : { page_permissions: P().buildDefaultPagePermissions(), is_admin: 0, can_grant_admin: 0 };
                fetch('/api/auth?action=approve_user', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id: parseInt(id, 10),
                        approve: action === 'approve',
                        is_admin: permissionState.is_admin,
                        can_grant_admin: permissionState.can_grant_admin,
                        page_permissions: permissionState.page_permissions,
                    }),
                })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            loadPendingUsers();
                            if (action === 'approve') loadEmployees();
                        }
                    });
            });
        }

        const employeeCreateBtn = document.getElementById('employeeCreateBtn');
        if (employeeCreateBtn) employeeCreateBtn.addEventListener('click', openEmployeeCreateModal);

        const employeeCreateForm = document.getElementById('employeeCreateForm');
        if (employeeCreateForm) {
            employeeCreateForm.addEventListener('submit', e => {
                e.preventDefault();
                const permissionState = P().collectPermissionEditorState('employeeCreatePermissionEditor');
                const payload = {
                    username: document.getElementById('employeeUsername').value.trim(),
                    password: document.getElementById('employeePassword').value,
                    name: document.getElementById('employeeName').value.trim(),
                    phone: document.getElementById('employeePhone').value.trim(),
                    birthday: document.getElementById('employeeBirthday').value,
                    hire_date: (document.getElementById('employeeHireDate') || {}).value || '',
                    job_title: (document.getElementById('employeeJobTitle') || {}).value.trim(),
                    direct_supervisor_id: (document.getElementById('employeeCreateDirectSupervisor') || {}).value || '',
                    is_admin: permissionState.is_admin,
                    can_grant_admin: permissionState.can_grant_admin,
                    page_permissions: permissionState.page_permissions,
                };
                if (!payload.username || !payload.password) {
                    showModalHint('employeeCreateHint', '请填写用户名与密码', true);
                    return;
                }
                fetch('/api/employee', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            showModalHint('employeeCreateHint', '已新增账号', false);
                            e.target.reset();
                            setTimeout(() => { closeEmployeeCreateModal(); loadEmployees(); }, 400);
                        } else {
                            showModalHint('employeeCreateHint', data.message || '保存失败', true);
                        }
                    })
                    .catch(() => showModalHint('employeeCreateHint', '请求失败', true));
            });
        }

        const employeeEditForm = document.getElementById('employeeEditForm');
        if (employeeEditForm) {
            employeeEditForm.addEventListener('submit', e => {
                e.preventDefault();
                if (!isAdmin) {
                    showModalHint('employeeEditHint', '仅管理员可编辑员工资料', true);
                    return;
                }
                const id = document.getElementById('employeeEditId').value;
                const permissionState = P().collectPermissionEditorState('employeeEditPermissionEditor');
                const factoryScopeMode = getEmployeeEditFactoryScopeMode();
                const factoryScopeIds = factoryScopeMode === 'custom' ? getEmployeeEditFactoryScopeIds() : [];
                if (factoryScopeMode === 'custom' && factoryScopeIds.length === 0) {
                    showModalHint('employeeEditHint', '自定义工厂范围至少选择一个工厂', true);
                    return;
                }
                const payload = {
                    id: parseInt(id, 10),
                    username: document.getElementById('employeeEditUsername').value.trim(),
                    name: document.getElementById('employeeEditName').value.trim(),
                    birthday: document.getElementById('employeeEditBirthday').value,
                    hire_date: (document.getElementById('employeeEditHireDate') || {}).value || '',
                    job_title: (document.getElementById('employeeEditJobTitle').value || '').trim(),
                    direct_supervisor_id: (document.getElementById('employeeEditDirectSupervisor') || {}).value || '',
                    phone: document.getElementById('employeeEditPhone').value.trim(),
                    is_admin: permissionState.is_admin,
                    can_grant_admin: permissionState.can_grant_admin,
                    page_permissions: permissionState.page_permissions,
                    factory_scope_mode: factoryScopeMode,
                    factory_scope_ids: factoryScopeIds,
                };
                fetch('/api/employee', {
                    method: 'PUT',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'success') {
                            showModalHint('employeeEditHint', '资料已更新', false);
                            setTimeout(() => { closeEmployeeEditModal(); loadEmployees(); }, 400);
                        } else {
                            showModalHint('employeeEditHint', data.message || '保存失败', true);
                        }
                    })
                    .catch(() => showModalHint('employeeEditHint', '请求失败', true));
            });
        }

        const employeeTable = document.getElementById('employeeTable');
        if (employeeTable) {
            employeeTable.addEventListener('change', e => {
                if (!e.target.matches('[data-role="is_admin"], [data-role="can_grant_admin"], [data-role="page_permission"], [data-role="module_gate"]')) return;
                const row = e.target.closest('tr[data-employee-id]');
                if (!row) return;
                if (e.target.matches('[data-role="module_gate"]')) P().handlePermissionGateToggle(row, e.target);
                else P().syncPermissionEditor(row);
                const payload = P().collectPermissionEditorState(row);
                fetch('/api/employee', {
                    method: 'PUT',
                    credentials: 'include',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        id: parseInt(row.dataset.employeeId, 10),
                        is_admin: payload.is_admin,
                        can_grant_admin: payload.can_grant_admin,
                        page_permissions: payload.page_permissions,
                    }),
                }).then(() => loadEmployees());
            });
            employeeTable.addEventListener('click', async e => {
                const action = e.target.dataset.action;
                const id = e.target.dataset.id;
                if (!action || !id) return;
                if (action === 'edit') {
                    openEmployeeEditModal((window.employeeMap || {})[String(id)] || {});
                    return;
                }
                if (action === 'reset-password') {
                    resetEmployeePassword(id);
                    return;
                }
                if (action === 'delete') {
                    const item = (window.employeeMap || {})[String(id)] || null;
                    const confirmPayload = await confirmEmployeeDeletion(item);
                    if (!confirmPayload.ok) return;
                    fetch('/api/employee', {
                        method: 'DELETE',
                        credentials: 'include',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            id,
                            confirm_username: confirmPayload.confirm_username,
                            confirm_phrase: confirmPayload.confirm_phrase,
                        }),
                    })
                        .then(r => r.json())
                        .then(data => {
                            if (data && data.status === 'error') alert(data.message || '删除失败');
                            loadEmployees();
                        });
                }
            });
        }

        ['employeeCreatePermissionEditor', 'employeeEditPermissionEditor'].forEach(editorId => {
            const el = document.getElementById(editorId);
            if (!el) return;
            el.addEventListener('change', e => {
                if (!e.target.matches('[data-role="module_gate"], [data-role="page_permission"], [data-role="is_admin"], [data-role="can_grant_admin"]')) return;
                if (e.target.matches('[data-role="module_gate"]')) P().handlePermissionGateToggle(el, e.target);
                else P().syncPermissionEditor(el);
            });
        });

        const employeeEditFactoryScopeMode = document.getElementById('employeeEditFactoryScopeMode');
        if (employeeEditFactoryScopeMode) {
            employeeEditFactoryScopeMode.addEventListener('change', () => {
                syncEmployeeEditFactoryScopeMode();
                closeEmployeeEditFactoryScopeDropdown();
            });
        }
        const employeeEditFactoryScopeToggle = document.getElementById('employeeEditFactoryScopeToggle');
        if (employeeEditFactoryScopeToggle) {
            employeeEditFactoryScopeToggle.addEventListener('click', ev => {
                ev.stopPropagation();
                if (getEmployeeEditFactoryScopeMode() !== 'custom') return;
                const dropdown = document.getElementById('employeeEditFactoryScopeDropdown');
                if (dropdown) {
                    dropdown.classList.toggle('open');
                    dropdown.classList.toggle('expanded');
                }
            });
        }
        const employeeEditFactoryScopeSearch = document.getElementById('employeeEditFactoryScopeSearch');
        if (employeeEditFactoryScopeSearch) {
            employeeEditFactoryScopeSearch.addEventListener('input', () => renderEmployeeEditFactoryScopeOptions(employeeEditFactoryScopeSearch.value));
        }
        const employeeEditFactoryScopeList = document.getElementById('employeeEditFactoryScopeList');
        if (employeeEditFactoryScopeList) {
            employeeEditFactoryScopeList.addEventListener('click', ev => {
                const option = ev.target.closest('[data-factory-id]');
                if (!option) return;
                const fid = parseInt(option.dataset.factoryId, 10);
                if (!Number.isFinite(fid) || fid <= 0) return;
                const selected = new Set(getEmployeeEditFactoryScopeIds());
                selected.add(fid);
                setEmployeeEditFactoryScopeIds(Array.from(selected));
                updateEmployeeEditFactoryScopeSelected();
                renderEmployeeEditFactoryScopeOptions(employeeEditFactoryScopeSearch ? employeeEditFactoryScopeSearch.value : '');
            });
        }
        const employeeEditFactoryScopeSelected = document.getElementById('employeeEditFactoryScopeSelected');
        if (employeeEditFactoryScopeSelected) {
            employeeEditFactoryScopeSelected.addEventListener('click', ev => {
                const removeId = parseInt(ev.target.dataset.removeFactoryId || '0', 10);
                if (!removeId) return;
                setEmployeeEditFactoryScopeIds(getEmployeeEditFactoryScopeIds().filter(x => x !== removeId));
                updateEmployeeEditFactoryScopeSelected();
                renderEmployeeEditFactoryScopeOptions(employeeEditFactoryScopeSearch ? employeeEditFactoryScopeSearch.value : '');
            });
        }

        const bindBackdrop = window.bindPmModalBackdropClose;
        if (typeof bindBackdrop === 'function') {
            const createModal = document.getElementById('employeeCreateModal');
            const editModal = document.getElementById('employeeEditModal');
            if (createModal) bindBackdrop(createModal, closeEmployeeCreateModal);
            if (editModal) bindBackdrop(editModal, closeEmployeeEditModal);
        }

        document.addEventListener('change', e => {
            if (!e.target.matches('[data-role="is_admin"], [data-role="can_grant_admin"]')) return;
            const scope = e.target.closest('[data-permission-editor]') || e.target.closest('tr');
            if (scope) P().syncPermissionEditor(scope);
        });
    }

    window.addEventListener('load', () => {
        fetch('/api/auth?action=current', { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                if (data.status !== 'success') {
                    window.location.href = '/login';
                    return;
                }
                currentUser = data;
                isAdmin = isAuthAdminUser(data);
                P().initPermContext(data);
                if (!canAccessEmployeePage(data)) {
                    window.location.href = '/';
                    return;
                }
                bindEmployeePageEvents();
                if (isAdmin) loadPendingUsers();
                loadEmployees();
            })
            .catch(() => { window.location.href = '/login'; });
    });
})();
