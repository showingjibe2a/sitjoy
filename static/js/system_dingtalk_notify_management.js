/**
 * 系统设置：钉钉群聊 CRUD 与通知功能绑定管理。
 */
(function () {
    'use strict';

    let groupItems = [];
    let bindingRows = [];
    let groupOptions = [];
    let editingGroupId = null;

    // -------------------------------------------------------------------------
    // 通用 UI
    // -------------------------------------------------------------------------

    function escapeHtml(value) {
        return String(value == null ? '' : value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function showModalStatus(msg, isError) {
        const el = document.getElementById('dtGroupModalStatus');
        if (!el) return;
        el.style.display = 'block';
        el.textContent = msg || '';
        el.style.color = isError ? '#9b2226' : '#2f6b3f';
    }

    function resetModalStatus() {
        const el = document.getElementById('dtGroupModalStatus');
        if (!el) return;
        el.style.display = 'none';
        el.textContent = '';
    }

    function setSegmentValue(seg, value) {
        if (!seg) return;
        const val = String(value);
        seg.dataset.value = val;
        seg.querySelectorAll('.status-pill').forEach((btn) => {
            btn.classList.toggle('is-active', String(btn.getAttribute('data-value') || '') === val);
        });
    }

    function bindSegment(segId) {
        const seg = document.getElementById(segId);
        if (!seg || seg.dataset.bound === '1') return;
        seg.dataset.bound = '1';
        seg.addEventListener('click', (ev) => {
            const btn = ev.target && ev.target.closest ? ev.target.closest('.status-pill') : null;
            if (!btn || !seg.contains(btn)) return;
            setSegmentValue(seg, btn.getAttribute('data-value') || '1');
        });
    }

    async function fetchJson(url, options) {
        const resp = await fetch(url, Object.assign({ credentials: 'include' }, options || {}));
        return resp.json();
    }

    // -------------------------------------------------------------------------
    // 群聊列表
    // -------------------------------------------------------------------------

    function renderGroupTable() {
        const tbody = document.querySelector('#dtGroupTable tbody');
        if (!tbody) return;
        if (!groupItems.length) {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">暂无群聊，请先新增</td></tr>';
            return;
        }
        tbody.innerHTML = groupItems.map((item) => `
            <tr>
                <td>${escapeHtml(item.group_name)}</td>
                <td><code>${escapeHtml(item.webhook_url)}</code></td>
                <td>${escapeHtml(item.secret)}</td>
                <td>${Number(item.is_enabled) ? '是' : '否'}</td>
                <td>${escapeHtml(item.remark || '-')}</td>
                <td>
                    <div class="pm-actions">
                        <button type="button" class="btn-secondary btn-small" data-action="edit-group" data-id="${item.id}">编辑</button>
                        <button type="button" class="btn-danger btn-small" data-action="delete-group" data-id="${item.id}">删除</button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    function groupSelectHtml(selectedId) {
        const selected = Number(selectedId || 0);
        const opts = ['<option value="">请选择群聊</option>']
            .concat(groupOptions.map((g) => {
                const id = Number(g.id || 0);
                const disabled = Number(g.is_enabled) ? '' : ' disabled';
                const suffix = Number(g.is_enabled) ? '' : '（已停用）';
                const sel = id === selected ? ' selected' : '';
                return `<option value="${id}"${sel}${disabled}>${escapeHtml(g.group_name)}${suffix}</option>`;
            }));
        return opts.join('');
    }

    // -------------------------------------------------------------------------
    // 通知功能绑定
    // -------------------------------------------------------------------------

    function readBindingRowState(notifyKey) {
        const row = document.querySelector(`tr[data-notify-key="${CSS.escape(notifyKey)}"]`);
        if (!row) return null;
        const enabledSeg = row.querySelector('.dt-binding-enabled-seg');
        return {
            groupId: Number(row.querySelector('.dt-binding-group-select')?.value || 0),
            isEnabled: enabledSeg && enabledSeg.dataset.value === '1' ? 1 : 0,
        };
    }

    function renderBindingTable() {
        const tbody = document.querySelector('#dtBindingTable tbody');
        if (!tbody) return;
        if (!bindingRows.length) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">暂无通知功能</td></tr>';
            return;
        }
        tbody.innerHTML = bindingRows.map((row) => {
            const notifyKey = String(row.notify_key || '');
            const enabledSeg = `
                <div class="status-segment status-segment--inline dt-binding-enabled-seg" data-notify-key="${escapeHtml(notifyKey)}" data-value="${row.is_enabled ? '1' : '0'}">
                    <button type="button" class="status-pill status-pill--yes ${row.is_enabled ? 'is-active' : ''}" data-value="1">是</button>
                    <button type="button" class="status-pill status-pill--no ${row.is_enabled ? '' : 'is-active'}" data-value="0">否</button>
                </div>`;
            return `
                <tr data-notify-key="${escapeHtml(notifyKey)}">
                    <td>${escapeHtml(row.notify_label || notifyKey)}</td>
                    <td>${escapeHtml(row.page_label || row.page_key || '-')}</td>
                    <td>
                        <select class="dt-binding-group-select" data-notify-key="${escapeHtml(notifyKey)}">
                            ${groupSelectHtml(row.dingtalk_group_id)}
                        </select>
                    </td>
                    <td>${enabledSeg}</td>
                    <td>
                        <div class="pm-actions">
                            <button type="button" class="btn-primary btn-small dt-binding-save-btn" data-notify-key="${escapeHtml(notifyKey)}">保存绑定</button>
                            ${row.is_bound ? `<button type="button" class="btn-secondary btn-small dt-binding-clear-btn" data-notify-key="${escapeHtml(notifyKey)}">清除</button>` : ''}
                        </div>
                    </td>
                </tr>`;
        }).join('');
        document.querySelectorAll('.dt-binding-enabled-seg').forEach((seg) => {
            seg.addEventListener('click', (ev) => {
                const btn = ev.target && ev.target.closest ? ev.target.closest('.status-pill') : null;
                if (!btn || !seg.contains(btn)) return;
                setSegmentValue(seg, btn.getAttribute('data-value') || '1');
            });
        });
    }

    async function loadGroups() {
        const data = await fetchJson('/api/dingtalk-group');
        if (data.status !== 'success') throw new Error(data.message || '加载群聊失败');
        groupItems = data.items || [];
        renderGroupTable();
    }

    async function loadBindings() {
        const data = await fetchJson('/api/dingtalk-notify-binding');
        if (data.status !== 'success') throw new Error(data.message || '加载绑定失败');
        groupOptions = data.groups || [];
        bindingRows = data.bindings || [];
        renderBindingTable();
    }

    async function reloadAll() {
        await Promise.all([loadGroups(), loadBindings()]);
    }

    // -------------------------------------------------------------------------
    // 群聊模态框
    // -------------------------------------------------------------------------

    function openGroupModal(item) {
        editingGroupId = item && item.id ? Number(item.id) : null;
        document.getElementById('dtGroupModalTitle').textContent = editingGroupId ? '编辑群聊' : '新增群聊';
        document.getElementById('dtGroupName').value = (item && item.group_name) || '';
        document.getElementById('dtGroupWebhook').value = editingGroupId ? '' : ((item && item.webhook_url) || '');
        document.getElementById('dtGroupSecret').value = '';
        document.getElementById('dtGroupRemark').value = (item && item.remark) || '';
        setSegmentValue(document.getElementById('dtGroupEnabledSegment'), String(item && item.is_enabled != null ? item.is_enabled : 1));
        resetModalStatus();
        document.getElementById('dtGroupModal').classList.add('active');
        if (editingGroupId) {
            fetchJson(`/api/dingtalk-group?id=${encodeURIComponent(editingGroupId)}`).then((data) => {
                if (data.status !== 'success' || !data.item) return;
                document.getElementById('dtGroupWebhook').value = data.item.webhook_url || '';
            }).catch(() => {});
        }
    }

    function closeGroupModal() {
        document.getElementById('dtGroupModal').classList.remove('active');
        editingGroupId = null;
    }

    async function saveGroupModal() {
        const payload = {
            group_name: document.getElementById('dtGroupName').value.trim(),
            webhook_url: document.getElementById('dtGroupWebhook').value.trim(),
            secret: document.getElementById('dtGroupSecret').value.trim(),
            remark: document.getElementById('dtGroupRemark').value.trim(),
            is_enabled: document.getElementById('dtGroupEnabledSegment').dataset.value === '1' ? 1 : 0,
        };
        if (!payload.group_name) {
            showModalStatus('请填写群聊名称', true);
            return;
        }
        if (!editingGroupId) {
            if (!payload.webhook_url || !payload.secret) {
                showModalStatus('请填写 Webhook 与 Secret', true);
                return;
            }
        }
        const method = editingGroupId ? 'PUT' : 'POST';
        if (editingGroupId) payload.id = editingGroupId;
        const data = await fetchJson('/api/dingtalk-group', {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (data.status !== 'success') {
            showModalStatus(data.message || '保存失败', true);
            return;
        }
        if (window.showAppSaveResult) window.showAppSaveResult({ action: editingGroupId ? 'save' : 'create' });
        closeGroupModal();
        await reloadAll();
    }

    async function deleteGroup(id) {
        const ok = window.showAppConfirmAsync
            ? await window.showAppConfirmAsync({ title: '删除群聊', message: '确认删除该钉钉群聊配置？', confirmText: '确认删除' })
            : false;
        if (!ok) return;
        const data = await fetchJson('/api/dingtalk-group', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id }),
        });
        if (data.status !== 'success') {
            if (window.showAppToast) window.showAppToast(data.message || '删除失败', true, 0);
            return;
        }
        if (window.showAppSaveResult) window.showAppSaveResult({ action: 'delete' });
        await reloadAll();
    }

    async function saveBinding(notifyKey) {
        const state = readBindingRowState(notifyKey);
        if (!state) return;
        if (!state.groupId) {
            if (window.showAppToast) window.showAppToast('请选择钉钉群聊', true, 0);
            return;
        }
        const data = await fetchJson('/api/dingtalk-notify-binding', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                notify_key: notifyKey,
                dingtalk_group_id: state.groupId,
                is_enabled: state.isEnabled,
            }),
        });
        if (data.status !== 'success') {
            if (window.showAppToast) window.showAppToast(data.message || '保存失败', true, 0);
            return;
        }
        if (window.showAppSaveResult) window.showAppSaveResult({ action: 'save' });
        await loadBindings();
    }

    async function clearBinding(notifyKey) {
        const ok = window.showAppConfirmAsync
            ? await window.showAppConfirmAsync({ title: '清除绑定', message: '确认清除该通知功能的钉钉群绑定？', confirmText: '确认清除' })
            : false;
        if (!ok) return;
        const data = await fetchJson('/api/dingtalk-notify-binding', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ notify_key: notifyKey }),
        });
        if (data.status !== 'success') {
            if (window.showAppToast) window.showAppToast(data.message || '清除失败', true, 0);
            return;
        }
        if (window.showAppSaveResult) window.showAppSaveResult({ action: 'delete' });
        await loadBindings();
    }

    // -------------------------------------------------------------------------
    // 事件绑定与初始化
    // -------------------------------------------------------------------------

    function bindEvents() {
        document.getElementById('dtGroupCreateBtn')?.addEventListener('click', () => openGroupModal(null));
        document.getElementById('dtGroupModalCancel')?.addEventListener('click', closeGroupModal);
        document.getElementById('dtGroupModalSave')?.addEventListener('click', () => {
            saveGroupModal().catch((err) => showModalStatus(String(err.message || err), true));
        });
        document.querySelector('#dtGroupTable tbody')?.addEventListener('click', (ev) => {
            const btn = ev.target && ev.target.closest ? ev.target.closest('button[data-action]') : null;
            if (!btn) return;
            const id = Number(btn.getAttribute('data-id') || 0);
            if (!id) return;
            if (btn.getAttribute('data-action') === 'edit-group') {
                const item = groupItems.find((g) => Number(g.id) === id);
                openGroupModal(item || { id });
            } else if (btn.getAttribute('data-action') === 'delete-group') {
                deleteGroup(id).catch((err) => {
                    if (window.showAppToast) window.showAppToast(String(err.message || err), true, 0);
                });
            }
        });
        document.querySelector('#dtBindingTable tbody')?.addEventListener('click', (ev) => {
            const saveBtn = ev.target && ev.target.closest ? ev.target.closest('.dt-binding-save-btn') : null;
            const clearBtn = ev.target && ev.target.closest ? ev.target.closest('.dt-binding-clear-btn') : null;
            if (saveBtn) {
                saveBinding(saveBtn.getAttribute('data-notify-key') || '').catch((err) => {
                    if (window.showAppToast) window.showAppToast(String(err.message || err), true, 0);
                });
            } else if (clearBtn) {
                clearBinding(clearBtn.getAttribute('data-notify-key') || '').catch((err) => {
                    if (window.showAppToast) window.showAppToast(String(err.message || err), true, 0);
                });
            }
        });
        bindSegment('dtGroupEnabledSegment');
        const modal = document.getElementById('dtGroupModal');
        if (modal && typeof window.bindPmModalBackdropClose === 'function') {
            window.bindPmModalBackdropClose(modal, closeGroupModal);
        }
    }

    window.addEventListener('load', () => {
        bindEvents();
        reloadAll().catch((err) => {
            const msg = String(err.message || err);
            document.querySelector('#dtGroupTable tbody').innerHTML = `<tr><td colspan="6" style="text-align:center;color:#a33;">${escapeHtml(msg)}</td></tr>`;
            document.querySelector('#dtBindingTable tbody').innerHTML = `<tr><td colspan="5" style="text-align:center;color:#a33;">${escapeHtml(msg)}</td></tr>`;
        });
    });
})();
