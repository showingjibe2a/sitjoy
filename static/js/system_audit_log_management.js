/**
 * 系统审计日志：页面访问与操作记录分页查询、托管表、清理全部。
 */
(function () {
    let currentUser = null;
    let auditLogType = 'access';
    let auditLogPage = 1;
    let auditLogTotal = 0;
    let auditLogPageSize = 50;
    let auditManagedTableReady = false;

    // -------------------------------------------------------------------------
    // 权限与渲染辅助
    // -------------------------------------------------------------------------

    function canViewAuditLogs() {
        if (!currentUser) return false;
        if (Number(currentUser.can_view_audit_logs || 0) === 1) return true;
        if (Number(currentUser.id || 0) === 1) return true;
        return Number(currentUser.is_admin || 0) === 1 && Number(currentUser.can_grant_admin || 0) === 1;
    }

    function escapeHtml(value) {
        return String(value || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function formatAuditDateTime(value) {
        if (!value) return '';
        const text = String(value).trim();
        if (!text) return '';
        return text.replace('T', ' ').slice(0, 19);
    }

    function moduleLabel(row) {
        const key = String(row.module_key || '').trim();
        const labels = (currentUser && currentUser.page_permission_labels) || {};
        return labels[key] || key || '—';
    }

    function renderOperationSummaryHtml(row) {
        let meta = null;
        if (row.changes_json) {
            try {
                meta = typeof row.changes_json === 'string' ? JSON.parse(row.changes_json) : row.changes_json;
            } catch (_err) {
                meta = null;
            }
        }
        if (meta && Array.isArray(meta.changes) && meta.changes.length) {
            const verbMap = { post: '新增', put: '更新', patch: '更新', delete: '删除' };
            const verb = verbMap[String(meta.action || '').toLowerCase()] || '更新';
            const head = verb + ' · ' + (meta.entity_label || meta.entity_type || '记录')
                + (meta.entity_id ? ' #' + meta.entity_id : '');
            const rows = meta.changes.map(ch => `
                <tr>
                    <th>${escapeHtml(ch.label || ch.field || '字段')}</th>
                    <td>${escapeHtml(ch.old || '（空）')}</td>
                    <td>${escapeHtml(ch.new || '（空）')}</td>
                </tr>
            `).join('');
            return `<div class="audit-log-change-head">${escapeHtml(head)}</div>
                <table class="audit-log-change-table">
                    <thead><tr><th>字段</th><th>变更前</th><th>变更后</th></tr></thead>
                    <tbody>${rows}</tbody>
                </table>`;
        }
        const summary = String(row.request_summary || '').trim();
        if (!summary) return '—';
        return escapeHtml(summary);
    }

    function auditColSpan() {
        return auditLogType === 'access' ? 6 : 8;
    }

    function auditTotalPages() {
        return Math.max(1, Math.ceil(auditLogTotal / Math.max(1, auditLogPageSize)));
    }

    // -------------------------------------------------------------------------
    // 托管表
    // -------------------------------------------------------------------------

    function ensureAuditManagedTableReady() {
        const M = window.SitjoyManagedPmTable;
        const table = document.getElementById('auditLogTable');
        if (!M || !table) return;
        if (typeof M.getState === 'function' && M.getState(table)) return;
        if (typeof M.enhance === 'function') M.enhance(document);
    }

    function initAuditManagedTable() {
        if (auditManagedTableReady) return;
        ensureAuditManagedTableReady();
        const M = window.SitjoyManagedPmTable;
        const table = document.getElementById('auditLogTable');
        if (!M || !table || typeof M.registerServerList !== 'function') return;
        if (typeof M.getState !== 'function' || !M.getState(table)) {
            window.setTimeout(initAuditManagedTable, 120);
            return;
        }
        auditManagedTableReady = true;
        M.registerServerList('#auditLogTable', {
            pageSizeMin: 20,
            pageSizeMax: 200,
            getPager() {
                return {
                    page: auditLogPage,
                    pageSize: auditLogPageSize,
                    total: auditLogTotal,
                    totalPages: auditTotalPages(),
                };
            },
            loadPage(page, options) {
                loadAuditLogs(page, options);
            },
            reload(page, options) {
                const src = options && options.source;
                if (src === 'clear-toolbar' || src === 'clear') {
                    clearAuditPageFilters();
                }
                loadAuditLogs(page || 1, options);
            },
            onPageSizeChange(size) {
                auditLogPageSize = size;
            },
            onClear() {
                clearAuditPageFilters();
                loadAuditLogs(1);
            },
        });
    }

    function clearAuditPageFilters() {
        const q = document.getElementById('auditSearchQ');
        const df = document.getElementById('auditDateFrom');
        const dt = document.getElementById('auditDateTo');
        if (q) q.value = '';
        if (df) df.value = '';
        if (dt) dt.value = '';
    }

    function syncAuditManagedTablePager() {
        const M = window.SitjoyManagedPmTable;
        if (!M || typeof M.syncServerPager !== 'function') return;
        M.syncServerPager('#auditLogTable', {
            page: auditLogPage,
            pageSize: auditLogPageSize,
            total: auditLogTotal,
            totalPages: auditTotalPages(),
        });
    }

    function refreshAuditManagedTableLayout() {
        const M = window.SitjoyManagedPmTable;
        const table = document.getElementById('auditLogTable');
        if (!M || !table) return;
        if (typeof M.invalidateLayout === 'function') M.invalidateLayout(table);
        else if (typeof M.syncLayout === 'function') M.syncLayout(table);
    }

    // -------------------------------------------------------------------------
    // 列表加载与分页
    // -------------------------------------------------------------------------

    function renderAuditLogTableHead() {
        const head = document.getElementById('auditLogTableHead');
        if (!head) return;
        if (auditLogType === 'access') {
            head.innerHTML = `
                <tr>
                    <th data-manage-col-key="created_at">时间</th>
                    <th data-manage-col-key="username">账号</th>
                    <th data-manage-col-key="user_name">姓名</th>
                    <th data-manage-col-key="page_path">页面路径</th>
                    <th data-manage-col-key="page_label">页面</th>
                    <th data-manage-col-key="client_ip">IP</th>
                </tr>`;
        } else {
            head.innerHTML = `
                <tr>
                    <th data-manage-col-key="created_at">时间</th>
                    <th data-manage-col-key="username">账号</th>
                    <th data-manage-col-key="user_name">姓名</th>
                    <th data-manage-col-key="http_method">方法</th>
                    <th data-manage-col-key="api_path">API</th>
                    <th data-manage-col-key="module_key">模块</th>
                    <th data-manage-col-key="request_summary">摘要</th>
                    <th data-manage-col-key="client_ip">IP</th>
                </tr>`;
        }
    }

    function renderAuditLogRows(items) {
        const colSpan = auditColSpan();
        if (!items.length) {
            return '<tr><td colspan="' + colSpan + '" style="text-align:center;">暂无记录</td></tr>';
        }
        if (auditLogType === 'access') {
            return items.map(row => `
                <tr>
                    <td data-manage-col-key="created_at">${escapeHtml(formatAuditDateTime(row.created_at))}</td>
                    <td data-manage-col-key="username">${escapeHtml(row.username || '')}</td>
                    <td data-manage-col-key="user_name">${escapeHtml(row.user_name || '')}</td>
                    <td data-manage-col-key="page_path">${escapeHtml(row.page_path || '')}</td>
                    <td data-manage-col-key="page_label">${escapeHtml(row.page_label || row.page_key || '')}</td>
                    <td data-manage-col-key="client_ip">${escapeHtml(row.client_ip || '')}</td>
                </tr>
            `).join('');
        }
        return items.map(row => `
            <tr>
                <td data-manage-col-key="created_at">${escapeHtml(formatAuditDateTime(row.created_at))}</td>
                <td data-manage-col-key="username">${escapeHtml(row.username || '')}</td>
                <td data-manage-col-key="user_name">${escapeHtml(row.user_name || '')}</td>
                <td data-manage-col-key="http_method">${escapeHtml(row.http_method || '')}</td>
                <td data-manage-col-key="api_path">${escapeHtml(row.api_path || '')}</td>
                <td data-manage-col-key="module_key">${escapeHtml(moduleLabel(row))}</td>
                <td class="audit-log-summary-cell" data-manage-col-key="request_summary">${renderOperationSummaryHtml(row)}</td>
                <td data-manage-col-key="client_ip">${escapeHtml(row.client_ip || '')}</td>
            </tr>
        `).join('');
    }

    async function loadAuditLogs(page = 1, options) {
        if (!canViewAuditLogs()) return;
        ensureAuditManagedTableReady();
        initAuditManagedTable();

        const M = window.SitjoyManagedPmTable;
        auditLogPage = Math.max(1, page);
        if (options && Number(options.pageSize) > 0) {
            const norm = (M && typeof M.normalizePageSize === 'function')
                ? M.normalizePageSize(options.pageSize, auditLogPageSize, 20, 200)
                : Math.max(20, Math.min(200, Number(options.pageSize) || 50));
            auditLogPageSize = norm;
        }

        const q = (document.getElementById('auditSearchQ') || {}).value || '';
        const dateFrom = (document.getElementById('auditDateFrom') || {}).value || '';
        const dateTo = (document.getElementById('auditDateTo') || {}).value || '';
        const params = new URLSearchParams({
            type: auditLogType,
            page: String(auditLogPage),
            page_size: String(auditLogPageSize),
        });
        if (q.trim()) params.set('q', q.trim());
        if (dateFrom) params.set('date_from', dateFrom);
        if (dateTo) params.set('date_to', dateTo);

        const tbody = document.querySelector('#auditLogTable tbody');
        const colSpan = auditColSpan();
        renderAuditLogTableHead();

        const paintLoading = () => {
            if (tbody) tbody.innerHTML = '<tr><td colspan="' + colSpan + '" style="text-align:center;">加载中…</td></tr>';
        };
        if (M && typeof M.withBodyUpdate === 'function') {
            M.withBodyUpdate('#auditLogTable', paintLoading);
        } else {
            paintLoading();
        }

        try {
            const resp = await fetch('/api/audit-log?' + params.toString(), { credentials: 'include' });
            const data = await resp.json();
            if (data.status !== 'success') {
                const errHtml = '<tr><td colspan="' + colSpan + '" style="text-align:center;color:#a33;">'
                    + escapeHtml(data.message || '加载失败') + '</td></tr>';
                if (M && typeof M.withBodyUpdate === 'function') {
                    M.withBodyUpdate('#auditLogTable', () => { if (tbody) tbody.innerHTML = errHtml; });
                } else if (tbody) {
                    tbody.innerHTML = errHtml;
                }
                auditLogTotal = 0;
                syncAuditManagedTablePager();
                return;
            }

            auditLogTotal = Number(data.total || 0);
            auditLogPage = Math.max(1, Number(data.page || auditLogPage || 1));
            auditLogPageSize = Math.max(20, Math.min(200, Number(data.page_size || auditLogPageSize || 50)));
            const items = data.items || [];
            const html = renderAuditLogRows(items);

            const table = document.getElementById('auditLogTable');
            if (table) {
                table.dataset.serverPaginationMode = 'server';
                table.dataset.serverCurrentPage = String(auditLogPage);
                table.dataset.serverPageSize = String(auditLogPageSize);
                table.dataset.serverTotalRows = String(auditLogTotal);
            }

            if (M && typeof M.withBodyUpdate === 'function') {
                M.withBodyUpdate('#auditLogTable', () => { if (tbody) tbody.innerHTML = html; });
            } else if (tbody) {
                tbody.innerHTML = html;
            }

            syncAuditManagedTablePager();
            refreshAuditManagedTableLayout();
        } catch (err) {
            const errHtml = '<tr><td colspan="' + colSpan + '" style="text-align:center;color:#a33;">网络错误</td></tr>';
            if (M && typeof M.withBodyUpdate === 'function') {
                M.withBodyUpdate('#auditLogTable', () => { if (tbody) tbody.innerHTML = errHtml; });
            } else if (tbody) {
                tbody.innerHTML = errHtml;
            }
            auditLogTotal = 0;
            syncAuditManagedTablePager();
        }
    }

    // -------------------------------------------------------------------------
    // 类型切换、清理与事件绑定
    // -------------------------------------------------------------------------

    function setSegmentValue(seg, value) {
        if (!seg) return;
        const v = value === 'operation' ? 'operation' : 'access';
        seg.dataset.value = v;
        seg.querySelectorAll('.status-pill[data-value]').forEach(btn => {
            const active = String(btn.dataset.value || '') === v;
            btn.classList.toggle('is-active', active);
            btn.setAttribute('aria-selected', active ? 'true' : 'false');
        });
    }

    function setAuditLogTab(type) {
        auditLogType = type === 'operation' ? 'operation' : 'access';
        setSegmentValue(document.getElementById('auditLogTypeSegment'), auditLogType);
        auditLogPage = 1;
        loadAuditLogs(1);
    }

    function bindAuditLogTypeSegment() {
        const seg = document.getElementById('auditLogTypeSegment');
        if (!seg || seg.dataset.bound === '1') return;
        seg.dataset.bound = '1';
        seg.addEventListener('click', (e) => {
            const btn = e.target && e.target.closest ? e.target.closest('.status-pill[data-value]') : null;
            if (!btn) return;
            setAuditLogTab(String(btn.dataset.value || 'access'));
        });
    }

    async function cleanupAuditLogs() {
        if (!canViewAuditLogs()) return;
        const typeLabel = auditLogType === 'operation' ? '操作记录' : '页面访问';
        const confirmAsync = window.showAppConfirmAsync;
        if (!confirmAsync) return;
        const ok = await confirmAsync({
            title: '清理全部审计日志',
            message: '将永久删除当前「' + typeLabel + '」下的全部日志，不可恢复。',
            confirmText: '确认清理',
            cancelText: '取消',
            requireConfirmCheck: true,
        });
        if (!ok) return;
        try {
            const resp = await fetch('/api/audit-log?action=cleanup', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: auditLogType }),
            });
            const data = await resp.json();
            if (data.status === 'success') {
                const deleted = auditLogType === 'operation'
                    ? Number(data.deleted_operation || 0)
                    : Number(data.deleted_access || 0);
                const msg = '已清理「' + typeLabel + '」共 ' + deleted + ' 条';
                if (window.showAppToast) window.showAppToast(msg, false);
                else alert(msg);
                loadAuditLogs(1);
            } else if (window.showAppToast) {
                window.showAppToast(data.message || '清理失败', true);
            } else {
                alert(data.message || '清理失败');
            }
        } catch (err) {
            if (window.showAppToast) window.showAppToast('清理失败：网络错误', true);
            else alert('清理失败：网络错误');
        }
    }

    function bindAuditLogEvents() {
        bindAuditLogTypeSegment();
        const searchBtn = document.getElementById('auditSearchBtn');
        if (searchBtn) searchBtn.addEventListener('click', () => loadAuditLogs(1));
        const cleanupBtn = document.getElementById('auditCleanupBtn');
        if (cleanupBtn) cleanupBtn.addEventListener('click', cleanupAuditLogs);
        const qInput = document.getElementById('auditSearchQ');
        if (qInput) qInput.addEventListener('keydown', e => { if (e.key === 'Enter') loadAuditLogs(1); });
    }

    function bootAuditLogPage() {
        fetch('/api/auth?action=current', { credentials: 'include' })
            .then(r => r.json())
            .then(data => {
                if (data.status !== 'success') {
                    window.location.href = '/login';
                    return;
                }
                currentUser = data;
                if (!canViewAuditLogs()) {
                    window.location.href = '/';
                    return;
                }
                bindAuditLogEvents();
                ensureAuditManagedTableReady();
                window.requestAnimationFrame(() => {
                    initAuditManagedTable();
                    loadAuditLogs(1);
                });
            })
            .catch(() => { window.location.href = '/login'; });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bootAuditLogPage);
    } else {
        bootAuditLogPage();
    }
})();
