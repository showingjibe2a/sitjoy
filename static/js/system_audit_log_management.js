/** 系统审计日志 */
(function () {
    let currentUser = null;
    let auditLogType = 'access';
    let auditLogPage = 1;
    let auditLogTotal = 0;
    const auditLogPageSize = 50;

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
        return escapeHtml(summary).replace(/\n/g, '<br>');
    }

    function renderAuditLogTableHead() {
        const head = document.getElementById('auditLogTableHead');
        if (!head) return;
        if (auditLogType === 'access') {
            head.innerHTML = '<tr><th>时间</th><th>账号</th><th>姓名</th><th>页面路径</th><th>页面</th><th>IP</th></tr>';
        } else {
            head.innerHTML = '<tr><th>时间</th><th>账号</th><th>姓名</th><th>方法</th><th>API</th><th>模块</th><th>摘要</th><th>IP</th></tr>';
        }
    }

    async function loadAuditLogs(page = 1) {
        if (!canViewAuditLogs()) return;
        auditLogPage = Math.max(1, page);
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
        const hint = document.getElementById('auditLogHint');
        if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;">加载中…</td></tr>';
        renderAuditLogTableHead();

        try {
            const resp = await fetch('/api/audit-log?' + params.toString(), { credentials: 'include' });
            const data = await resp.json();
            if (data.status !== 'success') {
                if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#a33;">' + escapeHtml(data.message || '加载失败') + '</td></tr>';
                return;
            }
            auditLogTotal = Number(data.total || 0);
            const items = data.items || [];
            const colSpan = auditLogType === 'access' ? 6 : 8;
            if (!items.length) {
                if (tbody) tbody.innerHTML = '<tr><td colspan="' + colSpan + '" style="text-align:center;">暂无记录</td></tr>';
            } else if (auditLogType === 'access') {
                tbody.innerHTML = items.map(row => `
                    <tr>
                        <td>${escapeHtml(formatAuditDateTime(row.created_at))}</td>
                        <td>${escapeHtml(row.username || '')}</td>
                        <td>${escapeHtml(row.user_name || '')}</td>
                        <td>${escapeHtml(row.page_path || '')}</td>
                        <td>${escapeHtml(row.page_label || row.page_key || '')}</td>
                        <td>${escapeHtml(row.client_ip || '')}</td>
                    </tr>
                `).join('');
            } else {
                tbody.innerHTML = items.map(row => `
                    <tr>
                        <td>${escapeHtml(formatAuditDateTime(row.created_at))}</td>
                        <td>${escapeHtml(row.username || '')}</td>
                        <td>${escapeHtml(row.user_name || '')}</td>
                        <td>${escapeHtml(row.http_method || '')}</td>
                        <td>${escapeHtml(row.api_path || '')}</td>
                        <td>${escapeHtml(moduleLabel(row))}</td>
                        <td class="audit-log-summary-cell">${renderOperationSummaryHtml(row)}</td>
                        <td>${escapeHtml(row.client_ip || '')}</td>
                    </tr>
                `).join('');
            }
            const totalPages = Math.max(1, Math.ceil(auditLogTotal / auditLogPageSize));
            if (hint) {
                hint.textContent = (auditLogType === 'access' ? '页面访问' : '操作记录')
                    + '：共 ' + auditLogTotal + ' 条，第 ' + auditLogPage + ' / ' + totalPages + ' 页';
            }
            const pageInfo = document.getElementById('auditPageInfo');
            if (pageInfo) pageInfo.textContent = '第 ' + auditLogPage + ' / ' + totalPages + ' 页';
            const prevBtn = document.getElementById('auditPrevBtn');
            const nextBtn = document.getElementById('auditNextBtn');
            if (prevBtn) prevBtn.disabled = auditLogPage <= 1;
            if (nextBtn) nextBtn.disabled = auditLogPage >= totalPages;
        } catch (err) {
            if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#a33;">网络错误</td></tr>';
        }
    }

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
        const keepDaysRaw = prompt('保留最近多少天的日志？（默认 90，将删除更早的记录）', '90');
        if (keepDaysRaw === null) return;
        const keepDays = Math.max(1, Math.min(3650, parseInt(String(keepDaysRaw).trim(), 10) || 90));
        const typeLabel = auditLogType === 'operation' ? '操作记录' : '页面访问';
        const ok = window.showAppConfirmAsync
            ? await window.showAppConfirmAsync({
                title: '清理审计日志',
                message: '将删除「' + typeLabel + '」中早于 ' + keepDays + ' 天的记录，是否继续？',
                confirmText: '确认清理',
            })
            : confirm('将删除早于 ' + keepDays + ' 天的「' + typeLabel + '」，是否继续？');
        if (!ok) return;
        try {
            const resp = await fetch('/api/audit-log?action=cleanup', {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: auditLogType, keep_days: keepDays }),
            });
            const data = await resp.json();
            if (data.status === 'success') {
                alert('已清理：访问 ' + (data.deleted_access || 0) + ' 条，操作 ' + (data.deleted_operation || 0) + ' 条');
                loadAuditLogs(1);
            } else {
                alert(data.message || '清理失败');
            }
        } catch (err) {
            alert('清理失败：网络错误');
        }
    }

    function bindAuditLogEvents() {
        bindAuditLogTypeSegment();
        const searchBtn = document.getElementById('auditSearchBtn');
        if (searchBtn) searchBtn.addEventListener('click', () => loadAuditLogs(1));
        const prevBtn = document.getElementById('auditPrevBtn');
        if (prevBtn) prevBtn.addEventListener('click', () => { if (auditLogPage > 1) loadAuditLogs(auditLogPage - 1); });
        const nextBtn = document.getElementById('auditNextBtn');
        if (nextBtn) nextBtn.addEventListener('click', () => loadAuditLogs(auditLogPage + 1));
        const cleanupBtn = document.getElementById('auditCleanupBtn');
        if (cleanupBtn) cleanupBtn.addEventListener('click', cleanupAuditLogs);
        const qInput = document.getElementById('auditSearchQ');
        if (qInput) qInput.addEventListener('keydown', e => { if (e.key === 'Enter') loadAuditLogs(1); });
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
                if (!canViewAuditLogs()) {
                    window.location.href = '/';
                    return;
                }
                bindAuditLogEvents();
                loadAuditLogs(1);
            })
            .catch(() => { window.location.href = '/login'; });
    });
})();
