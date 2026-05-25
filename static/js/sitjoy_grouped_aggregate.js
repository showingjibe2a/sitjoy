/**
 * 汇总分组表格：组行折叠点击、托管表头下的「组内排序」（拦截全局列排序）、表头一键展开/收起。
 * 依赖 header.js 提供的 window.SitjoyManagedPmTable.resolveBodyTableFromHeaderTh（可选）。
 */
(function(global) {
    'use strict';

    function resolveBodyTableForHeaderTh(th, wantTable) {
        if (!th || !wantTable) return null;
        if (global.SitjoyManagedPmTable && typeof global.SitjoyManagedPmTable.resolveBodyTableFromHeaderTh === 'function') {
            const resolved = global.SitjoyManagedPmTable.resolveBodyTableFromHeaderTh(th);
            if (resolved === wantTable) return wantTable;
        }
        const host = th.closest && th.closest('table');
        if (host && host === wantTable) return wantTable;
        return null;
    }

    /**
     * @param {object} opts
     * @param {string|HTMLTableElement} opts.bodyTable — 主表（tbody 所在 table）
     * @param {() => boolean} opts.isAggregateMode
     * @param {() => object} opts.getSortState — { key, dir }
     * @param {(next: object) => void} opts.setSortState
     * @param {() => void} opts.onAfterSortChange
     * @param {boolean} [opts.ignoreColumnFilterClicks]
     */
    function bindDocumentAggregateGroupSort(opts) {
        const bodyTable = typeof opts.bodyTable === 'string'
            ? document.querySelector(opts.bodyTable)
            : opts.bodyTable;
        if (!bodyTable) return;
        const mark = `sjDocAggSort_${String(bodyTable.id || bodyTable.getAttribute('data-manage-key') || 'table').replace(/[^a-zA-Z0-9_\-]/g, '_')}`;
        if (document.body.dataset[mark] === '1') return;
        document.body.dataset[mark] = '1';

        document.addEventListener('click', function(e) {
            if (typeof opts.isAggregateMode === 'function' && !opts.isAggregateMode()) return;
            if (opts.ignoreColumnFilterClicks !== false && e.target && e.target.closest && e.target.closest('.pm-column-filter-btn')) return;
            const th = e.target && e.target.closest ? e.target.closest('th[data-sort-key]') : null;
            if (!th) return;
            if (!resolveBodyTableForHeaderTh(th, bodyTable)) return;

            e.preventDefault();
            e.stopPropagation();
            if (typeof e.stopImmediatePropagation === 'function') e.stopImmediatePropagation();

            const key = String(th.getAttribute('data-sort-key') || '').trim();
            if (!key) return;
            const sort = typeof opts.getSortState === 'function' ? opts.getSortState() : null;
            if (!sort || typeof sort !== 'object') return;
            if (sort.key === key) {
                sort.dir = sort.dir === 'asc' ? 'desc' : 'asc';
            } else {
                sort.key = key;
                sort.dir = 'asc';
            }
            if (typeof opts.setSortState === 'function') opts.setSortState(sort);
            if (typeof opts.onAfterSortChange === 'function') opts.onAfterSortChange();
        }, true);
    }

    /**
     * @param {object} opts
     * @param {HTMLTableSectionElement} opts.tbody
     * @param {string} opts.groupRowSelector — e.g. 'tr.wip-group-row[data-group-key]'
     * @param {() => Set<string>} opts.getCollapsedSet
     * @param {() => void} opts.onAfterToggle
     */
    function bindGroupRowToggle(opts) {
        const tbody = opts.tbody;
        if (!tbody || tbody.dataset.sjGroupRowToggleBound === '1') return;
        tbody.dataset.sjGroupRowToggleBound = '1';
        const sel = String(opts.groupRowSelector || '').trim();
        if (!sel) return;

        tbody.addEventListener('click', function(e) {
            if (e.target && e.target.closest && e.target.closest('input, button, a, label, .pm-column-filter-btn')) return;
            const row = e.target && e.target.closest ? e.target.closest(sel) : null;
            if (!row) return;
            const key = String(row.dataset.groupKey || '').trim();
            if (!key) return;
            const set = typeof opts.getCollapsedSet === 'function' ? opts.getCollapsedSet() : null;
            if (!set || typeof set.has !== 'function') return;
            if (set.has(key)) set.delete(key);
            else set.add(key);
            if (typeof opts.onAfterToggle === 'function') opts.onAfterToggle();
        });
    }

    /**
     * 表头「全部展开/收起」：须在托管表头所在的外层（如 .sj-wip-table-host）上委托，克隆表头不在主 table 内。
     * @param {object} opts
     * @param {HTMLElement} [opts.scopeEl] — 默认取 opts.table 的 .sj-wip-table-host / .sj-sales-table-host 祖先
     * @param {HTMLTableElement} opts.table — 主表，用于推导 scope
     * @param {() => boolean} opts.isAggregateMode
     * @param {() => void} opts.onToggle — 单击三角时调用（内部自行判断当前应全展或全收）
     * @param {string} [opts.toggleSelector]
     */
    function bindAggregateHeaderExpandCollapse(opts) {
        const table = opts.table;
        const scope = opts.scopeEl
            || (table && table.closest && (table.closest('.sj-wip-table-host') || table.closest('.sj-sales-table-host')))
            || table;
        if (!scope || scope.dataset.sjAggToggleScopeBound === '1') return;
        scope.dataset.sjAggToggleScopeBound = '1';
        const sel = String(opts.toggleSelector || '[data-sj-agg-all-toggle]');

        scope.addEventListener('click', function(e) {
            const btn = e.target && e.target.closest ? e.target.closest(sel) : null;
            if (!btn) return;
            if (typeof opts.isAggregateMode === 'function' && !opts.isAggregateMode()) return;
            e.preventDefault();
            e.stopPropagation();
            if (typeof opts.onToggle === 'function') opts.onToggle();
        });
    }

    /**
     * 汇总分组父行（托管表筛选/分页须排除，筛选后须同步显隐）。
     * 约定：class 含 `-group-row`、`group-row`，或 `perf-group-parent-row`。
     */
    function isGroupRow(row) {
        if (!row || !row.classList) return false;
        if (row.classList.contains('perf-group-parent-row')) return true;
        if (row.classList.contains('group-row')) return true;
        for (let i = 0; i < row.classList.length; i++) {
            const cls = row.classList[i];
            if (cls && cls.endsWith('-group-row')) return true;
        }
        return false;
    }

    function isAggregateChildRowVisible(row) {
        if (!row) return false;
        if (String(row.dataset.pmFilterHidden || '0') === '1') return false;
        if (row.style && row.style.display === 'none') return false;
        if (row.classList) {
            for (let i = 0; i < row.classList.length; i++) {
                const cls = row.classList[i];
                if (cls && cls.endsWith('-row-hidden')) return false;
            }
        }
        return true;
    }

    function tableHasGroupRows(tbody) {
        if (!tbody || !tbody.rows) return false;
        return Array.from(tbody.rows).some((row) => isGroupRow(row));
    }

    /**
     * 托管表列筛选 / 分页后：按子行可见性同步父组行，恢复展开三角与组头显示。
     * @param {object} state — header.js managedTableState（需含 table、tbody）
     */
    function syncManagedTableGroupRows(state) {
        const tbody = state && (state.tbody || (state.table && state.table.tBodies && state.table.tBodies[0]));
        if (!tbody || !tableHasGroupRows(tbody)) return;

        const bodyRows = Array.from(tbody.rows || []);
        let i = 0;
        while (i < bodyRows.length) {
            const row = bodyRows[i];
            if (!isGroupRow(row)) {
                i++;
                continue;
            }
            const children = [];
            let j = i + 1;
            while (j < bodyRows.length && !isGroupRow(bodyRows[j])) {
                children.push(bodyRows[j]);
                j++;
            }
            const anyVisible = children.some((child) => isAggregateChildRowVisible(child));
            row.style.display = anyVisible ? '' : 'none';
            row.dataset.pmFilterHidden = anyVisible ? '0' : '1';
            i = j;
        }
    }

    global.SitjoyGroupedAggregate = {
        bindDocumentAggregateGroupSort,
        bindGroupRowToggle,
        bindAggregateHeaderExpandCollapse,
        isGroupRow,
        isAggregateChildRowVisible,
        tableHasGroupRows,
        syncManagedTableGroupRows
    };
})(typeof window !== 'undefined' ? window : this);
