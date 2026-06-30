/**
 * SitjoyPageUI — 全站页面 UI 统一入口（表格/下拉/状态分段/筛选条）。
 *
 * 依赖 header.js（SitjoyManagedPmTable、initUniversalSingleSelects 等）。
 * 新页面优先调用 SitjoyPageUI.init()，再写本页特有逻辑。
 *
 * @see static/css/STYLE_GUIDE.md
 */
(function (global) {
    'use strict';

    const OPTION_BAR = 'sj-option-bar';
    const OPTION_ADD = 'sj-option-add';
    const OPTION_RADIO = 'sj-option-radio';
    const OPTION_PILL = 'sj-option-pill';
    const STATUS_SEGMENT_BIND_SELECTOR = '.status-segment[data-sj-status-segment]';

    // -------------------------------------------------------------------------
    // DOM 与转义工具
    // -------------------------------------------------------------------------
    function el(root, selector) {
        const base = root && root.querySelector ? root : document;
        if (!selector) return null;
        if (typeof selector === 'string') return base.querySelector(selector);
        return selector;
    }

    function escapeHtml(text) {
        return String(text || '')
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    // -------------------------------------------------------------------------
    // 状态分段（status-segment）读写与绑定
    // -------------------------------------------------------------------------
    function getStatusSegmentValue(segment) {
        const seg = el(document, segment);
        if (!seg) return '';
        const fromData = String(seg.dataset.value || seg.getAttribute('data-value') || '').trim();
        if (fromData !== '') return fromData;
        const active = seg.querySelector('.status-pill.is-active');
        return active ? String(active.getAttribute('data-value') || '').trim() : '';
    }

    /** 写入 status-segment 并同步 pill 激活态 */
    function setStatusSegmentValue(segment, value) {
        const seg = el(document, segment);
        if (!seg) return;
        const val = String(value == null ? '' : value);
        seg.dataset.value = val;
        seg.setAttribute('data-value', val);
        seg.querySelectorAll('button[data-value], .status-pill[data-value]').forEach((btn) => {
            const active = String(btn.getAttribute('data-value') || '') === val;
            btn.classList.toggle('is-active', active);
        });
    }

    /**
     * 绑定 status-segment 点击；options.onChange(value, segmentEl)
     * segment 可为选择器或元素；segment 上可加 data-sj-status-segment 标记（仅文档用途）。
     */
    function bindStatusSegment(segment, options) {
        const seg = el(document, segment);
        if (!seg || seg.dataset.sjStatusBound === '1') return seg;
        if (!seg.classList.contains('status-segment')) return seg;
        const opts = options && typeof options === 'object' ? options : {};
        seg.dataset.sjStatusBound = '1';
        seg.querySelectorAll('button[data-value], .status-pill[data-value]').forEach((btn) => {
            btn.addEventListener('click', function () {
                const val = String(this.getAttribute('data-value') || '');
                setStatusSegmentValue(seg, val);
                if (typeof opts.onChange === 'function') opts.onChange(val, seg);
            });
        });
        return seg;
    }

    /** 批量绑定页面内 [data-sj-status-segment] 或传入选择器列表 */
    function bindStatusSegments(targets, options) {
        const list = [];
        if (Array.isArray(targets)) {
            targets.forEach((t) => list.push(el(document, t)));
        } else if (typeof targets === 'string') {
            document.querySelectorAll(targets).forEach((node) => list.push(node));
        } else {
            document.querySelectorAll(STATUS_SEGMENT_BIND_SELECTOR).forEach((node) => list.push(node));
        }
        list.filter(Boolean).forEach((seg) => bindStatusSegment(seg, options));
    }

    // -------------------------------------------------------------------------
    // 筛选条（sj-option-bar）
    // -------------------------------------------------------------------------
    /**
     * 渲染筛选/标签条（统一替代 material-type-bar / option-bar 手写逻辑）。
     *
     * config.mode: 'radio'（单选筛选，默认）| 'pill'（纯按钮，用于打开编辑）
     * config.items: [{ id, label, value?, raw? }]
     */
    function renderOptionBar(container, config) {
        const wrap = el(document, container);
        if (!wrap) return;
        const cfg = config && typeof config === 'object' ? config : {};
        const mode = cfg.mode === 'pill' ? 'pill' : 'radio';
        wrap.classList.add(OPTION_BAR, 'option-bar');
        wrap.innerHTML = '';

        if (cfg.showAdd !== false && typeof cfg.onAdd === 'function') {
            const addBtn = document.createElement('button');
            addBtn.type = 'button';
            addBtn.className = `${OPTION_ADD} option-add material-type-add`;
            addBtn.setAttribute('aria-label', cfg.addAriaLabel || '新增');
            addBtn.textContent = cfg.addLabel || '+';
            addBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                cfg.onAdd();
            });
            wrap.appendChild(addBtn);
        }

        const items = Array.isArray(cfg.items) ? cfg.items : [];
        const selected = cfg.selectedValue == null ? '' : String(cfg.selectedValue);

        if (mode === 'radio') {
            const radioName = cfg.radioName || `sjOptionBar_${wrap.id || 'filter'}`;
            if (cfg.showAll !== false) {
                const allLabel = document.createElement('label');
                allLabel.className = `${OPTION_RADIO} option-radio material-type-radio material-type-option sj-option-radio`;
                const allVal = cfg.allValue == null ? '' : String(cfg.allValue);
                allLabel.innerHTML = `<input type="radio" name="${escapeHtml(radioName)}" value="${escapeHtml(allVal)}"><span>${escapeHtml(cfg.allLabel || '全部')}</span>`;
                const allInput = allLabel.querySelector('input');
                if (selected === allVal) allInput.checked = true;
                allInput.addEventListener('click', () => {
                    if (typeof cfg.onSelect === 'function') cfg.onSelect(allVal, null);
                });
                wrap.appendChild(allLabel);
            }
            items.forEach((item) => {
                const value = item.value != null ? String(item.value) : String(item.id != null ? item.id : '');
                const label = document.createElement('label');
                label.className = `${OPTION_RADIO} option-radio material-type-radio material-type-option sj-option-radio`;
                label.innerHTML = `<input type="radio" name="${escapeHtml(radioName)}" value="${escapeHtml(value)}"><span>${escapeHtml(item.label || '')}</span>`;
                const input = label.querySelector('input');
                if (selected === value) input.checked = true;
                input.addEventListener('click', () => {
                    if (typeof cfg.onSelect === 'function') cfg.onSelect(value, item);
                });
                if (typeof cfg.onItemDblClick === 'function') {
                    label.addEventListener('dblclick', () => cfg.onItemDblClick(item));
                }
                if (typeof cfg.onItemMount === 'function') {
                    cfg.onItemMount(label, item, 'radio');
                }
                wrap.appendChild(label);
            });
            return;
        }

        items.forEach((item) => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = `${OPTION_PILL} option-pill material-type-pill`;
            btn.textContent = item.label || '';
            btn.addEventListener('click', () => {
                if (typeof cfg.onItemClick === 'function') cfg.onItemClick(item);
            });
            if (typeof cfg.onItemDblClick === 'function') {
                btn.addEventListener('dblclick', () => cfg.onItemDblClick(item));
            }
            wrap.appendChild(btn);
        });
    }

    // -------------------------------------------------------------------------
    // 下拉、表格与模态增强
    // -------------------------------------------------------------------------
    /** 增强本页所有原生 select（委托 header.js） */
    function enhanceSelects(root) {
        if (typeof global.initUniversalSingleSelects === 'function') {
            global.initUniversalSingleSelects(root || document);
        }
        if (typeof global.refreshAllUniversalSingleSelects === 'function') {
            global.refreshAllUniversalSingleSelects();
        }
    }

    /**
     * 托管表格增强；options 透传 SitjoyManagedPmTable.enhance 第二参数（若有）。
     * tables: 选择器 | 元素 | 数组
     */
    function enhanceTables(tables, options) {
        const MT = global.SitjoyManagedPmTable;
        if (!MT || typeof MT.enhance !== 'function') return;
        const list = [];
        if (!tables) {
            document.querySelectorAll('table.pm-table').forEach((t) => list.push(t));
        } else if (Array.isArray(tables)) {
            tables.forEach((t) => list.push(el(document, t)));
        } else {
            list.push(el(document, tables));
        }
        list.filter(Boolean).forEach((table) => {
            if (table.dataset.disableTableManage === '1') return;
            MT.enhance(table, options || {});
        });
    }

    /** 模态框点击遮罩关闭；依赖 header.js bindPmModalBackdropClose */
    function bindModalBackdrop(modal, onClose) {
        const node = el(document, modal);
        if (!node || typeof onClose !== 'function') return;
        const binder = global.bindPmModalBackdropClose;
        if (typeof binder === 'function') binder(node, onClose);
    }

    // -------------------------------------------------------------------------
    // 页面初始化入口 SitjoyPageUI.init
    // -------------------------------------------------------------------------
    /**
     * 标准页面初始化（在 DOMContentLoaded/load 中调用一次）。
     *
     * options:
     * - root: 根节点，默认 document
     * - selects: true | 选择器 — 增强下拉
     * - tables: true | 选择器 | 元素[] — 托管表
     * - statusSegments: 选择器[] | true（自动 [data-sj-status-segment]）
     * - modals: [{ el, onClose }]
     * - onReady: 回调（增强完成后）
     */
    function init(options) {
        const opts = options && typeof options === 'object' ? options : {};
        const root = opts.root || document;

        if (opts.selects) enhanceSelects(root);
        if (opts.statusSegments) {
            if (opts.statusSegments === true) bindStatusSegments();
            else bindStatusSegments(opts.statusSegments, opts.statusSegmentOptions);
        }
        if (opts.tables) {
            enhanceTables(opts.tables === true ? null : opts.tables, opts.tableOptions);
        }
        if (Array.isArray(opts.modals)) {
            opts.modals.forEach((m) => {
                if (m && m.el) bindModalBackdrop(m.el, m.onClose);
            });
        }
        if (typeof opts.onReady === 'function') opts.onReady();
    }

    const api = {
        OPTION_BAR,
        OPTION_ADD,
        OPTION_RADIO,
        OPTION_PILL,
        getStatusSegmentValue,
        setStatusSegmentValue,
        bindStatusSegment,
        bindStatusSegments,
        renderOptionBar,
        enhanceSelects,
        enhanceTables,
        bindModalBackdrop,
        init,
        /** @deprecated 使用 bindStatusSegment */
        bindSegmentButtons: bindStatusSegment,
    };

    global.SitjoyPageUI = api;
    document.dispatchEvent(new CustomEvent('sitjoy:page-ui-ready', { detail: api }));
})(typeof window !== 'undefined' ? window : globalThis);
