/**
 * 全局左下角：多选表格数字单元格时显示求和、均值。
 * 监听 sitjoy:grid-selection-change（header.js 托管表、销量预测等页面派发）。
 */
(function(global) {
    'use strict';

    const PANEL_ID = 'sitjoyCellSelectionStats';
    const MIN_NUMERIC_CELLS = 2;

    function extractPlainTextFromCell(td, customExtract) {
        if (!td) return '';
        if (typeof customExtract === 'function') {
            try { return String(customExtract(td) || '').trim(); } catch (_) { return ''; }
        }
        const explicit = String(td.getAttribute('data-export-value') || td.dataset.exportValue || '').trim();
        if (explicit) return explicit;
        const inp = td.querySelector('input:not([type="checkbox"]):not([type="hidden"]), textarea');
        if (inp) return String(inp.value != null ? inp.value : '').trim();
        const numInner = td.querySelector('.sf-cell-num-text, .sf-inv-cell-inner');
        if (numInner) return String(numInner.textContent || '').replace(/\s+/g, ' ').trim();
        return String(td.innerText || td.textContent || '')
            .replace(/\r/g, '')
            .replace(/\n+/g, ' ')
            .replace(/\s+/g, ' ')
            .trim();
    }

    function parseNumericFromText(raw) {
        let s = String(raw == null ? '' : raw).trim();
        if (!s || s === '—' || s === '-' || s === '–') return null;
        if (/∞/.test(s)) return null;
        const pct = s.endsWith('%');
        if (pct) s = s.slice(0, -1).trim();
        s = s.replace(/,/g, '').replace(/\s/g, '');
        if (!s || !/^-?\d+(\.\d+)?$/.test(s)) return null;
        const n = Number(s);
        return Number.isFinite(n) ? n : null;
    }

    function formatStatNumber(value, opts) {
        const n = Number(value);
        if (!Number.isFinite(n)) return '—';
        const o = opts || {};
        const asAvg = !!o.asAvg;
        const allInt = !!o.allInt && !asAvg;
        if (asAvg) {
            const abs = Math.abs(n);
            const maxFrac = abs >= 1000 ? 0 : (abs >= 100 ? 1 : 2);
            return n.toLocaleString('zh-CN', { maximumFractionDigits: maxFrac, minimumFractionDigits: 0 });
        }
        return n.toLocaleString('zh-CN', {
            maximumFractionDigits: allInt ? 0 : 2,
            minimumFractionDigits: 0,
        });
    }

    function ensurePanel() {
        let panel = document.getElementById(PANEL_ID);
        if (panel) return panel;
        panel = document.createElement('div');
        panel.id = PANEL_ID;
        panel.className = 'sj-cell-stats-panel';
        panel.setAttribute('role', 'status');
        panel.setAttribute('aria-live', 'polite');
        panel.hidden = true;
        panel.innerHTML =
            '<div class="sj-cell-stats-head">'
            + '<span class="sj-cell-stats-title">选区统计</span>'
            + '<span class="sj-cell-stats-sub" data-sj-stats-count></span>'
            + '</div>'
            + '<div class="sj-cell-stats-body">'
            + '<div class="sj-cell-stats-row"><span class="sj-cell-stats-label">求和</span>'
            + '<strong class="sj-cell-stats-value" data-sj-stats-sum>—</strong></div>'
            + '<div class="sj-cell-stats-row"><span class="sj-cell-stats-label">均值</span>'
            + '<strong class="sj-cell-stats-value" data-sj-stats-avg>—</strong></div>'
            + '</div>';
        document.body.appendChild(panel);
        return panel;
    }

    function applySelectionDetail(detail) {
        const panel = ensurePanel();
        const cells = (detail && detail.cells) ? detail.cells.filter(Boolean) : [];
        const extractFn = detail && detail.extractCellText;
        const values = [];
        cells.forEach((td) => {
            const text = extractPlainTextFromCell(td, extractFn);
            const n = parseNumericFromText(text);
            if (n !== null) values.push(n);
        });

        if (values.length < MIN_NUMERIC_CELLS) {
            panel.hidden = true;
            return;
        }

        const sum = values.reduce((acc, v) => acc + v, 0);
        const avg = sum / values.length;
        const allInt = values.every((v) => Number.isInteger(v));
        const countEl = panel.querySelector('[data-sj-stats-count]');
        const sumEl = panel.querySelector('[data-sj-stats-sum]');
        const avgEl = panel.querySelector('[data-sj-stats-avg]');
        const selTotal = cells.length;
        const numTotal = values.length;
        if (countEl) {
            countEl.textContent = selTotal === numTotal
                ? `${numTotal} 个数字`
                : `${numTotal} 个数字 / 已选 ${selTotal} 格`;
        }
        if (sumEl) {
            sumEl.textContent = formatStatNumber(sum, { allInt });
            sumEl.title = String(sum);
        }
        if (avgEl) {
            avgEl.textContent = formatStatNumber(avg, { asAvg: true });
            avgEl.title = String(avg);
        }
        panel.hidden = false;
    }

    function onSelectionChange(ev) {
        applySelectionDetail(ev && ev.detail ? ev.detail : {});
    }

    document.addEventListener('sitjoy:grid-selection-change', onSelectionChange);

    global.SitjoyCellSelectionStats = {
        apply: applySelectionDetail,
        parseNumericFromText,
        extractPlainTextFromCell,
    };

    if (global.__sitjoyPendingGridSelection) {
        applySelectionDetail(global.__sitjoyPendingGridSelection);
    }
})();
