(function (global) {
    'use strict';

    function parseNumber(value) {
        if (value === null || value === undefined) return null;
        const text = String(value).trim();
        if (!text) return null;
        const num = Number(text);
        return Number.isFinite(num) ? num : null;
    }

    function ceilingPositiveInt(value) {
        const v = parseNumber(value);
        if (v === null || v <= 0) return null;
        return Math.ceil(v - 1e-9);
    }

    function sortedCeiledDims(lengthIn, widthIn, heightIn) {
        const a = ceilingPositiveInt(lengthIn);
        const b = ceilingPositiveInt(widthIn);
        const c = ceilingPositiveInt(heightIn);
        if (a === null || b === null || c === null) return null;
        const arr = [a, b, c].sort(function (x, y) { return x - y; });
        return { S: arr[0], M: arr[1], L: arr[2], raw: { a: a, b: b, c: c } };
    }

    /** 与后端 _order_product_classify_fedex_package 一致 */
    function classifyPackage(lengthIn, widthIn, heightIn, grossLbs) {
        const dims = sortedCeiledDims(lengthIn, widthIn, heightIn);
        const wInt = ceilingPositiveInt(grossLbs);
        if (!dims || wInt === null) return null;
        const S = dims.S;
        const M = dims.M;
        const L = dims.L;
        const G = (S + M) * 2 + L;
        const V = S * M * L;
        const W = wInt;
        if (W > 150 || L > 108 || G > 165) return 'LTL';
        if (L > 96 || G > 130 || V > 17280 || W > 110) return 'Oversize';
        if (V > 10368 || L > 48 || M > 30 || G > 105) return 'AHS-D';
        if (W >= 50) return 'AHS';
        return '小件';
    }

    function fmtNum(n) {
        if (n === null || n === undefined || n === '') return '—';
        return String(n);
    }

    function fmtRaw(n) {
        const v = parseNumber(n);
        if (v === null) return '—';
        return String(v);
    }

    function condLine(label, expr, hit) {
        return {
            label: label,
            expr: expr,
            hit: !!hit,
            text: expr + ' → ' + (hit ? '满足' : '不满足')
        };
    }

    function explainPackageClass(lengthIn, widthIn, heightIn, grossLbs) {
        const rawLen = parseNumber(lengthIn);
        const rawWid = parseNumber(widthIn);
        const rawHei = parseNumber(heightIn);
        const rawGross = parseNumber(grossLbs);

        if (rawLen === null || rawWid === null || rawHei === null || rawGross === null) {
            return {
                ok: false,
                message: '请填写包裹长、宽、高（inch）与毛重（lbs），且均为正数。'
            };
        }
        if (rawLen <= 0 || rawWid <= 0 || rawHei <= 0 || rawGross <= 0) {
            return {
                ok: false,
                message: '包裹三边与毛重须大于 0。'
            };
        }

        const ceiledA = ceilingPositiveInt(rawLen);
        const ceiledB = ceilingPositiveInt(rawWid);
        const ceiledC = ceilingPositiveInt(rawHei);
        const dims = sortedCeiledDims(rawLen, rawWid, rawHei);
        const W = ceilingPositiveInt(rawGross);
        if (!dims || W === null) {
            return { ok: false, message: '无法计算，请检查输入。' };
        }

        const S = dims.S;
        const M = dims.M;
        const L = dims.L;
        const G = (S + M) * 2 + L;
        const V = S * M * L;
        const result = classifyPackage(rawLen, rawWid, rawHei, rawGross);

        const prepSteps = [
            {
                title: '三边向上取整',
                lines: [
                    '最长边 L = ceil(' + fmtRaw(rawLen) + ') = ' + ceiledA + '，ceil(' + fmtRaw(rawWid) + ') = ' + ceiledB + '，ceil(' + fmtRaw(rawHei) + ') = ' + ceiledC
                ]
            },
            {
                title: '排序（长≥宽≥高）',
                lines: ['长 L = ' + L + ' in，宽 M = ' + M + ' in，高 S = ' + S + ' in']
            },
            {
                title: '毛重向上取整',
                lines: ['W = ceil(' + fmtRaw(rawGross) + ') = ' + W + ' lb']
            },
            {
                title: '围长 G',
                lines: [
                    'G = 长 + (宽+高)×2 = ' + L + ' + (' + M + '+' + S + ')×2 = ' + L + ' + ' + (2 * (M + S)) + ' = ' + G + ' in'
                ]
            },
            {
                title: '体积 V',
                lines: ['V = S×M×L = ' + S + '×' + M + '×' + L + ' = ' + V + ' 立方英寸']
            }
        ];

        const ltlConds = [
            condLine('W > 150', 'W=' + W + ' > 150', W > 150),
            condLine('L > 108', 'L=' + L + ' > 108', L > 108),
            condLine('围长 > 165', '围长=' + G + ' > 165', G > 165)
        ];
        const oversizeConds = [
            condLine('L > 96', 'L=' + L + ' > 96', L > 96),
            condLine('围长 > 130', '围长=' + G + ' > 130', G > 130),
            condLine('V > 17280', 'V=' + V + ' > 17280', V > 17280),
            condLine('W > 110', 'W=' + W + ' > 110', W > 110)
        ];
        const ahsDConds = [
            condLine('V > 10368', 'V=' + V + ' > 10368', V > 10368),
            condLine('L > 48', 'L=' + L + ' > 48', L > 48),
            condLine('M > 30', 'M=' + M + ' > 30', M > 30),
            condLine('围长 > 105', '围长=' + G + ' > 105', G > 105)
        ];
        const ahsConds = [
            condLine('W ≥ 50', 'W=' + W + ' ≥ 50', W >= 50)
        ];

        const ruleSteps = [];
        const ltlHit = ltlConds.some(function (c) { return c.hit; });
        ruleSteps.push({
            title: '1) LTL（超出小件承运上限）',
            subtitle: '任一满足即命中：W>150 或 L>108 或 围长>165',
            conditions: ltlConds,
            matched: ltlHit,
            resultIfMatch: 'LTL'
        });

        if (!ltlHit) {
            const osHit = oversizeConds.some(function (c) { return c.hit; });
            ruleSteps.push({
                title: '2) Oversize（大件费 / Large-Oversize）',
                subtitle: '任一满足即命中：L>96 或 围长>130 或 V>17280 或 W>110',
                conditions: oversizeConds,
                matched: osHit,
                resultIfMatch: 'Oversize'
            });
            if (!osHit) {
                const ahsDHit = ahsDConds.some(function (c) { return c.hit; });
                ruleSteps.push({
                    title: '3) AHS-D（附加操作·尺寸类）',
                    subtitle: '任一满足即命中：V>10368 或 L>48 或 M>30 或 围长>105（FedEx AHS-Dimension）',
                    conditions: ahsDConds,
                    matched: ahsDHit,
                    resultIfMatch: 'AHS-D'
                });
                if (!ahsDHit) {
                    const ahsHit = ahsConds.some(function (c) { return c.hit; });
                    ruleSteps.push({
                        title: '4) AHS（附加操作·重量类）',
                        subtitle: 'W ≥ 50 且无上述尺寸类情形',
                        conditions: ahsConds,
                        matched: ahsHit,
                        resultIfMatch: 'AHS'
                    });
                    if (!ahsHit) {
                        ruleSteps.push({
                            title: '5) 小件',
                            subtitle: '未命中以上任一规则',
                            conditions: [],
                            matched: true,
                            resultIfMatch: '小件'
                        });
                    }
                }
            }
        }

        return {
            ok: true,
            result: result,
            metrics: {
                raw_length_in: rawLen,
                raw_width_in: rawWid,
                raw_height_in: rawHei,
                raw_gross_lbs: rawGross,
                S: S,
                M: M,
                L: L,
                W: W,
                G: G,
                V: V
            },
            prepSteps: prepSteps,
            ruleSteps: ruleSteps
        };
    }

    function escapeHtml(text) {
        return String(text == null ? '' : text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderExplainHtml(explain, options) {
        options = options || {};
        if (!explain || !explain.ok) {
            return '<p class="pkg-class-explain-error">' + escapeHtml((explain && explain.message) || '无法计算') + '</p>';
        }
        const skuLine = options.sku
            ? '<p class="pkg-class-explain-sku">SKU：<strong>' + escapeHtml(options.sku) + '</strong></p>'
            : '';
        let html = skuLine;
        html += '<div class="pkg-class-explain-result">归类结果：<strong class="pkg-class-explain-badge">' + escapeHtml(explain.result) + '</strong></div>';
        html += '<div class="pkg-class-explain-section"><h4>中间量</h4><table class="pkg-class-metrics-table"><tbody>';
        html += '<tr><th>长 L</th><td>' + explain.metrics.L + ' in</td><th>宽 M</th><td>' + explain.metrics.M + ' in</td></tr>';
        html += '<tr><th>高 S</th><td>' + explain.metrics.S + ' in</td><th>毛重 W</th><td>' + explain.metrics.W + ' lb</td></tr>';
        html += '<tr><th>围长 G</th><td>' + explain.metrics.G + ' in</td><th>体积 V</th><td>' + explain.metrics.V + ' cu in</td></tr>';
        html += '</tbody></table></div>';

        html += '<div class="pkg-class-explain-section"><h4>计算过程</h4><ol class="pkg-class-prep-steps">';
        explain.prepSteps.forEach(function (step) {
            html += '<li><strong>' + escapeHtml(step.title) + '</strong>';
            step.lines.forEach(function (line) {
                html += '<div class="pkg-class-step-line">' + escapeHtml(line) + '</div>';
            });
            html += '</li>';
        });
        html += '</ol></div>';

        html += '<div class="pkg-class-explain-section"><h4>判定顺序</h4><ol class="pkg-class-rule-steps">';
        explain.ruleSteps.forEach(function (step) {
            const cls = step.matched ? ' is-matched' : ' is-skipped';
            html += '<li class="pkg-class-rule-step' + cls + '">';
            html += '<div class="pkg-class-rule-head"><strong>' + escapeHtml(step.title) + '</strong>';
            if (step.matched) {
                html += ' <span class="pkg-class-rule-hit">→ ' + escapeHtml(step.resultIfMatch) + '</span>';
            }
            html += '</div>';
            if (step.subtitle) {
                html += '<div class="pkg-class-rule-sub">' + escapeHtml(step.subtitle) + '</div>';
            }
            if (step.conditions && step.conditions.length) {
                html += '<ul class="pkg-class-conds">';
                step.conditions.forEach(function (c) {
                    html += '<li class="' + (c.hit ? 'is-hit' : 'is-miss') + '">' + escapeHtml(c.text) + '</li>';
                });
                html += '</ul>';
            }
            html += '</li>';
        });
        html += '</ol></div>';
        html += '<p class="pkg-class-footnote">三边与毛重均向上取整后判定；实际计费以承运商当期价表为准。</p>';
        return html;
    }

    function getModalEl() {
        return document.getElementById('packageClassCalcModal');
    }

    function closePackageClassModal() {
        const m = getModalEl();
        if (m) m.classList.remove('active');
    }

    function runPackageClassCalcFromForm() {
        const lenEl = document.getElementById('pkgClassCalcLength');
        const widEl = document.getElementById('pkgClassCalcWidth');
        const heiEl = document.getElementById('pkgClassCalcHeight');
        const gwEl = document.getElementById('pkgClassCalcGross');
        const outEl = document.getElementById('packageClassCalcResult');
        if (!lenEl || !widEl || !heiEl || !gwEl || !outEl) return;
        const explain = explainPackageClass(lenEl.value, widEl.value, heiEl.value, gwEl.value);
        outEl.innerHTML = renderExplainHtml(explain);
    }

    function openPackageClassCalculatorModal(initial) {
        const m = getModalEl();
        if (!m) return;
        initial = initial || {};
        const formWrap = document.getElementById('packageClassCalcForm');
        const titleEl = document.getElementById('packageClassCalcTitle');
        if (titleEl) titleEl.textContent = '包裹归类计算器';
        if (formWrap) formWrap.style.display = '';
        const lenEl = document.getElementById('pkgClassCalcLength');
        const widEl = document.getElementById('pkgClassCalcWidth');
        const heiEl = document.getElementById('pkgClassCalcHeight');
        const gwEl = document.getElementById('pkgClassCalcGross');
        const outEl = document.getElementById('packageClassCalcResult');
        if (lenEl) lenEl.value = initial.length != null ? String(initial.length) : '';
        if (widEl) widEl.value = initial.width != null ? String(initial.width) : '';
        if (heiEl) heiEl.value = initial.height != null ? String(initial.height) : '';
        if (gwEl) gwEl.value = initial.gross != null ? String(initial.gross) : '';
        if (outEl) outEl.innerHTML = '';
        m.classList.add('active');
        const hasAll = lenEl && widEl && heiEl && gwEl
            && String(lenEl.value).trim() && String(widEl.value).trim()
            && String(heiEl.value).trim() && String(gwEl.value).trim();
        if (hasAll) runPackageClassCalcFromForm();
        if (lenEl) lenEl.focus();
    }

    function openPackageClassExplainModal(params) {
        const m = getModalEl();
        if (!m) return;
        params = params || {};
        const formWrap = document.getElementById('packageClassCalcForm');
        const titleEl = document.getElementById('packageClassCalcTitle');
        const outEl = document.getElementById('packageClassCalcResult');
        if (titleEl) {
            titleEl.textContent = params.sku
                ? ('包裹归类 · ' + String(params.sku))
                : '包裹归类计算逻辑';
        }
        if (formWrap) formWrap.style.display = 'none';
        const explain = explainPackageClass(params.length, params.width, params.height, params.gross);
        if (outEl) {
            outEl.innerHTML = renderExplainHtml(explain);
        }
        m.classList.add('active');
    }

    function bindPackageClassModal() {
        const m = getModalEl();
        if (!m || m.dataset.pkgClassBound === '1') return;
        m.dataset.pkgClassBound = '1';
        const calcBtn = document.getElementById('pkgClassCalcSubmitBtn');
        if (calcBtn) calcBtn.addEventListener('click', runPackageClassCalcFromForm);
        const closeBtn = document.getElementById('packageClassCalcCloseBtn');
        if (closeBtn) closeBtn.addEventListener('click', closePackageClassModal);
        if (typeof window.bindPmModalBackdropClose === 'function') {
            window.bindPmModalBackdropClose(m, closePackageClassModal);
        } else {
            m.addEventListener('click', function (e) {
                if (e.target === m) closePackageClassModal();
            });
        }
        ['pkgClassCalcLength', 'pkgClassCalcWidth', 'pkgClassCalcHeight', 'pkgClassCalcGross'].forEach(function (id) {
            const el = document.getElementById(id);
            if (!el) return;
            el.addEventListener('keydown', function (e) {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    runPackageClassCalcFromForm();
                }
            });
        });
    }

    global.SitjoyPackageClass = {
        parseNumber: parseNumber,
        ceilingPositiveInt: ceilingPositiveInt,
        sortedCeiledDims: sortedCeiledDims,
        classifyPackage: classifyPackage,
        explainPackageClass: explainPackageClass,
        renderExplainHtml: renderExplainHtml,
        openPackageClassCalculatorModal: openPackageClassCalculatorModal,
        openPackageClassExplainModal: openPackageClassExplainModal,
        closePackageClassModal: closePackageClassModal,
        bindPackageClassModal: bindPackageClassModal,
        runPackageClassCalcFromForm: runPackageClassCalcFromForm
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', bindPackageClassModal);
    } else {
        bindPackageClassModal();
    }
}(typeof window !== 'undefined' ? window : this));
