(function (global) {
    'use strict';

    // -------------------------------------------------------------------------
    // 公共：取整、排序、中间量
    // -------------------------------------------------------------------------
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

    function buildMetrics(rawLen, rawWid, rawHei, rawGross) {
        const ceiledA = ceilingPositiveInt(rawLen);
        const ceiledB = ceilingPositiveInt(rawWid);
        const ceiledC = ceilingPositiveInt(rawHei);
        const dims = sortedCeiledDims(rawLen, rawWid, rawHei);
        const W = ceilingPositiveInt(rawGross);
        if (!dims || W === null) return null;
        const S = dims.S;
        const M = dims.M;
        const L = dims.L;
        const G = (S + M) * 2;
        const LG = L + G;
        const V = S * M * L;
        return {
            raw_length_in: rawLen,
            raw_width_in: rawWid,
            raw_height_in: rawHei,
            raw_gross_lbs: rawGross,
            ceiledA: ceiledA,
            ceiledB: ceiledB,
            ceiledC: ceiledC,
            S: S,
            M: M,
            L: L,
            W: W,
            G: G,
            LG: LG,
            V: V
        };
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

    function buildPrepSteps(m) {
        return [
            {
                title: '三边向上取整',
                lines: [
                    'ceil(' + fmtRaw(m.raw_length_in) + ')=' + m.ceiledA
                        + '，ceil(' + fmtRaw(m.raw_width_in) + ')=' + m.ceiledB
                        + '，ceil(' + fmtRaw(m.raw_height_in) + ')=' + m.ceiledC
                ]
            },
            {
                title: '排序（长≥宽≥高）',
                lines: ['长 L=' + m.L + ' in，宽 M=' + m.M + ' in，高 S=' + m.S + ' in']
            },
            {
                title: '毛重向上取整',
                lines: ['W = ceil(' + fmtRaw(m.raw_gross_lbs) + ') = ' + m.W + ' lb']
            },
            {
                title: '围长 G 与 长+围长',
                lines: [
                    'G = (M+S)×2 = (' + m.M + '+' + m.S + ')×2 = ' + m.G + ' in',
                    'L+G = ' + m.L + '+' + m.G + ' = ' + m.LG + ' in'
                ]
            },
            {
                title: '体积 V',
                lines: ['V = S×M×L = ' + m.S + '×' + m.M + '×' + m.L + ' = ' + m.V + ' cu in']
            }
        ];
    }

    // -------------------------------------------------------------------------
    // FedEx（与后端 _order_product_classify_fedex_package 一致）
    // -------------------------------------------------------------------------
    function classifyFedex(S, M, L, W, V, G) {
        const LG = L + G;
        if (W > 150 || L > 108 || LG > 165) return 'LTL';
        if (L > 96 || LG > 130 || V > 17280 || W > 110) return 'Oversize';
        if (V > 10368 || L > 48 || M > 30 || LG > 105) return 'AHS-D';
        if (W >= 50) return 'AHS';
        return '小件';
    }

    /** @deprecated 别名，下单产品批量仍调用 */
    function classifyPackage(lengthIn, widthIn, heightIn, grossLbs) {
        const m = buildMetrics(
            parseNumber(lengthIn), parseNumber(widthIn), parseNumber(heightIn), parseNumber(grossLbs)
        );
        if (!m) return null;
        return classifyFedex(m.S, m.M, m.L, m.W, m.V, m.G);
    }

    function explainFedex(m) {
        const S = m.S;
        const M = m.M;
        const L = m.L;
        const W = m.W;
        const G = m.G;
        const LG = m.LG;
        const V = m.V;
        const result = classifyFedex(S, M, L, W, V, G);

        const ltlConds = [
            condLine('W > 150', 'W=' + W + ' > 150', W > 150),
            condLine('L > 108', 'L=' + L + ' > 108', L > 108),
            condLine('L+G > 165', 'L+G=' + LG + ' > 165', LG > 165)
        ];
        const oversizeConds = [
            condLine('L > 96', 'L=' + L + ' > 96', L > 96),
            condLine('L+G > 130', 'L+G=' + LG + ' > 130', LG > 130),
            condLine('V > 17280', 'V=' + V + ' > 17280', V > 17280),
            condLine('W > 110', 'W=' + W + ' > 110', W > 110)
        ];
        const ahsDConds = [
            condLine('V > 10368', 'V=' + V + ' > 10368', V > 10368),
            condLine('L > 48', 'L=' + L + ' > 48', L > 48),
            condLine('M > 30', 'M=' + M + ' > 30', M > 30),
            condLine('L+G > 105', 'L+G=' + LG + ' > 105', LG > 105)
        ];
        const ahsConds = [condLine('W ≥ 50', 'W=' + W + ' ≥ 50', W >= 50)];

        const ruleSteps = [];
        const ltlHit = ltlConds.some(function (c) { return c.hit; });
        ruleSteps.push({
            title: '1) LTL',
            subtitle: '任一：W>150 或 L>108 或 L+G>165',
            conditions: ltlConds,
            matched: ltlHit,
            resultIfMatch: 'LTL'
        });
        if (!ltlHit) {
            const osHit = oversizeConds.some(function (c) { return c.hit; });
            ruleSteps.push({
                title: '2) Oversize',
                subtitle: '任一：L>96 或 L+G>130 或 V>17280 或 W>110',
                conditions: oversizeConds,
                matched: osHit,
                resultIfMatch: 'Oversize'
            });
            if (!osHit) {
                const ahsDHit = ahsDConds.some(function (c) { return c.hit; });
                ruleSteps.push({
                    title: '3) AHS-D',
                    subtitle: '任一：V>10368 或 L>48 或 M>30 或 L+G>105',
                    conditions: ahsDConds,
                    matched: ahsDHit,
                    resultIfMatch: 'AHS-D'
                });
                if (!ahsDHit) {
                    const ahsHit = ahsConds.some(function (c) { return c.hit; });
                    ruleSteps.push({
                        title: '4) AHS',
                        subtitle: 'W≥50 且无上述尺寸类',
                        conditions: ahsConds,
                        matched: ahsHit,
                        resultIfMatch: 'AHS'
                    });
                    if (!ahsHit) {
                        ruleSteps.push({
                            title: '5) 小件',
                            subtitle: '未命中以上规则',
                            conditions: [],
                            matched: true,
                            resultIfMatch: '小件'
                        });
                    }
                }
            }
        }

        return {
            carrier: 'FedEx',
            result: result,
            billingNote: '围长 G=(M+S)×2；尺寸阈值用 L+G（长+围长）比较。',
            ruleSteps: ruleSteps
        };
    }

    // -------------------------------------------------------------------------
    // UPS（Large Package 与 FedEx Oversize 同阈值；AH 体积>8640 in³，无 L+G>105）
    // -------------------------------------------------------------------------
    function classifyUps(S, M, L, W, V, G) {
        const LG = L + G;
        if (W > 150 || L > 108 || LG > 165) return '超限';
        if (L > 96 || LG > 130 || V > 17280 || W > 110) return 'Large Package';
        if (V > 8640 || L > 48 || M > 30) return 'Additional Handling';
        if (W >= 50) return 'Additional Handling';
        return '标准';
    }

    function explainUps(m) {
        const S = m.S;
        const M = m.M;
        const L = m.L;
        const W = m.W;
        const G = m.G;
        const LG = m.LG;
        const V = m.V;
        const result = classifyUps(S, M, L, W, V, G);

        const overConds = [
            condLine('W > 150', 'W=' + W + ' > 150', W > 150),
            condLine('L > 108', 'L=' + L + ' > 108', L > 108),
            condLine('L+G > 165', 'L+G=' + LG + ' > 165', LG > 165)
        ];
        const largeConds = [
            condLine('L > 96', 'L=' + L + ' > 96', L > 96),
            condLine('L+G > 130', 'L+G=' + LG + ' > 130', LG > 130),
            condLine('V > 17280', 'V=' + V + ' > 17280', V > 17280),
            condLine('W > 110', 'W=' + W + ' > 110', W > 110)
        ];
        const ahDimConds = [
            condLine('V > 8640', 'V=' + V + ' > 8640', V > 8640),
            condLine('L > 48', 'L=' + L + ' > 48', L > 48),
            condLine('M > 30', 'M=' + M + ' > 30', M > 30)
        ];
        const ahWeightConds = [condLine('W ≥ 50', 'W=' + W + ' ≥ 50', W >= 50)];

        const ruleSteps = [];
        const overHit = overConds.some(function (c) { return c.hit; });
        ruleSteps.push({
            title: '1) 超限',
            subtitle: '任一：W>150 或 L>108 或 L+G>165',
            conditions: overConds,
            matched: overHit,
            resultIfMatch: '超限'
        });
        if (!overHit) {
            const lgHit = largeConds.some(function (c) { return c.hit; });
            ruleSteps.push({
                title: '2) Large Package',
                subtitle: '与 FedEx Oversize 相同：L>96 或 L+G>130 或 V>17280 或 W>110',
                conditions: largeConds,
                matched: lgHit,
                resultIfMatch: 'Large Package'
            });
            if (!lgHit) {
                const ahDimHit = ahDimConds.some(function (c) { return c.hit; });
                ruleSteps.push({
                    title: '3) Additional Handling（尺寸）',
                    subtitle: '任一：V>8640 或 L>48 或 M>30（无 L+G>105）',
                    conditions: ahDimConds,
                    matched: ahDimHit,
                    resultIfMatch: 'Additional Handling'
                });
                if (!ahDimHit) {
                    const ahWeightHit = ahWeightConds.some(function (c) { return c.hit; });
                    ruleSteps.push({
                        title: '4) Additional Handling（重量）',
                        subtitle: 'W≥50 且无上述尺寸类',
                        conditions: ahWeightConds,
                        matched: ahWeightHit,
                        resultIfMatch: 'Additional Handling'
                    });
                    if (!ahWeightHit) {
                        ruleSteps.push({
                            title: '5) 标准',
                            subtitle: '未命中附加费/大件规则',
                            conditions: [],
                            matched: true,
                            resultIfMatch: '标准'
                        });
                    }
                }
            }
        }

        return {
            carrier: 'UPS',
            result: result,
            billingNote: '围长 G=(M+S)×2；Large Package 用 L+G；Additional Handling 体积 V=S×M×L>8640 in³，不含 L+G>105。',
            ruleSteps: ruleSteps
        };
    }

    // -------------------------------------------------------------------------
    // Wayfair CG 仓（忽略 Rolled rugs）
    // -------------------------------------------------------------------------
    function classifyWayfairCg(S, M, L, W, V, G) {
        const LG = L + G;

        if (S <= 6 && M <= 12 && L <= 19 && W <= 25) {
            return { tier: 'Bin - Small', billing: 'Bin - Small', volumeBump: false };
        }
        if (S <= 14 && M <= 17 && L <= 26 && W <= 25) {
            return { tier: 'Bin - Large', billing: 'Bin - Large', volumeBump: false };
        }
        if (S <= 14 && M <= 17 && L <= 26 && W <= 50) {
            return { tier: 'Bin - Heavy', billing: 'Bin - Heavy', volumeBump: false };
        }
        if (S <= 30 && M <= 30 && L <= 48 && LG <= 105 && W <= 50) {
            const bump = V > 10368;
            return {
                tier: 'Standard - Small',
                billing: bump ? 'Standard - Medium（V>10368 按 Medium 计费）' : 'Standard - Small',
                volumeBump: bump
            };
        }
        if (L <= 96 && LG <= 130 && W <= 110) {
            const bump = V > 17280;
            return {
                tier: 'Standard - Medium',
                billing: bump ? 'Standard - Large（V>17280 按 Large 计费）' : 'Standard - Medium',
                volumeBump: bump
            };
        }
        if (L <= 108 && LG <= 165 && W <= 120) {
            return { tier: 'Standard - Large', billing: 'Standard - Large', volumeBump: false };
        }
        if (L <= 108 && LG <= 165 && W <= 150) {
            return { tier: 'Standard - Oversize', billing: 'Standard - Oversize', volumeBump: false };
        }
        if (W <= 250) {
            return { tier: 'Large - Standard', billing: 'Large - Standard', volumeBump: false };
        }
        if (L <= 144 && W <= 800) {
            return { tier: 'Large - Heavy', billing: 'Large - Heavy', volumeBump: false };
        }
        return { tier: '超出表列范围', billing: '—', volumeBump: false };
    }

    function explainWayfairCg(m) {
        const S = m.S;
        const M = m.M;
        const L = m.L;
        const W = m.W;
        const G = m.G;
        const LG = m.LG;
        const V = m.V;
        const hit = classifyWayfairCg(S, M, L, W, V, G);

        const tierChecks = [
            {
                title: 'Bin - Small',
                subtitle: 'S≤6, M≤12, L≤19, W≤25',
                conditions: [
                    condLine('S≤6', 'S=' + S, S <= 6),
                    condLine('M≤12', 'M=' + M, M <= 12),
                    condLine('L≤19', 'L=' + L, L <= 19),
                    condLine('W≤25', 'W=' + W, W <= 25)
                ],
                resultIfMatch: 'Bin - Small'
            },
            {
                title: 'Bin - Large',
                subtitle: 'S≤14, M≤17, L≤26, W≤25',
                conditions: [
                    condLine('S≤14', 'S=' + S, S <= 14),
                    condLine('M≤17', 'M=' + M, M <= 17),
                    condLine('L≤26', 'L=' + L, L <= 26),
                    condLine('W≤25', 'W=' + W, W <= 25)
                ],
                resultIfMatch: 'Bin - Large'
            },
            {
                title: 'Bin - Heavy',
                subtitle: 'S≤14, M≤17, L≤26, 25<W≤50',
                conditions: [
                    condLine('S≤14', 'S=' + S, S <= 14),
                    condLine('M≤17', 'M=' + M, M <= 17),
                    condLine('L≤26', 'L=' + L, L <= 26),
                    condLine('25<W≤50', 'W=' + W, W > 25 && W <= 50)
                ],
                resultIfMatch: 'Bin - Heavy'
            },
            {
                title: 'Standard - Small',
                subtitle: 'S≤30, M≤30, L≤48, L+G≤105, W≤50',
                conditions: [
                    condLine('S≤30', 'S=' + S, S <= 30),
                    condLine('M≤30', 'M=' + M, M <= 30),
                    condLine('L≤48', 'L=' + L, L <= 48),
                    condLine('L+G≤105', 'L+G=' + LG, LG <= 105),
                    condLine('W≤50', 'W=' + W, W <= 50)
                ],
                resultIfMatch: 'Standard - Small'
            },
            {
                title: 'Standard - Medium',
                subtitle: 'L≤96, L+G≤130, W≤110',
                conditions: [
                    condLine('L≤96', 'L=' + L, L <= 96),
                    condLine('L+G≤130', 'L+G=' + LG, LG <= 130),
                    condLine('W≤110', 'W=' + W, W <= 110)
                ],
                resultIfMatch: 'Standard - Medium'
            },
            {
                title: 'Standard - Large',
                subtitle: 'L≤108, L+G≤165, W≤120',
                conditions: [
                    condLine('L≤108', 'L=' + L, L <= 108),
                    condLine('L+G≤165', 'L+G=' + LG, LG <= 165),
                    condLine('W≤120', 'W=' + W, W <= 120)
                ],
                resultIfMatch: 'Standard - Large'
            },
            {
                title: 'Standard - Oversize',
                subtitle: 'L≤108, L+G≤165, W≤150',
                conditions: [
                    condLine('L≤108', 'L=' + L, L <= 108),
                    condLine('L+G≤165', 'L+G=' + LG, LG <= 165),
                    condLine('W≤150', 'W=' + W, W <= 150)
                ],
                resultIfMatch: 'Standard - Oversize'
            },
            {
                title: 'Large - Standard',
                subtitle: 'W≤250',
                conditions: [condLine('W≤250', 'W=' + W, W <= 250)],
                resultIfMatch: 'Large - Standard'
            },
            {
                title: 'Large - Heavy',
                subtitle: 'L≤144, W≤800',
                conditions: [
                    condLine('L≤144', 'L=' + L, L <= 144),
                    condLine('W≤800', 'W=' + W, W <= 800)
                ],
                resultIfMatch: 'Large - Heavy'
            }
        ];

        const ruleSteps = [];
        let matched = false;
        tierChecks.forEach(function (tier, idx) {
            const allPass = tier.conditions.every(function (c) { return c.hit; });
            if (!matched && allPass) {
                matched = true;
                let billing = tier.resultIfMatch;
                if (tier.resultIfMatch === 'Standard - Small' && V > 10368) {
                    billing = 'Standard - Medium（V>10368）';
                } else if (tier.resultIfMatch === 'Standard - Medium' && V > 17280) {
                    billing = 'Standard - Large（V>17280）';
                }
                ruleSteps.push({
                    title: (idx + 1) + ') ' + tier.title,
                    subtitle: tier.subtitle + ' → 命中',
                    conditions: tier.conditions,
                    matched: true,
                    resultIfMatch: billing
                });
            } else if (!matched) {
                ruleSteps.push({
                    title: (idx + 1) + ') ' + tier.title,
                    subtitle: tier.subtitle,
                    conditions: tier.conditions,
                    matched: false,
                    resultIfMatch: tier.resultIfMatch
                });
            }
        });
        if (!matched) {
            ruleSteps.push({
                title: '超出 Wayfair CG 表列范围',
                subtitle: '未满足任一已列档位',
                conditions: [],
                matched: true,
                resultIfMatch: '超出表列范围'
            });
        }

        let billingNote = '';
        if (hit.volumeBump) {
            billingNote = '体积升档：' + hit.billing;
        }

        return {
            carrier: 'Wayfair CG',
            result: hit.tier,
            billing: hit.billing,
            billingNote: billingNote,
            ruleSteps: ruleSteps
        };
    }

    // -------------------------------------------------------------------------
    // 汇总解释
    // -------------------------------------------------------------------------
    function explainPackageClass(lengthIn, widthIn, heightIn, grossLbs) {
        const rawLen = parseNumber(lengthIn);
        const rawWid = parseNumber(widthIn);
        const rawHei = parseNumber(heightIn);
        const rawGross = parseNumber(grossLbs);

        if (rawLen === null || rawWid === null || rawHei === null || rawGross === null) {
            return { ok: false, message: '请填写包裹长、宽、高（inch）与毛重（lbs），且均为正数。' };
        }
        if (rawLen <= 0 || rawWid <= 0 || rawHei <= 0 || rawGross <= 0) {
            return { ok: false, message: '包裹三边与毛重须大于 0。' };
        }

        const metrics = buildMetrics(rawLen, rawWid, rawHei, rawGross);
        if (!metrics) {
            return { ok: false, message: '无法计算，请检查输入。' };
        }

        const fedex = explainFedex(metrics);
        const ups = explainUps(metrics);
        const wayfair = explainWayfairCg(metrics);

        return {
            ok: true,
            result: fedex.result,
            metrics: metrics,
            prepSteps: buildPrepSteps(metrics),
            carriers: { fedex: fedex, ups: ups, wayfair: wayfair },
            ruleSteps: fedex.ruleSteps
        };
    }

    // -------------------------------------------------------------------------
    // HTML 渲染
    // -------------------------------------------------------------------------
    function escapeHtml(text) {
        return String(text == null ? '' : text)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function renderRuleStepsHtml(ruleSteps) {
        let html = '<ol class="pkg-class-rule-steps">';
        ruleSteps.forEach(function (step) {
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
        html += '</ol>';
        return html;
    }

    function renderCarrierPanel(carrier) {
        if (!carrier) return '';
        let html = '<article class="pkg-class-carrier-panel">';
        html += '<h4 class="pkg-class-carrier-panel__title">' + escapeHtml(carrier.carrier) + '</h4>';
        html += '<div class="pkg-class-explain-result">归类：<strong class="pkg-class-explain-badge">'
            + escapeHtml(carrier.result) + '</strong></div>';
        if (carrier.billing && carrier.billing !== carrier.result) {
            html += '<div class="pkg-class-carrier-billing">计费档位：<strong>' + escapeHtml(carrier.billing) + '</strong></div>';
        }
        if (carrier.billingNote) {
            html += '<div class="pkg-class-carrier-note">' + escapeHtml(carrier.billingNote) + '</div>';
        }
        html += '<div class="pkg-class-explain-section"><h4>判定</h4>';
        html += renderRuleStepsHtml(carrier.ruleSteps || []);
        html += '</div></article>';
        return html;
    }

    function renderExplainHtml(explain, options) {
        options = options || {};
        if (!explain || !explain.ok) {
            return '<p class="pkg-class-explain-error">' + escapeHtml((explain && explain.message) || '无法计算') + '</p>';
        }
        const skuLine = options.sku
            ? '<p class="pkg-class-explain-sku">SKU：<strong>' + escapeHtml(options.sku) + '</strong></p>'
            : '';
        const m = explain.metrics;
        let html = skuLine;

        html += '<div class="pkg-class-explain-section"><h4>中间量</h4><table class="pkg-class-metrics-table"><tbody>';
        html += '<tr><th>长 L</th><td>' + m.L + ' in</td><th>宽 M</th><td>' + m.M + ' in</td></tr>';
        html += '<tr><th>高 S</th><td>' + m.S + ' in</td><th>毛重 W</th><td>' + m.W + ' lb</td></tr>';
        html += '<tr><th>围长 G</th><td>' + m.G + ' in</td><th>L+G</th><td>' + m.LG + ' in</td></tr>';
        html += '<tr><th>体积 V</th><td colspan="3">' + m.V + ' cu in</td></tr>';
        html += '</tbody></table></div>';

        html += '<div class="pkg-class-explain-section"><h4>计算过程</h4><ol class="pkg-class-prep-steps">';
        (explain.prepSteps || []).forEach(function (step) {
            html += '<li><strong>' + escapeHtml(step.title) + '</strong>';
            step.lines.forEach(function (line) {
                html += '<div class="pkg-class-step-line">' + escapeHtml(line) + '</div>';
            });
            html += '</li>';
        });
        html += '</ol></div>';

        const carriers = explain.carriers || {};
        const showAll = options.carrier !== 'fedex';
        if (showAll && carriers.fedex && carriers.ups && carriers.wayfair) {
            html += '<div class="pkg-class-carrier-grid">';
            html += renderCarrierPanel(carriers.fedex);
            html += renderCarrierPanel(carriers.ups);
            html += renderCarrierPanel(carriers.wayfair);
            html += '</div>';
        } else {
            const c = carriers.fedex || { result: explain.result, ruleSteps: explain.ruleSteps, carrier: 'FedEx' };
            html += '<div class="pkg-class-explain-result">归类结果：<strong class="pkg-class-explain-badge">'
                + escapeHtml(c.result) + '</strong></div>';
            html += '<div class="pkg-class-explain-section"><h4>判定顺序（FedEx）</h4>';
            html += renderRuleStepsHtml(c.ruleSteps || explain.ruleSteps || []);
            html += '</div>';
        }

        html += '<p class="pkg-class-footnote">三边与毛重均向上取整；围长 G=(M+S)×2；Large Package/Oversize 用 L+G；UPS AH 用 V>8640（无 L+G>105）；Wayfair 忽略 Rolled rugs；实际计费以价表为准。</p>';
        return html;
    }

    // -------------------------------------------------------------------------
    // 弹窗与页面
    // -------------------------------------------------------------------------
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
        if (window.bindFloatingHelpDots) bindFloatingHelpDots(outEl);
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
            outEl.innerHTML = renderExplainHtml(explain, { sku: params.sku });
            if (window.bindFloatingHelpDots) bindFloatingHelpDots(outEl);
        }
        m.classList.add('active');
    }

    function bindPackageClassFormInputs() {
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

    function bindPackageClassModal() {
        const m = getModalEl();
        if (!m || m.dataset.pkgClassBound === '1') return;
        m.dataset.pkgClassBound = '1';
        const calcBtn = document.getElementById('pkgClassCalcSubmitBtn');
        if (calcBtn && m.contains(calcBtn)) calcBtn.addEventListener('click', runPackageClassCalcFromForm);
        const closeBtn = document.getElementById('packageClassCalcCloseBtn');
        if (closeBtn) closeBtn.addEventListener('click', closePackageClassModal);
        if (typeof window.bindPmModalBackdropClose === 'function') {
            window.bindPmModalBackdropClose(m, closePackageClassModal);
        } else {
            m.addEventListener('click', function (e) {
                if (e.target === m) closePackageClassModal();
            });
        }
        bindPackageClassFormInputs();
    }

    function initCalculatorPage() {
        const form = document.getElementById('packageClassCalcForm');
        if (!form || form.dataset.pkgClassPageBound === '1') return;
        const modal = getModalEl();
        if (modal && modal.contains(form)) return;
        form.dataset.pkgClassPageBound = '1';
        const calcBtn = document.getElementById('pkgClassCalcSubmitBtn');
        if (calcBtn) calcBtn.addEventListener('click', runPackageClassCalcFromForm);
        bindPackageClassFormInputs();
    }

    global.SitjoyPackageClass = {
        parseNumber: parseNumber,
        ceilingPositiveInt: ceilingPositiveInt,
        sortedCeiledDims: sortedCeiledDims,
        classifyPackage: classifyPackage,
        classifyFedex: classifyFedex,
        classifyUps: classifyUps,
        classifyWayfairCg: classifyWayfairCg,
        explainPackageClass: explainPackageClass,
        renderExplainHtml: renderExplainHtml,
        openPackageClassCalculatorModal: openPackageClassCalculatorModal,
        openPackageClassExplainModal: openPackageClassExplainModal,
        closePackageClassModal: closePackageClassModal,
        bindPackageClassModal: bindPackageClassModal,
        initCalculatorPage: initCalculatorPage,
        runPackageClassCalcFromForm: runPackageClassCalcFromForm
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            bindPackageClassModal();
            initCalculatorPage();
        });
    } else {
        bindPackageClassModal();
        initCalculatorPage();
    }
}(typeof window !== 'undefined' ? window : this));
