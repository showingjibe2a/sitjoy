/**
 * 广告调整：盈利概率曲线（二项分布，独立点击模型）
 *
 * CVR_target = CPC / CPS（盈亏平衡转化率）
 * 纵轴 Y = P(X ≤ 订单数)，X ~ Binomial(点击量, CVR_target)；订单数可为 0。
 *
 * 含义：假设每次点击以「刚好盈亏平衡」的转化率独立转化，在若干次点击下，
 * 总转化数不超过本记录订单数的概率。随点击量增加，该概率单调下降并趋近 0。
 * 与 WPS 宏一致，不做 1−Y 变换。
 */
(function (global) {
  const NS = {};

  // -------------------------------------------------------------------------
  // 二项分布盈利概率与曲线数据
  // -------------------------------------------------------------------------
  function parseNum(v) {
    if (v == null || v === '') return null;
    const n = Number(String(v).replace(/,/g, '').replace(/%/g, ''));
    return Number.isFinite(n) ? n : null;
  }

  /** P(X <= k), X ~ Binomial(n, p) — 递推 PMF，避免阶乘溢出 */
  function binomialCdfLE(k, n, p) {
    const kk = Math.max(0, Math.floor(k));
    const nn = Math.max(0, Math.floor(n));
    if (nn === 0) return 1;
    if (p <= 0) return 1;
    if (p >= 1) return kk >= nn ? 1 : 0;
    if (kk >= nn) return 1;
    let pmf = Math.pow(1 - p, nn);
    let cdf = pmf;
    for (let i = 1; i <= kk; i++) {
      pmf *= ((nn - i + 1) / i) * (p / (1 - p));
      cdf += pmf;
      if (cdf > 1) return 1;
    }
    return Math.min(1, Math.max(0, cdf));
  }

  /** 曲线纵轴值：P(X ≤ 订单数) */
  function curveProbability(orders, clicks, cvrTarget) {
    const k = Math.max(0, Math.floor(orders));
    const n = Math.max(0, Math.floor(clicks));
    const p = Number(cvrTarget);
    if (!Number.isFinite(p) || p <= 0) return 1;
    return binomialCdfLE(k, n, p);
  }

  /**
   * 生成曲线点：从 clicks = orders+1 起，延伸至纵轴值趋近 0（< floor）
   * 若当前点击量更大，会继续向右延伸直至达标
   */
  function buildCurvePoints(orders, cvrTarget, options) {
    const opts = options || {};
    const floor = opts.probFloor != null ? opts.probFloor : 0.001;
    const maxPoints = opts.maxPoints != null ? opts.maxPoints : 160;
    const hardMaxSpan = opts.hardMaxSpan != null ? opts.hardMaxSpan : 12000;
    const ord = Math.max(0, Math.floor(orders));
    const p = Number(cvrTarget);
    if (!Number.isFinite(p) || p <= 0 || p >= 1) return [];
    const start = Math.max(ord + 1, 1);
    const minEnd = opts.currentClicks != null && opts.currentClicks >= start
      ? Math.floor(opts.currentClicks)
      : start;
    let end = minEnd;
    let yVal = curveProbability(ord, end, p);
    const hardMax = start + hardMaxSpan;
    while (yVal >= floor && end < hardMax) {
      end++;
      yVal = curveProbability(ord, end, p);
    }
    if (end <= start) end = start + 1;
    const span = end - start;
    const step = Math.max(1, Math.ceil(span / maxPoints));
    const points = [];
    for (let clicks = start; clicks <= end; clicks += step) {
      points.push({
        clicks,
        prob: curveProbability(ord, clicks, p),
      });
    }
    if (!points.length || points[points.length - 1].clicks !== end) {
      points.push({ clicks: end, prob: curveProbability(ord, end, p) });
    }
    return points;
  }

  function formatPct(ratio) {
    if (ratio == null || !Number.isFinite(ratio)) return '-';
    const pct = ratio * 100;
    if (pct > 0 && pct < 0.1) return pct.toFixed(2) + '%';
    if (pct >= 100) return pct.toFixed(1) + '%';
    return pct.toFixed(1) + '%';
  }

  function formatUsd(n) {
    if (n == null || !Number.isFinite(n)) return '-';
    return '$' + Number(n).toFixed(2);
  }

  function computeAxisTicks(min, max, targetCount) {
    const lo = Number(min);
    const hi = Number(max);
    if (!Number.isFinite(lo) || !Number.isFinite(hi)) return [];
    if (hi <= lo) return [lo];
    const span = hi - lo;
    const rawStep = span / Math.max(2, targetCount - 1);
    const mag = Math.pow(10, Math.floor(Math.log10(rawStep)));
    const norm = rawStep / mag;
    let step = mag;
    if (norm <= 1) step = mag;
    else if (norm <= 2) step = 2 * mag;
    else if (norm <= 5) step = 5 * mag;
    else step = 10 * mag;
    const start = Math.ceil(lo / step) * step;
    const ticks = [];
    for (let v = start; v <= hi + step * 0.001; v += step) {
      ticks.push(Math.round(v * 1000) / 1000);
    }
    if (!ticks.length) ticks.push(lo, hi);
    return ticks;
  }

  function formatClickTick(v) {
    const n = Number(v);
    if (!Number.isFinite(n)) return '-';
    if (Math.abs(n - Math.round(n)) < 0.001) return String(Math.round(n));
    return n.toFixed(1);
  }

  function buildChartLayout(points, currentClicks, cssW, cssH) {
    const pad = { top: 16, right: 12, bottom: 36, left: 48 };
    const innerW = cssW - pad.left - pad.right;
    const innerH = cssH - pad.top - pad.bottom;
    const xs = points.map(pt => pt.clicks);
    let xMin = Math.min(...xs);
    let xMax = Math.max(...xs);
    if (currentClicks != null && Number.isFinite(currentClicks)) {
      xMin = Math.min(xMin, currentClicks);
      xMax = Math.max(xMax, currentClicks);
    }
    if (xMax <= xMin) xMax = xMin + 1;
    const yMin = 0;
    const yMax = 1;
    const xAt = v => pad.left + ((v - xMin) / (xMax - xMin)) * innerW;
    const yAt = v => pad.top + ((yMax - v) / (yMax - yMin)) * innerH;
    const clicksAt = px => xMin + ((px - pad.left) / innerW) * (xMax - xMin);
    return {
      pad,
      innerW,
      innerH,
      xMin,
      xMax,
      yMin,
      yMax,
      xAt,
      yAt,
      clicksAt,
      xTicks: computeAxisTicks(xMin, xMax, 5),
      yTicks: [0, 0.25, 0.5, 0.75, 1],
    };
  }

  function probAtClicks(orders, cvrTarget, clicks) {
    return curveProbability(orders, clicks, cvrTarget);
  }

  // -------------------------------------------------------------------------
  // 曲线图表绘制与交互
  // -------------------------------------------------------------------------
  function drawChart(canvas, chartState) {
    if (!canvas || !chartState || !chartState.points.length) return;
    const { points, meta, currentClicks, hoverClicks } = chartState;
    const dpr = global.devicePixelRatio || 1;
    const cssW = canvas.clientWidth || 300;
    const cssH = canvas.clientHeight || 220;
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);

    const layout = buildChartLayout(points, currentClicks, cssW, cssH);
    chartState.layout = layout;
    const { pad, innerW, innerH, xAt, yAt, xTicks, yTicks } = layout;

    ctx.strokeStyle = 'rgba(207, 199, 189, 0.35)';
    ctx.lineWidth = 1;
    yTicks.forEach(tick => {
      const y = yAt(tick);
      ctx.beginPath();
      ctx.moveTo(pad.left, y);
      ctx.lineTo(pad.left + innerW, y);
      ctx.stroke();
    });
    xTicks.forEach(tick => {
      const x = xAt(tick);
      ctx.beginPath();
      ctx.moveTo(x, pad.top);
      ctx.lineTo(x, pad.top + innerH);
      ctx.stroke();
    });

    ctx.strokeStyle = 'rgba(107, 143, 126, 0.55)';
    ctx.lineWidth = 1.25;
    ctx.beginPath();
    ctx.moveTo(pad.left, pad.top);
    ctx.lineTo(pad.left, pad.top + innerH);
    ctx.lineTo(pad.left + innerW, pad.top + innerH);
    ctx.stroke();

    ctx.fillStyle = 'rgba(42, 36, 32, 0.55)';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    yTicks.forEach(tick => {
      ctx.fillText(formatPct(tick), pad.left - 6, yAt(tick));
    });
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    xTicks.forEach(tick => {
      ctx.fillText(formatClickTick(tick), xAt(tick), pad.top + innerH + 5);
    });
    ctx.fillText('点击量', pad.left + innerW / 2, cssH - 6);
    ctx.save();
    ctx.translate(12, pad.top + innerH / 2);
    ctx.rotate(-Math.PI / 2);
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('盈利概率', 0, 0);
    ctx.restore();

    ctx.strokeStyle = '#6b8f7e';
    ctx.lineWidth = 2;
    ctx.beginPath();
    points.forEach((pt, i) => {
      const x = xAt(pt.clicks);
      const y = yAt(pt.prob);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.stroke();

    const drawHoverOrCurrent = (clicks, color, dash) => {
      if (clicks == null || !Number.isFinite(clicks)) return;
      if (clicks < layout.xMin || clicks > layout.xMax) return;
      const cx = xAt(clicks);
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      ctx.setLineDash(dash || []);
      ctx.beginPath();
      ctx.moveTo(cx, pad.top);
      ctx.lineTo(cx, pad.top + innerH);
      ctx.stroke();
      ctx.setLineDash([]);
      const prob = probAtClicks(meta.orders, meta.cvrTarget, clicks);
      const cy = yAt(prob);
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(cx, cy, 4, 0, Math.PI * 2);
      ctx.fill();
    };

    if (currentClicks != null && Number.isFinite(currentClicks)) {
      drawHoverOrCurrent(currentClicks, '#c45c3e', [4, 3]);
    }
    if (hoverClicks != null && Number.isFinite(hoverClicks)
      && (currentClicks == null || Math.round(hoverClicks) !== Math.round(currentClicks))) {
      drawHoverOrCurrent(hoverClicks, 'rgba(42, 36, 32, 0.55)', [3, 3]);
    }
  }

  function hideChartTip() {
    const tip = document.getElementById('aaProfitChartTip');
    if (!tip) return;
    tip.classList.remove('is-visible');
    tip.setAttribute('aria-hidden', 'true');
  }

  function showChartTip(canvas, chartState, clientX, clientY) {
    const tip = document.getElementById('aaProfitChartTip');
    const wrap = document.getElementById('aaProfitChartWrap');
    if (!tip || !wrap || !canvas || !chartState || !chartState.layout) return;
    const rect = canvas.getBoundingClientRect();
    const layout = chartState.layout;
    const localX = clientX - rect.left;
    const localY = clientY - rect.top;
    const { pad, innerW, innerH } = layout;
    if (localX < pad.left || localX > pad.left + innerW
      || localY < pad.top || localY > pad.top + innerH) {
      chartState.hoverClicks = null;
      hideChartTip();
      drawChart(canvas, chartState);
      return;
    }
    const clicks = Math.round(layout.clicksAt(localX));
    const clamped = Math.max(layout.xMin, Math.min(layout.xMax, clicks));
    const prob = probAtClicks(chartState.meta.orders, chartState.meta.cvrTarget, clamped);
    chartState.hoverClicks = clamped;
    drawChart(canvas, chartState);

    tip.innerHTML = `<strong>曲线读数</strong>点击 ${clamped}<br>盈利概率 ${formatPct(prob)}`;
    tip.classList.add('is-visible');
    tip.setAttribute('aria-hidden', 'false');

    const wrapRect = wrap.getBoundingClientRect();
    const tipW = tip.offsetWidth || 120;
    const tipH = tip.offsetHeight || 48;
    let left = clientX - wrapRect.left + 12;
    let top = clientY - wrapRect.top - tipH - 10;
    if (left + tipW > wrapRect.width - 4) left = clientX - wrapRect.left - tipW - 12;
    if (left < 4) left = 4;
    if (top < 4) top = clientY - wrapRect.top + 12;
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
  }

  function bindChartInteractions(canvas) {
    if (!canvas || canvas.dataset.profitChartBound === '1') return;
    canvas.dataset.profitChartBound = '1';
    canvas.addEventListener('mousemove', (e) => {
      const chartState = canvas._profitChart;
      if (!chartState) return;
      showChartTip(canvas, chartState, e.clientX, e.clientY);
    });
    canvas.addEventListener('mouseleave', () => {
      const chartState = canvas._profitChart;
      if (!chartState) return;
      chartState.hoverClicks = null;
      hideChartTip();
      drawChart(canvas, chartState);
    });
  }

  const PROFIT_MODELS = {
    bernoulli: {
      label: '伯努利（独立点击）',
      desc: '每次点击以 CVR_target = CPC / CPS 独立转化；纵轴为 P(转化数 ≤ 订单数)。',
    },
  };

  function isSkuFamilyExpSaved(ctx) {
    return !!(ctx && ctx.amazon_exp_atv > 0 && ctx.amazon_exp_acos > 0);
  }

  function renderMetaRow(label, valueHtml) {
    return `<tr><th>${escapeHtml(label)}</th><td>${valueHtml}</td></tr>`;
  }

  function renderValueWithFormula(valueHtml, formulaHtml) {
    if (!formulaHtml) return valueHtml;
    return `${valueHtml}<span class="aa-profit-formula">${formulaHtml}</span>`;
  }

  function buildCpsFormulaHtml(ctx) {
    if (!ctx || !ctx.cps) return '';
    if (ctx.cps_source === 'product' && ctx.cps_detail) {
      const d = ctx.cps_detail;
      return `${escapeHtml(formatUsd(d.sale_price_usd))} × ${escapeHtml(formatPct(d.amazon_exp_acos))}`;
    }
    if (ctx.amazon_exp_atv > 0 && ctx.amazon_exp_acos > 0) {
      return `${escapeHtml(formatUsd(ctx.amazon_exp_atv))} × ${escapeHtml(formatPct(ctx.amazon_exp_acos))}`;
    }
    if (ctx.cps_detail && ctx.cps_detail.atv && ctx.cps_detail.acos) {
      return `${escapeHtml(formatUsd(ctx.cps_detail.atv))} × ${escapeHtml(formatPct(ctx.cps_detail.acos))}（近3月参考）`;
    }
    return '';
  }

  // -------------------------------------------------------------------------
  // 实验指标弹窗与面板渲染
  // -------------------------------------------------------------------------
  function renderMeta(el, ctx) {
    if (!el || !ctx) return;
    const curClicks = ctx.clicks != null && ctx.clicks >= 0 ? Math.floor(ctx.clicks) : null;
    let curProb = null;
    if (curClicks != null && ctx.cvr_target) {
      curProb = curveProbability(ctx.orders, curClicks, ctx.cvr_target);
    }
    const expMissing = !!ctx.sku_family_id && !isSkuFamilyExpSaved(ctx);
    const atvCell = ctx.amazon_exp_atv > 0
      ? escapeHtml(formatUsd(ctx.amazon_exp_atv))
      : '<span style="color:#9a4a32;">未维护</span>';
    const acosCell = ctx.amazon_exp_acos > 0
      ? escapeHtml(formatPct(ctx.amazon_exp_acos))
      : '<span style="color:#9a4a32;">未维护</span>';
    const acoasCell = ctx.amazon_exp_acoas > 0
      ? escapeHtml(formatPct(ctx.amazon_exp_acoas))
      : '<span style="color:var(--morandi-slate);">-</span>';
    const cpsCell = ctx.cps
      ? renderValueWithFormula(escapeHtml(formatUsd(ctx.cps)), buildCpsFormulaHtml(ctx))
      : '-';
    const cvrCell = ctx.cvr_target
      ? renderValueWithFormula(
        escapeHtml(formatPct(ctx.cvr_target)),
        `${escapeHtml(formatUsd(ctx.cpc))} / ${escapeHtml(formatUsd(ctx.cps))}`,
      )
      : '-';

    const skuRows = [
      renderMetaRow('货号', escapeHtml(ctx.sku_family || '-')),
      renderMetaRow('预估笔单价', atvCell),
      renderMetaRow('预估 ACOS', acosCell),
      renderMetaRow('预估 ACOAS', `${acoasCell}<span class="aa-profit-formula">参考，不参与 CPS 计算</span>`),
      renderMetaRow('理论 CPS', cpsCell),
    ];
    const recordRows = [
      renderMetaRow('订单数', escapeHtml(String(ctx.orders))),
      renderMetaRow('CPC', escapeHtml(formatUsd(ctx.cpc))),
      renderMetaRow('盈亏平衡 CVR', cvrCell),
    ];
    if (curClicks != null && curClicks >= 0) {
      recordRows.push(renderMetaRow('当前点击', escapeHtml(String(curClicks))));
      recordRows.push(renderMetaRow('盈利概率', escapeHtml(formatPct(curProb))));
    }

    const editBtn = ctx.sku_family_id
      ? '<button type="button" class="btn-secondary btn-small aa-profit-exp-edit-btn">编辑</button>'
      : '';
    const warnHtml = expMissing
      ? '<div class="aa-profit-meta-warn">货号预估笔单价 / ACOS 尚未写入数据库，请先维护后再用于非「修改商品」类操作的 CPS 计算。<button type="button" class="btn-secondary btn-small aa-profit-exp-edit-btn">去维护</button></div>'
      : '';

    const modelOptions = Object.keys(PROFIT_MODELS).map(key => {
      const m = PROFIT_MODELS[key];
      const sel = key === 'bernoulli' ? ' selected' : '';
      return `<option value="${escapeHtml(key)}"${sel}>${escapeHtml(m.label)}</option>`;
    }).join('');

    el.innerHTML = `
      <div class="aa-profit-meta-blocks">
        <div class="aa-profit-meta-block" data-block="sku">
          <div class="aa-profit-meta-block-head">
            <span>货号</span>
            ${editBtn}
          </div>
          <table class="aa-profit-meta-table"><tbody>${skuRows.join('')}</tbody></table>
          ${warnHtml}
        </div>
        <div class="aa-profit-meta-block" data-block="record">
          <div class="aa-profit-meta-block-head"><span>记录</span></div>
          <table class="aa-profit-meta-table"><tbody>${recordRows.join('')}</tbody></table>
        </div>
        <div class="aa-profit-meta-block aa-profit-meta-block--model" data-block="model">
          <div class="aa-profit-meta-block-head"><span>模型</span></div>
          <select id="aaProfitModelSelect" class="aa-profit-model-select" aria-label="盈利概率模型">
            ${modelOptions}
          </select>
          <p class="aa-profit-model-desc" id="aaProfitModelDesc">${escapeHtml(PROFIT_MODELS.bernoulli.desc)}</p>
        </div>
      </div>
    `;
  }

  function updateExpMetricsCalcLabels(ctx) {
    const atvCalc = document.getElementById('aaExpAtvCalc');
    const acosCalc = document.getElementById('aaExpAcosCalc');
    const acoasCalc = document.getElementById('aaExpAcoasCalc');
    const atvApply = document.getElementById('aaExpAtvApplyBtn');
    const acosApply = document.getElementById('aaExpAcosApplyBtn');
    const acoasApply = document.getElementById('aaExpAcoasApplyBtn');
    const sugAtv = ctx && ctx.suggested_atv > 0 ? formatUsd(ctx.suggested_atv) : '-';
    const sugAcos = ctx && ctx.suggested_acos > 0 ? formatPct(ctx.suggested_acos) : '-';
    const sugAcoas = ctx && ctx.suggested_acoas > 0 ? formatPct(ctx.suggested_acoas) : '-';
    if (atvCalc) atvCalc.textContent = `近3月：${sugAtv}`;
    if (acosCalc) acosCalc.textContent = `近3月：${sugAcos}`;
    if (acoasCalc) acoasCalc.textContent = `近3月：${sugAcoas}`;
    if (atvApply) atvApply.disabled = !(ctx && ctx.suggested_atv > 0);
    if (acosApply) acosApply.disabled = !(ctx && ctx.suggested_acos > 0);
    if (acoasApply) acoasApply.disabled = !(ctx && ctx.suggested_acoas > 0);
  }

  function fillExpMetricsInputs(ctx) {
    const atvEl = document.getElementById('aaExpAtv');
    const acosEl = document.getElementById('aaExpAcos');
    const acoasEl = document.getElementById('aaExpAcoas');
    const atvDefault = ctx.amazon_exp_atv > 0 ? ctx.amazon_exp_atv : ctx.suggested_atv;
    const acosDefault = ctx.amazon_exp_acos > 0 ? ctx.amazon_exp_acos : ctx.suggested_acos;
    const acoasDefault = ctx.amazon_exp_acoas > 0 ? ctx.amazon_exp_acoas : ctx.suggested_acoas;
    if (atvEl) atvEl.value = atvDefault != null ? String(Number(atvDefault).toFixed(2)) : '';
    if (acosEl) {
      acosEl.value = acosDefault != null ? String((Number(acosDefault) * 100).toFixed(2)) : '';
    }
    if (acoasEl) {
      acoasEl.value = acoasDefault != null ? String((Number(acoasDefault) * 100).toFixed(2)) : '';
    }
    updateExpMetricsCalcLabels(ctx);
  }

  function openExpMetricsModal(ctx, onSaved, options) {
    const opts = options || {};
    const modal = document.getElementById('aaExpMetricsModal');
    if (!modal) return Promise.resolve(false);
    if (!ctx || !ctx.sku_family_id) {
      if (global.showAppToast) global.showAppToast('当前广告未绑定货号，无法维护预估指标', true);
      return Promise.resolve(false);
    }
    const sfEl = document.getElementById('aaExpSkuFamily');
    const saveBtn = document.getElementById('aaExpMetricsSaveBtn');
    if (sfEl) sfEl.textContent = ctx.sku_family || '-';
    fillExpMetricsInputs(ctx);
    if (saveBtn) {
      saveBtn.textContent = opts.saveLabel || (opts.requireRecalc ? '保存并计算' : '保存');
    }
    pendingCalc = { ctx, onSaved, requireRecalc: !!opts.requireRecalc };
    modal.classList.add('active');
    return new Promise(resolve => {
      modal._profitResolve = resolve;
    });
  }

  function openExpMetricsFromPanel() {
    const panel = document.getElementById('aaProfitPanel');
    const ctx = panel && panel._lastCtx;
    if (!ctx) return;
    const adItemId = panel._lastAdItemId;
    const adjustmentId = panel._lastAdjustmentId;
    openExpMetricsModal(ctx, () => {
      if (adItemId && adjustmentId) {
        calculateForRecord(adItemId, adjustmentId);
      }
    });
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  let pendingCalc = null;

  function applySuggestedAtv() {
    if (!pendingCalc || !(pendingCalc.ctx.suggested_atv > 0)) return;
    const atvEl = document.getElementById('aaExpAtv');
    if (atvEl) atvEl.value = Number(pendingCalc.ctx.suggested_atv).toFixed(2);
  }

  function applySuggestedAcos() {
    if (!pendingCalc || !(pendingCalc.ctx.suggested_acos > 0)) return;
    const acosEl = document.getElementById('aaExpAcos');
    if (acosEl) acosEl.value = (Number(pendingCalc.ctx.suggested_acos) * 100).toFixed(2);
  }

  function applySuggestedAcoas() {
    if (!pendingCalc || !(pendingCalc.ctx.suggested_acoas > 0)) return;
    const acoasEl = document.getElementById('aaExpAcoas');
    if (acoasEl) acoasEl.value = (Number(pendingCalc.ctx.suggested_acoas) * 100).toFixed(2);
  }

  function closeExpMetricsModal(saved) {
    const modal = document.getElementById('aaExpMetricsModal');
    if (!modal) return;
    modal.classList.remove('active');
    if (typeof modal._profitResolve === 'function') {
      modal._profitResolve(!!saved);
      modal._profitResolve = null;
    }
    pendingCalc = null;
  }

  function saveExpMetricsAndContinue() {
    if (!pendingCalc) return;
    const atv = parseNum(document.getElementById('aaExpAtv')?.value);
    const acosPct = parseNum(document.getElementById('aaExpAcos')?.value);
    const acoasPct = parseNum(document.getElementById('aaExpAcoas')?.value);
    if (atv == null || atv <= 0 || acosPct == null || acosPct <= 0) {
      if (global.showAppToast) global.showAppToast('请填写有效的预估笔单价与 ACOS', true);
      return;
    }
    const payload = {
      sku_family_id: pendingCalc.ctx.sku_family_id,
      amazon_exp_atv: atv,
      amazon_exp_acos: acosPct / 100,
      amazon_exp_acoas: acoasPct != null && acoasPct > 0
        ? acoasPct / 100
        : (pendingCalc.ctx.amazon_exp_acoas > 0 ? pendingCalc.ctx.amazon_exp_acoas : null),
    };
    fetch('/api/amazon-ad-adjustment?action=save-exp-metrics', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'include',
    })
      .then(r => r.json())
      .then(data => {
        if (!data || data.status !== 'success') {
          if (global.showAppToast) global.showAppToast((data && data.message) || '保存失败', true);
          return;
        }
        const onSaved = pendingCalc.onSaved;
        closeExpMetricsModal(true);
        if (typeof onSaved === 'function') onSaved();
      })
      .catch(err => {
        if (global.showAppToast) global.showAppToast('保存失败: ' + err, true);
      });
  }

  function showProfitPanel(show) {
    const panel = document.getElementById('aaProfitPanel');
    if (!panel) return;
    panel.classList.toggle('is-active', !!show);
  }

  function renderProfitChart(ctx) {
    const canvas = document.getElementById('aaProfitChart');
    const metaEl = document.getElementById('aaProfitMeta');
    const titleEl = document.getElementById('aaProfitPanelTitle');
    const panel = document.getElementById('aaProfitPanel');
    if (!ctx) {
      if (global.showAppToast) global.showAppToast('无法计算', true);
      return;
    }
    showProfitPanel(true);
    if (panel) {
      panel._lastCtx = ctx;
      panel._lastAdItemId = ctx.ad_item_id;
      panel._lastAdjustmentId = ctx.adjustment_id;
    }
    if (titleEl) titleEl.textContent = `盈利概率 · 修改 #${ctx.adjustment_id || ''}`;
    renderMeta(metaEl, ctx);
    if (!ctx.cvr_target || !ctx.cps) {
      hideChartTip();
      if (canvas) canvas._profitChart = null;
      if (global.showAppToast) global.showAppToast(ctx.error || '无法计算曲线', true);
      return;
    }
    const meta = {
      orders: ctx.orders,
      cvrTarget: ctx.cvr_target,
    };
    const points = buildCurvePoints(ctx.orders, ctx.cvr_target, {
      currentClicks: ctx.clicks != null && ctx.clicks >= 0 ? ctx.clicks : null,
    });
    if (!points.length) {
      if (global.showAppToast) global.showAppToast('无法生成曲线', true);
      return;
    }
    if (titleEl) titleEl.textContent = `盈利概率 · 修改 #${ctx.adjustment_id || ''}`;
    const chartState = {
      points,
      meta,
      currentClicks: ctx.clicks != null && ctx.clicks >= 0 ? ctx.clicks : null,
      hoverClicks: null,
      layout: null,
    };
    canvas._profitChart = chartState;
    bindChartInteractions(canvas);
    hideChartTip();
    drawChart(canvas, chartState);
    renderMeta(metaEl, ctx);
  }

  // -------------------------------------------------------------------------
  // API 拉取与 UI 绑定
  // -------------------------------------------------------------------------
  function fetchContext(adItemId, adjustmentId) {
    const url = `/api/amazon-ad-adjustment?action=profit-probability&ad_item_id=${encodeURIComponent(adItemId)}&adjustment_id=${encodeURIComponent(adjustmentId)}`;
    return fetch(url, { credentials: 'include' }).then(r => r.json());
  }

  function calculateForRecord(adItemId, adjustmentId) {
    return fetchContext(adItemId, adjustmentId).then(data => {
      if (!data || data.status !== 'success') {
        if (global.showAppToast) global.showAppToast((data && data.message) || '加载失败', true);
        return;
      }
      const ctx = data.context || {};
      if (ctx.error && !ctx.cps) {
        if (ctx.sku_family_id) {
          return openExpMetricsModal(ctx, () => calculateForRecord(adItemId, adjustmentId), {
            requireRecalc: true,
            saveLabel: '保存并计算',
          });
        }
        if (global.showAppToast) global.showAppToast(ctx.error, true);
        return;
      }
      renderProfitChart(ctx);
    });
  }

  function bindUi() {
    const saveBtn = document.getElementById('aaExpMetricsSaveBtn');
    const cancelBtn = document.getElementById('aaExpMetricsCancelBtn');
    const atvApplyBtn = document.getElementById('aaExpAtvApplyBtn');
    const acosApplyBtn = document.getElementById('aaExpAcosApplyBtn');
    const acoasApplyBtn = document.getElementById('aaExpAcoasApplyBtn');
    const metaEl = document.getElementById('aaProfitMeta');
    if (saveBtn && !saveBtn.dataset.bound) {
      saveBtn.dataset.bound = '1';
      saveBtn.addEventListener('click', saveExpMetricsAndContinue);
    }
    if (cancelBtn && !cancelBtn.dataset.bound) {
      cancelBtn.dataset.bound = '1';
      cancelBtn.addEventListener('click', () => closeExpMetricsModal(false));
    }
    if (atvApplyBtn && !atvApplyBtn.dataset.bound) {
      atvApplyBtn.dataset.bound = '1';
      atvApplyBtn.addEventListener('click', applySuggestedAtv);
    }
    if (acosApplyBtn && !acosApplyBtn.dataset.bound) {
      acosApplyBtn.dataset.bound = '1';
      acosApplyBtn.addEventListener('click', applySuggestedAcos);
    }
    if (acoasApplyBtn && !acoasApplyBtn.dataset.bound) {
      acoasApplyBtn.dataset.bound = '1';
      acoasApplyBtn.addEventListener('click', applySuggestedAcoas);
    }
    if (metaEl && !metaEl.dataset.profitBound) {
      metaEl.dataset.profitBound = '1';
      metaEl.addEventListener('click', (e) => {
        if (!e.target.closest('.aa-profit-exp-edit-btn')) return;
        e.preventDefault();
        openExpMetricsFromPanel();
      });
      metaEl.addEventListener('change', (e) => {
        if (e.target.id !== 'aaProfitModelSelect') return;
        const key = e.target.value || 'bernoulli';
        const descEl = document.getElementById('aaProfitModelDesc');
        const model = PROFIT_MODELS[key] || PROFIT_MODELS.bernoulli;
        if (descEl) descEl.textContent = model.desc;
      });
    }
    const modal = document.getElementById('aaExpMetricsModal');
    if (modal && global.bindPmModalBackdropClose && !modal.dataset.profitBound) {
      modal.dataset.profitBound = '1';
      global.bindPmModalBackdropClose(modal, () => closeExpMetricsModal(false));
    }
    const canvas = document.getElementById('aaProfitChart');
    if (canvas && !canvas.dataset.profitChartBound) {
      bindChartInteractions(canvas);
    }
    global.addEventListener('resize', () => {
      const panel = document.getElementById('aaProfitPanel');
      if (!panel || !panel.classList.contains('is-active') || !panel._lastCtx) return;
      renderProfitChart(panel._lastCtx);
    });
  }

  NS.calculateForRecord = calculateForRecord;
  NS.renderProfitChart = renderProfitChart;
  NS.bindUi = bindUi;

  global.AmazonAdProfitProbability = NS;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindUi);
  } else {
    bindUi();
  }
})(typeof window !== 'undefined' ? window : this);
