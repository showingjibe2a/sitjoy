/* 全局共享：图片编辑弹窗（gallery / 销售产品管理共用）
 * - 统一 DOM（运行时注入 static/html/pm_image_edit_modal.html）
 * - 统一逻辑：推荐命名、启用/弃用、类型、备注、重命名、批量应用到规格、picker、提交
 */
(function () {
  function $(id) { return document.getElementById(id); }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function decodeB64Utf8(b64) {
    if (!b64) return '';
    try {
      const binary = atob(b64);
      if (typeof TextDecoder !== 'undefined') {
        const bytes = Uint8Array.from(binary, ch => ch.charCodeAt(0));
        return new TextDecoder('utf-8').decode(bytes);
      }
      return decodeURIComponent(escape(binary));
    } catch (e) {
      try { return decodeURIComponent(escape(atob(b64))); } catch (_) { return ''; }
    }
  }

  function utf8ToB64(text) {
    try {
      if (typeof TextEncoder !== 'undefined') {
        const bytes = new TextEncoder().encode(text);
        let binary = '';
        bytes.forEach(b => binary += String.fromCharCode(b));
        return btoa(binary);
      }
      return btoa(unescape(encodeURIComponent(text)));
    } catch (e) {
      return '';
    }
  }

  function getBaseNameWithoutExt(fullName) {
    const n = String(fullName || '').trim();
    if (!n) return '';
    const idx = n.lastIndexOf('.');
    return idx > 0 ? n.slice(0, idx) : n;
  }

  async function ensureInjectedOnce() {
    if (document.body && $('pmImageEditModal')) return true;
    if (!document.body) return false;
    try {
      const resp = await fetch('/static/html/pm_image_edit_modal.html', { cache: 'no-store' });
      const html = await resp.text();
      const wrap = document.createElement('div');
      wrap.innerHTML = html;
      while (wrap.firstChild) document.body.appendChild(wrap.firstChild);
      return !!$('pmImageEditModal');
    } catch (e) {
      return false;
    }
  }

  function showStatus(el, message, type) {
    if (!el) return;
    if (!message) {
      el.textContent = '';
      el.className = 'status-message';
      el.style.display = 'none';
      return;
    }
    el.textContent = message;
    el.className = 'status-message ' + (type || '');
    el.style.display = 'block';
  }

  function pickActiveRadioValue(name, fallback) {
    const el = document.querySelector(`input[name="${name}"]:checked`);
    return el ? String(el.value || fallback || '') : String(fallback || '');
  }

  // Single compatibility entry for HTML confirm dialogs.
  // `showAppConfirmAsync` in header.js only renders plain text (textContent),
  // so HTML dialogs must use this custom renderer.
  function showHtmlConfirmCompat(opts) {
    const conf = opts || {};
    const htmlText = String(conf.htmlText || conf.message || conf.description || '').trim();
    if (!htmlText) return Promise.resolve(false);
    const title = String(conf.title || '确认');
    const confirmText = String(conf.confirmText || '确定');
    const cancelText = String(conf.cancelText || '取消');
    const maxWidth = Number(conf.maxWidth || 920);

    return new Promise((resolve) => {
      const modal = document.createElement('div');
      modal.className = 'pm-modal active';
      modal.innerHTML = `
        <div class="pm-modal-content" style="max-width:${maxWidth}px;">
          <h3 style="margin-top:0;">${escapeHtml(title)}</h3>
          <div class="pm-modal-scroll"><div id="appHtmlConfirmBody"></div></div>
          <div class="pm-modal-actions">
            <button type="button" class="btn-secondary" id="appHtmlConfirmCancel">${escapeHtml(cancelText)}</button>
            <button type="button" class="btn-primary" id="appHtmlConfirmOk">${escapeHtml(confirmText)}</button>
          </div>
        </div>
      `;
      const bodyEl = modal.querySelector('#appHtmlConfirmBody');
      if (bodyEl) bodyEl.innerHTML = htmlText;
      const okBtn = modal.querySelector('#appHtmlConfirmOk');
      const cancelBtn = modal.querySelector('#appHtmlConfirmCancel');

      const cleanup = (result) => {
        document.removeEventListener('keydown', onEsc);
        if (modal && modal.parentNode) modal.parentNode.removeChild(modal);
        if (window.syncModalScrollLock) window.syncModalScrollLock();
        resolve(!!result);
      };
      const onEsc = (e) => { if (e.key === 'Escape') cleanup(false); };

      okBtn && okBtn.addEventListener('click', () => cleanup(true));
      cancelBtn && cancelBtn.addEventListener('click', () => cleanup(false));
      modal.addEventListener('click', (e) => {
        if (e.target === modal) cleanup(false);
      });
      document.addEventListener('keydown', onEsc);
      document.body.appendChild(modal);
      if (window.syncModalScrollLock) window.syncModalScrollLock();
    });
  }
  if (!window.showHtmlConfirmCompat) {
    window.showHtmlConfirmCompat = showHtmlConfirmCompat;
  }

  function bindSegment(segEl, onPick) {
    if (!segEl || segEl.dataset._bound === '1') return;
    segEl.dataset._bound = '1';
    segEl.querySelectorAll('button[data-value]').forEach(btn => {
      btn.addEventListener('click', () => {
        const v = String(btn.getAttribute('data-value') || '').trim();
        onPick(v);
      });
    });
  }

  function setSegmentValue(segEl, value) {
    if (!segEl) return;
    const v = String(value == null ? '' : value).trim();
    segEl.dataset.value = v;
    segEl.querySelectorAll('button[data-value]').forEach(btn => {
      const bv = String(btn.getAttribute('data-value') || '').trim();
      btn.classList.toggle('is-active', bv === v);
    });
  }

  function getSegmentValue(segEl, fallback) {
    const v = String(segEl?.dataset?.value || '').trim();
    if (v === '') return String(fallback == null ? '' : fallback);
    return v;
  }

  // ====== module state ======
  let inited = false;
  let ctx = null; // { mode, hooks }

  let current = null; // { pathB64, name }
  let variantOptions = [];
  let selectedVariantIds = new Set();
  let fabricOptions = [];
  let orderProductOptions = [];
  let selectedFabricIds = new Set();
  let selectedOrderProductIds = new Set();
  /** name -> { applies_fabric, applies_sales, applies_order_product } */
  let typeScopeByName = {};

  let touched = {
    type: false,
    enabled: false,
    desc: false,
    recommendName: false,
  };
  let initial = {
    enabled: 1,
    desc: '',
  };

  function isRecommendNameEnabled() {
    return getSegmentValue($('pmImageEditRecommendNameSegment'), '1') === '1';
  }

  function setRecommendNameEnabled(enabled) {
    const seg = $('pmImageEditRecommendNameSegment');
    setSegmentValue(seg, enabled ? '1' : '0');
    applyRecommendedNameIfNeeded(true);
  }

  function getSelectedTypeName() {
    return getSegmentValue($('pmImageEditTypeSegment'), '');
  }

  function setTypeName(name, fromUser) {
    setSegmentValue($('pmImageEditTypeSegment'), String(name || '').trim());
    if (fromUser) touched.type = true;
    applyRecommendedNameIfNeeded();
    updateApplyHintUi();
    updatePickerButtonsState();
  }

  function getEnabledValue() {
    return getSegmentValue($('pmImageEditEnabledSegment'), '1') === '1' ? 1 : 0;
  }

  function setEnabledValue(v, fromUser) {
    setSegmentValue($('pmImageEditEnabledSegment'), String(Number(v) ? 1 : 0));
    if (fromUser) touched.enabled = true;
  }

  function getDescValue() {
    return String($('pmImageEditDescInput')?.value || '').trim();
  }

  function setDescValue(v, fromUser) {
    const el = $('pmImageEditDescInput');
    if (el) el.value = String(v || '');
    if (fromUser) touched.desc = true;
  }

  function getCommonFabricName() {
    const fids = Array.from(selectedFabricIds || []).map(v => Number(v)).filter(v => v > 0);
    if (fids.length) {
      const fmap = new Map((fabricOptions || []).map(it => [Number(it.fabric_id || 0), it]));
      const names = fids.map(fid => {
        const it = fmap.get(fid) || {};
        return String(it.fabric_name_en || it.fabric_code || '').trim();
      }).filter(Boolean);
      if (!names.length) return '';
      const first = names[0];
      if (names.every(f => f === first)) return first;
      return '';
    }
    const vids = Array.from(selectedVariantIds || []).map(v => Number(v)).filter(v => v > 0);
    if (!vids.length) return '';
    const map = new Map((variantOptions || []).map(it => [Number(it.variant_id || 0), it]));
    const fabrics = vids.map(vid => {
      const it = map.get(vid) || {};
      return String(it.fabric_name_en || it.fabric_code || '').trim();
    }).filter(Boolean);
    if (!fabrics.length) return '';
    const first = fabrics[0];
    if (fabrics.every(f => f === first)) return first;
    return '';
  }

  function getTypeScopeForCurrentType() {
    const name = getSelectedTypeName();
    if (!name) return { applies_fabric: false, applies_sales: false, applies_order_product: false };
    const sc = typeScopeByName[name];
    if (sc) return sc;
    return { applies_fabric: true, applies_sales: true, applies_order_product: true };
  }

  function validateLinkSelectionVsType() {
    const typeName = getSelectedTypeName();
    const errs = [];
    const hasFab = Number(selectedFabricIds && selectedFabricIds.size) > 0;
    const hasVar = Number(selectedVariantIds && selectedVariantIds.size) > 0;
    const hasOp = Number(selectedOrderProductIds && selectedOrderProductIds.size) > 0;
    if ((hasFab || hasVar || hasOp) && !typeName) {
      errs.push('已勾选关联目标时必须先选择图片类型');
      return { ok: false, errors: errs };
    }
    if (!typeName) return { ok: true, errors: [] };
    const sc = getTypeScopeForCurrentType();
    if (hasFab && !sc.applies_fabric) errs.push('当前类型不允许关联面料');
    if (hasVar && !sc.applies_sales) errs.push('当前类型不允许关联销售规格');
    if (hasOp && !sc.applies_order_product) errs.push('当前类型不允许关联下单产品');
    return { ok: errs.length === 0, errors: errs };
  }

  function updateApplyHintUi() {
    const hint = $('pmImageEditApplyHint');
    const submit = $('pmImageEditSubmitBtn');
    const v = validateLinkSelectionVsType();
    if (!hint) return;
    if (!v.ok) {
      hint.textContent = v.errors.join('；');
      if (submit) submit.disabled = true;
      return;
    }
    hint.textContent = '';
    if (submit) submit.disabled = false;
  }

  function updatePickerButtonsState() {
    const typeOk = !!getSelectedTypeName();
    const sc = getTypeScopeForCurrentType();
    const pf = $('pmImageEditPickFabricBtn');
    const pv = $('pmImageEditPickVariantBtn');
    const po = $('pmImageEditPickOrderProductBtn');
    if (pf) {
      pf.disabled = !typeOk || !sc.applies_fabric;
      pf.title = !typeOk ? '请先选择图片类型' : (!sc.applies_fabric ? '当前图片类型不适用面料' : '');
    }
    if (pv) {
      pv.disabled = !typeOk || !sc.applies_sales;
      pv.title = !typeOk ? '请先选择图片类型' : (!sc.applies_sales ? '当前图片类型不适用规格主图' : '');
    }
    if (po) {
      po.disabled = !typeOk || !sc.applies_order_product;
      po.title = !typeOk ? '请先选择图片类型' : (!sc.applies_order_product ? '当前图片类型不适用下单产品主图' : '');
    }
  }

  function computeRecommendedBaseName() {
    if (!current) return '';
    const fabric = getCommonFabricName();
    const typeName = getSelectedTypeName();
    const base = getBaseNameWithoutExt(current.name);
    const wantType = String(typeName || '').trim();
    const wantFabric = String(fabric || '').trim();
    if (!wantType) return '';

    const alreadyOk = (() => {
      if (wantFabric) {
        const prefix = `${wantFabric}-${wantType}-`;
        return base.startsWith(prefix) && base.length > prefix.length;
      }
      const prefix = `${wantType}-`;
      return base.startsWith(prefix) && base.length > prefix.length;
    })();
    if (alreadyOk) return base;

    const parts = [];
    if (wantFabric) parts.push(wantFabric);
    parts.push(wantType);
    parts.push(base || '');
    return parts.filter(Boolean).join('-');
  }

  function applyRecommendedNameIfNeeded(force) {
    if (!current) return;
    const input = $('pmImageEditNewNameInput');
    if (!input) return;
    if (!isRecommendNameEnabled()) return;
    const rec = computeRecommendedBaseName();
    if (!rec) return;
    if (force || !touched.recommendName) input.value = rec;
  }

  function updateSelectedVariantTable() {
    const tbody = $('pmImageEditSelectedTbody');
    if (!tbody) return;
    const vids = Array.from(selectedVariantIds || []).map(v => Number(v)).filter(v => v > 0);
    if (!vids.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="helper-text" style="text-align:center;">未选择</td></tr>`;
      applyRecommendedNameIfNeeded();
      updateApplyHintUi();
      return;
    }
    const map = new Map((variantOptions || []).map(it => [Number(it.variant_id || 0), it]));
    tbody.innerHTML = vids.map(vid => {
      const it = map.get(vid) || {};
      const sku = escapeHtml(String(it.sku_family || '-'));
      const spec = escapeHtml(String(it.spec_name || '-'));
      const fabric = escapeHtml(String(it.fabric_name_en || it.fabric_code || '-'));
      return `
        <tr>
          <td>${sku}</td>
          <td>${spec}</td>
          <td>${fabric}</td>
          <td style="text-align:right;">
            <button type="button" class="btn-danger" style="padding:0.28rem 0.55rem; font-size:0.82rem; min-height:28px;" data-remove-vid="${vid}">移除</button>
          </td>
        </tr>
      `;
    }).join('');
    tbody.querySelectorAll('button[data-remove-vid]').forEach(btn => {
      btn.addEventListener('click', () => {
        const vid = Number(btn.getAttribute('data-remove-vid') || 0);
        if (!vid) return;
        selectedVariantIds.delete(vid);
        updateSelectedVariantTable();
      });
    });
    applyRecommendedNameIfNeeded();
    updateApplyHintUi();
  }

  function updateSelectedFabricTable() {
    const tbody = $('pmImageEditSelectedFabricTbody');
    if (!tbody) return;
    const ids = Array.from(selectedFabricIds || []).map(v => Number(v)).filter(v => v > 0);
    if (!ids.length) {
      tbody.innerHTML = `<tr><td colspan="3" class="helper-text" style="text-align:center;">未选择</td></tr>`;
      applyRecommendedNameIfNeeded();
      updateApplyHintUi();
      return;
    }
    const map = new Map((fabricOptions || []).map(it => [Number(it.fabric_id || 0), it]));
    tbody.innerHTML = ids.map(fid => {
      const it = map.get(fid) || {};
      const code = escapeHtml(String(it.fabric_code || '-'));
      const name = escapeHtml(String(it.fabric_name_en || '-'));
      return `
        <tr>
          <td>${code}</td>
          <td>${name}</td>
          <td style="text-align:right;">
            <button type="button" class="btn-danger" style="padding:0.28rem 0.55rem; font-size:0.82rem; min-height:28px;" data-remove-fid="${fid}">移除</button>
          </td>
        </tr>
      `;
    }).join('');
    tbody.querySelectorAll('button[data-remove-fid]').forEach(btn => {
      btn.addEventListener('click', () => {
        const fid = Number(btn.getAttribute('data-remove-fid') || 0);
        if (!fid) return;
        selectedFabricIds.delete(fid);
        updateSelectedFabricTable();
      });
    });
    applyRecommendedNameIfNeeded();
    updateApplyHintUi();
  }

  function updateSelectedOrderProductTable() {
    const tbody = $('pmImageEditSelectedOrderProductTbody');
    if (!tbody) return;
    const ids = Array.from(selectedOrderProductIds || []).map(v => Number(v)).filter(v => v > 0);
    if (!ids.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="helper-text" style="text-align:center;">未选择</td></tr>`;
      updateApplyHintUi();
      return;
    }
    const map = new Map((orderProductOptions || []).map(it => [Number(it.order_product_id || 0), it]));
    tbody.innerHTML = ids.map(oid => {
      const it = map.get(oid) || {};
      const fam = escapeHtml(String(it.sku_family || '-'));
      const sku = escapeHtml(String(it.sku || '-'));
      const spec = escapeHtml(String(it.spec_qty_short || '-'));
      return `
        <tr>
          <td>${fam}</td>
          <td>${sku}</td>
          <td>${spec}</td>
          <td style="text-align:right;">
            <button type="button" class="btn-danger" style="padding:0.28rem 0.55rem; font-size:0.82rem; min-height:28px;" data-remove-opid="${oid}">移除</button>
          </td>
        </tr>
      `;
    }).join('');
    tbody.querySelectorAll('button[data-remove-opid]').forEach(btn => {
      btn.addEventListener('click', () => {
        const oid = Number(btn.getAttribute('data-remove-opid') || 0);
        if (!oid) return;
        selectedOrderProductIds.delete(oid);
        updateSelectedOrderProductTable();
      });
    });
    updateApplyHintUi();
  }

  async function ensureFabricOptions() {
    if (Array.isArray(fabricOptions) && fabricOptions.length) return fabricOptions;
    const resp = await fetch('/api/gallery-fabric-picker');
    const data = await resp.json();
    if (!data || data.status !== 'success') throw new Error((data && data.message) ? data.message : '无法加载面料列表');
    fabricOptions = Array.isArray(data.items) ? data.items : [];
    return fabricOptions;
  }

  async function ensureOrderProductOptions() {
    if (Array.isArray(orderProductOptions) && orderProductOptions.length) return orderProductOptions;
    const resp = await fetch('/api/gallery-order-product-picker');
    const data = await resp.json();
    if (!data || data.status !== 'success') throw new Error((data && data.message) ? data.message : '无法加载下单产品列表');
    orderProductOptions = Array.isArray(data.items) ? data.items : [];
    return orderProductOptions;
  }

  async function ensureVariantOptions() {
    if (Array.isArray(variantOptions) && variantOptions.length) return variantOptions;
    const resp = await fetch('/api/gallery-variant-picker');
    const data = await resp.json();
    if (!data || data.status !== 'success') throw new Error((data && data.message) ? data.message : '无法加载规格列表');
    variantOptions = Array.isArray(data.items) ? data.items : [];
    return variantOptions;
  }

  function openVariantPicker() {
    if (!getSelectedTypeName()) {
      window.showAppToast && window.showAppToast('请先选择图片类型', true, 6000);
      return;
    }
    const sc = getTypeScopeForCurrentType();
    if (!sc.applies_sales) {
      window.showAppToast && window.showAppToast('当前图片类型不允许关联销售规格', true, 7000);
      return;
    }
    ensureVariantOptions().then(items => {
      const STORAGE_KEY = 'sitjoy_gallery_variant_search_v1';
      const loadSearchState = () => { try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') || {}; } catch (_) { return {}; } };
      const saveSearchState = (next) => { try { localStorage.setItem(STORAGE_KEY, JSON.stringify(next || {})); } catch (_) {} };

      const html = `
        <div style="display:grid; gap:0.6rem;">
          <div class="helper-text" style="margin:0;">可分别搜索：货号 / 规格 / 面料（支持多选）</div>
          <div style="border:1px solid rgba(207,199,189,0.7); border-radius:10px; background:#fff; overflow:hidden;">
            <table class="pm-table" data-disable-table-manage="1" style="margin:0;">
              <thead style="position:sticky; top:0; z-index:1;">
                <tr>
                  <th style="width:68px; text-align:center;">
                    <label style="display:inline-flex; align-items:center; gap:0.35rem; user-select:none; cursor:pointer;">
                      <input type="checkbox" id="pmVariantSelectAll">
                      <span style="font-size:0.86rem;">全选</span>
                    </label>
                  </th>
                  <th style="width:210px;">
                    <div style="display:grid; gap:0.25rem;">
                      <div style="font-size:0.82rem; color:var(--morandi-slate);">货号</div>
                      <input type="text" id="pmVariantSearchSku" class="pm-select-search" placeholder="搜索货号" style="margin:0;">
                    </div>
                  </th>
                  <th style="width:210px;">
                    <div style="display:grid; gap:0.25rem;">
                      <div style="font-size:0.82rem; color:var(--morandi-slate);">规格</div>
                      <input type="text" id="pmVariantSearchSpec" class="pm-select-search" placeholder="搜索规格" style="margin:0;">
                    </div>
                  </th>
                  <th>
                    <div style="display:grid; gap:0.25rem;">
                      <div style="font-size:0.82rem; color:var(--morandi-slate);">面料</div>
                      <input type="text" id="pmVariantSearchFabric" class="pm-select-search" placeholder="搜索面料" style="margin:0;">
                    </div>
                  </th>
                </tr>
              </thead>
              <tbody id="pmVariantTbody"></tbody>
            </table>
          </div>
          <div class="helper-text" style="margin:0;">提示：输入框会在本地记忆（同一次访问）以节省重复筛选时间。</div>
        </div>
      `;

      if (!window.showAppConfirmAsync) {
        window.showAppToast && window.showAppToast('当前环境缺少通用确认弹窗（showAppConfirmAsync），无法打开选择规格。', true, 8000);
        return;
      }

      const p = showHtmlConfirmCompat({
        title: '选择规格',
        htmlText: html,
        confirmText: '确定',
        cancelText: '取消',
        maxWidth: 920
      });

      const bindPickerUi = (retryCount) => {
        const state = loadSearchState();
        const skuEl = $('pmVariantSearchSku');
        const specEl = $('pmVariantSearchSpec');
        const fabEl = $('pmVariantSearchFabric');
        const tbody = $('pmVariantTbody');
        if (!skuEl || !specEl || !fabEl || !tbody) {
          if ((retryCount || 0) < 12) {
            setTimeout(() => bindPickerUi((retryCount || 0) + 1), 30);
          }
          return;
        }
        if (skuEl) skuEl.value = String(state.sku || '');
        if (specEl) specEl.value = String(state.spec || '');
        if (fabEl) fabEl.value = String(state.fabric || '');

        const render = () => {
          const skuQ = String(skuEl?.value || '').trim().toLowerCase();
          const specQ = String(specEl?.value || '').trim().toLowerCase();
          const fabQ = String(fabEl?.value || '').trim().toLowerCase();
          saveSearchState({ sku: skuEl?.value || '', spec: specEl?.value || '', fabric: fabEl?.value || '' });
          const tbody = $('pmVariantTbody');
          if (!tbody) return;
          const rows = (items || []).filter(it => {
            const sku = String(it.sku_family || '').toLowerCase();
            const spec = String(it.spec_name || '').toLowerCase();
            const fab = String(it.fabric_name_en || it.fabric_code || '').toLowerCase();
            if (skuQ && !sku.includes(skuQ)) return false;
            if (specQ && !spec.includes(specQ)) return false;
            if (fabQ && !fab.includes(fabQ)) return false;
            return true;
          });
          tbody.innerHTML = rows.map(it => {
            const vid = Number(it.variant_id || 0);
            const checked = selectedVariantIds.has(vid) ? 'checked' : '';
            return `
              <tr>
                <td style="text-align:center;"><input type="checkbox" class="pmVariantPickBox" data-vid="${vid}" ${checked}></td>
                <td>${escapeHtml(it.sku_family || '')}</td>
                <td>${escapeHtml(it.spec_name || '')}</td>
                <td>${escapeHtml(it.fabric_name_en || it.fabric_code || '')}</td>
              </tr>
            `;
          }).join('');
          tbody.querySelectorAll('input.pmVariantPickBox').forEach(box => {
            box.addEventListener('change', () => {
              const vid = Number(box.getAttribute('data-vid') || 0);
              if (!vid) return;
              if (box.checked) selectedVariantIds.add(vid);
              else selectedVariantIds.delete(vid);
            });
          });
          const selAll = $('pmVariantSelectAll');
          if (selAll) selAll.checked = rows.length > 0 && rows.every(r => selectedVariantIds.has(Number(r.variant_id || 0)));
        };

        [skuEl, specEl, fabEl].forEach(el => el && el.addEventListener('input', render));
        const selAll = $('pmVariantSelectAll');
        if (selAll) {
          selAll.addEventListener('change', () => {
            const tbody = $('pmVariantTbody');
            if (!tbody) return;
            const boxes = Array.from(tbody.querySelectorAll('input.pmVariantPickBox'));
            boxes.forEach(box => {
              const vid = Number(box.getAttribute('data-vid') || 0);
              if (!vid) return;
              if (selAll.checked) selectedVariantIds.add(vid);
              else selectedVariantIds.delete(vid);
              box.checked = selAll.checked;
            });
          });
        }
        render();
      };
      bindPickerUi(0);

      Promise.resolve(p).then(ok => {
        if (!ok) return;
        updateSelectedVariantTable();
        applyRecommendedNameIfNeeded(true);
      }).catch(() => {});
    }).catch(err => {
      window.showAppToast && window.showAppToast('加载规格列表失败：' + (err && err.message ? err.message : err), true, 8000);
    });
  }

  function openFabricPicker() {
    if (!getSelectedTypeName()) {
      window.showAppToast && window.showAppToast('请先选择图片类型', true, 6000);
      return;
    }
    const sc = getTypeScopeForCurrentType();
    if (!sc.applies_fabric) {
      window.showAppToast && window.showAppToast('当前图片类型不允许关联面料', true, 7000);
      return;
    }
    ensureFabricOptions().then(items => {
      const html = `
        <div style="display:grid; gap:0.6rem;">
          <div class="helper-text" style="margin:0;">搜索面料代码或名称（支持多选）</div>
          <div style="border:1px solid rgba(207,199,189,0.7); border-radius:10px; background:#fff; overflow:hidden;">
            <table class="pm-table" data-disable-table-manage="1" style="margin:0;">
              <thead style="position:sticky; top:0; z-index:1;">
                <tr>
                  <th style="width:68px; text-align:center;">选</th>
                  <th style="width:200px;"><div style="font-size:0.82rem;">代码</div><input type="text" id="pmFabricSearchCode" class="pm-select-search" placeholder="搜索" style="margin:0;"></th>
                  <th><div style="font-size:0.82rem;">英文名称</div><input type="text" id="pmFabricSearchName" class="pm-select-search" placeholder="搜索" style="margin:0;"></th>
                </tr>
              </thead>
              <tbody id="pmFabricTbody"></tbody>
            </table>
          </div>
        </div>
      `;
      const p = showHtmlConfirmCompat({ title: '选择面料', htmlText: html, confirmText: '确定', cancelText: '取消', maxWidth: 720 });
      const bindUi = (n) => {
        const cEl = $('pmFabricSearchCode');
        const nEl = $('pmFabricSearchName');
        const tbody = $('pmFabricTbody');
        if (!cEl || !nEl || !tbody) {
          if ((n || 0) < 12) setTimeout(() => bindUi((n || 0) + 1), 30);
          return;
        }
        const render = () => {
          const cq = String(cEl.value || '').trim().toLowerCase();
          const nq = String(nEl.value || '').trim().toLowerCase();
          const rows = (items || []).filter(it => {
            const code = String(it.fabric_code || '').toLowerCase();
            const nm = String(it.fabric_name_en || '').toLowerCase();
            if (cq && !code.includes(cq)) return false;
            if (nq && !nm.includes(nq)) return false;
            return true;
          });
          tbody.innerHTML = rows.map(it => {
            const fid = Number(it.fabric_id || 0);
            const ck = selectedFabricIds.has(fid) ? 'checked' : '';
            return `<tr><td style="text-align:center;"><input type="checkbox" class="pmFabricPickBox" data-fid="${fid}" ${ck}></td><td>${escapeHtml(it.fabric_code || '')}</td><td>${escapeHtml(it.fabric_name_en || '')}</td></tr>`;
          }).join('');
          tbody.querySelectorAll('input.pmFabricPickBox').forEach(box => {
            box.addEventListener('change', () => {
              const fid = Number(box.getAttribute('data-fid') || 0);
              if (!fid) return;
              if (box.checked) selectedFabricIds.add(fid);
              else selectedFabricIds.delete(fid);
            });
          });
        };
        [cEl, nEl].forEach(el => el && el.addEventListener('input', render));
        render();
      };
      bindUi(0);
      Promise.resolve(p).then(ok => {
        if (!ok) return;
        updateSelectedFabricTable();
        applyRecommendedNameIfNeeded(true);
      }).catch(() => {});
    }).catch(err => {
      window.showAppToast && window.showAppToast('加载面料失败：' + (err && err.message ? err.message : err), true, 8000);
    });
  }

  function openOrderProductPicker() {
    if (!getSelectedTypeName()) {
      window.showAppToast && window.showAppToast('请先选择图片类型', true, 6000);
      return;
    }
    const sc = getTypeScopeForCurrentType();
    if (!sc.applies_order_product) {
      window.showAppToast && window.showAppToast('当前图片类型不允许关联下单产品', true, 7000);
      return;
    }
    ensureOrderProductOptions().then(items => {
      const html = `
        <div style="display:grid; gap:0.6rem;">
          <div class="helper-text" style="margin:0;">搜索货号 / SKU / 规格简称（支持多选；列表最多约 8000 条）</div>
          <div style="border:1px solid rgba(207,199,189,0.7); border-radius:10px; background:#fff; overflow:hidden; max-height:62vh;">
            <table class="pm-table" data-disable-table-manage="1" style="margin:0;">
              <thead style="position:sticky; top:0; z-index:1;">
                <tr>
                  <th style="width:68px; text-align:center;">选</th>
                  <th style="width:140px;"><div style="font-size:0.82rem;">货号</div><input type="text" id="pmOpSearchFam" class="pm-select-search" placeholder="搜索" style="margin:0;"></th>
                  <th style="width:220px;"><div style="font-size:0.82rem;">SKU</div><input type="text" id="pmOpSearchSku" class="pm-select-search" placeholder="搜索" style="margin:0;"></th>
                  <th><div style="font-size:0.82rem;">规格简称</div><input type="text" id="pmOpSearchSpec" class="pm-select-search" placeholder="搜索" style="margin:0;"></th>
                </tr>
              </thead>
              <tbody id="pmOpTbody"></tbody>
            </table>
          </div>
        </div>
      `;
      const p = showHtmlConfirmCompat({ title: '选择下单产品', htmlText: html, confirmText: '确定', cancelText: '取消', maxWidth: 920 });
      const bindUi = (n) => {
        const a = $('pmOpSearchFam');
        const b = $('pmOpSearchSku');
        const c = $('pmOpSearchSpec');
        const tbody = $('pmOpTbody');
        if (!a || !b || !c || !tbody) {
          if ((n || 0) < 12) setTimeout(() => bindUi((n || 0) + 1), 30);
          return;
        }
        const render = () => {
          const fq = String(a.value || '').trim().toLowerCase();
          const sq = String(b.value || '').trim().toLowerCase();
          const pq = String(c.value || '').trim().toLowerCase();
          const rows = (items || []).filter(it => {
            const fam = String(it.sku_family || '').toLowerCase();
            const sku = String(it.sku || '').toLowerCase();
            const sp = String(it.spec_qty_short || '').toLowerCase();
            if (fq && !fam.includes(fq)) return false;
            if (sq && !sku.includes(sq)) return false;
            if (pq && !sp.includes(pq)) return false;
            return true;
          });
          tbody.innerHTML = rows.map(it => {
            const oid = Number(it.order_product_id || 0);
            const ck = selectedOrderProductIds.has(oid) ? 'checked' : '';
            return `<tr><td style="text-align:center;"><input type="checkbox" class="pmOpPickBox" data-opid="${oid}" ${ck}></td><td>${escapeHtml(it.sku_family || '')}</td><td>${escapeHtml(it.sku || '')}</td><td>${escapeHtml(it.spec_qty_short || '')}</td></tr>`;
          }).join('');
          tbody.querySelectorAll('input.pmOpPickBox').forEach(box => {
            box.addEventListener('change', () => {
              const oid = Number(box.getAttribute('data-opid') || 0);
              if (!oid) return;
              if (box.checked) selectedOrderProductIds.add(oid);
              else selectedOrderProductIds.delete(oid);
            });
          });
        };
        [a, b, c].forEach(el => el && el.addEventListener('input', render));
        render();
      };
      bindUi(0);
      Promise.resolve(p).then(ok => {
        if (!ok) return;
        updateSelectedOrderProductTable();
      }).catch(() => {});
    }).catch(err => {
      window.showAppToast && window.showAppToast('加载下单产品失败：' + (err && err.message ? err.message : err), true, 8000);
    });
  }

  async function refreshTypeOptions() {
    const seg = $('pmImageEditTypeSegment');
    if (!seg) return;
    try {
      let resp = await fetch('/api/gallery-image-types');
      let data = await resp.json();
      if (!data || data.status !== 'success' || !Array.isArray(data.items)) {
        resp = await fetch('/api/sales-image-type?usage=sales');
        data = await resp.json();
      }
      const items = (data && data.status === 'success' && Array.isArray(data.items)) ? data.items : [];
      typeScopeByName = {};
      items.forEach(it => {
        const nm = String(it.name || '').trim();
        if (!nm) return;
        typeScopeByName[nm] = {
          applies_fabric: !!it.applies_fabric,
          applies_sales: !!it.applies_sales,
          applies_order_product: !!it.applies_order_product,
        };
      });
      const current = String(seg.dataset.value || '').trim();
      const btns = items.map(it => {
        const name = String(it.name || '').trim();
        if (!name) return '';
        const safe = escapeHtml(name);
        const isActive = current && current === name;
        return `<button type="button" class="status-pill status-pill--yes ${isActive ? 'is-active' : ''}" data-value="${safe}">${safe}</button>`;
      }).filter(Boolean);
      seg.innerHTML = btns.length ? btns.join('') : `<button type="button" class="status-pill status-pill--no is-active" data-value="">暂无可用类型</button>`;
      seg.dataset._bound = '';
      bindSegment(seg, v => setTypeName(v, true));
      if (current) setTypeName(current, false);
      updateApplyHintUi();
      updatePickerButtonsState();
    } catch (e) {
      // ignore
    }
  }

  async function tryPrefillMetaFromDb() {
    if (!current || !current.pathB64) return;
    try {
      const resp = await fetch('/api/gallery-image-meta?id=' + encodeURIComponent(current.pathB64));
      const data = await resp.json();
      if (!data || data.status !== 'success' || !data.linked) return;
      if (!touched.enabled && typeof data.is_enabled !== 'undefined') {
        const enabled = Number(data.is_enabled) ? 1 : 0;
        initial.enabled = enabled;
        setEnabledValue(enabled, false);
      }
      if (!touched.desc && typeof data.description !== 'undefined') {
        const desc = String(data.description || '');
        initial.desc = desc;
        setDescValue(desc, false);
      }
      if (!touched.type) {
        if (data.image_type_name) setTypeName(String(data.image_type_name || '').trim(), false);
        else setTypeName('', false);
      }
    } catch (e) {
      // ignore
    }
  }

  async function tryPrefillVariantLinksFromDbIfEnabled() {
    if (!ctx || !ctx.hooks || !ctx.hooks.prefillVariantLinks) return;
    if (!current || !current.pathB64) return;
    try {
      const resp = await fetch('/api/gallery-image-links?id=' + encodeURIComponent(current.pathB64));
      const data = await resp.json();
      if (!data || data.status !== 'success' || !data.linked) return;
      const vids = Array.isArray(data.variant_ids) ? data.variant_ids : [];
      const nextV = new Set(vids.map(v => Number(v)).filter(v => v > 0));
      if (nextV.size) selectedVariantIds = nextV;

      const fids = Array.isArray(data.fabric_ids) ? data.fabric_ids : [];
      const nextF = new Set(fids.map(v => Number(v)).filter(v => v > 0));
      if (nextF.size) selectedFabricIds = nextF;
      const fabrics = Array.isArray(data.fabrics) ? data.fabrics : [];
      if (fabrics.length) {
        const merged = Array.isArray(fabricOptions) ? fabricOptions.slice() : [];
        const seen = new Set(merged.map(x => Number(x.fabric_id || 0)));
        fabrics.forEach(f => {
          const id = Number(f.fabric_id || 0);
          if (!id || seen.has(id)) return;
          seen.add(id);
          merged.push({
            fabric_id: id,
            fabric_code: String(f.fabric_code || ''),
            fabric_name_en: String(f.fabric_name_en || ''),
          });
        });
        fabricOptions = merged;
      }

      const opids = Array.isArray(data.order_product_ids) ? data.order_product_ids : [];
      const nextO = new Set(opids.map(v => Number(v)).filter(v => v > 0));
      if (nextO.size) selectedOrderProductIds = nextO;
      const ops = Array.isArray(data.order_products) ? data.order_products : [];
      if (ops.length) {
        const merged = Array.isArray(orderProductOptions) ? orderProductOptions.slice() : [];
        const seen = new Set(merged.map(x => Number(x.order_product_id || 0)));
        ops.forEach(f => {
          const id = Number(f.order_product_id || 0);
          if (!id || seen.has(id)) return;
          seen.add(id);
          merged.push({
            order_product_id: id,
            sku: String(f.sku || ''),
            sku_family: String(f.sku_family || ''),
            spec_qty_short: String(f.spec_qty_short || ''),
          });
        });
        orderProductOptions = merged;
      }

      updateSelectedVariantTable();
      updateSelectedFabricTable();
      updateSelectedOrderProductTable();
      updateApplyHintUi();
    } catch (e) {}
  }

  function openModal() {
    const m = $('pmImageEditModal');
    if (m) m.classList.add('active');
  }
  function closeModal() {
    const m = $('pmImageEditModal');
    if (m) m.classList.remove('active');
    showStatus($('pmImageEditStatus'), '', '');
    current = null;
  }

  async function confirmSubmit() {
    if (!current || !current.pathB64) return;
    const statusDiv = $('pmImageEditStatus');

    // name
    const oldName = String(current.name || '').trim();
    const oldBase = getBaseNameWithoutExt(oldName);
    let newBase = String($('pmImageEditNewNameInput')?.value || '').trim();
    if (!newBase) newBase = oldBase;
    const renameNeeded = newBase !== oldBase;

    const typeName = getSelectedTypeName();
    const enabledVal = getEnabledValue();
    const enabledChanged = Number(enabledVal) !== Number(initial.enabled);
    const descVal = getDescValue();
    const descChanged = String(descVal) !== String(initial.desc || '');

    const vids = Array.from(selectedVariantIds || []).map(v => Number(v)).filter(v => v > 0);
    const fids = Array.from(selectedFabricIds || []).map(v => Number(v)).filter(v => v > 0);
    const opids = Array.from(selectedOrderProductIds || []).map(v => Number(v)).filter(v => v > 0);

    if (!renameNeeded && !typeName && !enabledChanged && !descChanged && !vids.length && !fids.length && !opids.length) {
      showStatus(statusDiv, '未做任何修改', 'error');
      return;
    }

    const scopeCheck = validateLinkSelectionVsType();
    if (!scopeCheck.ok) {
      showStatus(statusDiv, scopeCheck.errors.join('；'), 'error');
      return;
    }

    if ((vids.length || fids.length || opids.length) && !typeName) {
      showStatus(statusDiv, '请选择图片类型后再提交', 'error');
      return;
    }

    showStatus(statusDiv, '处理中...', 'info');
    window.showAppUploadProgress && window.showAppUploadProgress({ title: '正在提交...', summary: '关联/重命名/保存属性', percent: 25 });

    try {
      // 1) rename
      if (renameNeeded) {
        const resp = await fetch('/api/rename', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: current.pathB64, new_name_b64: utf8ToB64(newBase) })
        });
        const data = await resp.json();
        if (!data || data.status !== 'success') throw new Error((data && data.message) ? data.message : '重命名失败');

        // 更新 current.name（pathB64 的更新交给调用方 hooks）
        const ext = oldName.includes('.') ? oldName.slice(oldName.lastIndexOf('.')) : '';
        const newFilename = String(newBase || '').trim() + (ext || '');
        current.name = newFilename;
        if (ctx && ctx.hooks && typeof ctx.hooks.onRenamed === 'function') {
          // 让业务侧基于“同文件夹替换 basename”更新 pathB64
          const newPathB64 = ctx.hooks.onRenamed({ oldPathB64: current.pathB64, newFilename, oldFilename: oldName });
          if (newPathB64) current.pathB64 = newPathB64;
        }
      }

      // 2) meta
      const respMeta = await fetch('/api/gallery-image-meta', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: current.pathB64, image_type_name: typeName, is_enabled: enabledVal, description: descVal })
      });
      const meta = await respMeta.json();
      if (!meta || meta.status !== 'success') throw new Error((meta && meta.message) ? meta.message : '保存失败');
      initial.enabled = enabledVal;
      initial.desc = descVal;

      // 3) apply image（规格 / 面料 / 下单产品）
      if (vids.length || fids.length || opids.length) {
        window.showAppUploadProgress && window.showAppUploadProgress({ title: '正在提交...', summary: '写入数据库并处理文件移动/复制', percent: 65 });
        const action = pickActiveRadioValue('pmImageEditApplyAction', 'move');
        const promptDup = !!$('pmImageEditPromptDuplicate')?.checked;
        const payload = {
          image_path_b64: current.pathB64,
          variant_ids: vids,
          fabric_ids: fids,
          order_product_ids: opids,
          action,
          image_type_name: typeName,
          prompt_duplicate: promptDup ? 1 : 0
        };
        const resp2 = await fetch('/api/gallery-apply-image', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data2 = await resp2.json();
        if (!data2 || data2.status !== 'success') throw new Error((data2 && data2.message) ? data2.message : '关联失败');
      }

      showStatus(statusDiv, '✓ 已提交', 'success');
      window.showAppToast && window.showAppToast('保存成功', false, 6000);
      setTimeout(() => {
        closeModal();
        ctx && ctx.hooks && typeof ctx.hooks.onAfterSuccess === 'function' && ctx.hooks.onAfterSuccess();
      }, 220);
    } catch (e) {
      const msg = '✗ ' + (e && e.message ? e.message : e);
      showStatus(statusDiv, msg, 'error');
      window.showAppToast && window.showAppToast(msg, true, 10000);
    } finally {
      window.hideAppUploadProgress && window.hideAppUploadProgress();
    }
  }

  async function open(opts) {
    const ok = await ensureInjectedOnce();
    if (!ok) {
      window.showAppToast && window.showAppToast('弹窗注入失败：未能加载共享模板', true, 10000);
      return;
    }
    if (!inited) initOnce();

    current = { pathB64: String(opts?.pathB64 || ''), name: String(opts?.name || '') };
    touched = { type: false, enabled: false, desc: false, recommendName: false };
    initial = { enabled: 1, desc: '' };

    // reset UI
    setEnabledValue(1, false);
    setTypeName('', false);
    setDescValue('', false);
    setRecommendNameEnabled(true);
    $('pmImageEditNewNameInput').value = getBaseNameWithoutExt(current.name);
    selectedVariantIds = new Set(Array.isArray(opts?.defaultVariantIds) ? opts.defaultVariantIds.map(x => Number(x)).filter(x => x > 0) : []);
    selectedFabricIds = new Set();
    selectedOrderProductIds = new Set();
    fabricOptions = [];
    orderProductOptions = [];
    updateSelectedVariantTable();
    updateSelectedFabricTable();
    updateSelectedOrderProductTable();

    // preview
    const img = $('pmImageEditPreviewImg');
    if (img) img.src = `/api/image-preview?id=${encodeURIComponent(current.pathB64)}&mode=thumb&w=900&q=85`;

    openModal();
    await refreshTypeOptions();
    await ensureVariantOptions().catch(() => {});
    await ensureFabricOptions().catch(() => {});
    await ensureOrderProductOptions().catch(() => {});
    updateSelectedVariantTable();
    updateSelectedFabricTable();
    updateSelectedOrderProductTable();
    await tryPrefillVariantLinksFromDbIfEnabled();
    await tryPrefillMetaFromDb();
    applyRecommendedNameIfNeeded(true);
    updateApplyHintUi();
    updatePickerButtonsState();
  }

  function initOnce() {
    inited = true;

    // base bindings
    const modal = $('pmImageEditModal');
    if (modal && modal.dataset._bound !== '1') {
      modal.dataset._bound = '1';
      modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(); });
    }

    $('pmImageEditCancelBtn')?.addEventListener('click', closeModal);
    $('pmImageEditSubmitBtn')?.addEventListener('click', confirmSubmit);

    // zoom / replace
    $('pmImageEditZoomBtn')?.addEventListener('click', () => {
      if (!current || !current.pathB64) return;
      window.open(`/api/image-preview?id=${encodeURIComponent(current.pathB64)}`, '_blank');
    });
    $('pmImageEditReplaceBtn')?.addEventListener('click', () => {
      const inp = $('pmImageEditReplaceInput');
      if (!inp) return;
      inp.value = '';
      inp.click();
    });

    // Replace upload is delegated to business side (sales-product-main-images-replace etc.)
    $('pmImageEditReplaceInput')?.addEventListener('change', (e) => {
      const f = e.target && e.target.files && e.target.files[0] ? e.target.files[0] : null;
      if (!f) return;
      if (ctx && ctx.hooks && typeof ctx.hooks.onReplaceSelected === 'function') {
        ctx.hooks.onReplaceSelected({ file: f, current: Object.assign({}, current) });
      } else {
        window.showAppToast && window.showAppToast('当前页面未配置替换逻辑', true, 8000);
      }
      e.target.value = '';
    });

    // segments
    bindSegment($('pmImageEditEnabledSegment'), v => setEnabledValue(v === '1' ? 1 : 0, true));
    bindSegment($('pmImageEditRecommendNameSegment'), v => setRecommendNameEnabled(v === '1'));
    bindSegment($('pmImageEditTypeSegment'), v => setTypeName(v, true));

    // name typing
    $('pmImageEditNewNameInput')?.addEventListener('input', () => { touched.recommendName = true; });
    $('pmImageEditDescInput')?.addEventListener('input', () => { touched.desc = true; });

    // variant actions
    $('pmImageEditVariantClearBtn')?.addEventListener('click', () => {
      selectedVariantIds = new Set();
      updateSelectedVariantTable();
    });
    $('pmImageEditPickVariantBtn')?.addEventListener('click', openVariantPicker);
    $('pmImageEditFabricClearBtn')?.addEventListener('click', () => {
      selectedFabricIds = new Set();
      updateSelectedFabricTable();
    });
    $('pmImageEditPickFabricBtn')?.addEventListener('click', openFabricPicker);
    $('pmImageEditOrderProductClearBtn')?.addEventListener('click', () => {
      selectedOrderProductIds = new Set();
      updateSelectedOrderProductTable();
    });
    $('pmImageEditPickOrderProductBtn')?.addEventListener('click', openOrderProductPicker);
  }

  // Public API
  window.PmImageEditModal = {
    init: function (options) { ctx = options || {}; return true; },
    open: open,
    isOpen: function () { return $('pmImageEditModal')?.classList.contains('active'); }
  };
})();

