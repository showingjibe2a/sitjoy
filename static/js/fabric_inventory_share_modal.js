/**
 * 面料库存比例弹窗（可跨页面复用）。
 * 使用：FabricInventoryShareModal.open({ skuFamilyId: 123 })
 */
(function (global) {
  let mounted = false;
  let items = [];

  function el(id) {
    return document.getElementById(id);
  }

  // -------------------------------------------------------------------------
  // 比例输入与行状态
  // -------------------------------------------------------------------------

  function setStatus(msg, isError) {
    const node = el('fisStatus');
    if (!node) return;
    const text = String(msg || '').trim();
    if (!text) {
      node.style.display = 'none';
      node.textContent = '';
      return;
    }
    node.style.display = '';
    node.className = 'response' + (isError ? ' error' : '');
    node.textContent = text;
  }

  function pctText(ratio) {
    const n = Math.round(Number(ratio || 0) * 1000) / 10;
    return String(n) + '%';
  }

  function parseRatioInput(val) {
    const raw = String(val || '').trim().replace('%', '');
    if (!raw) return 0;
    const n = Number(raw);
    if (!Number.isFinite(n)) return 0;
    if (n > 1) return Math.max(0, Math.min(1, n / 100));
    return Math.max(0, Math.min(1, n));
  }

  function normalizeRow(row) {
    const item = Object.assign({}, row || {});
    const persisted = !!item.ratio_persisted;
    let savedRatio = item.saved_ratio;
    if (savedRatio != null && savedRatio !== '') {
      savedRatio = parseRatioInput(savedRatio);
    } else if (persisted) {
      savedRatio = parseRatioInput(item.inventory_share_ratio);
    } else {
      savedRatio = null;
    }
    item.ratio_persisted = persisted;
    item.saved_ratio = savedRatio;
    if (item.inventory_share_ratio == null) {
      item.inventory_share_ratio = item.suggested_ratio != null ? item.suggested_ratio : 0;
    }
    return item;
  }

  function syncRatioInputState(input, idx) {
    const row = items[idx];
    if (!row || !input) return;
    input.classList.remove('is-not-persisted', 'is-dirty');
    const saved = row.saved_ratio;
    const current = parseRatioInput(row.inventory_share_ratio);
    if (saved == null) {
      input.classList.add('is-not-persisted');
      return;
    }
    if (Math.abs(current - saved) > 0.0001) {
      input.classList.add('is-dirty');
    }
  }

  function onRatioInputChange(input) {
    const i = Number(input.getAttribute('data-idx'));
    if (!Number.isFinite(i) || !items[i]) return;
    items[i].inventory_share_ratio = parseRatioInput(input.value);
    input.value = pctText(items[i].inventory_share_ratio);
    syncRatioInputState(input, i);
  }

  // -------------------------------------------------------------------------
  // 弹窗挂载与表格渲染
  // -------------------------------------------------------------------------

  async function ensureMounted() {
    if (mounted && el('fabricInventoryShareModal')) return;
    const resp = await fetch('/static/partials/fabric_inventory_share_modal.html', { credentials: 'include' });
    if (!resp.ok) throw new Error('无法加载面料库存比例弹窗');
    const html = await resp.text();
    const wrap = document.createElement('div');
    wrap.innerHTML = html.trim();
    const modal = wrap.firstElementChild;
    if (!modal) throw new Error('弹窗模板为空');
    document.body.appendChild(modal);
    bindUi();
    if (global.initUniversalSingleSelects) {
      global.initUniversalSingleSelects(modal);
    }
    mounted = true;
  }

  function renderTable() {
    const tbody = el('fisRatioTbody');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;">该货号暂无关联面料</td></tr>';
      return;
    }
    tbody.innerHTML = items.map((row, idx) => {
      const ratio = row.inventory_share_ratio != null ? row.inventory_share_ratio : row.suggested_ratio;
      const ratioPct = pctText(ratio);
      const sug = pctText(row.suggested_ratio);
      return `<tr data-idx="${idx}">
        <td>${escapeHtml(row.fabric_code || '')}</td>
        <td>${escapeHtml(row.fabric_name_en || '')}</td>
        <td style="text-align:right;">${Number(row.history_sales_qty || 0)}</td>
        <td style="text-align:right;">${sug}</td>
        <td><input type="text" class="inline-input preview-edit-input fis-ratio-input" style="width:5.5rem;max-width:100%;" data-idx="${idx}" value="${ratioPct}"></td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('.fis-ratio-input').forEach(input => {
      const idx = Number(input.getAttribute('data-idx'));
      syncRatioInputState(input, idx);
      input.addEventListener('input', function () { onRatioInputChange(this); });
      input.addEventListener('change', function () { onRatioInputChange(this); });
    });
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function refreshSkuFamilySelect() {
    const sel = el('fisSkuFamily');
    if (!sel) return;
    if (global.refreshUniversalSingleSelect) {
      global.refreshUniversalSingleSelect(sel);
    } else if (global.initUniversalSingleSelects) {
      global.initUniversalSingleSelects(sel.parentElement || document);
    }
  }

  async function loadSkuFamilies(preferredId) {
    const sel = el('fisSkuFamily');
    if (!sel) return;
    const ensureId = String(preferredId || sel.value || '').trim();
    const params = new URLSearchParams({ brief: '1', limit: '3000' });
    if (ensureId) params.set('ensure_id', ensureId);
    const resp = await fetch(`/api/sku?${params.toString()}`, { credentials: 'include' });
    const data = await resp.json();
    const rows = (data && data.status === 'success') ? (data.items || []) : [];
    sel.innerHTML = ['<option value="">请选择货号</option>'].concat(
      rows.map(r => `<option value="${r.id}">${escapeHtml(r.sku_family || '')}${r.category ? ' / ' + escapeHtml(r.category) : ''}</option>`)
    ).join('');
    const old = ensureId;
    if (old) sel.value = old;
    refreshSkuFamilySelect();
  }

  function currentSkuFamilyId() {
    return String(el('fisSkuFamily')?.value || '').trim();
  }

  function histMonths() {
    return Math.max(1, Math.min(36, Number(el('fisHistMonths')?.value || 12)));
  }

  // -------------------------------------------------------------------------
  // API：加载 / 重算 / 保存
  // -------------------------------------------------------------------------

  function applyPayload(data) {
    items = (data && data.items) ? data.items.map(normalizeRow) : [];
    const meta = el('fisMetaText');
    if (meta && data) {
      const sf = data.sku_family ? `货号 ${data.sku_family}` : '';
      const range = (data.history_start_month && data.history_end_month)
        ? `统计区间 ${String(data.history_start_month).slice(0, 7)} ~ ${String(data.history_end_month).slice(0, 7)}`
        : '';
      const maxQ = data.max_history_sales_qty != null ? `最高销量 ${data.max_history_sales_qty}` : '';
      meta.textContent = [sf, range, maxQ].filter(Boolean).join(' · ');
    }
    renderTable();
  }

  async function loadCurrent(useCalculate) {
    const skuFamilyId = currentSkuFamilyId();
    if (!skuFamilyId) {
      items = [];
      renderTable();
      setStatus('请选择货号', true);
      return;
    }
    setStatus('', false);
    try {
      let resp;
      if (useCalculate) {
        resp = await fetch('/api/fabric-inventory-share', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            action: 'calculate',
            sku_family_id: Number(skuFamilyId),
            months: histMonths(),
          }),
        });
      } else {
        resp = await fetch(`/api/fabric-inventory-share?sku_family_id=${encodeURIComponent(skuFamilyId)}&months=${histMonths()}`, {
          credentials: 'include',
        });
      }
      const data = await resp.json();
      if (!resp.ok || !data || data.status === 'error') {
        throw new Error((data && data.message) ? data.message : '加载失败');
      }
      applyPayload(data);
      setStatus(useCalculate ? '已按历史销量重算比例，可微调后保存' : '', false);
    } catch (e) {
      setStatus((e && e.message) ? e.message : String(e), true);
    }
  }

  async function saveCurrent() {
    const skuFamilyId = currentSkuFamilyId();
    if (!skuFamilyId) {
      setStatus('请选择货号', true);
      return;
    }
    if (!items.length) {
      setStatus('无可保存的面料', true);
      return;
    }
    try {
      const resp = await fetch('/api/fabric-inventory-share', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          action: 'save',
          sku_family_id: Number(skuFamilyId),
          items: items.map(row => ({
            fabric_id: row.fabric_id,
            inventory_share_ratio: parseRatioInput(row.inventory_share_ratio),
          })),
        }),
      });
      const data = await resp.json();
      if (!resp.ok || !data || data.status === 'error') {
        throw new Error((data && data.message) ? data.message : '保存失败');
      }
      setStatus('', false);
      if (global.showAppToast) global.showAppToast('面料库存比例已保存', false, 2200);
      await loadCurrent(false);
    } catch (e) {
      setStatus((e && e.message) ? e.message : String(e), true);
    }
  }

  // -------------------------------------------------------------------------
  // 打开 / 关闭与事件绑定
  // -------------------------------------------------------------------------

  function syncScrollLock() {
    const hasActive = !!document.querySelector('.pm-modal.active');
    document.documentElement.classList.toggle('has-active-modal', hasActive);
    document.body.classList.toggle('has-active-modal', hasActive);
  }

  function closeModal() {
    el('fabricInventoryShareModal')?.classList.remove('active');
    syncScrollLock();
  }

  async function openModal(opts) {
    try {
      await ensureMounted();
      setStatus('');
      await loadSkuFamilies(opts && opts.skuFamilyId);
      if (opts && opts.skuFamilyId) {
        const sel = el('fisSkuFamily');
        if (sel) sel.value = String(opts.skuFamilyId);
        refreshSkuFamilySelect();
      }
      if (opts && opts.months) {
        const m = el('fisHistMonths');
        if (m) m.value = String(opts.months);
      }
      el('fabricInventoryShareModal')?.classList.add('active');
      syncScrollLock();
      if (currentSkuFamilyId()) await loadCurrent(false);
      else renderTable();
    } catch (e) {
      if (global.showAppToast) {
        global.showAppToast((e && e.message) ? e.message : '无法打开面料库存比例弹窗', true, 5000);
      }
    }
  }

  function bindUi() {
    const modal = el('fabricInventoryShareModal');
    if (!modal || modal.dataset.fisBound === '1') return;
    modal.dataset.fisBound = '1';
    const tbl = el('fisRatioTable');
    if (tbl) tbl.dataset.disableTableManage = '1';
    el('fisCloseBtn')?.addEventListener('click', closeModal);
    el('fisSaveBtn')?.addEventListener('click', saveCurrent);
    el('fisReloadBtn')?.addEventListener('click', () => loadCurrent(false));
    el('fisCalcBtn')?.addEventListener('click', () => loadCurrent(true));
    el('fisSkuFamily')?.addEventListener('change', () => loadCurrent(false));
    if (global.bindPmModalBackdropClose) {
      global.bindPmModalBackdropClose(modal, closeModal);
    }
  }

  global.FabricInventoryShareModal = {
    open: openModal,
    close: closeModal,
    ensureMounted,
  };
})(window);
