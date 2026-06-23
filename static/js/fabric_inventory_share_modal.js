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
        <td><input type="text" class="fis-ratio-input spi-num-input" style="width:5.5rem;max-width:100%;" data-idx="${idx}" value="${ratioPct}"></td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('.fis-ratio-input').forEach(input => {
      input.addEventListener('change', function () {
        const i = Number(this.getAttribute('data-idx'));
        if (!Number.isFinite(i) || !items[i]) return;
        items[i].inventory_share_ratio = parseRatioInput(this.value);
        this.value = pctText(items[i].inventory_share_ratio);
      });
    });
  }

  function escapeHtml(s) {
    return String(s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  async function loadSkuFamilies(preferredId) {
    const sel = el('fisSkuFamily');
    if (!sel) return;
    const resp = await fetch('/api/sku', { credentials: 'include' });
    const data = await resp.json();
    const rows = (data && data.status === 'success') ? (data.items || []) : [];
    sel.innerHTML = ['<option value="">请选择货号</option>'].concat(
      rows.map(r => `<option value="${r.id}">${escapeHtml(r.sku_family || '')}${r.category ? ' / ' + escapeHtml(r.category) : ''}</option>`)
    ).join('');
    const old = String(preferredId || sel.value || '').trim();
    if (old) sel.value = old;
  }

  function currentSkuFamilyId() {
    return String(el('fisSkuFamily')?.value || '').trim();
  }

  function histMonths() {
    return Math.max(1, Math.min(36, Number(el('fisHistMonths')?.value || 12)));
  }

  function applyPayload(data) {
    items = (data && data.items) ? data.items.slice() : [];
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
    setStatus(useCalculate ? '正在统计历史销量…' : '加载中…', false);
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
    setStatus('保存中…', false);
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
      setStatus('已保存', false);
      if (global.showAppToast) global.showAppToast('面料库存比例已保存', false, 2200);
      await loadCurrent(false);
    } catch (e) {
      setStatus((e && e.message) ? e.message : String(e), true);
    }
  }

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
