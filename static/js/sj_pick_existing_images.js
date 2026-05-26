/**
 * 全局「选择已有图片」弹窗：面料库 / 销售主图+通用 / 下单配件图+通用。
 * 用法：SjPickExistingImages.open({ context, fabricId, variantId, orderProductId, title, onConfirm(items) })
 */
(function (global) {
  const MODAL_ID = 'sjPickExistingModal';
  let injected = false;
  /** 先占位，避免脚本晚于内联逻辑时误判「未加载」 */
  const api = { open: null, close: null, loadList: null };
  global.SjPickExistingImages = api;
  let state = {
    context: '',
    params: {},
    pathB64: '',
    selected: new Set(),
    items: [],
    onConfirm: null,
  };

  function $(id) { return document.getElementById(id); }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showStatus(msg, isError) {
    const el = $('sjPickExistingStatus');
    if (!el) return;
    el.style.display = msg ? 'block' : 'none';
    el.textContent = msg || '';
    el.style.color = isError ? '#9b2226' : 'var(--morandi-ink)';
  }

  async function ensureInjected() {
    if (injected && $(MODAL_ID)) return true;
    try {
      const resp = await fetch('/static/html/sj_pick_existing_images_modal.html', { cache: 'no-store' });
      const html = await resp.text();
      const wrap = document.createElement('div');
      wrap.innerHTML = html;
      while (wrap.firstChild) document.body.appendChild(wrap.firstChild);
      injected = true;
      bindStaticEvents();
      return !!$(MODAL_ID);
    } catch (e) {
      return false;
    }
  }

  function buildQuery() {
    const p = new URLSearchParams();
    p.set('context', state.context);
    if (state.pathB64) p.set('path', state.pathB64);
    const q = ($( 'sjPickExistingSearch')?.value || '').trim();
    if (q) p.set('q', q);
    const pr = state.params || {};
    if (pr.fabricId) p.set('fabric_id', String(pr.fabricId));
    if (pr.variantId) p.set('variant_id', String(pr.variantId));
    if (pr.salesProductId) p.set('sales_product_id', String(pr.salesProductId));
    if (pr.orderProductId) p.set('order_product_id', String(pr.orderProductId));
    return p.toString();
  }

  async function loadList() {
    showStatus('加载中…', false);
    const resp = await fetch('/api/image-picker?' + buildQuery(), { credentials: 'include' });
    const data = await resp.json();
    if (data.status !== 'success') {
      showStatus(data.message || '加载失败', true);
      return;
    }
    state.pathB64 = data.path_b64 || '';
    state.items = data.items || [];
    renderRoots(data.roots || []);
    renderBreadcrumbs(data.breadcrumbs || []);
    renderFolders(data.folders || []);
    renderGrid(state.items);
    showStatus('', false);
  }

  function renderRoots(roots) {
    const wrap = $('sjPickExistingRootsWrap');
    const bar = $('sjPickExistingRootsBar');
    if (!wrap || !bar) return;
    if (!roots.length || roots.length < 2) {
      wrap.style.display = 'none';
      return;
    }
    wrap.style.display = '';
    bar.innerHTML = roots.map((r, idx) => {
      const active = (r.path_b64 || '') === (state.pathB64 || '') ? ' is-active' : '';
      return `<button type="button" class="status-pill${active}" data-root-idx="${idx}">${escapeHtml(r.label || '目录')}</button>`;
    }).join('');
    bar.querySelectorAll('button[data-root-idx]').forEach(btn => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-root-idx'), 10);
        const r = roots[idx];
        if (!r) return;
        state.pathB64 = r.path_b64 || '';
        state.selected.clear();
        loadList();
      });
    });
  }

  function renderBreadcrumbs(crumbs) {
    const nav = $('sjPickExistingBreadcrumbs');
    if (!nav) return;
    nav.innerHTML = (crumbs || []).map((c, i) => {
      const sep = i > 0 ? '<span class="nas-main-image-crumb-sep">›</span>' : '';
      const label = escapeHtml(c.label || '');
      const pb = escapeHtml(c.path_b64 || '');
      return `${sep}<a href="#" class="nas-main-image-crumb" data-path-b64="${pb}">${label}</a>`;
    }).join('');
    nav.querySelectorAll('a.nas-main-image-crumb').forEach(a => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        state.pathB64 = a.getAttribute('data-path-b64') || '';
        state.selected.clear();
        loadList();
      });
    });
  }

  function renderFolders(folders) {
    const grid = $('sjPickExistingFolders');
    if (!grid) return;
    if (!folders.length) {
      grid.innerHTML = '';
      return;
    }
    grid.innerHTML = folders.map(f => {
      const label = escapeHtml(f.display || f.name || '文件夹');
      const pb = escapeHtml(f.path_b64 || '');
      return `<div class="browser-card browser-card--folder" role="button" tabindex="0" data-folder-b64="${pb}" title="双击进入">
        <div class="browser-card-icon">📁</div>
        <div class="browser-card-name">${label}</div>
      </div>`;
    }).join('');
    grid.querySelectorAll('.browser-card--folder').forEach(card => {
      const enter = () => {
        state.pathB64 = card.getAttribute('data-folder-b64') || '';
        state.selected.clear();
        loadList();
      };
      card.addEventListener('dblclick', (e) => { e.preventDefault(); enter(); });
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); enter(); }
      });
    });
  }

  function renderGrid(items) {
    const grid = $('sjPickExistingGrid');
    const countEl = $('sjPickExistingCountText');
    if (!grid) return;
    if (countEl) countEl.textContent = `共 ${(items || []).length} 张可选图片`;
    if (!items.length) {
      grid.innerHTML = '<div class="sj-media-image-empty" style="grid-column:1/-1;">当前目录下暂无未绑定图片</div>';
      patchSelectAll();
      return;
    }
    grid.innerHTML = items.map(it => {
      const pb = String(it.path_b64 || it.b64 || '');
      const checked = state.selected.has(pb) ? ' checked' : '';
      const name = escapeHtml(it.display || it.name || '');
      const src = `/api/image-preview?id=${encodeURIComponent(pb)}&mode=thumb&w=240&q=68`;
      return `<label class="browser-card browser-card--image nas-pick-card${state.selected.has(pb) ? ' is-selected' : ''}">
        <input type="checkbox" class="nas-pick-check" data-path-b64="${escapeHtml(pb)}"${checked} style="position:absolute;left:8px;top:8px;z-index:2;">
        <img src="${src}" alt="${name}" loading="lazy" class="browser-card-thumb">
        <div class="browser-card-name">${name}</div>
      </label>`;
    }).join('');
    grid.querySelectorAll('input.nas-pick-check').forEach(cb => {
      cb.addEventListener('change', () => {
        const pb = cb.getAttribute('data-path-b64') || '';
        if (cb.checked) state.selected.add(pb);
        else state.selected.delete(pb);
        cb.closest('.nas-pick-card')?.classList.toggle('is-selected', cb.checked);
        patchSelectAll();
      });
    });
    patchSelectAll();
  }

  function patchSelectAll() {
    const box = $('sjPickExistingSelectAllBox');
    if (!box) return;
    const checks = document.querySelectorAll('#sjPickExistingGrid input.nas-pick-check');
    const all = checks.length && Array.from(checks).every(c => c.checked);
    box.checked = all;
  }

  function bindStaticEvents() {
    $('sjPickExistingCloseBtn')?.addEventListener('click', close);
    $('sjPickExistingConfirmBtn')?.addEventListener('click', confirmPick);
    $('sjPickExistingSearchBtn')?.addEventListener('click', () => { state.selected.clear(); loadList(); });
    $('sjPickExistingSearch')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { state.selected.clear(); loadList(); }
    });
    $('sjPickExistingSelectAllBox')?.addEventListener('change', function () {
      const on = !!this.checked;
      document.querySelectorAll('#sjPickExistingGrid input.nas-pick-check').forEach(cb => {
        cb.checked = on;
        const pb = cb.getAttribute('data-path-b64') || '';
        if (on) state.selected.add(pb);
        else state.selected.delete(pb);
        cb.closest('.nas-pick-card')?.classList.toggle('is-selected', on);
      });
    });
    const modal = $(MODAL_ID);
    if (modal && typeof global.bindPmModalBackdropClose === 'function') {
      global.bindPmModalBackdropClose(modal, close);
    }
  }

  function close() {
    $(MODAL_ID)?.classList.remove('active');
    state.selected.clear();
    showStatus('', false);
  }

  function confirmPick() {
    const picked = (state.items || []).filter(it => state.selected.has(String(it.path_b64 || it.b64 || '')));
    if (!picked.length) {
      showStatus('请至少选择一张图片', true);
      return;
    }
    if (typeof state.onConfirm === 'function') {
      state.onConfirm(picked);
    }
    close();
  }

  async function open(opts) {
    const ok = await ensureInjected();
    if (!ok) {
      if (global.showAppToast) global.showAppToast('选择已有图片组件加载失败', true);
      return;
    }
    state.context = String(opts?.context || 'fabric').trim().toLowerCase();
    state.params = {
      fabricId: opts?.fabricId || opts?.fabric_id || null,
      variantId: opts?.variantId || opts?.variant_id || opts?.salesProductId || null,
      salesProductId: opts?.salesProductId || opts?.sales_product_id || null,
      orderProductId: opts?.orderProductId || opts?.order_product_id || null,
    };
    state.pathB64 = '';
    state.selected = new Set();
    state.onConfirm = opts?.onConfirm || null;
    const title = $('sjPickExistingTitle');
    if (title) title.textContent = opts?.title || '选择已有图片';
    if ($('sjPickExistingSearch')) $('sjPickExistingSearch').value = '';
    $(MODAL_ID)?.classList.add('active');
    await loadList();
  }

  api.open = open;
  api.close = close;
  api.loadList = loadList;
})(typeof window !== 'undefined' ? window : this);
