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

  const THUMB_LS_KEY = 'sj.pickExisting.nasThumbSize.v1';
  const PICK_GRID_IDS = ['sjPickExistingGrid', 'sjPickExistingFolders'];

  function resolveDisplayName(item) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.resolveItemDisplayName === 'function') {
      return global.SitjoyFsName.resolveItemDisplayName(item);
    }
    return String((item && (item.display || item.name)) || '');
  }

  function normalizePickerItem(it) {
    const display = resolveDisplayName(it);
    return {
      display,
      name: display,
      path_b64: String(it.path_b64 || it.b64 || ''),
      b64: String(it.b64 || it.path_b64 || ''),
      name_raw_b64: String(it.name_raw_b64 || it.rawB64 || ''),
    };
  }

  function applyThumbToPickGrids(mode) {
    const Ui = getBrowserUi();
    if (!Ui) return;
    PICK_GRID_IDS.forEach((id) => Ui.applyThumbSizeToGrid(id, mode));
  }

  function initThumbSizeSegment() {
    const Ui = getBrowserUi();
    if (!Ui || !Ui.bindThumbSizeSegment) return;
    Ui.bindThumbSizeSegment({
      segmentId: 'sjPickExistingThumbSizeSegment',
      gridId: 'sjPickExistingGrid',
      storageKey: THUMB_LS_KEY,
      defaultMode: 'sm',
      onApply: (mode) => applyThumbToPickGrids(mode),
    });
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showStatus(msg, isError) {
    const text = String(msg || '').trim();
    const el = $('sjPickExistingStatus');
    if (!text) {
      if (el) {
        el.style.display = 'none';
        el.textContent = '';
      }
      return;
    }
    const isProgress = !isError && /^(正在|加载中|加载中…)/.test(text);
    if (isProgress) {
      if (el) {
        el.style.display = 'block';
        el.textContent = text;
        el.style.color = 'var(--morandi-ink)';
      }
      return;
    }
    if (global.showPageStatus) global.showPageStatus(text, !!isError);
    else if (global.showAppToast) global.showAppToast(text, !!isError);
    if (el) {
      el.style.display = 'none';
      el.textContent = '';
    }
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
      initThumbSizeSegment();
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
    if (pr.memberPathB64) p.set('member_path_b64', String(pr.memberPathB64));
    return p.toString();
  }

  async function loadFabricPickerList() {
    const params = new URLSearchParams();
    params.set('unbound', '1');
    if (state.params.fabricId) params.set('fabric_id', String(state.params.fabricId));
    const resp = await fetch('/api/fabric-images?' + params.toString(), { credentials: 'include' });
    const data = await resp.json();
    if (data.status !== 'success') {
      showStatus(data.message || '加载失败', true);
      return;
    }
    const q = ($('sjPickExistingSearch') && $('sjPickExistingSearch').value || '').trim().toLowerCase();
    let items = (data.items || []).map(normalizePickerItem);
    if (q) {
      items = items.filter((it) => String(it.display || '').toLowerCase().includes(q));
    }
    state.pathB64 = '';
    state.items = items;
    const rootsWrap = $('sjPickExistingRootsWrap');
    if (rootsWrap) rootsWrap.style.display = 'none';
    renderBreadcrumbs([{ label: '『上架资源』/『面料』', path_b64: '' }]);
    renderFolders([]);
    renderGrid(items);
    applyThumbToPickGrids(getBrowserUi()?.readThumbSegmentValue('sjPickExistingThumbSizeSegment') || 'sm');
    showStatus('', false);
  }

  async function loadList() {
    showStatus('加载中…', false);
    if (state.context === 'fabric') {
      await loadFabricPickerList();
      return;
    }
    const resp = await fetch('/api/image-picker?' + buildQuery(), { credentials: 'include' });
    const data = await resp.json();
    if (data.status !== 'success') {
      showStatus(data.message || '加载失败', true);
      return;
    }
    state.pathB64 = data.path_b64 || '';
    state.items = (data.items || []).map(normalizePickerItem);
    renderRoots(data.roots || []);
    renderBreadcrumbs(data.breadcrumbs || []);
    renderFolders(data.folders || []);
    renderGrid(state.items);
    applyThumbToPickGrids(getBrowserUi()?.readThumbSegmentValue('sjPickExistingThumbSizeSegment') || 'sm');
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

  function getBrowserUi() {
    return global.NasMainImageBrowserUi || null;
  }

  function renderFolders(folders) {
    const grid = $('sjPickExistingFolders');
    if (!grid) return;
    grid.innerHTML = '';
    if (!folders.length) return;
    const Ui = getBrowserUi();
    folders.forEach((f) => {
      const pb = String(f.path_b64 || '');
      const label = resolveDisplayName(f) || '文件夹';
      const card = document.createElement('div');
      card.className = 'item-card item-card--folder item-card--nas-browse';
      const enter = () => {
        state.pathB64 = pb;
        state.selected.clear();
        loadList();
      };
      if (Ui) {
        Ui.wireNasFolderBrowseCard(card, enter);
      } else {
        card.setAttribute('role', 'button');
        card.tabIndex = 0;
        card.setAttribute('title', '双击进入文件夹');
        card.addEventListener('dblclick', (e) => { e.preventDefault(); enter(); });
        card.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); enter(); }
        });
      }
      const thumb = document.createElement('div');
      thumb.className = 'item-thumbnail folder';
      const icon = document.createElement('div');
      icon.className = 'folder-icon';
      icon.textContent = '📁';
      thumb.appendChild(icon);
      const info = document.createElement('div');
      info.className = 'item-info';
      const title = document.createElement('div');
      title.className = 'item-name';
      title.textContent = label;
      info.appendChild(title);
      card.appendChild(thumb);
      card.appendChild(info);
      grid.appendChild(card);
    });
  }

  function renderGrid(items) {
    const grid = $('sjPickExistingGrid');
    const countEl = $('sjPickExistingCountText');
    if (!grid) return;
    grid.innerHTML = '';
    if (countEl) countEl.textContent = `共 ${(items || []).length} 张可选图片`;
    if (!items.length) {
      const empty = document.createElement('div');
      empty.className = 'pm-select-empty nas-main-image-grid-empty';
      empty.textContent = '当前目录下暂无未绑定图片';
      grid.appendChild(empty);
      patchSelectAll();
      return;
    }
    const Ui = getBrowserUi();
    (items || []).forEach((it) => {
      const pb = String(it.path_b64 || it.b64 || '');
      const name = resolveDisplayName(it);
      const isSelected = state.selected.has(pb);
      const card = document.createElement('div');
      card.className = 'item-card item-card--nas-browse' + (isSelected ? ' item-card--selected' : '');

      const toggleSelected = (checked) => {
        if (checked) state.selected.add(pb);
        else state.selected.delete(pb);
        card.classList.toggle('item-card--selected', !!checked);
        patchSelectAll();
      };

      if (Ui) {
        Ui.wireNasImageBrowseCard(card, 'multi', {
          onMultiClick: () => {
            const cb = card.querySelector('input.nas-pick-check');
            if (!cb) return;
            cb.checked = !cb.checked;
            toggleSelected(cb.checked);
          },
        });
      } else {
        card.addEventListener('click', () => {
          const cb = card.querySelector('input.nas-pick-check');
          if (!cb) return;
          cb.checked = !cb.checked;
          toggleSelected(cb.checked);
        });
      }

      const selectWrap = document.createElement('div');
      selectWrap.className = 'item-select';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.className = 'nas-pick-check';
      cb.setAttribute('data-path-b64', pb);
      cb.checked = isSelected;
      selectWrap.addEventListener('click', (e) => e.stopPropagation());
      cb.addEventListener('click', (e) => e.stopPropagation());
      cb.addEventListener('change', () => toggleSelected(cb.checked));
      selectWrap.appendChild(cb);

      const thumb = document.createElement('div');
      thumb.className = 'item-thumbnail';
      const im = document.createElement('img');
      im.src = `/api/image-preview?id=${encodeURIComponent(pb)}&mode=thumb&w=240&q=68`;
      im.alt = name;
      im.loading = 'lazy';
      thumb.appendChild(im);

      const info = document.createElement('div');
      info.className = 'item-info';
      const title = document.createElement('div');
      title.className = 'item-name';
      title.textContent = name;
      title.title = name;
      info.appendChild(title);

      card.appendChild(selectWrap);
      card.appendChild(thumb);
      card.appendChild(info);
      grid.appendChild(card);
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
        cb.closest('.item-card')?.classList.toggle('item-card--selected', on);
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

  function renderFabricImageTypeBar() {
    const wrap = $('sjPickExistingImageTypeWrap');
    const bar = $('sjPickExistingImageTypeBar');
    if (!wrap || !bar) return;
    const isFabric = state.context === 'fabric';
    wrap.style.display = isFabric ? '' : 'none';
    if (!isFabric) return;
    const flow = global.FabricImageFlow;
    const opts = typeof state.getImageTypeOptions === 'function' ? (state.getImageTypeOptions() || []) : [];
    const current = typeof state.getImportImageType === 'function'
      ? state.getImportImageType()
      : (opts[0] && opts[0].name) || '';
    if (flow && flow.renderImageTypeBar) {
      flow.renderImageTypeBar(bar, opts, current);
    } else if (!opts.length) {
      bar.innerHTML = '<span class="pm-select-empty" style="padding:0 .4rem;">暂无图片类型</span>';
    }
  }

  function getFabricImageType() {
    const flow = global.FabricImageFlow;
    const fallback = typeof state.getImportImageType === 'function' ? state.getImportImageType() : '';
    if (flow && flow.readActiveImageType) {
      return flow.readActiveImageType($('sjPickExistingImageTypeBar'), fallback);
    }
    return String(fallback || '').trim();
  }

  async function confirmPickFabric() {
    const fabricCode = String(state.params.fabricCode || '').trim();
    if (!fabricCode) {
      showStatus('请先在面料表单中填写面料编号', true);
      return;
    }
    const imageType = getFabricImageType();
    if (!imageType) {
      showStatus('请先选择图片类型', true);
      return;
    }
    const picked = (state.items || []).filter((it) => state.selected.has(String(it.path_b64 || it.b64 || '')));
    if (!picked.length) {
      showStatus('请至少选择一张图片', true);
      return;
    }
    const itemsRawB64 = picked.map((it) => String(it.name_raw_b64 || '').trim()).filter(Boolean);
    if (!itemsRawB64.length) {
      showStatus('所选图片缺少文件名信息，请刷新后重试', true);
      return;
    }
    const flow = global.FabricImageFlow;
    if (!flow || typeof flow.attachLibraryImages !== 'function') {
      showStatus('面料绑定组件未加载，请刷新页面', true);
      return;
    }
    showStatus(`正在重命名并绑定 ${itemsRawB64.length} 张…`, false);
    const btn = $('sjPickExistingConfirmBtn');
    if (btn) btn.disabled = true;
    try {
      const data = await flow.attachLibraryImages({
        fabricCode,
        fabricId: state.params.fabricId || null,
        imageType,
        itemsRawB64,
      });
      if (!data || data.status !== 'success') {
        showStatus((data && data.message) ? data.message : '绑定失败', true);
        return;
      }
      const names = data.image_names || [];
      if (typeof state.onConfirm === 'function') {
        state.onConfirm(names, imageType, data);
      }
      close();
    } catch (e) {
      showStatus('绑定失败: ' + e, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function confirmPick() {
    if (state.context === 'fabric') {
      confirmPickFabric();
      return;
    }
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
      fabricCode: opts?.fabricCode || opts?.fabric_code || '',
      variantId: opts?.variantId || opts?.variant_id || opts?.salesProductId || null,
      salesProductId: opts?.salesProductId || opts?.sales_product_id || null,
      orderProductId: opts?.orderProductId || opts?.order_product_id || null,
      memberPathB64: opts?.memberPathB64 || opts?.member_path_b64 || '',
    };
    state.getImageTypeOptions = opts?.getImageTypeOptions || null;
    state.getImportImageType = opts?.getImportImageType || null;
    state.pathB64 = '';
    state.selected = new Set();
    state.onConfirm = opts?.onConfirm || null;
    const title = $('sjPickExistingTitle');
    if (title) title.textContent = opts?.title || '选择已有图片';
    const confirmBtn = $('sjPickExistingConfirmBtn');
    if (confirmBtn) {
      confirmBtn.textContent = state.context === 'fabric' ? '确认绑定' : '确认选择';
    }
    renderFabricImageTypeBar();
    if ($('sjPickExistingSearch')) $('sjPickExistingSearch').value = '';
    $(MODAL_ID)?.classList.add('active');
    await loadList();
  }

  api.open = open;
  api.close = close;
  api.loadList = loadList;
})(typeof window !== 'undefined' ? window : this);
