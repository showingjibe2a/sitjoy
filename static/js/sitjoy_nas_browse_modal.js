/**
 * 统一 NAS 浏览弹窗（云端关联 / 选择已有图片 / 通道关联 共用布局与交互）。
 *
 * SitjoyNasBrowseModal.open({
 *   profile: 'link' | 'pick',       // link=双击关联, pick=多选确认
 *   title, helpTip,
 *   dataSource: 'browse' | 'image-picker' | 'fabric-images',
 *   startPathB64, rootLabel,         // browse
 *   context, params,                 // image-picker
 *   onPick(pathB64), onConfirm(items),
 *   getImageTypeOptions, getImportImageType,
 *   importTarget: 'fabric',
 *   onAfterImport(names, type, data),
 * })
 */
(function (global) {
  const MODAL_ID = 'sitjoyNasBrowseModal';
  const THUMB_LS_KEY = 'sj.nasBrowse.thumbSize.v1';
  const DEFAULT_ROOT_LABEL = '上架资源';

  let injected = false;
  let state = createEmptyState();

  const api = { open: open, close: close, reload: reload };
  global.SitjoyNasBrowseModal = api;
  global.NasChannelLinkPicker = {
    open: (opts) => open(Object.assign({}, opts || {}, { profile: 'link', dataSource: 'browse' })),
    close: close,
  };

  function createEmptyState() {
    return {
      profile: 'pick',
      dataSource: 'image-picker',
      title: '',
      helpTip: '',
      pathB64: '',
      navStack: [],
      rootLabel: DEFAULT_ROOT_LABEL,
      activeRootIdx: 0,
      roots: [],
      context: '',
      params: {},
      selected: new Set(),
      items: [],
      onPick: null,
      onConfirm: null,
      getImageTypeOptions: null,
      getImportImageType: null,
      importTarget: '',
      onAfterImport: null,
      busy: false,
    };
  }

  function $(id) { return document.getElementById(id); }

  function getUi() { return global.NasMainImageBrowserUi || null; }

  function isNasBrowsePathMode() {
    return state.dataSource === 'browse';
  }

  function persistBrowseLocation() {
    if (!isNasBrowsePathMode()) return;
    const Ui = getUi();
    if (Ui && typeof Ui.persistNasBrowseLocationState === 'function') {
      Ui.persistNasBrowseLocationState(state.pathB64, state.navStack);
    }
  }

  async function restoreBrowsePathIfNeeded() {
    if (!isNasBrowsePathMode()) return;
    const Ui = getUi();
    if (!Ui || typeof Ui.restoreSavedNasBrowseLocation !== 'function') return;
    const restored = await Ui.restoreSavedNasBrowseLocation({
      pathB64: state.pathB64,
      navStack: state.navStack,
    });
    if (restored) {
      state.pathB64 = restored.pathB64 || '';
      state.navStack = Array.isArray(restored.navStack) ? restored.navStack : [];
      if (restored.fellBack) persistBrowseLocation();
    }
  }

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function decodeNameFromB64(b64) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.decodeFsNameFromB64 === 'function') {
      const n = global.SitjoyFsName.decodeFsNameFromB64(b64);
      if (n) return n;
    }
    const Ui = getUi();
    if (Ui && typeof Ui.decodePathB64 === 'function') {
      const full = Ui.decodePathB64(b64);
      if (full) {
        const parts = full.replace(/\\/g, '/').split('/').filter(Boolean);
        return parts.length ? parts[parts.length - 1] : full;
      }
    }
    try {
      const binary = atob(String(b64 || ''));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      if (typeof TextDecoder !== 'undefined') {
        return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      }
      return decodeURIComponent(escape(binary));
    } catch (e) {
      return '';
    }
  }

  function resolveDisplayName(item) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.resolveItemDisplayName === 'function') {
      return global.SitjoyFsName.resolveItemDisplayName(item);
    }
    if (item && item.display) return String(item.display);
    if (item && item.name && typeof item.name === 'string' && !/^[A-Za-z0-9+/=]+$/.test(item.name)) {
      return String(item.name);
    }
    if (item && item.name) return decodeNameFromB64(item.name);
    return '';
  }

  function normalizePickerItem(it) {
    const display = resolveDisplayName(it);
    const nameRawB64 = String(it.name_raw_b64 || it.rawB64 || '').trim();
    return {
      display,
      name: display,
      path_b64: String(it.path_b64 || it.b64 || it.path || ''),
      b64: String(it.b64 || it.path_b64 || it.path || ''),
      name_raw_b64: nameRawB64,
    };
  }

  function showStatus(msg, isError) {
    const text = String(msg || '').trim();
    const el = $('sjNasBrowseStatus');
    if (!text) {
      if (el) {
        el.style.display = 'none';
        el.textContent = '';
      }
      return;
    }
    const isProgress = !isError && /^(正在|加载中)/.test(text);
    if (isProgress) {
      if (el) {
        el.style.display = 'block';
        el.textContent = text;
        el.className = 'nas-main-image-status status-message';
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

  function actionMode() {
    if (state.profile === 'link' && state.importTarget !== 'fabric') return 'double';
    const Ui = getUi();
    if (Ui && Ui.readActionModeFromSegment) {
      return Ui.readActionModeFromSegment('sjNasBrowseActionModeSegment');
    }
    const seg = $('sjNasBrowseActionModeSegment');
    return seg && String(seg.getAttribute('data-value') || '') === 'double' ? 'double' : 'multi';
  }

  function applyProfileUi() {
    const isLink = state.profile === 'link' && state.importTarget !== 'fabric';
    const isPick = state.profile === 'pick';
    const isFabric = isPick && state.dataSource === 'fabric-images';
    const isFabricImport = state.importTarget === 'fabric';

    $('sjNasBrowseActionModeWrap').style.display = isLink ? 'none' : '';
    $('sjNasBrowseSearchWrap').style.display = isPick && state.dataSource === 'image-picker' ? '' : 'none';
    $('sjNasBrowseRootsWrap').style.display = isPick && state.roots.length > 1 ? '' : 'none';
    $('sjNasBrowseImageTypeWrap').style.display = (isFabric || isFabricImport) ? '' : 'none';
    $('sjNasBrowseSelectAllLabel').style.display = (isPick || isFabricImport) ? '' : 'none';
    $('sjNasBrowseConfirmBtn').style.display = (isPick || isFabricImport) ? '' : 'none';

    const help = $('sjNasBrowseHelpDot');
    if (help) {
      help.setAttribute('data-tip', state.helpTip || (isFabricImport
        ? '从「上架资源」浏览 NAS 文件，移动至「『面料』」目录。文件夹请双击进入。'
        : isLink
          ? '从『上架资源』浏览 NAS 文件；双击图片即可关联。'
          : '仅显示尚未绑定的图片。文件夹请双击进入。'));
    }

    const confirmBtn = $('sjNasBrowseConfirmBtn');
    if (confirmBtn) {
      if (isFabricImport) confirmBtn.textContent = '批量导入所选';
      else if (isFabric) confirmBtn.textContent = '确认绑定';
      else confirmBtn.textContent = '确认选择';
    }

    if (isLink) {
      const seg = $('sjNasBrowseActionModeSegment');
      if (seg) seg.setAttribute('data-value', 'double');
    }
  }

  async function ensureInjected() {
    if (injected && $(MODAL_ID)) return true;
    try {
      const resp = await fetch('/static/html/sitjoy_nas_browse_modal.html', { cache: 'no-store' });
      const html = await resp.text();
      const wrap = document.createElement('div');
      wrap.innerHTML = html;
      while (wrap.firstChild) document.body.appendChild(wrap.firstChild);
      injected = true;
      bindStaticEvents();
      initThumbSegment();
      initActionModeSegment();
      return !!$(MODAL_ID);
    } catch (e) {
      return false;
    }
  }

  function initThumbSegment() {
    const Ui = getUi();
    if (!Ui || !Ui.bindThumbSizeSegment) return;
    Ui.bindThumbSizeSegment({
      segmentId: 'sjNasBrowseThumbSizeSegment',
      gridId: 'sjNasBrowseList',
      storageKey: THUMB_LS_KEY,
      defaultMode: 'lg',
    });
  }

  function initActionModeSegment() {
    const seg = $('sjNasBrowseActionModeSegment');
    if (!seg || seg.dataset.sjNasBound === '1') return;
    seg.dataset.sjNasBound = '1';
    seg.querySelectorAll('button[data-value]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const val = String(btn.getAttribute('data-value') || 'multi');
        seg.setAttribute('data-value', val);
        seg.querySelectorAll('button[data-value]').forEach((b) => {
          b.classList.toggle('is-active', b.getAttribute('data-value') === val);
        });
        if (val === 'double') state.selected.clear();
        renderListAsync();
      });
    });
  }

  function bindStaticEvents() {
    $('sjNasBrowseCloseBtn')?.addEventListener('click', close);
    $('sjNasBrowseConfirmBtn')?.addEventListener('click', confirmPick);
    $('sjNasBrowseSearchBtn')?.addEventListener('click', () => { state.selected.clear(); reload(); });
    $('sjNasBrowseSearch')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { state.selected.clear(); reload(); }
    });
    $('sjNasBrowseSelectAllBox')?.addEventListener('change', function () {
      const on = !!this.checked;
      document.querySelectorAll('#sjNasBrowseList input.sj-nas-pick-check').forEach((cb) => {
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
    } else if (modal) {
      modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
    }
  }

  function activeRoot() {
    const roots = state.roots || [];
    if (!roots.length) return null;
    const idx = Math.max(0, Math.min(state.activeRootIdx, roots.length - 1));
    return roots[idx];
  }

  function rootCrumbLabel() {
    if (state.dataSource === 'browse') return state.rootLabel || DEFAULT_ROOT_LABEL;
    const r = activeRoot();
    return (r && r.label) ? String(r.label) : (state.rootLabel || DEFAULT_ROOT_LABEL);
  }

  function buildBreadcrumbsHtml() {
    const crumbs = [`<a href="#" class="nas-main-image-crumb" data-crumb-idx="-1">${escapeHtml(rootCrumbLabel())}</a>`];
    (state.navStack || []).forEach((seg, idx) => {
      const label = escapeHtml(String((seg && seg.name) ? seg.name : `目录${idx + 1}`));
      crumbs.push('<span class="nas-main-image-crumb-sep" aria-hidden="true">›</span>');
      crumbs.push(`<a href="#" class="nas-main-image-crumb" data-crumb-idx="${idx}">${label}</a>`);
    });
    return crumbs.join('');
  }

  function renderBreadcrumbs() {
    const el = $('sjNasBrowseBreadcrumbs');
    if (!el) return;
    el.innerHTML = buildBreadcrumbsHtml();
    el.querySelectorAll('a.nas-main-image-crumb[data-crumb-idx]').forEach((a) => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        const raw = String(a.getAttribute('data-crumb-idx') || '');
        jumpToCrumb(raw === '-1' ? -1 : Number(raw));
      });
    });
  }

  function renderRoots() {
    const bar = $('sjNasBrowseRootsBar');
    if (!bar) return;
    const roots = state.roots || [];
    if (roots.length < 2) return;
    bar.innerHTML = roots.map((r, idx) => {
      const active = idx === state.activeRootIdx ? ' is-active' : '';
      return `<button type="button" class="status-pill${active}" data-root-idx="${idx}">${escapeHtml(r.label || '目录')}</button>`;
    }).join('');
    bar.querySelectorAll('button[data-root-idx]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const idx = parseInt(btn.getAttribute('data-root-idx'), 10);
        if (!Number.isFinite(idx)) return;
        state.activeRootIdx = idx;
        const r = roots[idx];
        state.pathB64 = r ? String(r.path_b64 || '') : '';
        state.navStack = [];
        state.selected.clear();
        renderRoots();
        reload();
      });
    });
  }

  function renderFabricImageTypeBar() {
    const bar = $('sjNasBrowseImageTypeBar');
    if (!bar) return;
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

  function updateCount(imageCount) {
    const el = $('sjNasBrowseCountText');
    if (!el) return;
    const n = Number(imageCount) || 0;
    if (state.profile === 'link') {
      el.textContent = `共 ${n} 张图片 · 双击关联`;
    } else if (state.importTarget === 'fabric') {
      el.textContent = `共 ${n} 张图片`;
    } else if (state.dataSource === 'image-picker') {
      el.textContent = `共 ${n} 张可选图片`;
    } else {
      el.textContent = `共 ${n} 张图片`;
    }
  }

  function patchSelectAll() {
    const box = $('sjNasBrowseSelectAllBox');
    if (!box) return;
    const checks = document.querySelectorAll('#sjNasBrowseList input.sj-nas-pick-check');
    box.checked = checks.length > 0 && Array.from(checks).every((c) => c.checked);
  }

  async function jumpToCrumb(idx) {
    if (idx < 0) {
      if (state.dataSource === 'browse') {
        state.pathB64 = '';
        state.navStack = [];
      } else {
        const r = activeRoot();
        state.pathB64 = r ? String(r.path_b64 || '') : '';
        state.navStack = [];
      }
    } else {
      state.navStack = (state.navStack || []).slice(0, idx + 1);
      const last = state.navStack[state.navStack.length - 1];
      state.pathB64 = last && last.pathB64 ? String(last.pathB64) : '';
    }
    state.selected.clear();
    persistBrowseLocation();
    await reload();
  }

  async function enterFolder(pathB64, folderName, folderItem) {
    const pb = String(pathB64 || '').trim();
    if (!pb) return;
    let name = String(folderName || '').trim();
    if (!name && folderItem) name = resolveDisplayName(folderItem);
    if (!name) name = decodeNameFromB64(folderItem && folderItem.name);
    state.pathB64 = pb;
    state.navStack.push({ name: name || '文件夹', pathB64: pb });
    state.selected.clear();
    persistBrowseLocation();
    await reload();
  }

  function buildImagePickerQuery() {
    const p = new URLSearchParams();
    p.set('context', state.context);
    if (state.pathB64) p.set('path', state.pathB64);
    const q = ($('sjNasBrowseSearch')?.value || '').trim();
    if (q) p.set('q', q);
    const pr = state.params || {};
    if (pr.fabricId) p.set('fabric_id', String(pr.fabricId));
    if (pr.variantId) p.set('variant_id', String(pr.variantId));
    if (pr.salesProductId) p.set('sales_product_id', String(pr.salesProductId));
    if (pr.orderProductId) p.set('order_product_id', String(pr.orderProductId));
    return p.toString();
  }

  async function fetchBrowseData() {
    const Ui = getUi();
    let pathB64 = String(state.pathB64 || '').trim();
    if (Ui && Ui.resolveAccessibleNasBrowsePath) {
      const resolved = await Ui.resolveAccessibleNasBrowsePath({ pathB64, fallbackPathB64: '' });
      if (!resolved.ok) throw new Error('无法浏览该目录');
      if (resolved.fellBack && resolved.failedPathB64 && Ui.notifyNasPathFallback) {
        Ui.notifyNasPathFallback(resolved.failedPathB64);
      }
      pathB64 = resolved.pathB64 || '';
      if (pathB64 !== state.pathB64) {
        state.pathB64 = pathB64;
        if (!pathB64) state.navStack = [];
      }
      return {
        folders: (resolved.data && resolved.data.folders) || [],
        images: (resolved.data && resolved.data.images) || [],
        roots: [],
      };
    }
    const url = pathB64 ? '/api/browse?path=' + encodeURIComponent(pathB64) : '/api/browse';
    const resp = await fetch(url, { credentials: 'include' });
    const data = await resp.json();
    if (!data || data.status !== 'success') {
      throw new Error((data && data.message) ? data.message : '浏览失败');
    }
    return { folders: data.folders || [], images: data.images || [], roots: [] };
  }

  async function fetchImagePickerData() {
    const resp = await fetch('/api/image-picker?' + buildImagePickerQuery(), { credentials: 'include' });
    const data = await resp.json();
    if (!data || data.status !== 'success') {
      throw new Error((data && data.message) ? data.message : '加载失败');
    }
    state.pathB64 = data.path_b64 || state.pathB64 || '';
    if ((state.roots || []).length === 0 && Array.isArray(data.roots)) {
      state.roots = data.roots;
    }
    return {
      folders: data.folders || [],
      images: (data.items || []).map(normalizePickerItem),
      roots: data.roots || [],
    };
  }

  async function fetchFabricData() {
    const params = new URLSearchParams();
    params.set('unbound', '1');
    if (state.params.fabricId) params.set('fabric_id', String(state.params.fabricId));
    const resp = await fetch('/api/fabric-images?' + params.toString(), { credentials: 'include' });
    const data = await resp.json();
    if (!data || data.status !== 'success') {
      throw new Error((data && data.message) ? data.message : '加载失败');
    }
    const q = ($('sjNasBrowseSearch')?.value || '').trim().toLowerCase();
    let items = (data.items || []).map(normalizePickerItem);
    if (q) items = items.filter((it) => String(it.display || '').toLowerCase().includes(q));
    state.pathB64 = '';
    state.navStack = [];
    return { folders: [], images: items, roots: [] };
  }

  async function loadData() {
    if (state.dataSource === 'browse') return fetchBrowseData();
    if (state.dataSource === 'fabric-images') return fetchFabricData();
    return fetchImagePickerData();
  }

  async function pickImage(pathB64) {
    if (state.busy) return;
    const pb = String(pathB64 || '').trim();
    if (!pb) return;
    if (state.importTarget === 'fabric') {
      state.busy = true;
      showStatus('正在移动…', false);
      try {
        const ok = await importFabricPaths([pb], false);
        if (ok) await reload();
      } catch (e) {
        const msg = e && e.message ? e.message : String(e);
        showStatus(msg, true);
        if (global.showAppToast) global.showAppToast(msg, true, 8000);
      } finally {
        state.busy = false;
      }
      return;
    }
    if (typeof state.onPick !== 'function') return;
    state.busy = true;
    showStatus('正在处理…', false);
    try {
      await state.onPick(pb);
      close();
    } catch (e) {
      const msg = e && e.message ? e.message : String(e);
      showStatus(msg, true);
      if (global.showAppToast) global.showAppToast(msg, true, 8000);
    } finally {
      state.busy = false;
    }
  }

  function renderList() {
    return renderListAsync();
  }

  async function renderListAsync() {
    const list = $('sjNasBrowseList');
    if (!list) return;
    const Ui = getUi();
    list.innerHTML = '';
    const loading = document.createElement('div');
    loading.className = 'pm-select-empty nas-main-image-grid-loading';
    loading.textContent = '加载中...';
    list.appendChild(loading);
    showStatus('加载中…', false);

    try {
      const data = await loadData();
      if (data.roots && data.roots.length) state.roots = data.roots;
      renderRoots();
      applyProfileUi();

      const folders = Array.isArray(data.folders) ? data.folders : [];
      const images = Array.isArray(data.images) ? data.images : [];
      state.items = images;
      renderBreadcrumbs();
      list.innerHTML = '';
      if (Ui && Ui.syncGridThumbClassFromSegment) {
        Ui.syncGridThumbClassFromSegment('sjNasBrowseThumbSizeSegment', 'sjNasBrowseList');
      }
      updateCount(images.length);
      showStatus('', false);

      if (!folders.length && !images.length) {
        const empty = document.createElement('div');
        empty.className = 'pm-select-empty nas-main-image-grid-empty';
        empty.textContent = state.profile === 'pick' ? '当前目录下暂无未绑定图片' : '此目录为空';
        list.appendChild(empty);
        patchSelectAll();
        return;
      }

      const mode = actionMode();

      folders.forEach((f) => {
        const pb = String(f.path_b64 || f.path || '');
        const label = resolveDisplayName(f) || decodeNameFromB64(f.name) || '文件夹';
        const card = document.createElement('div');
        card.className = 'item-card item-card--folder item-card--nas-browse';
        const enter = () => enterFolder(pb, label, f);
        if (Ui && Ui.wireNasFolderBrowseCard) {
          Ui.wireNasFolderBrowseCard(card, enter);
        } else {
          card.addEventListener('dblclick', (e) => { e.preventDefault(); enter(); });
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
        list.appendChild(card);
      });

      images.forEach((img) => {
        const pb = String(img.path_b64 || img.b64 || img.path || '');
        const name = resolveDisplayName(img) || decodeNameFromB64(img.name) || '';
        const isSelected = state.selected.has(pb);
        const card = document.createElement('div');
        card.className = 'item-card item-card--nas-browse' + (isSelected ? ' item-card--selected' : '');
        const thumbUrl = `/api/image-preview?id=${encodeURIComponent(pb)}&mode=thumb&w=240&q=72`;

        const toggleSelected = (checked) => {
          if (checked) state.selected.add(pb);
          else state.selected.delete(pb);
          card.classList.toggle('item-card--selected', !!checked);
          patchSelectAll();
        };

        if (state.profile === 'link' || mode === 'double') {
          card.title = state.importTarget === 'fabric' ? '双击移动并绑定' : '双击关联';
          if (Ui && Ui.wireNasImageBrowseCard) {
            Ui.wireNasImageBrowseCard(card, 'double', {
              onDoubleImport: () => pickImage(pb),
            });
          } else {
            card.addEventListener('dblclick', () => pickImage(pb));
            card.addEventListener('click', (e) => e.preventDefault());
          }
        } else {
          if (Ui && Ui.wireNasImageBrowseCard) {
            Ui.wireNasImageBrowseCard(card, 'multi', {
              onMultiClick: () => {
                const cb = card.querySelector('input.sj-nas-pick-check');
                if (!cb) return;
                cb.checked = !cb.checked;
                toggleSelected(cb.checked);
              },
            });
          } else {
            card.addEventListener('click', () => {
              const cb = card.querySelector('input.sj-nas-pick-check');
              if (!cb) return;
              cb.checked = !cb.checked;
              toggleSelected(cb.checked);
            });
          }
          const selectWrap = document.createElement('div');
          selectWrap.className = 'item-select';
          const cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.className = 'sj-nas-pick-check';
          cb.setAttribute('data-path-b64', pb);
          cb.checked = isSelected;
          selectWrap.addEventListener('click', (e) => e.stopPropagation());
          cb.addEventListener('click', (e) => e.stopPropagation());
          cb.addEventListener('change', () => toggleSelected(cb.checked));
          selectWrap.appendChild(cb);
          card.appendChild(selectWrap);
        }

        const thumb = document.createElement('div');
        thumb.className = 'item-thumbnail';
        const im = document.createElement('img');
        im.src = thumbUrl;
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
        card.appendChild(thumb);
        card.appendChild(info);
        list.appendChild(card);
      });
      patchSelectAll();
    } catch (e) {
      list.innerHTML = '';
      const err = document.createElement('div');
      err.className = 'pm-select-empty nas-main-image-grid-empty';
      err.textContent = '加载失败';
      list.appendChild(err);
      showStatus((e && e.message) ? e.message : String(e), true);
      updateCount(0);
    }
  }

  async function reload() {
    await renderListAsync();
  }

  function getFabricImageType() {
    const flow = global.FabricImageFlow;
    const fallback = typeof state.getImportImageType === 'function' ? state.getImportImageType() : '';
    if (flow && flow.readActiveImageType) {
      return flow.readActiveImageType($('sjNasBrowseImageTypeBar'), fallback);
    }
    return String(fallback || '').trim();
  }

  async function importFabricPaths(paths, closeAfter) {
    const fabricCode = String(state.params.fabricCode || '').trim();
    if (!fabricCode) {
      showStatus('请先在面料表单中填写面料编号', true);
      return false;
    }
    const imageType = getFabricImageType();
    if (!imageType) {
      showStatus('请先选择图片类型', true);
      return false;
    }
    const list = (Array.isArray(paths) ? paths : []).map((p) => String(p || '').trim()).filter(Boolean);
    if (!list.length) {
      showStatus('请至少选择一张图片', true);
      return false;
    }
    showStatus(`正在移动 ${list.length} 张…`, false);
    const resp = await fetch('/api/fabric-import-by-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        fabric_code: fabricCode,
        fabric_id: state.params.fabricId || null,
        source_paths_b64: list,
        image_type: imageType,
      }),
    });
    const data = await resp.json();
    if (!data || data.status !== 'success') {
      showStatus((data && data.message) ? data.message : '导入失败', true);
      return false;
    }
    const names = data.image_names || [];
    const msg = data.message || `已导入 ${names.length} 张`;
    showStatus(msg, false);
    if (typeof state.onAfterImport === 'function') {
      state.onAfterImport(names, imageType, data);
    }
    if (closeAfter) close();
    return true;
  }

  async function confirmPickFabricMove() {
    const picked = (state.items || []).filter((it) => state.selected.has(String(it.path_b64 || it.b64 || it.path || '')));
    if (!picked.length) {
      showStatus('请至少选择一张图片', true);
      return;
    }
    const paths = picked.map((it) => String(it.path_b64 || it.b64 || it.path || '').trim()).filter(Boolean);
    const btn = $('sjNasBrowseConfirmBtn');
    if (btn) btn.disabled = true;
    try {
      await importFabricPaths(paths, true);
    } finally {
      if (btn) btn.disabled = false;
    }
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
    const btn = $('sjNasBrowseConfirmBtn');
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
      if (typeof state.onConfirm === 'function') {
        state.onConfirm(data.image_names || [], imageType, data);
      }
      close();
    } catch (e) {
      showStatus('绑定失败: ' + e, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function confirmPick() {
    if (state.importTarget === 'fabric') {
      confirmPickFabricMove();
      return;
    }
    if (state.dataSource === 'fabric-images') {
      confirmPickFabric();
      return;
    }
    const picked = (state.items || []).filter((it) => state.selected.has(String(it.path_b64 || it.b64 || '')));
    if (!picked.length) {
      showStatus('请至少选择一张图片', true);
      return;
    }
    if (typeof state.onConfirm === 'function') state.onConfirm(picked);
    close();
  }

  function close() {
    persistBrowseLocation();
    $(MODAL_ID)?.classList.remove('active');
    state.selected.clear();
    showStatus('', false);
    state.busy = false;
  }

  async function open(opts) {
    opts = opts || {};
    if (!(await ensureInjected())) {
      if (global.showAppToast) global.showAppToast('NAS 浏览弹窗加载失败，请刷新页面', true, 8000);
      return;
    }
    if (!getUi()) {
      if (global.showAppToast) global.showAppToast('NAS 浏览组件未加载，请刷新页面', true, 8000);
      return;
    }

    state = createEmptyState();
    state.profile = String(opts.profile || (opts.onPick ? 'link' : 'pick')).trim();
    state.title = String(opts.title || (state.profile === 'link' ? '云端关联' : '选择已有图片')).trim();
    state.helpTip = String(opts.helpTip || '').trim();
    state.onPick = typeof opts.onPick === 'function' ? opts.onPick : null;
    state.onConfirm = typeof opts.onConfirm === 'function' ? opts.onConfirm : null;
    state.getImageTypeOptions = opts.getImageTypeOptions || null;
    state.getImportImageType = opts.getImportImageType || null;
    state.importTarget = String(opts.importTarget || '').trim();
    state.onAfterImport = typeof opts.onAfterImport === 'function' ? opts.onAfterImport : null;

    if (state.importTarget === 'fabric') {
      state.profile = 'pick';
      state.dataSource = 'browse';
      state.rootLabel = String(opts.rootLabel || DEFAULT_ROOT_LABEL).trim() || DEFAULT_ROOT_LABEL;
      state.params = {
        fabricId: opts.fabricId || opts.fabric_id || null,
        fabricCode: opts.fabricCode || opts.fabric_code || '',
      };
      const explicitPath = String(opts.startPathB64 || opts.pathB64 || '').trim();
      if (explicitPath) {
        state.pathB64 = explicitPath;
        state.navStack = Array.isArray(opts.navStack) ? opts.navStack.slice() : [];
      } else {
        const Ui = getUi();
        const saved = (Ui && Ui.loadNasBrowseLocationState) ? Ui.loadNasBrowseLocationState() : { pathB64: '', navStack: [] };
        state.pathB64 = saved.pathB64 || '';
        state.navStack = Array.isArray(saved.navStack) ? saved.navStack.slice() : [];
      }
    } else if (state.profile === 'link' || opts.dataSource === 'browse') {
      state.dataSource = 'browse';
      state.rootLabel = String(opts.rootLabel || DEFAULT_ROOT_LABEL).trim() || DEFAULT_ROOT_LABEL;
      const explicitPath = String(opts.startPathB64 || opts.pathB64 || '').trim();
      if (explicitPath) {
        state.pathB64 = explicitPath;
        state.navStack = Array.isArray(opts.navStack) ? opts.navStack.slice() : [];
      } else {
        const Ui = getUi();
        const saved = (Ui && Ui.loadNasBrowseLocationState) ? Ui.loadNasBrowseLocationState() : { pathB64: '', navStack: [] };
        state.pathB64 = saved.pathB64 || '';
        state.navStack = Array.isArray(saved.navStack) ? saved.navStack.slice() : [];
      }
    } else if (opts.context === 'fabric' || opts.dataSource === 'fabric-images') {
      state.dataSource = 'fabric-images';
      state.context = 'fabric';
      state.params = {
        fabricId: opts.fabricId || opts.fabric_id || null,
        fabricCode: opts.fabricCode || opts.fabric_code || '',
      };
      state.rootLabel = '『上架资源』/『面料』';
    } else {
      state.dataSource = 'image-picker';
      state.context = String(opts.context || 'sales_variant').trim().toLowerCase();
      state.params = {
        fabricId: opts.fabricId || opts.fabric_id || null,
        fabricCode: opts.fabricCode || opts.fabric_code || '',
        variantId: opts.variantId || opts.variant_id || opts.salesProductId || null,
        salesProductId: opts.salesProductId || opts.sales_product_id || null,
        orderProductId: opts.orderProductId || opts.order_product_id || null,
      };
      state.pathB64 = '';
      state.navStack = [];
    }

    const titleEl = $('sjNasBrowseTitle');
    if (titleEl) titleEl.textContent = state.title;

    if ($('sjNasBrowseSearch')) $('sjNasBrowseSearch').value = '';
    state.roots = [];
    state.activeRootIdx = 0;

    applyProfileUi();
    renderFabricImageTypeBar();
    initThumbSegment();
    initActionModeSegment();

    $(MODAL_ID)?.classList.add('active');
    await restoreBrowsePathIfNeeded();
    await reload();
  }
})(typeof window !== 'undefined' ? window : this);
