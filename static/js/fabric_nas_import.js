/**
 * 面料管理：从 NAS 选择并移动（与销售/下单 NAS 主图弹窗 UI 一致）
 */
(function (global) {
  const MODAL_ID = 'fabric-nas-import-modal';
  const LIST_ID = 'fabricNasList';
  const LAST_PATH_KEY = 'sj.fabricNas.lastPathB64.v1';
  const LAST_STACK_KEY = 'sj.fabricNas.navStack.v1';
  const ACTION_MODE_KEY = 'sj.fabricNas.actionMode.v1';
  const THUMB_SIZE_KEY = 'sj.fabricNas.thumbSize.v1';

  const FABRIC_LIBRARY_ROOT_B64 = '44CO6Z2i5paZ44CP'; /* UTF-8 『面料』 */

  function fabricLibraryRootStack() {
    return [{ name: '『面料』', pathB64: FABRIC_LIBRARY_ROOT_B64 }];
  }

  function ensureFabricLibraryPath() {
    if (!pathB64) {
      pathB64 = FABRIC_LIBRARY_ROOT_B64;
      navStack = fabricLibraryRootStack();
    }
  }
  let selected = new Set();
  let hooks = {};
  let selectAllBound = false;

  function $(id) { return document.getElementById(id); }

  function safeGet(key) {
    try { return global.localStorage.getItem(key); } catch (e) { return null; }
  }
  function safeSet(key, val) {
    try { global.localStorage.setItem(key, val); } catch (e) {}
  }

  function decodeB64Utf8(b64) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.decodeFsNameFromB64 === 'function') {
      return global.SitjoyFsName.decodeFsNameFromB64(b64);
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

  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function showStatus(msg, isError) {
    const el = $('fabricNasStatus');
    if (!el) return;
    el.textContent = msg || '';
    el.style.display = msg ? 'block' : 'none';
    el.classList.toggle('error', !!msg && !!isError);
    el.classList.toggle('success', !!msg && !isError);
  }

  function persistLocation() {
    safeSet(LAST_PATH_KEY, pathB64 || '');
    safeSet(LAST_STACK_KEY, JSON.stringify(Array.isArray(navStack) ? navStack : []));
  }

  function buildBreadcrumbsHtml() {
    const crumbs = [`<a href="#" class="nas-main-image-crumb" data-crumb-idx="-1">『面料』</a>`];
    (navStack || []).forEach((seg, idx) => {
      const label = escapeHtml(String((seg && seg.name) ? seg.name : `目录${idx + 1}`));
      crumbs.push('<span class="nas-main-image-crumb-sep" aria-hidden="true">›</span>');
      crumbs.push(`<a href="#" class="nas-main-image-crumb" data-crumb-idx="${idx}">${label}</a>`);
    });
    return crumbs.join('');
  }

  function renderBreadcrumbs() {
    const el = $('fabricNasBreadcrumbs');
    if (!el) return;
    el.innerHTML = buildBreadcrumbsHtml();
    el.querySelectorAll('a.nas-main-image-crumb[data-crumb-idx]').forEach(a => {
      a.addEventListener('click', function (e) {
        e.preventDefault();
        const raw = String(this.getAttribute('data-crumb-idx') || '');
        const idx = raw === '-1' ? -1 : Number(raw);
        jumpTo(idx);
      });
    });
  }

  function getSelectedImageType() {
    if (typeof hooks.getImportImageType === 'function') {
      return String(hooks.getImportImageType() || '').trim();
    }
    const bar = $('fabricNasImageTypeBar');
    const active = bar && bar.querySelector('button.status-pill.is-active');
    return active ? String(active.getAttribute('data-value') || '').trim() : '';
  }

  function renderImageTypeBar() {
    const bar = $('fabricNasImageTypeBar');
    if (!bar) return;
    const list = typeof hooks.getImageTypeOptions === 'function' ? (hooks.getImageTypeOptions() || []) : [];
    const names = list.map(x => String(x.name || '').trim()).filter(Boolean);
    if (!names.length) {
      bar.innerHTML = '<span class="pm-select-empty" style="padding:0 .4rem;">暂无图片类型</span>';
      return;
    }
    let current = getSelectedImageType();
    if (!names.includes(current)) current = names[0];
    bar.innerHTML = names.map(name => {
      const active = name === current ? ' is-active' : '';
      return `<button type="button" class="status-pill${active}" data-value="${escapeHtml(name)}">${escapeHtml(name)}</button>`;
    }).join('');
    bar.querySelectorAll('button.status-pill[data-value]').forEach(btn => {
      btn.addEventListener('click', function () {
        const v = String(this.getAttribute('data-value') || '').trim();
        bar.querySelectorAll('button.status-pill[data-value]').forEach(b => {
          b.classList.toggle('is-active', String(b.getAttribute('data-value') || '').trim() === v);
        });
      });
    });
  }

  function applyActionMode(mode) {
    const m = mode === 'double' ? 'double' : 'multi';
    const seg = $('fabricNasActionModeSegment');
    if (seg) {
      seg.setAttribute('data-value', m);
      seg.querySelectorAll('button.status-pill[data-value]').forEach(btn => {
        btn.classList.toggle('is-active', String(btn.getAttribute('data-value')) === m);
      });
    }
    const grid = $(LIST_ID);
    if (grid) grid.classList.toggle('is-mode-double', m === 'double');
    if (m === 'double') selected = new Set();
    safeSet(ACTION_MODE_KEY, m);
    updateMeta(0);
  }

  function initActionModeSegment() {
    const seg = $('fabricNasActionModeSegment');
    if (!seg || seg.dataset.fabricNasBound === '1') return;
    seg.dataset.fabricNasBound = '1';
    seg.querySelectorAll('button.status-pill[data-value]').forEach(btn => {
      btn.addEventListener('click', function () {
        applyActionMode(String(this.getAttribute('data-value') || 'multi'));
        renderList({ preserveScroll: true });
      });
    });
    const initial = String(safeGet(ACTION_MODE_KEY) || seg.getAttribute('data-value') || 'multi');
    applyActionMode(initial);
  }

  function initThumbSizeSegment() {
    if (!global.NasMainImageBrowserUi) return;
    global.NasMainImageBrowserUi.bindThumbSizeSegment({
      segmentId: 'fabricNasThumbSizeSegment',
      gridId: LIST_ID,
      storageKey: THUMB_SIZE_KEY,
      defaultMode: 'lg',
    });
  }

  function initSelectAllBox() {
    const box = $('fabricNasSelectAllBox');
    if (!box || selectAllBound) return;
    selectAllBound = true;
    box.addEventListener('change', function () {
      const mode = global.NasMainImageBrowserUi
        ? global.NasMainImageBrowserUi.readActionModeFromSegment('fabricNasActionModeSegment')
        : 'multi';
      if (mode === 'double') {
        this.checked = false;
        this.indeterminate = false;
        return;
      }
      if (this.checked) selectAll();
      else clearSelection();
      const list = $(LIST_ID);
      const n = list ? list.querySelectorAll('.item-card:not(.item-card--folder)').length : 0;
      updateMeta(n);
    });
  }

  function updateMeta(totalImages) {
    const countEl = $('fabricNasCountText');
    if (countEl) countEl.textContent = `共 ${Math.max(0, Number(totalImages || 0))} 张图片`;
    const seg = $('fabricNasActionModeSegment');
    const mode = seg ? String(seg.getAttribute('data-value') || 'multi') : 'multi';
    const meta = $('fabricNasGridMeta');
    if (meta) meta.classList.toggle('is-mode-double', mode === 'double');
    const box = $('fabricNasSelectAllBox');
    if (!box) return;
    if (mode === 'double') {
      box.checked = false;
      box.indeterminate = false;
      return;
    }
    const list = $(LIST_ID);
    const boxes = list ? Array.from(list.querySelectorAll('input[type="checkbox"][data-path]')) : [];
    const checkedCount = boxes.filter(b => !!b.checked).length;
    box.checked = boxes.length > 0 && checkedCount === boxes.length;
    box.indeterminate = checkedCount > 0 && checkedCount < boxes.length;
  }

  function patchSelectionUi() {
    const list = $(LIST_ID);
    if (!list) return;
    list.querySelectorAll('input[type="checkbox"][data-path]').forEach(cb => {
      const p = String(cb.dataset.path || '');
      const on = selected.has(p);
      cb.checked = !!on;
      const card = cb.closest('.item-card');
      if (card) card.classList.toggle('item-card--selected', !!on);
    });
    const n = list.querySelectorAll('.item-card:not(.item-card--folder)').length;
    updateMeta(n);
  }

  function toggle(pathB64Val, fromCheckbox, forcedChecked) {
    const p = String(pathB64Val || '');
    if (!p) return;
    if (fromCheckbox && (forcedChecked === true || forcedChecked === false)) {
      if (forcedChecked) selected.add(p);
      else selected.delete(p);
      return;
    }
    if (selected.has(p)) selected.delete(p);
    else selected.add(p);
    patchSelectionUi();
  }

  function selectAll() {
    const list = $(LIST_ID);
    if (!list) return;
    Array.from(list.querySelectorAll('input[type="checkbox"][data-path]')).forEach(b => {
      const p = String(b.dataset.path || '');
      if (!p) return;
      selected.add(p);
      b.checked = true;
      const card = b.closest('.item-card');
      if (card) card.classList.add('item-card--selected');
    });
  }

  function clearSelection() {
    const list = $(LIST_ID);
    if (!list) return;
    selected = new Set();
    Array.from(list.querySelectorAll('input[type="checkbox"][data-path]')).forEach(b => {
      b.checked = false;
      const card = b.closest('.item-card');
      if (card) card.classList.remove('item-card--selected');
    });
  }

  async function browse() {
    const url = pathB64 ? `/api/browse?path=${encodeURIComponent(pathB64)}` : '/api/browse';
    const resp = await fetch(url, { credentials: 'include' });
    const data = await resp.json();
    if (!data || data.status !== 'success') {
      throw new Error((data && data.message) ? data.message : '浏览失败');
    }
    return data;
  }

  async function importPaths(paths) {
    const code = typeof hooks.getFabricCode === 'function' ? String(hooks.getFabricCode() || '').trim() : '';
    if (!code) {
      showStatus('请先填写面料编号', true);
      return false;
    }
    const fabricId = typeof hooks.getFabricId === 'function' ? hooks.getFabricId() : null;
    const list = (paths || []).filter(Boolean);
    if (!list.length) {
      showStatus('请先勾选要导入的图片', true);
      return false;
    }
    showStatus(`正在移动 ${list.length} 张…`, false);
    const resp = await fetch('/api/fabric-import-by-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        fabric_code: code,
        fabric_id: fabricId,
        source_paths_b64: list,
        image_type: getSelectedImageType(),
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
    if (typeof hooks.onAfterImport === 'function') {
      hooks.onAfterImport(names, getSelectedImageType(), data);
    }
    return true;
  }

  async function importOne(filePathB64) {
    await importPaths([filePathB64]);
    await renderList({ preserveScroll: true });
  }

  async function importSelected() {
    const paths = Array.from(selected || []);
    const ok = await importPaths(paths);
    if (ok) {
      selected = new Set();
      await renderList({ preserveScroll: true });
    }
  }

  async function enterFolder(folderPathB64, folderName) {
    pathB64 = String(folderPathB64 || '');
    navStack = Array.isArray(navStack) ? navStack : [];
    const label = String(folderName || '').replace(/^📁\s*/, '').trim()
      || decodeB64Utf8(folderPathB64).split('/').filter(Boolean).pop() || '文件夹';
    navStack.push({ name: label, pathB64 });
    const ok = await renderList();
    if (ok) persistLocation();
  }

  async function jumpTo(stackIdx) {
    const idx = Number(stackIdx);
    if (idx < 0 || Number.isNaN(idx)) {
      pathB64 = FABRIC_LIBRARY_ROOT_B64;
      navStack = fabricLibraryRootStack();
    } else {
      navStack = Array.isArray(navStack) ? navStack.slice(0, idx + 1) : [];
      const last = navStack.length ? navStack[navStack.length - 1] : null;
      pathB64 = last && last.pathB64 ? last.pathB64 : '';
    }
    const ok = await renderList();
    if (ok) persistLocation();
  }

  async function renderList(opts) {
    const list = $(LIST_ID);
    if (!list) return false;
    const preserveScroll = !!(opts && opts.preserveScroll);
    const scrollTop = preserveScroll ? list.scrollTop : 0;
    try {
      list.innerHTML = '';
      const loading = document.createElement('div');
      loading.className = 'pm-select-empty nas-main-image-grid-loading';
      loading.textContent = '加载中...';
      list.appendChild(loading);
      showStatus('', false);
      const data = await browse();
      const folders = Array.isArray(data.folders) ? data.folders : [];
      const images = Array.isArray(data.images) ? data.images : [];
      renderBreadcrumbs();
      list.innerHTML = '';
      if (global.NasMainImageBrowserUi) {
        global.NasMainImageBrowserUi.syncGridThumbClassFromSegment('fabricNasThumbSizeSegment', LIST_ID);
      }
      updateMeta(images.length);
      if (!folders.length && !images.length) {
        const empty = document.createElement('div');
        empty.className = 'pm-select-empty nas-main-image-grid-empty';
        empty.textContent = '此目录为空';
        list.appendChild(empty);
        if (preserveScroll) list.scrollTop = scrollTop;
        return true;
      }
      const Ui = global.NasMainImageBrowserUi;
      const actionMode = Ui
        ? Ui.readActionModeFromSegment('fabricNasActionModeSegment')
        : 'multi';

      folders.forEach(f => {
        const fp = String(f.path || '');
        const displayName = decodeB64Utf8(f.name) || '';
        const card = document.createElement('div');
        card.className = 'item-card item-card--folder item-card--nas-browse';
        if (Ui) {
          Ui.wireNasFolderBrowseCard(card, () => enterFolder(fp, displayName));
        } else {
          card.setAttribute('role', 'button');
          card.tabIndex = 0;
          card.setAttribute('title', '双击进入文件夹');
          card.addEventListener('dblclick', () => enterFolder(fp, displayName));
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
        title.textContent = displayName;
        info.appendChild(title);
        card.appendChild(thumb);
        card.appendChild(info);
        list.appendChild(card);
      });

      images.forEach(img => {
        const fullPathB64 = String(img.path || '');
        const displayName = decodeB64Utf8(img.name) || '';
        const thumbUrl = `/api/image-preview?id=${encodeURIComponent(fullPathB64)}&mode=thumb&w=240&q=72`;
        const isSelected = selected.has(fullPathB64);
        const card = document.createElement('div');
        card.className = 'item-card item-card--nas-browse' + (isSelected ? ' item-card--selected' : '');
        if (Ui) {
          Ui.wireNasImageBrowseCard(card, actionMode, {
            onMultiClick: () => toggle(fullPathB64),
            onDoubleImport: () => importOne(fullPathB64),
          });
        } else if (actionMode === 'double') {
          card.addEventListener('dblclick', () => importOne(fullPathB64));
        } else {
          card.addEventListener('click', () => toggle(fullPathB64));
        }
        const selectWrap = document.createElement('div');
        selectWrap.className = 'item-select';
        const cb = document.createElement('input');
        cb.type = 'checkbox';
        cb.dataset.path = fullPathB64;
        cb.checked = isSelected;
        if (Ui) {
          Ui.wireNasImageCheckboxInteractions(selectWrap, cb, card, {
            actionModeSegmentId: 'fabricNasActionModeSegment',
            pathB64: fullPathB64,
            onToggle: toggle,
            updateMeta: () => updateMeta(images.length),
          });
        }
        selectWrap.appendChild(cb);
        const thumb = document.createElement('div');
        thumb.className = 'item-thumbnail';
        const im = document.createElement('img');
        im.src = thumbUrl;
        im.alt = displayName;
        im.loading = 'lazy';
        thumb.appendChild(im);
        const info = document.createElement('div');
        info.className = 'item-info';
        const title = document.createElement('div');
        title.className = 'item-name';
        title.textContent = displayName;
        info.appendChild(title);
        card.appendChild(selectWrap);
        card.appendChild(thumb);
        card.appendChild(info);
        list.appendChild(card);
      });
      if (preserveScroll) list.scrollTop = scrollTop;
      return true;
    } catch (e) {
      list.innerHTML = '';
      const err = document.createElement('div');
      err.className = 'pm-select-empty nas-main-image-grid-empty';
      err.textContent = '加载失败';
      list.appendChild(err);
      showStatus('浏览失败: ' + e, true);
      updateMeta(0);
      return false;
    }
  }

  function bindModalBackdrop() {
    const modal = $(MODAL_ID);
    if (modal && typeof global.bindPmModalBackdropClose === 'function') {
      global.bindPmModalBackdropClose(modal, close);
    }
  }

  function configure(h) {
    hooks = h || {};
  }

  async function open() {
    pathB64 = safeGet(LAST_PATH_KEY) || '';
    navStack = [];
    try {
      const raw = safeGet(LAST_STACK_KEY) || '';
      const parsed = raw ? JSON.parse(raw) : null;
      if (Array.isArray(parsed)) {
        navStack = parsed
          .filter(x => x && typeof x.pathB64 === 'string')
          .map(x => ({ name: String(x.name || ''), pathB64: String(x.pathB64 || '') }));
        const last = navStack.length ? navStack[navStack.length - 1] : null;
        if (last && last.pathB64) pathB64 = last.pathB64;
      }
    } catch (e) {
      navStack = [];
    }
    selected = new Set();
    ensureFabricLibraryPath();
    $(MODAL_ID)?.classList.add('active');
    renderImageTypeBar();
    initActionModeSegment();
    initThumbSizeSegment();
    initSelectAllBox();
    const savedPath = pathB64 || '';
    const savedStack = navStack.slice();
    if (global.NasMainImageBrowserUi && global.NasMainImageBrowserUi.restoreSavedNasBrowseLocation) {
      const restored = await global.NasMainImageBrowserUi.restoreSavedNasBrowseLocation({
        pathB64: savedPath,
        navStack: savedStack,
        fallbackPathB64: FABRIC_LIBRARY_ROOT_B64,
        crumbNameFn: (b) => decodeB64Utf8(b.name) || '目录',
      });
      if (restored) {
        pathB64 = restored.pathB64 || FABRIC_LIBRARY_ROOT_B64;
        navStack = restored.navStack.length
          ? restored.navStack
          : (pathB64 === FABRIC_LIBRARY_ROOT_B64 ? fabricLibraryRootStack() : []);
        if (restored.fellBack) persistLocation();
      }
    }
    await renderList();
  }

  function close() {
    $(MODAL_ID)?.classList.remove('active');
    persistLocation();
    pathB64 = '';
    navStack = [];
    selected = new Set();
    showStatus('', false);
  }

  global.FabricNasImportUi = {
    configure,
    open,
    close,
    bindModalBackdrop,
    renderList,
    importSelected,
  };
})(typeof window !== 'undefined' ? window : this);
