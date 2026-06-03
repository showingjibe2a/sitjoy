/**
 * NAS 主图浏览弹窗：缩略图尺寸、文件夹进入方式、图片卡片与多选误触防护等通用逻辑。
 * 供销售产品管理、下单产品管理、规格主图管理等页面复用。
 */
(function (global) {
  function safeGet(key) {
    if (!key) return null;
    try {
      return global.localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function safeSet(key, val) {
    if (!key) return;
    try {
      global.localStorage.setItem(key, val);
    } catch (e) {}
  }

  function decodePathB64(b64) {
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

  function utf8ToPathB64(text) {
    try {
      const s = String(text || '');
      if (typeof TextEncoder !== 'undefined') {
        const bytes = new TextEncoder().encode(s);
        let binary = '';
        bytes.forEach(function (b) { binary += String.fromCharCode(b); });
        return btoa(binary);
      }
      return btoa(unescape(encodeURIComponent(s)));
    } catch (e) {
      return '';
    }
  }

  function parentPathB64(pathB64) {
    const rel = decodePathB64(pathB64).replace(/\\/g, '/');
    if (!rel) return '';
    const parts = rel.split('/').filter(Boolean);
    if (!parts.length) return '';
    parts.pop();
    if (!parts.length) return '';
    return utf8ToPathB64(parts.join('/'));
  }

  function formatPathDisplayForToast(pathB64) {
    const rel = decodePathB64(pathB64).replace(/\\/g, '/');
    if (!rel) return '根目录';
    return rel.startsWith('/') ? rel : '/' + rel;
  }

  async function fetchNasBrowse(pathB64) {
    const url = pathB64 ? '/api/browse?path=' + encodeURIComponent(pathB64) : '/api/browse';
    const resp = await fetch(url, { credentials: 'include' });
    let data = null;
    try {
      data = await resp.json();
    } catch (e) {
      throw new Error(resp.ok ? '浏览响应解析失败' : ('浏览失败（HTTP ' + resp.status + '）'));
    }
    if (!data || data.status !== 'success') {
      throw new Error((data && data.message) ? data.message : '浏览失败');
    }
    return data;
  }

  function navStackFromBrowseData(data, nameFn) {
    const crumbs = data && Array.isArray(data.breadcrumbs) ? data.breadcrumbs : [];
    if (!crumbs.length) return [];
    return crumbs.map(function (b, idx) {
      const pathB64 = String(b.path || '');
      let name = '';
      if (typeof nameFn === 'function') {
        name = String(nameFn(b, idx) || '').trim();
      }
      if (!name) name = decodePathB64(b.name) || ('目录' + (idx + 1));
      return { name: name, pathB64: pathB64 };
    }).filter(function (seg) { return !!seg.pathB64; });
  }

  /**
   * 从目标路径起逐层向上尝试 browse，直到可访问或根目录/备用根。
   * @returns {Promise<{ok:boolean, pathB64:string, data:object|null, fellBack:boolean, failedPathB64:string}>}
   */
  async function resolveAccessibleNasBrowsePath(opts) {
    opts = opts || {};
    const originalPath = String(opts.pathB64 || '').trim();
    const fallbackPath = opts.fallbackPathB64 != null ? String(opts.fallbackPathB64 || '').trim() : '';
    let candidate = originalPath;
    const tried = new Set();

    while (true) {
      const key = candidate || '__root__';
      if (tried.has(key)) break;
      tried.add(key);
      try {
        const data = await fetchNasBrowse(candidate);
        return {
          ok: true,
          pathB64: candidate,
          data: data,
          fellBack: candidate !== originalPath,
          failedPathB64: candidate !== originalPath ? originalPath : '',
        };
      } catch (e) {
        if (!candidate) break;
        const parent = parentPathB64(candidate);
        if (!parent && parent !== '') break;
        if (parent === candidate) break;
        candidate = parent;
      }
    }

    if (!tried.has('__root__')) {
      try {
        const data = await fetchNasBrowse('');
        return {
          ok: true,
          pathB64: '',
          data: data,
          fellBack: !!originalPath,
          failedPathB64: originalPath,
        };
      } catch (e) {}
    }

    if (fallbackPath && !tried.has(fallbackPath)) {
      try {
        const data = await fetchNasBrowse(fallbackPath);
        return {
          ok: true,
          pathB64: fallbackPath,
          data: data,
          fellBack: true,
          failedPathB64: originalPath || fallbackPath,
        };
      } catch (e) {}
    }

    return { ok: false, pathB64: originalPath, data: null, fellBack: false, failedPathB64: originalPath };
  }

  function notifyNasPathFallback(failedPathB64) {
    const label = formatPathDisplayForToast(failedPathB64);
    const msg = '无法访问文件夹' + label + '，已自动返回上层目录。';
    if (typeof global.showAppToast === 'function') {
      global.showAppToast(msg, true, 5200);
    }
  }

  /**
   * 恢复上次记住的 NAS 路径；不可访问时自动回退到最近可访问的上层目录。
   * @returns {Promise<{pathB64:string, navStack:Array, fellBack:boolean, browseData:object|null}|null>}
   */
  async function restoreSavedNasBrowseLocation(opts) {
    opts = opts || {};
    let pathB64 = String(opts.pathB64 || '').trim();
    const navStack = Array.isArray(opts.navStack) ? opts.navStack : [];
    if (!pathB64 && navStack.length) {
      const last = navStack[navStack.length - 1];
      pathB64 = last && last.pathB64 ? String(last.pathB64) : '';
    }
    if (!pathB64 && !navStack.length) {
      return { pathB64: '', navStack: [], fellBack: false, browseData: null };
    }

    const resolved = await resolveAccessibleNasBrowsePath({
      pathB64: pathB64,
      fallbackPathB64: opts.fallbackPathB64,
    });
    if (!resolved.ok) return null;

    const nameFn = opts.crumbNameFn;
    let newStack = navStackFromBrowseData(resolved.data, nameFn);
    if (!newStack.length && resolved.pathB64) {
      const label = decodePathB64(resolved.pathB64).split(/[/\\]/).filter(Boolean).pop() || '文件夹';
      newStack = [{ name: label, pathB64: resolved.pathB64 }];
    }
    if (!resolved.pathB64) newStack = [];

    if (resolved.fellBack && resolved.failedPathB64) {
      notifyNasPathFallback(resolved.failedPathB64);
    }

    return {
      pathB64: resolved.pathB64,
      navStack: newStack,
      fellBack: !!resolved.fellBack,
      browseData: resolved.data,
    };
  }

  function resolveEl(idOrEl) {
    if (!idOrEl) return null;
    if (typeof idOrEl === 'string') return document.getElementById(idOrEl);
    return idOrEl;
  }

  function normalizeThumbMode(mode) {
    return String(mode || '').trim() === 'sm' ? 'sm' : 'lg';
  }

  function applyThumbSizeToGrid(gridIdOrEl, mode) {
    const grid = resolveEl(gridIdOrEl);
    if (!grid) return;
    const m = normalizeThumbMode(mode);
    grid.classList.toggle('is-thumb-sm', m === 'sm');
  }

  /** 从分段控件读取 lg | sm（看 attribute data-value） */
  function readThumbSegmentValue(segmentIdOrEl) {
    const seg = resolveEl(segmentIdOrEl);
    if (!seg) return 'lg';
    const raw = String(seg.getAttribute('data-value') || '').trim();
    return raw === 'sm' ? 'sm' : 'lg';
  }

  function setSegmentVisualState(segment, mode) {
    const seg = resolveEl(segment);
    if (!seg) return;
    const m = normalizeThumbMode(mode);
    seg.setAttribute('data-value', m);
    seg.querySelectorAll('button[data-value]').forEach(function (btn) {
      const bv = String(btn.getAttribute('data-value') || '').trim();
      btn.classList.toggle('is-active', bv === m);
    });
  }

  /**
   * @param {object} opts
   * @param {string} opts.segmentId
   * @param {string} opts.gridId
   * @param {string} [opts.storageKey] — 写入 localStorage
   * @param {'lg'|'sm'} [opts.defaultMode='lg']
   * @param {function('lg'|'sm'): void} [opts.onApply] — 每次应用尺寸时（含初始化）
   * @param {function('lg'|'sm'): void} [opts.onAfterClick] — 用户点击后（在应用与存储之后）
   */
  function bindThumbSizeSegment(opts) {
    if (!opts || !opts.segmentId || !opts.gridId) return;
    const seg = document.getElementById(opts.segmentId);
    if (!seg) return;
    const defaultMode = normalizeThumbMode(opts.defaultMode || 'lg');

    function applyAll(mode) {
      const m = normalizeThumbMode(mode);
      setSegmentVisualState(seg, m);
      applyThumbSizeToGrid(opts.gridId, m);
      if (opts.storageKey) safeSet(opts.storageKey, m);
      if (typeof opts.onApply === 'function') opts.onApply(m);
    }

    if (seg.dataset.nasThumbBound !== '1') {
      seg.dataset.nasThumbBound = '1';
      seg.querySelectorAll('button[data-value]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          const next = normalizeThumbMode(this.getAttribute('data-value') || defaultMode);
          applyAll(next);
          if (typeof opts.onAfterClick === 'function') opts.onAfterClick(next);
        });
      });
    }

    let initial = defaultMode;
    const stored = opts.storageKey ? safeGet(opts.storageKey) : null;
    if (stored === 'sm' || stored === 'lg') {
      initial = stored;
    } else {
      const attr = String(seg.getAttribute('data-value') || '').trim();
      if (attr === 'sm' || attr === 'lg') initial = attr;
    }
    applyAll(initial);
  }

  function syncGridThumbClassFromSegment(segmentId, gridId) {
    const m = readThumbSegmentValue(segmentId);
    applyThumbSizeToGrid(gridId, m);
  }

  /** 文件夹卡片 title / 无障碍提示（与销售页一致） */
  var FOLDER_ENTER_TOOLTIP = '双击进入文件夹';

  /** 双击进入文件夹后，列表重绘可能导致双击序列中的最后一次 click 落在新的图片卡片上；短时间内忽略图片卡片上的多选点击 */
  var _postNavigateClickCooldownUntil = 0;

  function markNasBrowseGridPostNavigateCooldown(ms) {
    var n = Number(ms);
    if (!(n > 0)) n = 450;
    _postNavigateClickCooldownUntil = Date.now() + n;
  }

  function shouldSuppressNasBrowseCardInteraction() {
    return Date.now() < _postNavigateClickCooldownUntil;
  }

  function readActionModeFromSegment(segmentIdOrEl) {
    const seg = resolveEl(segmentIdOrEl);
    if (!seg) return 'multi';
    return String(seg.getAttribute('data-value') || '').trim() === 'double' ? 'double' : 'multi';
  }

  /**
   * 文件夹：仅双击或 Enter/Space 进入（无单击进入），与销售/下单页一致。
   * @param {HTMLElement} card
   * @param {function(): void|Promise<void>} onEnter
   */
  function wireNasFolderBrowseCard(card, onEnter) {
    if (!card || typeof onEnter !== 'function') return;
    card.setAttribute('role', 'button');
    card.tabIndex = 0;
    card.setAttribute('title', FOLDER_ENTER_TOOLTIP);
    function invoke() {
      markNasBrowseGridPostNavigateCooldown(450);
      try {
        var ret = onEnter();
        if (ret && typeof ret.then === 'function') {
          ret.catch(function () {});
        }
      } catch (e) {}
    }
    card.addEventListener('dblclick', function (e) {
      e.preventDefault();
      invoke();
    });
    card.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        invoke();
      }
    });
  }

  /**
   * 图片卡片根节点：多选模式单击切换；双击模式双击导入且单击不产生选择。
   * @param {HTMLElement} card
   * @param {'double'|'multi'} actionMode
   * @param {{ onMultiClick?: function(Event): void, onDoubleImport?: function(): void }} handlers
   */
  function wireNasImageBrowseCard(card, actionMode, handlers) {
    if (!card) return;
    const h = handlers || {};
    const mode = String(actionMode || 'multi') === 'double' ? 'double' : 'multi';
    if (mode === 'double') {
      card.addEventListener('dblclick', function () {
        if (typeof h.onDoubleImport === 'function') h.onDoubleImport();
      });
      card.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
      });
    } else {
      card.addEventListener('click', function (e) {
        if (shouldSuppressNasBrowseCardInteraction()) {
          e.preventDefault();
          e.stopPropagation();
          return;
        }
        if (typeof h.onMultiClick === 'function') h.onMultiClick(e);
      });
    }
  }

  /**
   * 图片行复选框：双击模式下禁止多选；多选模式下提交 onToggle。
   */
  function wireNasImageCheckboxInteractions(selectWrap, checkboxEl, card, opts) {
    if (!selectWrap || !checkboxEl || !card || !opts) return;
    const segmentId = opts.actionModeSegmentId;
    const pathB64 = String(opts.pathB64 || '');
    const onToggle = opts.onToggle;
    const updateMeta = opts.updateMeta;
    selectWrap.addEventListener('click', function (e) {
      e.stopPropagation();
    });
    checkboxEl.addEventListener('click', function (e) {
      e.stopPropagation();
    });
    checkboxEl.addEventListener('change', function (e) {
      const m = readActionModeFromSegment(segmentId);
      if (m === 'double') {
        e.target.checked = false;
        return;
      }
      if (typeof onToggle === 'function') onToggle(pathB64, true, e.target.checked);
      card.classList.toggle('item-card--selected', !!e.target.checked);
      if (typeof updateMeta === 'function') updateMeta();
    });
  }

  global.NasMainImageBrowserUi = {
    FOLDER_ENTER_TOOLTIP: FOLDER_ENTER_TOOLTIP,
    markNasBrowseGridPostNavigateCooldown: markNasBrowseGridPostNavigateCooldown,
    shouldSuppressNasBrowseCardInteraction: shouldSuppressNasBrowseCardInteraction,
    readActionModeFromSegment: readActionModeFromSegment,
    wireNasFolderBrowseCard: wireNasFolderBrowseCard,
    wireNasImageBrowseCard: wireNasImageBrowseCard,
    wireNasImageCheckboxInteractions: wireNasImageCheckboxInteractions,
    applyThumbSizeToGrid: applyThumbSizeToGrid,
    readThumbSegmentValue: readThumbSegmentValue,
    bindThumbSizeSegment: bindThumbSizeSegment,
    syncGridThumbClassFromSegment: syncGridThumbClassFromSegment,
    decodePathB64: decodePathB64,
    parentPathB64: parentPathB64,
    fetchNasBrowse: fetchNasBrowse,
    navStackFromBrowseData: navStackFromBrowseData,
    resolveAccessibleNasBrowsePath: resolveAccessibleNasBrowsePath,
    restoreSavedNasBrowseLocation: restoreSavedNasBrowseLocation,
    notifyNasPathFallback: notifyNasPathFallback,
    formatPathDisplayForToast: formatPathDisplayForToast,
  };
})(typeof window !== 'undefined' ? window : this);
