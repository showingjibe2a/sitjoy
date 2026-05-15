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
  };
})(typeof window !== 'undefined' ? window : this);
