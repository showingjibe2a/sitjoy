/**

 * 销售产品管理：Amazon / Wayfair 库存导出弹窗与选项记忆。

 */

(function (global) {

  const LS_KEYS = {

    amazon: 'sj.salesPlatformInventoryExport.amazon.v4',

    wayfair: 'sj.salesPlatformInventoryExport.wayfair.v4',

  };

  const LEGACY_LS_KEYS = [

    'sj.salesPlatformInventoryExport.v2',

    'sj.salesPlatformInventoryExport.v1',

  ];



  const CALC_DEFAULTS = {

    calc_mode: 'strict_sets',

    max_missing_parts: 2,

    min_in_stock_parts: 2,

    flex_logic: 'and',

    cap_enabled: true,

    cap_max: 20,

    spec_gap_enabled: true,

    spec_gap_step: 1,

    spec_gap_per_part: 1,

    spec_gap_min: 0,

    min_nosync_qty: 0,

    use_fabric_share: true,

    fabric_share_min_qty: 0,

  };



  const AMAZON_DEFAULTS = Object.assign({}, CALC_DEFAULTS, {

    amazon_mode: 'generate',

    shop_id: '',

    parent_ids: [],

  });



  const WAYFAIR_DEFAULTS = Object.assign({}, CALC_DEFAULTS);



  function safeGet(key) {

    try { return global.localStorage.getItem(key); } catch (e) { return null; }

  }



  function safeSet(key, val) {

    try { global.localStorage.setItem(key, val); } catch (e) {}

  }



  function isAmazonPlatformName(name) {

    const p = String(name || '').trim().toLowerCase();

    return p.includes('amazon') || p.includes('亚马逊');

  }



  function defaultsForPlatform(platform) {

    return platform === 'wayfair' ? WAYFAIR_DEFAULTS : AMAZON_DEFAULTS;

  }



  function migrateLegacyPrefs(parsed) {

    const out = Object.assign({}, parsed);

    if (out.calc_mode === 'exclude_out_of_stock') {

      out.calc_mode = 'flexible';

      out.max_missing_parts = out.max_missing_parts || 2;

      out.min_in_stock_parts = out.min_in_stock_parts || 1;

      out.flex_logic = out.flex_logic || 'or';

    } else if (out.calc_mode === 'only_in_stock_parts') {

      out.calc_mode = 'flexible';

      out.max_missing_parts = out.max_missing_parts || 99;

      out.min_in_stock_parts = out.min_in_stock_parts || 2;

      out.flex_logic = out.flex_logic || 'or';

    }

    return out;

  }



  function readLegacySharedPrefs() {

    for (let i = 0; i < LEGACY_LS_KEYS.length; i += 1) {

      const raw = safeGet(LEGACY_LS_KEYS[i]);

      if (!raw) continue;

      try {

        return migrateLegacyPrefs(JSON.parse(raw) || {});

      } catch (e) {}

    }

    return null;

  }



  function loadPrefs(platform) {

    const pf = platform === 'wayfair' ? 'wayfair' : 'amazon';

    const defaults = defaultsForPlatform(pf);

    try {

      const raw = safeGet(LS_KEYS[pf]);

      if (raw) {

        const parsed = migrateLegacyPrefs(JSON.parse(raw) || {});

        return Object.assign({}, defaults, parsed);

      }

      const legacy = readLegacySharedPrefs();

      if (legacy) {

        return Object.assign({}, defaults, legacy);

      }

      return Object.assign({}, defaults);

    } catch (e) {

      return Object.assign({}, defaults);

    }

  }



  function savePrefs(prefs, platform) {

    const pf = platform === 'wayfair' ? 'wayfair' : 'amazon';

    safeSet(LS_KEYS[pf], JSON.stringify(prefs || {}));

  }



  function currentPlatform() {

    const modal = document.getElementById('spiExportModal');

    return modal?.dataset.platform === 'wayfair' ? 'wayfair' : 'amazon';

  }



  function persistFormPrefs() {

    savePrefs(readFormPrefs(), currentPlatform());

  }



  function bindSegment(segId, onChange) {

    const seg = document.getElementById(segId);

    if (!seg || seg.dataset.bound === '1') return;

    seg.dataset.bound = '1';

    seg.querySelectorAll('button.status-pill[data-value]').forEach(btn => {

      btn.addEventListener('click', function () {

        const val = String(this.getAttribute('data-value') || '');

        seg.setAttribute('data-value', val);

        seg.querySelectorAll('button.status-pill[data-value]').forEach(b => {

          b.classList.toggle('is-active', String(b.getAttribute('data-value') || '') === val);

        });

        if (typeof onChange === 'function') onChange(val, seg);

        persistFormPrefs();

      });

    });

  }



  function syncSegmentUi(segId, value) {

    const seg = document.getElementById(segId);

    if (!seg) return;

    const val = String(value || '');

    seg.setAttribute('data-value', val);

    seg.querySelectorAll('button.status-pill[data-value]').forEach(b => {

      b.classList.toggle('is-active', String(b.getAttribute('data-value') || '') === val);

    });

  }



  function segmentValue(segId, fallback) {

    const seg = document.getElementById(segId);

    if (!seg) return fallback;

    return String(seg.getAttribute('data-value') || fallback);

  }



  function syncCalcModeUi() {

    const mode = segmentValue('spiCalcModeSegment', 'strict_sets');

    const flex = document.getElementById('spiFlexPanel');

    if (flex) flex.classList.toggle('spi-panel-hidden', mode !== 'flexible');

  }



  function syncAmazonModeUi() {

    const mode = segmentValue('spiAmazonModeSegment', 'generate');

    const uploadWrap = document.getElementById('spiAmazonUploadWrap');

    const genWrap = document.getElementById('spiAmazonGenerateWrap');

    const parentWrap = document.getElementById('spiAmazonParentWrap');

    if (uploadWrap) uploadWrap.classList.toggle('spi-panel-hidden', mode !== 'fill');

    if (genWrap) genWrap.classList.toggle('spi-panel-hidden', mode !== 'generate');

    if (parentWrap) parentWrap.classList.toggle('spi-panel-hidden', mode !== 'generate');

  }



  function readFormPrefs() {

    const platform = currentPlatform();

    const prefs = {

      calc_mode: segmentValue('spiCalcModeSegment', 'strict_sets'),

      max_missing_parts: Math.max(0, Number(document.getElementById('spiMaxMissingParts')?.value || 2)),

      min_in_stock_parts: Math.max(0, Number(document.getElementById('spiMinInStockParts')?.value || 2)),

      flex_logic: segmentValue('spiFlexLogicSegment', 'and'),

      cap_enabled: segmentValue('spiCapEnabledSegment', '1') === '1',

      cap_max: Math.max(0, Number(document.getElementById('spiCapMax')?.value || 20)),

      spec_gap_enabled: segmentValue('spiSpecGapEnabledSegment', '1') === '1',

      spec_gap_step: Math.max(1, Number(document.getElementById('spiSpecGapStep')?.value || 1)),

      spec_gap_per_part: Math.max(0, Number(document.getElementById('spiSpecGapPerPart')?.value || 1)),

      spec_gap_min: Math.max(0, Number(document.getElementById('spiSpecGapMin')?.value || 0)),

      min_nosync_qty: Math.max(0, Number(document.getElementById('spiMinNosyncQty')?.value || 0)),

      use_fabric_share: segmentValue('spiFabricShareSegment', '1') === '1',

      fabric_share_min_qty: Math.max(0, Number(document.getElementById('spiFabricShareMinQty')?.value || 0)),

    };

    if (platform === 'amazon') {

      prefs.amazon_mode = segmentValue('spiAmazonModeSegment', 'generate');

      prefs.shop_id = String(document.getElementById('spiAmazonShop')?.value || '').trim();

      prefs.parent_ids = readSelectedParentIds();

    }

    return prefs;

  }



  function applyPrefsToForm(prefs, platform) {

    const pf = platform === 'wayfair' ? 'wayfair' : 'amazon';

    const p = Object.assign({}, defaultsForPlatform(pf), prefs || {});

    syncSegmentUi('spiCalcModeSegment', p.calc_mode);

    syncSegmentUi('spiFlexLogicSegment', p.flex_logic);

    syncSegmentUi('spiCapEnabledSegment', p.cap_enabled ? '1' : '0');

    syncSegmentUi('spiSpecGapEnabledSegment', p.spec_gap_enabled ? '1' : '0');

    syncSegmentUi('spiFabricShareSegment', p.use_fabric_share ? '1' : '0');

    if (pf === 'amazon') {

      syncSegmentUi('spiAmazonModeSegment', p.amazon_mode);

    }

    const maxMissing = document.getElementById('spiMaxMissingParts');

    const minInStock = document.getElementById('spiMinInStockParts');

    const capMax = document.getElementById('spiCapMax');

    const gapStep = document.getElementById('spiSpecGapStep');

    const gapN = document.getElementById('spiSpecGapPerPart');

    const gapMin = document.getElementById('spiSpecGapMin');

    const minNosync = document.getElementById('spiMinNosyncQty');

    const fabricShareMin = document.getElementById('spiFabricShareMinQty');

    const shopSel = document.getElementById('spiAmazonShop');

    if (maxMissing) maxMissing.value = String(p.max_missing_parts);

    if (minInStock) minInStock.value = String(p.min_in_stock_parts);

    if (capMax) capMax.value = String(p.cap_max);

    if (gapStep) gapStep.value = String(Math.max(1, Number(p.spec_gap_step || 1)));

    if (gapN) gapN.value = String(p.spec_gap_per_part);

    if (gapMin) gapMin.value = String(p.spec_gap_min);

    if (minNosync) minNosync.value = String(p.min_nosync_qty);

    if (fabricShareMin) fabricShareMin.value = String(p.fabric_share_min_qty ?? 0);

    if (shopSel && p.shop_id) shopSel.value = String(p.shop_id);

    syncCalcModeUi();

    syncAmazonModeUi();

  }



  let _spiParentItemsCache = null;

  let _spiParentShopId = '';

  let _spiSelectedParentIds = [];

  let _spiParentsForShop = [];



  function parentMarkerLabel(item) {

    const marker = String((item && item.sku_marker) || '').trim();

    if (marker) return marker;

    const code = String((item && item.parent_code) || '').trim();

    if (code) return code;

    return `父体#${item && item.id}`;

  }



  async function loadSpiParentItems() {

    if (_spiParentItemsCache) return _spiParentItemsCache;

    try {

      const resp = await fetch('/api/parent', { credentials: 'include' });

      const data = await resp.json();

      if (!resp.ok || !data || data.status === 'error') {

        _spiParentItemsCache = [];

        return _spiParentItemsCache;

      }

      _spiParentItemsCache = Array.isArray(data.items) ? data.items : [];

    } catch (e) {

      _spiParentItemsCache = [];

    }

    return _spiParentItemsCache;

  }



  function readSelectedParentIds() {

    return _spiSelectedParentIds

      .map(id => Number(id))

      .filter(n => Number.isFinite(n) && n > 0);

  }



  function closeAmazonParentDropdown() {

    const dropdown = document.getElementById('spiAmazonParentDropdown');

    if (!dropdown) return;

    dropdown.classList.remove('open');

    dropdown.classList.remove('expanded');

  }



  function ensureAmazonParentMenuVisible() {

    const modal = document.getElementById('spiExportModal');

    const toggle = document.getElementById('spiAmazonParentToggle');

    const menu = document.getElementById('spiAmazonParentMenu');

    if (!toggle || !menu) return;

    const desiredSpace = 280;

    const firstRect = toggle.getBoundingClientRect();

    const firstAvailable = window.innerHeight - firstRect.bottom - 12;

    if (modal && firstAvailable < desiredSpace) {

      modal.scrollTop += (desiredSpace - firstAvailable);

    }

    window.requestAnimationFrame(function () {

      const rect = toggle.getBoundingClientRect();

      const available = window.innerHeight - rect.bottom - 12;

      const maxHeight = Math.max(120, Math.min(380, available));

      menu.style.maxHeight = `${maxHeight}px`;

      menu.style.overflowY = 'auto';

    });

  }



  function openAmazonParentDropdown() {

    if (!_spiParentShopId || !_spiParentsForShop.length) return;

    const dropdown = document.getElementById('spiAmazonParentDropdown');

    if (!dropdown) return;

    dropdown.classList.add('expanded');

    dropdown.classList.add('open');

    ensureAmazonParentMenuVisible();

  }



  function renderAmazonParentPickerUi() {

    const chips = document.getElementById('spiAmazonParentChips');

    const options = document.getElementById('spiAmazonParentOptions');

    const toggle = document.getElementById('spiAmazonParentToggle');

    const searchEl = document.getElementById('spiAmazonParentSearch');

    if (!chips || !options) return;

    const keyword = String(searchEl?.value || '').trim().toLowerCase();

    const parentById = new Map(_spiParentsForShop.map(p => [String(p.id), p]));

    chips.innerHTML = '';

    _spiSelectedParentIds.forEach(id => {

      const item = parentById.get(String(id));

      if (!item) return;

      const chip = document.createElement('span');

      chip.className = 'feature-category-chip';

      chip.textContent = parentMarkerLabel(item);

      const removeBtn = document.createElement('button');

      removeBtn.type = 'button';

      removeBtn.className = 'feature-category-remove';

      removeBtn.innerText = '×';

      removeBtn.addEventListener('click', function () {

        _spiSelectedParentIds = _spiSelectedParentIds.filter(x => String(x) !== String(id));

        renderAmazonParentPickerUi();

        persistFormPrefs();

      });

      chip.appendChild(removeBtn);

      chips.appendChild(chip);

    });

    const selectedSet = new Set(_spiSelectedParentIds.map(String));

    const available = _spiParentsForShop.filter(p => {

      if (selectedSet.has(String(p.id))) return false;

      if (!keyword) return true;

      return parentMarkerLabel(p).toLowerCase().includes(keyword);

    });

    options.innerHTML = '';

    if (!_spiParentShopId) {

      options.innerHTML = '<div class="feature-category-empty">请先选择店铺</div>';

      if (toggle) toggle.disabled = true;

      return;

    }

    if (!_spiParentsForShop.length) {

      options.innerHTML = '<div class="feature-category-empty">该店铺暂无父体</div>';

      if (toggle) toggle.disabled = true;

      return;

    }

    if (toggle) toggle.disabled = false;

    if (!available.length) {

      options.innerHTML = '<div class="feature-category-empty">无匹配父体</div>';

      return;

    }

    available.forEach(item => {

      const btn = document.createElement('button');

      btn.type = 'button';

      btn.className = 'feature-category-option';

      btn.textContent = parentMarkerLabel(item);

      btn.addEventListener('click', function () {

        _spiSelectedParentIds.push(String(item.id));

        renderAmazonParentPickerUi();

        persistFormPrefs();

      });

      options.appendChild(btn);

    });

  }



  async function renderAmazonParentPicker(shopId, selectedIds) {

    _spiParentShopId = String(shopId || '').trim();

    closeAmazonParentDropdown();

    if (!_spiParentShopId) {

      _spiParentsForShop = [];

      _spiSelectedParentIds = [];

      const searchEl = document.getElementById('spiAmazonParentSearch');

      if (searchEl) searchEl.value = '';

      renderAmazonParentPickerUi();

      return;

    }

    const items = await loadSpiParentItems();

    _spiParentsForShop = items

      .filter(p => String(p.shop_id || '') === _spiParentShopId && Number(p.is_enabled) !== 0)

      .sort((a, b) => parentMarkerLabel(a).localeCompare(parentMarkerLabel(b), 'zh-CN'));

    const incoming = Array.isArray(selectedIds) ? selectedIds.map(String) : _spiSelectedParentIds.map(String);

    const allowed = new Set(_spiParentsForShop.map(p => String(p.id)));

    _spiSelectedParentIds = incoming.filter(id => allowed.has(id));

    const searchEl = document.getElementById('spiAmazonParentSearch');

    if (searchEl) searchEl.value = '';

    renderAmazonParentPickerUi();

  }



  function bindAmazonParentPickerUi() {

    const toggle = document.getElementById('spiAmazonParentToggle');

    const searchEl = document.getElementById('spiAmazonParentSearch');

    const dropdown = document.getElementById('spiAmazonParentDropdown');

    const modal = document.getElementById('spiExportModal');

    if (!toggle || toggle.dataset.spiParentBound === '1') return;

    toggle.dataset.spiParentBound = '1';

    toggle.addEventListener('click', function () {

      if (toggle.disabled) return;

      openAmazonParentDropdown();

      searchEl?.focus();

    });

    if (searchEl) {

      searchEl.addEventListener('input', function () {

        renderAmazonParentPickerUi();

        ensureAmazonParentMenuVisible();

      });

    }

    if (dropdown) {

      dropdown.addEventListener('click', function (e) {

        e.stopPropagation();

      });

    }

    if (modal) {

      modal.addEventListener('scroll', function () {

        const dd = document.getElementById('spiAmazonParentDropdown');

        if (dd && dd.classList.contains('open')) {

          ensureAmazonParentMenuVisible();

        }

      });

    }

    window.addEventListener('resize', function () {

      const dd = document.getElementById('spiAmazonParentDropdown');

      if (dd && dd.classList.contains('open')) {

        ensureAmazonParentMenuVisible();

      }

    });

    document.addEventListener('click', function (e) {

      const dd = document.getElementById('spiAmazonParentDropdown');

      if (dd && !dd.contains(e.target)) {

        closeAmazonParentDropdown();

      }

    });

  }



  async function populateAmazonShops(preferredShopId) {

    const sel = document.getElementById('spiAmazonShop');

    if (!sel) return;

    let items = [];

    if (typeof global.getSalesShopOptions === 'function') {

      items = global.getSalesShopOptions() || [];

    }

    if (!items.length) {

      try {

        const resp = await fetch('/api/shop', { credentials: 'include' });

        const data = await resp.json();

        items = (data && data.status === 'success') ? (data.items || []) : [];

      } catch (e) {

        items = [];

      }

    }

    const amazonShops = items.filter(s => isAmazonPlatformName(s.platform_type_name));

    const old = preferredShopId || sel.value || '';

    sel.innerHTML = ['<option value="">请选择亚马逊店铺</option>'].concat(

      amazonShops.map(s => `<option value="${s.id}">${String(s.shop_name || '')} / ${String(s.brand_name || '')}</option>`)

    ).join('');

    if (old && amazonShops.some(s => String(s.id) === String(old))) {

      sel.value = String(old);

    }

  }



  function setStatus(msg, isError) {

    const el = document.getElementById('spiExportStatus');

    if (!el) return;

    const text = String(msg || '').trim();

    if (!text) {

      el.style.display = 'none';

      el.textContent = '';

      return;

    }

    el.style.display = '';

    el.className = 'response' + (isError ? ' error' : '');

    el.textContent = text;

  }



  function resetFileInputs() {

    ['spiAmazonFile', 'spiWayfairFile'].forEach(id => {

      const el = document.getElementById(id);

      if (el) el.value = '';

    });

  }



  async function openModal(platform) {

    const modal = document.getElementById('spiExportModal');

    if (!modal) return;

    const pf = platform === 'wayfair' ? 'wayfair' : 'amazon';

    if (modal.classList.contains('active') && modal.dataset.platform) {

      savePrefs(readFormPrefs(), modal.dataset.platform);

    }

    modal.dataset.platform = pf;

    document.getElementById('spiAmazonPanel')?.classList.toggle('spi-panel-hidden', pf !== 'amazon');

    document.getElementById('spiWayfairPanel')?.classList.toggle('spi-panel-hidden', pf !== 'wayfair');

    const title = document.getElementById('spiExportModalTitle');

    if (title) {

      title.textContent = pf === 'wayfair' ? '下载 Wayfair 库存' : '下载亚马逊库存';

    }

    const prefs = loadPrefs(pf);

    applyPrefsToForm(prefs, pf);

    if (pf === 'amazon') {

      await populateAmazonShops(prefs.shop_id);

      await renderAmazonParentPicker(prefs.shop_id, prefs.parent_ids || []);

    }

    resetFileInputs();

    setStatus('');

    modal.classList.add('active');

  }



  function closeModal() {

    persistFormPrefs();

    document.getElementById('spiExportModal')?.classList.remove('active');

  }



  async function downloadBlobResponse(resp, fallbackName) {

    const blob = await resp.blob();

    const ct = resp.headers.get('content-disposition') || '';

    let filename = fallbackName;

    const m = /filename\*=UTF-8''([^;]+)/i.exec(ct);

    if (m && m[1]) {

      try { filename = decodeURIComponent(m[1]); } catch (e) {}

    }

    const url = URL.createObjectURL(blob);

    const a = document.createElement('a');

    a.href = url;

    a.download = filename;

    document.body.appendChild(a);

    a.click();

    a.remove();

    setTimeout(() => URL.revokeObjectURL(url), 5000);

  }



  async function ensureFileResponse(resp, fallbackName) {

    const ct = (resp.headers.get('content-type') || '').toLowerCase();

    if (ct.includes('application/json')) {

      const data = await resp.json();

      if (!resp.ok || !data || data.status === 'error') {

        throw new Error((data && data.message) ? data.message : ('导出失败（HTTP ' + resp.status + '）'));

      }

    } else if (!resp.ok) {

      let msg = '导出失败（HTTP ' + resp.status + '）';

      try {

        const text = await resp.text();

        if (text) {

          try {

            const data = JSON.parse(text);

            if (data && data.message) msg = data.message;

          } catch (e) {

            if (text.length <= 200) msg = text;

          }

        }

      } catch (e) {}

      throw new Error(msg);

    }

    await downloadBlobResponse(resp, fallbackName);

  }



  function buildExportOptions(prefs) {

    const platform = currentPlatform();

    const parentIds = platform === 'amazon' ? readSelectedParentIds() : [];

    return {

      calc_mode: prefs.calc_mode,

      max_missing_parts: prefs.max_missing_parts,

      min_in_stock_parts: prefs.min_in_stock_parts,

      flex_logic: prefs.flex_logic,

      cap_enabled: prefs.cap_enabled,

      cap_max: prefs.cap_max,

      spec_gap_enabled: prefs.spec_gap_enabled,

      spec_gap_step: Math.max(1, Number(prefs.spec_gap_step || 1)),

      spec_gap_per_part: prefs.spec_gap_per_part,

      spec_gap_min: prefs.spec_gap_min,

      min_nosync_qty: prefs.min_nosync_qty,

      use_fabric_share: !!prefs.use_fabric_share,

      fabric_share_min_qty: Math.max(0, Number(prefs.fabric_share_min_qty || 0)),

      shop_id: prefs.shop_id ? Number(prefs.shop_id) : null,

      parent_ids: parentIds,

    };

  }



  function escapeHtmlLite(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escapeAttrLite(value) {
    return escapeHtmlLite(value);
  }

  function previewThumbHtml(previewB64) {
    const b64 = String(previewB64 || '').trim();
    if (!b64) return '<span class="sj-table-thumb-empty">暂无</span>';
    const src = `/api/image-preview?id=${encodeURIComponent(b64)}&mode=thumb&w=120&q=60`;
    return `<span class="sj-table-thumb-lazy" data-sj-lazy-thumb="${escapeAttrLite(src)}" aria-hidden="true"></span>`;
  }

  function setPreviewStatus(msg, isError) {
    const el = document.getElementById('spiPreviewStatus');
    if (!el) return;
    const text = String(msg || '').trim();
    if (!text) {
      el.style.display = 'none';
      el.textContent = '';
      return;
    }
    el.style.display = '';
    el.className = 'response' + (isError ? ' error' : '');
    el.textContent = text;
  }

  function renderPreviewRows(platform, items) {
    const tbody = document.getElementById('spiPreviewTableBody');
    const summary = document.getElementById('spiPreviewSummary');
    const whCol = document.getElementById('spiPreviewWarehouseCol');
    const title = document.getElementById('spiPreviewModalTitle');
    const table = tbody ? tbody.closest('table') : null;
    if (table) table.dataset.disableTableManage = '1';
    if (!tbody) return;
    const rows = Array.isArray(items) ? items : [];
    if (title) {
      title.textContent = platform === 'wayfair' ? 'Wayfair 库存导出预览' : 'Amazon 库存导出预览';
    }
    if (whCol) {
      whCol.textContent = platform === 'wayfair' ? '仓库（Wayfair）' : '仓库';
    }
    const qtySum = rows.reduce((acc, row) => acc + Math.max(0, Number(row.qty || 0)), 0);
    if (summary) {
      const scrollHint = rows.length > 30 ? '，可滚动查看全部' : '';
      summary.textContent = `共 ${rows.length} 行，合计数量 ${qtySum}${scrollHint}`;
    }
    tbody.innerHTML = rows.map(row => {
      const remark = String(row.remark || '').trim();
      const remarkClass = remark ? 'spi-preview-remark' : 'spi-preview-remark is-empty';
      const remarkText = remark || '-';
      return `<tr>
        <td class="sj-cell-thumb cell-center" style="text-align:center;">${previewThumbHtml(row.preview_image_b64)}</td>
        <td>${escapeHtmlLite(row.sku || '')}</td>
        <td>${escapeHtmlLite(row.warehouse || '-')}</td>
        <td class="spi-preview-qty">${Math.max(0, Number(row.qty || 0))}</td>
        <td class="${remarkClass}">${escapeHtmlLite(remarkText)}</td>
      </tr>`;
    }).join('');
    const wrap = tbody.closest('.spi-preview-scroll');
    if (wrap && global.SitjoyRowImageRefresh && typeof global.SitjoyRowImageRefresh.observeLazyThumbsIn === 'function') {
      global.SitjoyRowImageRefresh.observeLazyThumbsIn(wrap);
    }
  }

  function openPreviewModal() {
    document.getElementById('spiPreviewModal')?.classList.add('active');
  }

  function closePreviewModal() {
    document.getElementById('spiPreviewModal')?.classList.remove('active');
  }

  async function submitPreview() {
    const modal = document.getElementById('spiExportModal');
    const platform = modal?.dataset.platform === 'wayfair' ? 'wayfair' : 'amazon';
    const prefs = readFormPrefs();
    savePrefs(prefs, platform);
    const previewBtn = document.getElementById('spiPreviewBtn');
    if (previewBtn?.dataset.busy === '1') return;
    if (previewBtn) {
      previewBtn.dataset.busy = '1';
      previewBtn.disabled = true;
    }
    setStatus('正在计算预览…', false);
    setPreviewStatus('');
    const opts = buildExportOptions(prefs);
    opts.platform = platform;
    try {
      let resp;
      if (platform === 'amazon') {
        const mode = prefs.amazon_mode === 'fill' ? 'fill' : 'generate';
        opts.mode = mode;
        if (mode === 'fill') {
          const fileEl = document.getElementById('spiAmazonFile');
          const file = fileEl && fileEl.files && fileEl.files[0];
          if (!file) {
            setStatus('请上传 Amazon txt 模板', true);
            return;
          }
          const fd = new FormData();
          fd.append('file', file);
          fd.append('options', JSON.stringify(opts));
          resp = await fetch('/api/sales-product-inventory-export-preview', { method: 'POST', body: fd, credentials: 'include' });
        } else {
          if (!opts.shop_id) {
            setStatus('请选择亚马逊店铺', true);
            return;
          }
          resp = await fetch('/api/sales-product-inventory-export-preview', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(Object.assign({ mode: 'generate' }, opts)),
            credentials: 'include',
          });
        }
      } else {
        const fileEl = document.getElementById('spiWayfairFile');
        const file = fileEl && fileEl.files && fileEl.files[0];
        if (!file) {
          setStatus('请上传 Wayfair csv 模板', true);
          return;
        }
        const fd = new FormData();
        fd.append('file', file);
        fd.append('options', JSON.stringify(opts));
        resp = await fetch('/api/sales-product-inventory-export-preview', { method: 'POST', body: fd, credentials: 'include' });
      }
      const data = await resp.json();
      if (!resp.ok || !data || data.status === 'error') {
        throw new Error((data && data.message) ? data.message : ('预览失败（HTTP ' + resp.status + '）'));
      }
      renderPreviewRows(platform, data.items || []);
      setStatus('');
      openPreviewModal();
    } catch (e) {
      setStatus((e && e.message) ? e.message : String(e), true);
    } finally {
      if (previewBtn) {
        previewBtn.dataset.busy = '0';
        previewBtn.disabled = false;
      }
    }
  }


  async function submitExport() {

    const modal = document.getElementById('spiExportModal');

    const platform = modal?.dataset.platform === 'wayfair' ? 'wayfair' : 'amazon';

    const prefs = readFormPrefs();

    savePrefs(prefs, platform);

    const submitBtn = document.querySelector('#spiExportModal .pm-modal-actions .btn-primary');

    if (submitBtn?.dataset.busy === '1') return;

    if (submitBtn) {

      submitBtn.dataset.busy = '1';

      submitBtn.disabled = true;

    }

    setStatus('正在计算库存并生成文件，请稍候…', false);

    const opts = buildExportOptions(prefs);

    try {

      if (platform === 'amazon') {

        const mode = prefs.amazon_mode === 'fill' ? 'fill' : 'generate';

        opts.mode = mode;

        if (mode === 'fill') {

          const fileEl = document.getElementById('spiAmazonFile');

          const file = fileEl && fileEl.files && fileEl.files[0];

          if (!file) {

            setStatus('请上传 Amazon txt 模板', true);

            return;

          }

          const fd = new FormData();

          fd.append('file', file);

          fd.append('options', JSON.stringify(opts));

          const resp = await fetch('/api/sales-product-amazon-inventory-export', { method: 'POST', body: fd, credentials: 'include' });

          await ensureFileResponse(resp, 'amazon_inventory.txt');

        } else {

          if (!opts.shop_id) {

            setStatus('请选择亚马逊店铺', true);

            return;

          }

          const resp = await fetch('/api/sales-product-amazon-inventory-export', {

            method: 'POST',

            headers: { 'Content-Type': 'application/json' },

            body: JSON.stringify(Object.assign({ mode: 'generate' }, opts)),

            credentials: 'include',

          });

          await ensureFileResponse(resp, 'amazon_inventory.txt');

        }

      } else {

        const fileEl = document.getElementById('spiWayfairFile');

        const file = fileEl && fileEl.files && fileEl.files[0];

        if (!file) {

          setStatus('请上传 Wayfair csv 模板', true);

          return;

        }

        const fd = new FormData();

        fd.append('file', file);

        fd.append('options', JSON.stringify(opts));

        const resp = await fetch('/api/sales-product-wayfair-inventory-export', { method: 'POST', body: fd, credentials: 'include' });

        await ensureFileResponse(resp, 'wayfair_inventory.csv');

      }

      setStatus('已下载', false);

      if (global.showAppToast) global.showAppToast('库存文件已下载', false, 2500);

    } catch (e) {

      setStatus((e && e.message) ? e.message : String(e), true);

    } finally {

      if (submitBtn) {

        submitBtn.dataset.busy = '0';

        submitBtn.disabled = false;

      }

    }

  }



  async function submitFromPreview() {

    closePreviewModal();

    await submitExport();

  }



  function bindPrefAutoSave() {

    [

      'spiMaxMissingParts',

      'spiMinInStockParts',

      'spiCapMax',

      'spiSpecGapStep',

      'spiSpecGapPerPart',

      'spiSpecGapMin',

      'spiMinNosyncQty',

      'spiFabricShareMinQty',

      'spiAmazonShop',

    ].forEach(id => {

      const el = document.getElementById(id);

      if (!el || el.dataset.spiPrefBound === '1') return;

      el.dataset.spiPrefBound = '1';

      el.addEventListener('change', persistFormPrefs);

      if (el.type === 'number') {

        el.addEventListener('input', persistFormPrefs);

      }

    });

  }



  function bindUi() {

    bindSegment('spiCalcModeSegment', syncCalcModeUi);

    bindSegment('spiFlexLogicSegment');

    bindSegment('spiCapEnabledSegment');

    bindSegment('spiSpecGapEnabledSegment');

    bindSegment('spiFabricShareSegment');

    bindSegment('spiAmazonModeSegment', syncAmazonModeUi);

    bindPrefAutoSave();

    bindAmazonParentPickerUi();

    const shopSel = document.getElementById('spiAmazonShop');

    if (shopSel && shopSel.dataset.spiParentBound !== '1') {

      shopSel.dataset.spiParentBound = '1';

      shopSel.addEventListener('change', async function () {

        const prefs = loadPrefs('amazon');

        await renderAmazonParentPicker(this.value, prefs.parent_ids || []);

        persistFormPrefs();

      });

    }

    const modal = document.getElementById('spiExportModal');

    if (modal && global.bindPmModalBackdropClose) {

      global.bindPmModalBackdropClose(modal, closeModal);

    }

    const previewModal = document.getElementById('spiPreviewModal');

    if (previewModal && global.bindPmModalBackdropClose) {

      global.bindPmModalBackdropClose(previewModal, closePreviewModal);

    }

  }



  global.SalesPlatformInventoryExport = {

    openAmazon: () => openModal('amazon'),

    openWayfair: () => openModal('wayfair'),

    close: closeModal,

    preview: submitPreview,

    closePreview: closePreviewModal,

    submitFromPreview,

    submit: submitExport,

    bindUi,

  };



  if (document.readyState === 'loading') {

    document.addEventListener('DOMContentLoaded', bindUi);

  } else {

    bindUi();

  }

})(window);


