/**
 * 面料图片统一前端：绑定/导入结果合并、路径 B64、预览 URL。
 * 与后端 file_utils_mixin 绑定命名规则及 /api/fabric-attach、/api/fabric-import-by-path 配套。
 */
(function (global) {
  const FABRIC_FOLDER = '『面料』';

  // -------------------------------------------------------------------------
  // 路径 B64、预览 URL 与绑定合并
  // -------------------------------------------------------------------------
  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function encodeUtf8PathB64(text) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.encodeUtf8ToB64 === 'function') {
      return global.SitjoyFsName.encodeUtf8ToB64(text) || '';
    }
    return '';
  }

  function decodeFsNameFromB64(rawB64) {
    if (global.SitjoyFsName && typeof global.SitjoyFsName.decodeFsNameFromB64 === 'function') {
      return global.SitjoyFsName.decodeFsNameFromB64(rawB64) || '';
    }
    return '';
  }

  function fabricRelPath(imageName) {
    const name = String(imageName || '').trim();
    if (!name) return '';
    return name.includes('/') ? name : `${FABRIC_FOLDER}/${name}`;
  }

  function resolveFabricImagePathB64(img, catalog) {
    if (!img) return '';
    const stored = String(img.preview_b64 || '').trim();
    if (stored) return stored;
    const list = catalog || [];
    const imageName = String(img.image_name || '').trim();
    if (imageName && list.length) {
      const found = list.find((it) => {
        if (!it) return false;
        if (it.name === imageName) return true;
        const dec = decodeFsNameFromB64(it.rawB64 || it.name_raw_b64 || '');
        return dec === imageName;
      });
      if (found && found.b64) return String(found.b64).trim();
    }
    if (img.image_name_raw_b64) {
      const nameDec = decodeFsNameFromB64(img.image_name_raw_b64) || imageName;
      if (nameDec) return encodeUtf8PathB64(fabricRelPath(nameDec));
    }
    return encodeUtf8PathB64(fabricRelPath(imageName));
  }

  function previewUrlFromPathB64(pathB64, width, quality) {
    const w = Number(width) > 0 ? Number(width) : 520;
    const q = Number(quality) > 0 ? Number(quality) : 72;
    const id = String(pathB64 || '').trim();
    if (!id) return '';
    return `/api/image-preview?id=${encodeURIComponent(id)}&mode=thumb&w=${w}&q=${q}`;
  }

  function previewUrlForFabricImage(imageName, catalog, width, quality) {
    const list = catalog || [];
    const name = String(imageName || '').trim();
    let pathB64 = '';
    if (name && list.length) {
      const found = list.find((it) => {
        if (!it) return false;
        if (it.name === name) return true;
        return decodeFsNameFromB64(it.rawB64 || it.name_raw_b64 || '') === name;
      });
      if (found && found.b64) pathB64 = String(found.b64).trim();
    }
    if (!pathB64) pathB64 = encodeUtf8PathB64(fabricRelPath(name));
    return previewUrlFromPathB64(pathB64, width, quality);
  }

  /** 绑定/云端关联成功后合并到 selectedImageObjects */
  function mergeAttachItemsIntoSelection(selectedImageObjects, imageNames, imageType, attachData) {
    const selected = selectedImageObjects || [];
    const typeName = String(imageType || '').trim();
    const itemsMap = new Map();
    ((attachData && attachData.items) || []).forEach((it) => {
      const name = String(it.new_name || '').trim();
      if (name) itemsMap.set(name, it);
    });
    (imageNames || []).forEach((name) => {
      const n = String(name || '').trim();
      if (!n) return;
      if (selected.some((x) => (x.image_name || '') === n)) return;
      const meta = itemsMap.get(n) || {};
      selected.push({
        image_name: n,
        preview_b64: String(meta.preview_b64 || '').trim(),
        remark: typeName || String(meta.remark || '').trim(),
        description: '',
        sort_order: selected.length,
        is_enabled: 1,
        is_deprecated: 0,
      });
    });
    return selected;
  }

  // -------------------------------------------------------------------------
  // 图片类型筛选条
  // -------------------------------------------------------------------------
  function readActiveImageType(barEl, fallback) {
    const bar = typeof barEl === 'string' ? document.getElementById(barEl) : barEl;
    if (!bar) return String(fallback || '').trim();
    const active = bar.querySelector('button.status-pill.is-active');
    const v = active ? String(active.getAttribute('data-value') || '').trim() : '';
    return v || String(fallback || '').trim();
  }

  function renderImageTypeBar(barEl, typeOptions, currentValue) {
    const bar = typeof barEl === 'string' ? document.getElementById(barEl) : barEl;
    if (!bar) return '';
    const names = (typeOptions || []).map((x) => String(x.name || x || '').trim()).filter(Boolean);
    if (!names.length) {
      bar.innerHTML = '<span class="pm-select-empty" style="padding:0 .4rem;">暂无图片类型</span>';
      return '';
    }
    let current = String(currentValue || '').trim();
    if (!names.includes(current)) current = names[0];
    bar.innerHTML = names.map((name) => {
      const active = name === current ? ' is-active' : '';
      return `<button type="button" class="status-pill${active}" data-value="${escapeHtml(name)}">${escapeHtml(name)}</button>`;
    }).join('');
    if (bar.dataset.fabricTypeBarBound !== '1') {
      bar.dataset.fabricTypeBarBound = '1';
      bar.addEventListener('click', (ev) => {
        const btn = ev.target.closest('button.status-pill[data-value]');
        if (!btn) return;
        bar.querySelectorAll('button.status-pill').forEach((b) => b.classList.remove('is-active'));
        btn.classList.add('is-active');
      });
    }
    return current;
  }

  async function attachLibraryImages(opts) {
    const fabricCode = String(opts?.fabricCode || opts?.fabric_code || '').trim();
    const fabricId = opts?.fabricId || opts?.fabric_id || null;
    const imageType = String(opts?.imageType || opts?.image_type || opts?.remark || '').trim();
    const items = (opts?.itemsRawB64 || opts?.items || []).filter(Boolean);
    if (!fabricCode) {
      return { status: 'error', message: '请先填写面料编号' };
    }
    if (!imageType) {
      return { status: 'error', message: '请先选择图片类型' };
    }
    if (!items.length) {
      return { status: 'error', message: '请至少选择一张图片' };
    }
    const resp = await fetch('/api/fabric-attach', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        fabric_code: fabricCode,
        fabric_id: fabricId,
        image_type: imageType,
        items,
      }),
    });
    return resp.json();
  }

  global.FabricImageFlow = {
    FABRIC_FOLDER: FABRIC_FOLDER,
    encodeUtf8PathB64: encodeUtf8PathB64,
    decodeFsNameFromB64: decodeFsNameFromB64,
    fabricRelPath: fabricRelPath,
    resolveFabricImagePathB64: resolveFabricImagePathB64,
    previewUrlFromPathB64: previewUrlFromPathB64,
    previewUrlForFabricImage: previewUrlForFabricImage,
    mergeAttachItemsIntoSelection: mergeAttachItemsIntoSelection,
    readActiveImageType: readActiveImageType,
    renderImageTypeBar: renderImageTypeBar,
    attachLibraryImages: attachLibraryImages,
  };
})(typeof window !== 'undefined' ? window : this);
