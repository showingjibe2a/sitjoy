/**
 * 主图/媒体网格卡片：信息区排版（类型徽章 + 启用/弃用 + 原文件名 + 备注）
 * 供销售产品、下单产品、规格主图、面料管理等页面共用。
 */
(function (global) {
  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function imageIsEnabled(item) {
    if (!item || typeof item !== 'object') return true;
    if (typeof item.is_enabled !== 'undefined') return Number(item.is_enabled) !== 0;
    return Number(item.is_deprecated || 0) === 0;
  }

  function stripDecorativeBase(base, fabricCandidates, typeCandidates) {
    const fn = global.PmImageEditModal && global.PmImageEditModal.stripDecorativeImageBaseName;
    if (typeof fn === 'function') {
      return fn(base, fabricCandidates, typeCandidates);
    }
    let rest = String(base || '').trim();
    const types = (typeCandidates || []).map((s) => String(s || '').trim()).filter(Boolean)
      .sort((a, b) => b.length - a.length);
    types.forEach((t) => {
      const p = `${t}-`;
      if (rest.startsWith(p) && rest.length > p.length) rest = rest.slice(p.length);
    });
    return rest;
  }

  function resolveOriginalDisplayName(item, opts) {
    const options = opts && typeof opts === 'object' ? opts : {};
    const imageName = String(item.image_name || '').trim();
    const ofn = String(item.original_filename || '').trim();
    const src = ofn || imageName;
    if (!src) return '-';
    let ext = '';
    let base = src;
    if (src.includes('.')) {
      ext = src.slice(src.lastIndexOf('.'));
      base = src.slice(0, src.lastIndexOf('.'));
    }
    const types = (options.typeCandidates || [])
      .concat([String(item.image_type_name || '').trim()])
      .map((s) => String(s || '').trim())
      .filter(Boolean);
    const fabrics = (options.fabricCandidates || []).map((s) => String(s || '').trim()).filter(Boolean);
    base = stripDecorativeBase(base, fabrics, types);
    const display = (base + ext).trim();
    return display || '-';
  }

  function buildInfoHtml(item, opts) {
    const options = opts && typeof opts === 'object' ? opts : {};
    const readonly = !!(options.readonly || options.readOnly);
    const typeLabel = String(item.image_type_name || '').trim() || '未设置类型';
    const enabled = imageIsEnabled(item);
    const b64 = String(item.image_b64 || '').trim();
    const original = resolveOriginalDisplayName(item, options);
    const descRaw = String(item.description || '').trim();
    const descHtml = descRaw ? escapeHtml(descRaw) : '-';
    const descTitle = descRaw ? escapeHtml(descRaw) : '双击编辑备注';
    const statusSeg = `<div class="sj-media-image-status status-segment sj-media-image-status-segment${readonly ? ' readonly' : ''}"${b64 && !readonly ? ` data-image-b64="${escapeHtml(b64)}"` : ''} data-value="${enabled ? '1' : '0'}">
      <button type="button" class="status-pill status-pill--yes${enabled ? ' is-active' : ''}" data-value="1">启用</button>
      <button type="button" class="status-pill status-pill--no${enabled ? '' : ' is-active'}" data-value="0">弃用</button>
    </div>`;
    return `<div class="sj-media-image-info">
      <div class="sj-media-image-info-head">
        <span class="sj-media-image-type-badge" title="${escapeHtml(typeLabel)}">${escapeHtml(typeLabel)}</span>
        ${statusSeg}
      </div>
      <div class="sj-media-image-original" title="${escapeHtml(original)}">${escapeHtml(original)}</div>
      <div class="sj-media-image-desc" title="${descTitle}">${descHtml}</div>
    </div>`;
  }

  function setSegmentVisual(seg, val) {
    if (!seg) return;
    const v = String(val) === '0' ? '0' : '1';
    seg.dataset.value = v;
    seg.querySelectorAll('.status-pill[data-value]').forEach((btn) => {
      const bv = String(btn.getAttribute('data-value') || '');
      btn.classList.toggle('is-active', bv === v);
    });
  }

  function bindStatusSegments(root, opts) {
    const options = opts && typeof opts === 'object' ? opts : {};
    const container = typeof root === 'string' ? document.getElementById(root) : root;
    if (!container) return;
    if (container.dataset.sjMediaStatusBound === '1') return;
    container.dataset.sjMediaStatusBound = '1';
    container.addEventListener('click', async (e) => {
      const btn = e.target && e.target.closest
        ? e.target.closest('.sj-media-image-status-segment:not(.readonly) .status-pill[data-value]')
        : null;
      if (!btn) return;
      const seg = btn.closest('.sj-media-image-status-segment');
      if (!seg || seg.classList.contains('readonly')) return;
      e.preventDefault();
      e.stopPropagation();
      const nextVal = String(btn.getAttribute('data-value') || '1') === '1' ? '1' : '0';
      const prevVal = String(seg.dataset.value || '1') === '0' ? '0' : '1';
      if (nextVal === prevVal) return;
      const pathB64 = String(seg.getAttribute('data-image-b64') || '').trim();
      if (!pathB64) return;
      setSegmentVisual(seg, nextVal);
      const enabled = nextVal === '1';
      try {
        if (typeof options.onEnabledChange === 'function') {
          await options.onEnabledChange({ enabled, pathB64, segment: seg });
        } else {
          const resp = await fetch('/api/gallery-image-meta', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: pathB64, is_enabled: enabled ? 1 : 0 }),
          });
          const data = await resp.json();
          if (!data || data.status !== 'success') {
            throw new Error((data && data.message) ? data.message : '保存失败');
          }
          if (global.showAppToast) {
            global.showAppToast(enabled ? '已启用' : '已弃用', false, 3000);
          }
        }
      } catch (err) {
        setSegmentVisual(seg, prevVal);
        const msg = (err && err.message) ? err.message : String(err);
        if (global.showAppToast) global.showAppToast(msg, true, 8000);
      }
    });
  }

  global.SjMediaImageCard = {
    escapeHtml,
    imageIsEnabled,
    resolveOriginalDisplayName,
    buildInfoHtml,
    bindStatusSegments,
    setSegmentVisual,
  };
})(window);
