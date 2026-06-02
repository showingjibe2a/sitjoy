/**
 * 面料图片：库内绑定（重命名 + 可选 DB 映射），与 NAS 导入共用后端 /api/fabric-attach。
 */
(function (global) {
  function escapeHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

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
    readActiveImageType,
    renderImageTypeBar,
    attachLibraryImages,
  };
})(typeof window !== 'undefined' ? window : this);
