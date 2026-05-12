/**
 * 列表行「关联缩略图」刷新（多模块复用）
 * - bustImagesIn：对容器内 /api/image-preview 等地址追加缓存破坏参数，避免浏览器沿用旧图
 * - setThumbHtml：按 preview id（URL 的 id= 参数，通常为路径的 base64）重写单元格内缩略图
 * - refreshRowPreviewFromApi：请求单条详情后更新该行 [data-sj-preview="1"]（或自定义选择器）
 * - patchTableRow：用新 <tr> 的 HTML 替换已有行（局部刷新，不改变搜索词与其它行状态）
 *
 * 约定：表格行 <tr data-sj-row-entity-id="...">，预览列 <td data-sj-preview="1">...</td>
 */
(function (global) {
  'use strict';

  var DEFAULT_IMG_SELECTOR = 'img[src*="/api/image-preview"]';

  function withCacheBust(url) {
    var u = String(url || '').trim();
    if (!u || u.indexOf('blob:') === 0 || u.indexOf('data:') === 0) return u;
    var ts = Date.now();
    u = u.replace(/([?&])_sjcb=\d+/g, '$1');
    u = u.replace(/([?&])_sjcb=(?=&|$)/g, '$1');
    u = u.replace(/\?&/g, '?').replace(/&&/g, '&');
    if (u.endsWith('?') || u.endsWith('&')) u = u.slice(0, -1);
    var join = u.indexOf('?') >= 0 ? '&' : '?';
    return u + join + '_sjcb=' + ts;
  }

  function defaultFindRow(entityId) {
    var id = String(entityId);
    if (global.CSS && typeof global.CSS.escape === 'function') {
      return document.querySelector('tr[data-sj-row-entity-id="' + global.CSS.escape(id) + '"]');
    }
    return document.querySelector('tr[data-sj-row-entity-id="' + id.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"]');
  }

  var NS = {
    DEFAULT_IMG_SELECTOR: DEFAULT_IMG_SELECTOR,
    withCacheBust: withCacheBust,

    /**
     * @param {Element|string} root
     * @param {{ imgSelector?: string }} [opt]
     * @returns {number} 更新的 img 数量
     */
    bustImagesIn: function (root, opt) {
      opt = opt || {};
      var rootEl = typeof root === 'string' ? document.querySelector(root) : root;
      if (!rootEl || !rootEl.querySelectorAll) return 0;
      var sel = opt.imgSelector || DEFAULT_IMG_SELECTOR;
      var n = 0;
      rootEl.querySelectorAll(sel).forEach(function (img) {
        try {
          var cur = String(img.getAttribute('src') || img.src || '');
          if (!cur || cur.indexOf('blob:') === 0) return;
          img.setAttribute('src', withCacheBust(cur));
          n++;
        } catch (e) {}
      });
      return n;
    },

    /**
     * @param {Element|null} cell
     * @param {string} idB64 传给 /api/image-preview?id= 的值
     * @param {{ w?: number, q?: number, imgClass?: string, imgStyle?: string, emptyHtml?: string }} [opt]
     */
    setThumbHtml: function (cell, idB64, opt) {
      opt = opt || {};
      if (!cell) return;
      var b64 = String(idB64 || '').trim();
      var w = opt.w != null ? opt.w : 120;
      var q = opt.q != null ? opt.q : 72;
      var imgClass = String(opt.imgClass || '').trim();
      var imgStyle = String(opt.imgStyle || '').trim();
      if (!b64) {
        if (opt.emptyHtml != null) cell.innerHTML = opt.emptyHtml;
        else cell.innerHTML = '';
        return;
      }
      var enc = encodeURIComponent(b64);
      var src = withCacheBust('/api/image-preview?id=' + enc + '&mode=thumb&w=' + w + '&q=' + q);
      var cls = imgClass ? ' class="' + imgClass.replace(/"/g, '') + '"' : '';
      var st = imgStyle ? ' style="' + imgStyle.replace(/"/g, '&quot;') + '"' : '';
      cell.innerHTML = '<img' + cls + st + ' src="' + src.replace(/"/g, '&quot;') + '" alt="" loading="lazy">';
    },

    /**
     * @param {object} opt
     * @param {string|number} opt.entityId
     * @param {string|((id: string|number) => string)} opt.fetchUrl
     * @param {(item: object) => string} opt.extractPreviewIdB64
     * @param {(id: string|number) => Element|null} [opt.findRow]
     * @param {string} [opt.previewSelector='[data-sj-preview="1"]']
     * @param {object} [opt.fetchInit] fetch 的第二个参数
     * @param {object} [opt.thumb] 传给 setThumbHtml
     */
    refreshRowPreviewFromApi: function (opt) {
      var entityId = opt.entityId;
      var url = typeof opt.fetchUrl === 'function' ? opt.fetchUrl(entityId) : String(opt.fetchUrl || '').replace(/\{id\}/g, encodeURIComponent(entityId));
      var findRow = opt.findRow || defaultFindRow;
      var pSel = opt.previewSelector != null ? opt.previewSelector : '[data-sj-preview="1"]';
      var row = findRow(entityId);
      if (!row) return Promise.resolve(false);
      return fetch(url, opt.fetchInit || {})
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (!data || data.status !== 'success') return false;
          var item = data.item != null ? data.item : null;
          if (!item || typeof item !== 'object') return false;
          var b64 = opt.extractPreviewIdB64(item);
          var cell = pSel ? row.querySelector(pSel) : null;
          if (!cell) return false;
          NS.setThumbHtml(cell, b64, opt.thumb || {});
          return true;
        })
        .catch(function () { return false; });
    },

    /**
     * @param {HTMLTableRowElement|Element} rowEl
     * @param {string} newTrOuterHtml 完整 <tr>...</tr>
     * @returns {boolean}
     */
    patchTableRow: function (rowEl, newTrOuterHtml) {
      if (!rowEl || !rowEl.parentNode) return false;
      var html = String(newTrOuterHtml || '').trim();
      if (!html) return false;
      var doc = rowEl.ownerDocument || document;
      var t = doc.createElement('tbody');
      t.innerHTML = html;
      var next = t.firstElementChild;
      if (!next || String(next.tagName || '').toLowerCase() !== 'tr') return false;
      rowEl.parentNode.replaceChild(next, rowEl);
      return true;
    },
  };

  global.SitjoyRowImageRefresh = NS;
})(typeof window !== 'undefined' ? window : this);
