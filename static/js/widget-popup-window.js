/**
 * 小组件独立小窗：记忆上次位置与尺寸（localStorage，各 widget 独立 key）
 */
(function (global) {
  'use strict';

  const STORAGE_PREFIX = 'sitjoy_widget_popup_bounds_';

  // -------------------------------------------------------------------------
  // 边界读写与归一化
  // -------------------------------------------------------------------------
  function clamp(n, min, max) {
    return Math.min(max, Math.max(min, n));
  }

  function getScreenAvail() {
    const s = global.screen || {};
    return {
      width: s.availWidth || global.innerWidth || 800,
      height: s.availHeight || global.innerHeight || 600,
      left: typeof s.availLeft === 'number' ? s.availLeft : 0,
      top: typeof s.availTop === 'number' ? s.availTop : 0,
    };
  }

  function readBounds(key) {
    try {
      const raw = global.localStorage.getItem(STORAGE_PREFIX + key);
      if (!raw) return null;
      const o = JSON.parse(raw);
      if (!o || typeof o !== 'object') return null;
      const width = Number(o.width);
      const height = Number(o.height);
      const left = Number(o.left);
      const top = Number(o.top);
      if (![width, height, left, top].every((n) => Number.isFinite(n) && n > 0)) return null;
      return { width, height, left, top };
    } catch (_) {
      return null;
    }
  }

  function writeBounds(key, bounds) {
    if (!bounds) return;
    try {
      global.localStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(bounds));
    } catch (_) {}
  }

  function normalizeBounds(bounds, defaults) {
    const scr = getScreenAvail();
    const minW = (defaults && defaults.minWidth) || 320;
    const minH = (defaults && defaults.minHeight) || 360;
    const maxW = Math.max(minW, scr.width);
    const maxH = Math.max(minH, scr.height);
    const width = clamp(Math.round(bounds.width), minW, maxW);
    const height = clamp(Math.round(bounds.height), minH, maxH);
    const left = clamp(Math.round(bounds.left), scr.left, scr.left + scr.width - width);
    const top = clamp(Math.round(bounds.top), scr.top, scr.top + scr.height - height);
    return { width, height, left, top };
  }

  function defaultBounds(defaults) {
    const scr = getScreenAvail();
    const defs = defaults || {};
    const width = defs.width || 580;
    const height = defs.height || Math.min(640, scr.height);
    const left = scr.left + Math.max(0, Math.round((scr.width - width) / 2));
    const top = scr.top + Math.max(0, Math.round((scr.height - height) / 2));
    return normalizeBounds({ width, height, left, top }, defs);
  }

  function resolveBounds(key, defaults) {
    const saved = readBounds(key);
    return saved ? normalizeBounds(saved, defaults || {}) : defaultBounds(defaults);
  }

  function windowFeatures(bounds) {
    const b = bounds;
    return [
      'popup=yes',
      'width=' + Math.round(b.width),
      'height=' + Math.round(b.height),
      'left=' + Math.round(b.left),
      'top=' + Math.round(b.top),
      'resizable=yes',
      'scrollbars=no',
    ].join(',');
  }

  function readPopupBounds(popup) {
    if (!popup || popup.closed) return null;
    try {
      const width = popup.outerWidth;
      const height = popup.outerHeight;
      const left = popup.screenX;
      const top = popup.screenY;
      if (![width, height, left, top].every((n) => Number.isFinite(n))) return null;
      return { width, height, left, top };
    } catch (_) {
      return null;
    }
  }

  function applyBounds(popup, bounds, defaults) {
    if (!popup || popup.closed || !bounds) return null;
    const b = normalizeBounds(bounds, defaults || {});
    try {
      popup.moveTo(b.left, b.top);
      popup.resizeTo(b.width, b.height);
    } catch (_) {}
    return b;
  }

  // -------------------------------------------------------------------------
  // 打开小窗
  // -------------------------------------------------------------------------
  function openWithRememberedBounds(key, url, name, defaults) {
    const defs = defaults || {};
    const bounds = resolveBounds(key, defs);
    const popup = global.open(url, name, windowFeatures(bounds));
    if (!popup) return null;
    applyBounds(popup, bounds, defs);
    global.setTimeout(() => applyBounds(popup, bounds, defs), 60);
    global.setTimeout(() => applyBounds(popup, bounds, defs), 240);
    return popup;
  }

  // -------------------------------------------------------------------------
  // 位置记忆
  // -------------------------------------------------------------------------
  function attachBoundsSaver(key, popup, defaults) {
    if (!popup) return { save: function () {}, stop: function () {} };
    const defs = defaults || {};
    let stopped = false;
    const save = () => {
      if (stopped) return;
      const b = readPopupBounds(popup);
      if (b) writeBounds(key, normalizeBounds(b, defs));
    };
    const interval = global.setInterval(() => {
      if (!popup || popup.closed) {
        save();
        stop();
        return;
      }
      save();
    }, 900);
    const onUnload = () => save();
    try {
      global.addEventListener('beforeunload', onUnload);
    } catch (_) {}
    function stop() {
      if (stopped) return;
      stopped = true;
      global.clearInterval(interval);
      try {
        global.removeEventListener('beforeunload', onUnload);
      } catch (_) {}
    }
    return { save, stop };
  }

  global.SitjoyWidgetPopup = {
    readBounds,
    writeBounds,
    resolveBounds,
    defaultBounds,
    windowFeatures,
    readPopupBounds,
    applyBounds,
    openWithRememberedBounds,
    attachBoundsSaver,
  };
})(typeof window !== 'undefined' ? window : this);
