/**
 * 小组件牌桌/棋盘中央弹窗（确认框、对局状态提示等）
 * 围棋、麻将及后续 widgets 共用。
 */
(function (global) {
  'use strict';
  const win = global || (typeof window !== 'undefined' ? window : globalThis);

  // -------------------------------------------------------------------------
  // DOM 辅助（解析、转义、按钮）
  // -------------------------------------------------------------------------
  function resolveEl(id) {
    if (!id) return null;
    return typeof id === 'string' ? document.getElementById(id) : id;
  }

  function escHtml(text) {
    const d = document.createElement('div');
    d.textContent = String(text || '');
    return d.innerHTML;
  }

  function makeActionButton(label, className, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = className;
    b.textContent = label;
    b.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (onClick) onClick();
    });
    return b;
  }

  function setOverlayVisible(els, show) {
    if (!els || !els.overlay) return;
    els.overlay.classList.toggle('pm-u-hidden', !show);
    if (show) els.overlay.removeAttribute('hidden');
    else els.overlay.setAttribute('hidden', '');
  }

  // -------------------------------------------------------------------------
  // 中央浮层控制器
  // -------------------------------------------------------------------------
  function createController(ids) {
    const els = {
      overlay: resolveEl(ids.overlayId || ids.overlay),
      titleEl: resolveEl(ids.titleId || ids.title),
      msgEl: resolveEl(ids.messageId || ids.message || ids.msg),
      actionsEl: resolveEl(ids.actionsId || ids.actions),
    };
    if (!els.overlay || !els.titleEl || !els.msgEl || !els.actionsEl) {
      return {
        showConfirm() {},
        hideConfirm() {},
        hasConfirm() { return false; },
        refresh() {},
        setGameRenderer() {},
        clear() {},
        escHtml,
        makeActionButton,
        elements: null,
      };
    }

    let confirmState = null;
    let gameRender = null;
    let lastRenderData = null;

    function renderConfirm() {
      const c = confirmState;
      if (!c) return false;
      els.actionsEl.innerHTML = '';
      els.titleEl.textContent = c.title || '确认';
      if (c.messageHtml != null) {
        els.msgEl.innerHTML = c.messageHtml;
      } else {
        els.msgEl.textContent = c.message || '';
      }
      const confirmClass = c.danger ? 'btn-danger' : (c.confirmClass || 'btn-accent');
      els.actionsEl.appendChild(makeActionButton(c.confirmLabel || '确定', confirmClass, () => {
        const fn = confirmState && confirmState.onConfirm;
        hideConfirm();
        if (fn) fn();
      }));
      els.actionsEl.appendChild(makeActionButton(c.cancelLabel || '取消', 'btn-secondary', () => {
        const fn = confirmState && confirmState.onCancel;
        hideConfirm();
        if (fn) fn();
      }));
      setOverlayVisible(els, true);
      return true;
    }

    function showConfirm(opts) {
      confirmState = opts || null;
      renderConfirm();
    }

    function hideConfirm() {
      confirmState = null;
      refresh(lastRenderData);
    }

    function hasConfirm() {
      return !!confirmState;
    }

    function refresh(data) {
      if (data !== undefined) lastRenderData = data;
      if (confirmState) {
        renderConfirm();
        return;
      }
      if (typeof gameRender === 'function') {
        const show = !!gameRender(els, lastRenderData, {
          escHtml,
          makeActionButton,
        });
        setOverlayVisible(els, show);
        return;
      }
      els.actionsEl.innerHTML = '';
      els.titleEl.textContent = '';
      els.msgEl.textContent = '';
      setOverlayVisible(els, false);
    }

    function setGameRenderer(fn) {
      gameRender = fn;
    }

    function clear() {
      confirmState = null;
      els.actionsEl.innerHTML = '';
      els.titleEl.textContent = '';
      els.msgEl.textContent = '';
      setOverlayVisible(els, false);
    }

    return {
      showConfirm,
      hideConfirm,
      hasConfirm,
      refresh,
      setGameRenderer,
      clear,
      escHtml,
      makeActionButton,
      elements: els,
    };
  }

  win.WidgetBoardOverlay = {
    create: createController,
    escHtml,
    makeActionButton,
  };
})(typeof window !== 'undefined' ? window : globalThis);
