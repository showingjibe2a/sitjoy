/**
 * 小组件对局：轮到自己时的提示音与桌面通知（围棋、麻将等共用）。
 */
(function (global) {
  'use strict';
  const win = global || window;

  const STORAGE_SOUND = 'sitjoy.widget-turn-notify.sound';
  const STORAGE_DESKTOP = 'sitjoy.widget-turn-notify.desktop';
  const DEDUPE_KEY = 'sitjoy.widget-turn-notify.dedupe';

  function readBool(key, defaultVal) {
    try {
      const v = win.localStorage.getItem(key);
      if (v === null || v === '') return defaultVal;
      return v === '1' || v === 'true';
    } catch (_) {
      return defaultVal;
    }
  }

  function writeBool(key, val) {
    try {
      win.localStorage.setItem(key, val ? '1' : '0');
    } catch (_) {}
  }

  let audioCtx = null;

  function playTurnChime() {
    if (!readBool(STORAGE_SOUND, true)) return;
    try {
      const Ctx = win.AudioContext || win.webkitAudioContext;
      if (!Ctx) return;
      if (!audioCtx) audioCtx = new Ctx();
      const ctx = audioCtx;
      const resume = ctx.state === 'suspended' ? ctx.resume() : Promise.resolve();
      resume.then(() => {
        const t0 = ctx.currentTime;
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.type = 'sine';
        osc.frequency.setValueAtTime(740, t0);
        osc.frequency.exponentialRampToValueAtTime(988, t0 + 0.12);
        gain.gain.setValueAtTime(0.0001, t0);
        gain.gain.exponentialRampToValueAtTime(0.12, t0 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.42);
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.start(t0);
        osc.stop(t0 + 0.44);
      }).catch(() => {});
    } catch (_) {}
  }

  function shouldShowDesktopNotification() {
    if (!readBool(STORAGE_DESKTOP, true)) return false;
    if (!('Notification' in win)) return false;
    if (Notification.permission !== 'granted') return false;
    return !!(document.hidden || !document.hasFocus());
  }

  function showDesktopNotification(title, body, tag) {
    if (!shouldShowDesktopNotification()) return;
    try {
      const n = new Notification(String(title || '轮到你了'), {
        body: String(body || ''),
        tag: String(tag || 'sitjoy-turn'),
        silent: true,
      });
      n.onclick = () => {
        try { win.focus(); } catch (_) {}
        n.close();
      };
    } catch (_) {}
  }

  let titleFlashTimer = null;
  let titleFlashOriginal = '';

  function flashDocumentTitle(title) {
    if (!document.hidden && document.hasFocus()) return;
    titleFlashOriginal = document.title;
    let on = false;
    if (titleFlashTimer) clearInterval(titleFlashTimer);
    titleFlashTimer = setInterval(() => {
      on = !on;
      document.title = on ? String(title || '轮到你了') : titleFlashOriginal;
    }, 700);
    const stop = () => {
      if (!titleFlashTimer) return;
      clearInterval(titleFlashTimer);
      titleFlashTimer = null;
      document.title = titleFlashOriginal;
      document.removeEventListener('visibilitychange', stop);
      win.removeEventListener('focus', stop);
    };
    document.addEventListener('visibilitychange', stop);
    win.addEventListener('focus', stop);
    setTimeout(stop, 12000);
  }

  function shouldNotifyDedupe(fullKey) {
    const now = Date.now();
    let prev = null;
    try {
      const raw = win.sessionStorage.getItem(DEDUPE_KEY);
      prev = raw ? JSON.parse(raw) : null;
    } catch (_) {
      prev = null;
    }
    if (prev && prev.key === fullKey && now - Number(prev.at || 0) < 2500) return false;
    try {
      win.sessionStorage.setItem(DEDUPE_KEY, JSON.stringify({ key: fullKey, at: now }));
    } catch (_) {}
    return true;
  }

  function createTracker(gameKey) {
    let wasMyTurn = null;
    return {
      reset() {
        wasMyTurn = null;
      },
      update(opts) {
        const o = opts || {};
        const isMyTurn = !!o.isMyTurn;
        if (!isMyTurn) {
          wasMyTurn = false;
          return;
        }
        if (wasMyTurn === null) {
          wasMyTurn = true;
          return;
        }
        if (wasMyTurn) return;
        wasMyTurn = true;

        const dedupeKey = String(o.dedupeKey || 'turn');
        if (!shouldNotifyDedupe(String(gameKey || 'game') + ':' + dedupeKey)) return;

        const title = String(o.title || '轮到你了');
        const body = String(o.body || '');
        playTurnChime();
        flashDocumentTitle(title);
        showDesktopNotification(title, body, String(gameKey || 'game') + '-' + dedupeKey);
      },
    };
  }

  function getNotificationPermission() {
    if (!('Notification' in win)) return 'unsupported';
    const p = Notification.permission;
    if (p === 'granted' || p === 'denied' || p === 'default') return p;
    return 'default';
  }

  function permissionStatusText(state) {
    switch (state) {
      case 'granted':
        return '已授权（后台轮到你时会弹出系统通知）';
      case 'denied':
        return '已拒绝（需在浏览器站点设置中手动开启）';
      case 'default':
        return '未授权（点击下方按钮，或在勾选「后台桌面通知」时授权）';
      default:
        return '当前浏览器不支持桌面通知';
    }
  }

  function permissionButtonLabel(state) {
    switch (state) {
      case 'granted':
        return '已授权';
      case 'denied':
        return '已在浏览器中禁止';
      case 'default':
        return '授权桌面通知';
      default:
        return '不可用';
    }
  }

  function resolveEl(ref) {
    if (!ref) return null;
    return typeof ref === 'string' ? document.querySelector(ref) : ref;
  }

  function refreshPermissionUi(options) {
    const statusEl = resolveEl(options && options.permissionStatusEl);
    const btnEl = resolveEl(options && options.permissionBtnEl);
    const state = getNotificationPermission();
    if (statusEl) {
      statusEl.textContent = '通知权限：' + permissionStatusText(state);
      statusEl.dataset.permissionState = state;
      statusEl.classList.toggle('is-granted', state === 'granted');
      statusEl.classList.toggle('is-denied', state === 'denied');
      statusEl.classList.toggle('is-default', state === 'default');
      statusEl.classList.toggle('is-unsupported', state === 'unsupported');
    }
    if (btnEl) {
      btnEl.textContent = permissionButtonLabel(state);
      btnEl.disabled = state === 'granted' || state === 'unsupported';
      btnEl.classList.toggle('is-granted', state === 'granted');
      btnEl.title = state === 'denied'
        ? '请在浏览器地址栏左侧站点图标 → 通知/权限 中改为「允许」，然后刷新本页'
        : '';
    }
    return state;
  }

  async function requestNotificationPermission() {
    if (!('Notification' in win)) return 'unsupported';
    if (Notification.permission === 'granted') return 'granted';
    if (Notification.permission === 'denied') return 'denied';
    try {
      const result = await Notification.requestPermission();
      return result === 'granted' || result === 'denied' ? result : 'default';
    } catch (_) {
      return 'denied';
    }
  }

  function bindPermissionControls(options) {
    const btnEl = resolveEl(options && options.permissionBtnEl);
    const desktopEl = resolveEl(options && options.desktopEl);
    if (!btnEl || btnEl.dataset.turnNotifyPermBound === '1') return;
    btnEl.dataset.turnNotifyPermBound = '1';
    btnEl.addEventListener('click', async () => {
      const before = getNotificationPermission();
      if (before === 'granted' || before === 'unsupported') return;
      if (before === 'denied') {
        btnEl.title = '请在浏览器地址栏左侧站点图标 → 通知 中改为「允许」，然后刷新本页';
        return;
      }
      const state = await requestNotificationPermission();
      refreshPermissionUi(options);
      if (state === 'granted' && desktopEl) desktopEl.checked = true;
      writeBool(STORAGE_DESKTOP, state === 'granted' || (desktopEl && desktopEl.checked));
    });
    win.addEventListener('focus', () => refreshPermissionUi(options));
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) refreshPermissionUi(options);
    });
  }

  function bindPrefs(options) {
    const soundEl = resolveEl(options && options.soundEl);
    const desktopEl = resolveEl(options && options.desktopEl);
    if (soundEl) {
      soundEl.checked = readBool(STORAGE_SOUND, true);
      soundEl.addEventListener('change', () => writeBool(STORAGE_SOUND, !!soundEl.checked));
    }
    if (desktopEl) {
      desktopEl.checked = readBool(STORAGE_DESKTOP, true);
      desktopEl.addEventListener('change', async () => {
        const on = !!desktopEl.checked;
        writeBool(STORAGE_DESKTOP, on);
        if (on && getNotificationPermission() === 'default') {
          await requestNotificationPermission();
        }
        refreshPermissionUi(options);
      });
    }
    refreshPermissionUi(options);
    bindPermissionControls(options);
  }

  win.WidgetTurnNotify = {
    createTracker,
    bindPrefs,
    requestNotificationPermission,
    getNotificationPermission,
    permissionStatusText,
    refreshPermissionUi,
    readBool,
    writeBool,
  };
})(typeof window !== 'undefined' ? window : this);
