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

  function requestNotificationPermission() {
    if (!('Notification' in win)) return Promise.resolve('unsupported');
    if (Notification.permission === 'granted') return Promise.resolve('granted');
    if (Notification.permission === 'denied') return Promise.resolve('denied');
    try {
      return Notification.requestPermission();
    } catch (_) {
      return Promise.resolve('denied');
    }
  }

  function bindPrefs(options) {
    const soundEl = options && options.soundEl
      ? (typeof options.soundEl === 'string' ? document.querySelector(options.soundEl) : options.soundEl)
      : null;
    const desktopEl = options && options.desktopEl
      ? (typeof options.desktopEl === 'string' ? document.querySelector(options.desktopEl) : options.desktopEl)
      : null;
    if (soundEl) {
      soundEl.checked = readBool(STORAGE_SOUND, true);
      soundEl.addEventListener('change', () => writeBool(STORAGE_SOUND, !!soundEl.checked));
    }
    if (desktopEl) {
      desktopEl.checked = readBool(STORAGE_DESKTOP, true);
      desktopEl.addEventListener('change', () => {
        const on = !!desktopEl.checked;
        writeBool(STORAGE_DESKTOP, on);
        if (on) requestNotificationPermission();
      });
    }
  }

  win.WidgetTurnNotify = {
    createTracker,
    bindPrefs,
    requestNotificationPermission,
    readBool,
    writeBool,
  };
})(typeof window !== 'undefined' ? window : this);
