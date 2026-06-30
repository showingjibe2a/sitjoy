/**
 * 小组件对局：轮到自己时的提示音（围棋、麻将等共用）。
 */
(function (global) {
  'use strict';
  const win = global || window;

  const STORAGE_SOUND = 'sitjoy.widget-turn-notify.sound';
  const STORAGE_PRESET = 'sitjoy.widget-turn-notify.preset';
  const STORAGE_VOLUME = 'sitjoy.widget-turn-notify.volume';
  const DEDUPE_KEY = 'sitjoy.widget-turn-notify.dedupe';

  const SOUND_PRESETS = [
    { id: 'stone', label: '落子' },
    { id: 'chime', label: '清脆双音' },
    { id: 'bell', label: '铃声' },
    { id: 'soft', label: '柔和' },
    { id: 'alert', label: '短促双响' },
    { id: 'ping', label: '单音叮' },
  ];

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

  function readPreset() {
    try {
      const v = String(win.localStorage.getItem(STORAGE_PRESET) || 'stone').trim();
      return SOUND_PRESETS.some((p) => p.id === v) ? v : 'stone';
    } catch (_) {
      return 'stone';
    }
  }

  function writePreset(id) {
    try {
      win.localStorage.setItem(STORAGE_PRESET, String(id || 'stone'));
    } catch (_) {}
  }

  function readVolume() {
    try {
      const raw = win.localStorage.getItem(STORAGE_VOLUME);
      if (raw === null || raw === '') return 0.65;
      const n = Number(raw);
      if (!Number.isFinite(n)) return 0.65;
      return Math.max(0.05, Math.min(1, n));
    } catch (_) {
      return 0.65;
    }
  }

  function writeVolume(val) {
    try {
      const n = Math.max(0.05, Math.min(1, Number(val) || 0.65));
      win.localStorage.setItem(STORAGE_VOLUME, String(n));
    } catch (_) {}
  }

  function resolveEl(ref) {
    if (!ref) return null;
    return typeof ref === 'string' ? document.querySelector(ref) : ref;
  }

  let audioCtx = null;

  function getAudioContext() {
    try {
      const Ctx = win.AudioContext || win.webkitAudioContext;
      if (!Ctx) return null;
      if (!audioCtx) audioCtx = new Ctx();
      return audioCtx;
    } catch (_) {
      return null;
    }
  }

  function scheduleTone(ctx, t0, opts) {
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = opts.type || 'sine';
    osc.frequency.setValueAtTime(opts.freq, t0);
    if (opts.freqEnd && opts.freqEnd !== opts.freq) {
      osc.frequency.exponentialRampToValueAtTime(Math.max(1, opts.freqEnd), t0 + (opts.duration || 0.2));
    }
    const peak = Math.max(0.0001, Number(opts.peak) || 0.1);
    gain.gain.setValueAtTime(0.0001, t0);
    gain.gain.exponentialRampToValueAtTime(peak, t0 + 0.015);
    gain.gain.exponentialRampToValueAtTime(0.0001, t0 + (opts.duration || 0.2));
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start(t0);
    osc.stop(t0 + (opts.duration || 0.2) + 0.02);
  }

  /** 模拟围棋/象棋棋子落盘的短促叩击声 */
  function scheduleStoneTap(ctx, t0, peak) {
    const sr = ctx.sampleRate;
    const len = Math.max(1, Math.floor(sr * 0.07));
    const buffer = ctx.createBuffer(1, len, sr);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < len; i++) {
      const env = Math.exp(-i / (len * 0.22));
      data[i] = (Math.random() * 2 - 1) * env;
    }
    const noise = ctx.createBufferSource();
    noise.buffer = buffer;
    const bandpass = ctx.createBiquadFilter();
    bandpass.type = 'bandpass';
    bandpass.frequency.setValueAtTime(2200, t0);
    bandpass.Q.setValueAtTime(0.65, t0);
    const noiseGain = ctx.createGain();
    noiseGain.gain.setValueAtTime(0.0001, t0);
    noiseGain.gain.exponentialRampToValueAtTime(Math.max(0.0001, peak * 0.95), t0 + 0.004);
    noiseGain.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.065);
    noise.connect(bandpass);
    bandpass.connect(noiseGain);
    noiseGain.connect(ctx.destination);
    noise.start(t0);
    noise.stop(t0 + 0.08);
    scheduleTone(ctx, t0, {
      type: 'sine',
      freq: 320,
      freqEnd: 140,
      duration: 0.09,
      peak: peak * 0.38,
    });
  }

  function playPreset(ctx, t0, presetId, volume) {
    const vol = Math.max(0.05, Math.min(1, Number(volume) || 0.65));
    const peak = 0.22 * vol;
    switch (presetId) {
      case 'stone':
        scheduleStoneTap(ctx, t0, peak);
        break;
      case 'bell':
        scheduleTone(ctx, t0, { type: 'triangle', freq: 880, freqEnd: 660, duration: 0.55, peak });
        scheduleTone(ctx, t0 + 0.08, { type: 'sine', freq: 1320, duration: 0.35, peak: peak * 0.45 });
        break;
      case 'soft':
        scheduleTone(ctx, t0, { type: 'sine', freq: 520, freqEnd: 620, duration: 0.5, peak: peak * 0.75 });
        break;
      case 'alert':
        scheduleTone(ctx, t0, { type: 'square', freq: 880, duration: 0.1, peak: peak * 0.85 });
        scheduleTone(ctx, t0 + 0.14, { type: 'square', freq: 880, duration: 0.1, peak: peak * 0.85 });
        break;
      case 'ping':
        scheduleTone(ctx, t0, { type: 'sine', freq: 1046, duration: 0.18, peak });
        break;
      case 'chime':
        scheduleTone(ctx, t0, { type: 'sine', freq: 740, freqEnd: 988, duration: 0.42, peak });
        break;
      default:
        scheduleStoneTap(ctx, t0, peak);
        break;
    }
  }

  function playTurnChime(force) {
    if (!force && !readBool(STORAGE_SOUND, true)) return;
    const ctx = getAudioContext();
    if (!ctx) return;
    const resume = ctx.state === 'suspended' ? ctx.resume() : Promise.resolve();
    resume.then(() => {
      playPreset(ctx, ctx.currentTime, readPreset(), readVolume());
    }).catch(() => {});
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
        playTurnChime(false);
        flashDocumentTitle(title);
      },
    };
  }

  function syncSoundControlsDisabled(options) {
    const soundEl = resolveEl(options && options.soundEl);
    const enabled = !soundEl || !!soundEl.checked;
    const presetEl = resolveEl(options && options.presetEl);
    const volumeEl = resolveEl(options && options.volumeEl);
    const previewBtn = resolveEl(options && options.previewBtn);
    if (presetEl) presetEl.disabled = !enabled;
    if (volumeEl) volumeEl.disabled = !enabled;
    if (previewBtn) previewBtn.disabled = !enabled;
  }

  function bindPrefs(options) {
    const soundEl = resolveEl(options && options.soundEl);
    const presetEl = resolveEl(options && options.presetEl);
    const volumeEl = resolveEl(options && options.volumeEl);
    const previewBtn = resolveEl(options && options.previewBtn);

    if (presetEl && !presetEl.dataset.turnNotifyFilled) {
      presetEl.dataset.turnNotifyFilled = '1';
      presetEl.innerHTML = SOUND_PRESETS.map((p) =>
        `<option value="${p.id}">${p.label}</option>`
      ).join('');
    }

    if (soundEl) {
      soundEl.checked = readBool(STORAGE_SOUND, true);
      soundEl.addEventListener('change', () => {
        writeBool(STORAGE_SOUND, !!soundEl.checked);
        syncSoundControlsDisabled(options);
      });
    }
    if (presetEl) {
      presetEl.value = readPreset();
      presetEl.addEventListener('change', () => {
        writePreset(presetEl.value);
        if (readBool(STORAGE_SOUND, true)) playTurnChime(true);
      });
    }
    if (volumeEl) {
      const vol = readVolume();
      volumeEl.min = '5';
      volumeEl.max = '100';
      volumeEl.step = '5';
      volumeEl.value = String(Math.round(vol * 100));
      volumeEl.addEventListener('input', () => {
        writeVolume(Number(volumeEl.value) / 100);
      });
      volumeEl.addEventListener('change', () => {
        writeVolume(Number(volumeEl.value) / 100);
        if (readBool(STORAGE_SOUND, true)) playTurnChime(true);
      });
    }
    if (previewBtn && previewBtn.dataset.turnNotifyBound !== '1') {
      previewBtn.dataset.turnNotifyBound = '1';
      previewBtn.addEventListener('click', () => playTurnChime(true));
    }

    syncSoundControlsDisabled(options);
    if (presetEl && typeof win.refreshUniversalSingleSelect === 'function') {
      win.refreshUniversalSingleSelect(presetEl);
    }
  }

  win.WidgetTurnNotify = {
    createTracker,
    bindPrefs,
    playTurnChime,
    readPreset,
    readVolume,
    SOUND_PRESETS,
    readBool,
    writeBool,
  };
})(typeof window !== 'undefined' ? window : this);
