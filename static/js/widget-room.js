/**
 * 小组件多人房间：URL/存储/长连接辅助 + 房间内聊天 UI。
 */
(function (global) {
  'use strict';
  const win = global || window;

  function escHtml(s) {
    return String(s || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function formatChatTime(ts) {
    const d = new Date(Number(ts) * 1000 || Date.now());
    if (Number.isNaN(d.getTime())) return '';
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    return hh + ':' + mm;
  }

  function getAppBasePath(widgetPath) {
    if (win.SITJOY_BASE_PATH) {
      return String(win.SITJOY_BASE_PATH).replace(/\/$/, '');
    }
    const path = win.location.pathname || '/';
    const low = path.toLowerCase();
    const idx = low.indexOf(String(widgetPath || '').toLowerCase());
    if (idx >= 0) return path.slice(0, idx);
    return null;
  }

  function resolveAppUrl(pathAndQuery, widgetPath) {
    const raw = String(pathAndQuery || '').trim();
    const qIdx = raw.indexOf('?');
    const pathPart = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
    const queryPart = qIdx >= 0 ? raw.slice(qIdx) : '';
    const normalized = pathPart.startsWith('/') ? pathPart : '/' + pathPart;
    const base = getAppBasePath(widgetPath);
    if (base !== null) return (base || '') + normalized + queryPart;
    const rel = normalized.startsWith('/') ? '..' + normalized + queryPart : raw;
    try {
      return new URL(rel, win.location.href).href;
    } catch (_) {
      return raw;
    }
  }

  function fetchJson(url, options) {
    return fetch(url, Object.assign({ credentials: 'include' }, options || {})).then(async (r) => {
      const text = await r.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch (_) {
        const snippet = String(text || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        throw new Error(r.status === 404 ? '接口未找到(404)' : (snippet || `HTTP ${r.status}`));
      }
      if (!r.ok || (data && data.status === 'error')) {
        throw new Error((data && data.message) || `HTTP ${r.status}`);
      }
      return data;
    });
  }

  function createStorage(key, type) {
    const store = type === 'local' ? win.localStorage : win.sessionStorage;
    return {
      load() {
        try { return String(store.getItem(key) || '').trim().toUpperCase(); } catch (_) { return ''; }
      },
      save(code) {
        try {
          if (code) store.setItem(key, String(code).trim().toUpperCase());
          else store.removeItem(key);
        } catch (_) {}
      },
    };
  }

  function readUrlRoomParam() {
    try {
      return String(new URL(win.location.href).searchParams.get('room') || '').trim().toUpperCase();
    } catch (_) {
      return '';
    }
  }

  function setUrlRoomParam(code) {
    try {
      const u = new URL(win.location.href);
      const c = String(code || '').trim().toUpperCase();
      if (c) u.searchParams.set('room', c);
      else u.searchParams.delete('room');
      win.history.replaceState(null, '', u.pathname + u.search + u.hash);
    } catch (_) {}
  }

  /**
   * @param {object} opts
   * @param {HTMLElement} opts.root
   * @param {'below'|'side'} [opts.layout]
   * @param {() => boolean} [opts.isActive]
   * @param {(text:string)=>Promise<void>} opts.onSend
   */
  function createChat(opts) {
    const o = opts || {};
    const root = o.root;
    if (!root) return { render: () => {}, setVisible: () => {}, destroy: () => {} };

    const layout = o.layout === 'side' ? 'side' : 'below';
    root.classList.add('widget-room-chat', layout === 'side' ? 'widget-room-chat--side' : 'widget-room-chat--below');
    root.innerHTML =
      '<div class="widget-room-chat-head">房间对话</div>'
      + '<div class="widget-room-chat-log" role="log" aria-live="polite"></div>'
      + '<form class="widget-room-chat-form" autocomplete="off">'
      + '<input type="text" class="widget-room-chat-input inline-input" maxlength="400" placeholder="输入消息…" aria-label="房间消息">'
      + '<button type="submit" class="btn-secondary btn-small widget-room-chat-send">发送</button>'
      + '</form>';

    const logEl = root.querySelector('.widget-room-chat-log');
    const form = root.querySelector('.widget-room-chat-form');
    const input = root.querySelector('.widget-room-chat-input');
    let lastId = 0;
    let sending = false;

    function setVisible(on) {
      root.hidden = !on;
      root.classList.toggle('pm-u-hidden', !on);
    }

    function scrollBottom() {
      if (!logEl) return;
      logEl.scrollTop = logEl.scrollHeight;
    }

    function render(messages) {
      if (!logEl) return;
      const list = Array.isArray(messages) ? messages : [];
      if (!list.length) {
        logEl.innerHTML = '<p class="widget-room-chat-empty">暂无消息，打个招呼吧</p>';
        lastId = 0;
        return;
      }
      const maxId = list.reduce((m, x) => Math.max(m, Number(x.id) || 0), 0);
      const shouldRebuild = maxId < lastId || list.length < 3;
      lastId = maxId;
      if (shouldRebuild) {
        logEl.innerHTML = list.map((m) => {
          const mine = !!m.mine;
          const cls = 'widget-room-chat-msg' + (mine ? ' widget-room-chat-msg--mine' : '');
          return '<div class="' + cls + '" data-id="' + escHtml(String(m.id || '')) + '">'
            + '<span class="widget-room-chat-msg-meta">'
            + '<strong>' + escHtml(m.name || '—') + '</strong>'
            + '<span class="widget-room-chat-msg-time">' + escHtml(formatChatTime(m.ts)) + '</span>'
            + '</span>'
            + '<span class="widget-room-chat-msg-text">' + escHtml(m.text || '') + '</span>'
            + '</div>';
        }).join('');
      } else {
        const existing = new Set(Array.from(logEl.querySelectorAll('[data-id]')).map((el) => el.getAttribute('data-id')));
        list.forEach((m) => {
          const id = String(m.id || '');
          if (!id || existing.has(id)) return;
          const mine = !!m.mine;
          const cls = 'widget-room-chat-msg' + (mine ? ' widget-room-chat-msg--mine' : '');
          const div = document.createElement('div');
          div.className = cls;
          div.setAttribute('data-id', id);
          div.innerHTML =
            '<span class="widget-room-chat-msg-meta">'
            + '<strong>' + escHtml(m.name || '—') + '</strong>'
            + '<span class="widget-room-chat-msg-time">' + escHtml(formatChatTime(m.ts)) + '</span>'
            + '</span>'
            + '<span class="widget-room-chat-msg-text">' + escHtml(m.text || '') + '</span>';
          const empty = logEl.querySelector('.widget-room-chat-empty');
          if (empty) empty.remove();
          logEl.appendChild(div);
        });
      }
      scrollBottom();
    }

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      if (sending || typeof o.onSend !== 'function') return;
      if (o.isActive && !o.isActive()) return;
      const text = String(input.value || '').trim();
      if (!text) return;
      sending = true;
      input.disabled = true;
      o.onSend(text).then(() => {
        input.value = '';
      }).catch((err) => {
        if (win.alert) win.alert((err && err.message) || '发送失败');
      }).finally(() => {
        sending = false;
        input.disabled = false;
        input.focus();
      });
    });

    return {
      render,
      setVisible,
      scrollBottom,
      destroy() {
        root.innerHTML = '';
        root.hidden = true;
      },
    };
  }

  /**
   * SSE + 长轮询房间状态订阅（通用）。
   */
  function createWatcher(options) {
    const o = options || {};
    let watchAbort = false;
    let eventSource = null;
    let watchCtrl = null;
    let lastVersion = -1;

    function stop() {
      watchAbort = true;
      if (watchCtrl) {
        try { watchCtrl.abort(); } catch (_) {}
        watchCtrl = null;
      }
      if (eventSource) {
        try { eventSource.close(); } catch (_) {}
        eventSource = null;
      }
    }

    function streamUrl(roomCode) {
      const qs = new URLSearchParams({
        action: 'stream',
        room_code: roomCode,
        since_version: String(lastVersion >= 0 ? lastVersion : 0),
      });
      return o.apiUrl('/api/' + o.apiName + '?' + qs.toString());
    }

    function waitOnce(roomCode) {
      watchCtrl = new AbortController();
      const qs = new URLSearchParams({
        action: 'wait',
        room_code: roomCode,
        since_version: String(lastVersion >= 0 ? lastVersion : 0),
      });
      return fetchJson(o.apiUrl('/api/' + o.apiName + '?' + qs.toString()), { signal: watchCtrl.signal });
    }

    function handlePayload(data) {
      if (!data || data.status !== 'success') return;
      const ver = Number(data.version) || 0;
      if (data.unchanged && lastVersion >= 0 && ver <= lastVersion) return;
      lastVersion = ver;
      if (typeof o.onState === 'function') o.onState(data);
    }

    function connectSse(roomCode) {
      if (!roomCode || watchAbort || typeof EventSource === 'undefined') {
        watchLoop(roomCode);
        return;
      }
      let es;
      try {
        es = new EventSource(streamUrl(roomCode));
      } catch (_) {
        watchLoop(roomCode);
        return;
      }
      eventSource = es;
      es.addEventListener('state', (ev) => {
        if (watchAbort || !ev.data) return;
        try { handlePayload(JSON.parse(ev.data)); } catch (_) {}
      });
      const onEnd = (ev) => {
        if (watchAbort || !ev.data) return;
        try {
          const data = JSON.parse(ev.data);
          if (typeof o.onEnded === 'function') o.onEnded(data.message || '房间已结束', data);
        } catch (_) {
          if (typeof o.onEnded === 'function') o.onEnded('房间已结束');
        }
      };
      es.addEventListener('room_error', onEnd);
      es.addEventListener('room_dissolved', onEnd);
      es.onerror = () => {
        if (watchAbort) return;
        try { es.close(); } catch (_) {}
        if (eventSource === es) eventSource = null;
        win.setTimeout(() => {
          if (!watchAbort && roomCode) connectSse(roomCode);
        }, 500);
      };
    }

    function watchLoop(roomCode) {
      if (watchAbort || !roomCode) return;
      waitOnce(roomCode).then((data) => {
        if (watchAbort || !roomCode) return;
        if (data && data.status === 'success' && !data.unchanged) handlePayload(data);
        if (!watchAbort && roomCode) watchLoop(roomCode);
      }).catch((err) => {
        if (watchAbort || (err && err.name === 'AbortError')) return;
        const msg = String((err && err.message) || '');
        if (typeof o.onEnded === 'function' && (
          msg.indexOf('解散') >= 0 || msg.indexOf('不存在') >= 0 || msg.indexOf('过期') >= 0 || msg.indexOf('不在') >= 0
        )) {
          o.onEnded(msg);
          return;
        }
        if (!watchAbort && roomCode) win.setTimeout(() => watchLoop(roomCode), 1500);
      });
    }

    function start(roomCode, sinceVersion) {
      stop();
      watchAbort = false;
      lastVersion = sinceVersion != null ? Number(sinceVersion) : -1;
      const code = String(roomCode || '').trim().toUpperCase();
      if (!code) return;
      if (o.useSse !== false) connectSse(code);
      else watchLoop(code);
    }

    return {
      start,
      stop,
      getLastVersion() { return lastVersion; },
      setLastVersion(v) { lastVersion = Number(v) || 0; },
    };
  }

  win.WidgetRoom = {
    escHtml,
    getAppBasePath,
    resolveAppUrl,
    fetchJson,
    createStorage,
    readUrlRoomParam,
    setUrlRoomParam,
    createChat,
    createWatcher,
  };
})(typeof window !== 'undefined' ? window : this);
