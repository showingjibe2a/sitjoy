/**
 * 麻将：主控页 + 牌桌独立窗口（postMessage 同步）；SSE / 长轮询。
 */
(function (global) {
  'use strict';
  const win = global || window;
  const ROOM_KEY = 'sitjoy.mahjong.room.v1';
  const TABLE_POPUP_NAME = 'sitjoy_mj_table_popup';

  function mjPlayMode() {
    const mode = String((document.body && document.body.dataset.mjPlayMode) || '').trim().toLowerCase();
    const popup = mode === 'popup';
    const main = mode === 'main' || (!popup && !!document.getElementById('mjCreateBtn'));
    return { isPopup: popup, isMain: main };
  }

  const isPopup = mjPlayMode().isPopup;
  const isMain = mjPlayMode().isMain;

  let roomCode = '';
  let state = null;
  let lastVersion = -1;
  let watchAbort = false;
  let watchCtrl = null;
  let eventSource = null;
  let useSse = true;
  let tablePopup = null;
  let popupOpen = false;
  let popupMonitorTimer = null;
  let mjBoardOverlay = null;
  let joinInFlight = false;
  let roomChat = null;

  const $ = (id) => document.getElementById(id);

  function resolveMySeat(s) {
    if (!s) return null;
    const direct = s.my_seat;
    if (direct != null && direct >= 0) return direct;
    const uid = s.my_user_id;
    if (uid == null) return null;
    const seats = s.seats || [];
    for (let i = 0; i < seats.length; i++) {
      const st = seats[i];
      if (st && Number(st.user_id) === Number(uid)) return i;
    }
    return null;
  }

  function withResolvedSeat(s) {
    if (!s) return s;
    const mySeat = resolveMySeat(s);
    if (mySeat === s.my_seat) return s;
    return Object.assign({}, s, { my_seat: mySeat });
  }

  /** API 用 status=success 表示请求成功，对局阶段在 room_status */
  function normalizeRoomState(raw) {
    if (!raw) return raw;
    let phase = String(raw.room_status || raw.game_status || '').trim();
    if (!phase && raw.status === 'success') {
      if (raw.lobby != null) phase = 'lobby';
      else if (raw.dice_roll) phase = 'dealer_roll';
      else if (raw.last_hand_result) phase = 'hand_end';
      else if ((raw.my_hand || []).length || raw.wall_remaining != null) phase = 'playing';
    }
    if (!phase) {
      const cur = String(raw.status || '').trim();
      if (cur && cur !== 'success') return raw;
      return raw;
    }
    if (raw.status === phase) return raw;
    return Object.assign({}, raw, { status: phase, room_status: phase });
  }

  function initMjBoardOverlay() {
    if (mjBoardOverlay) return mjBoardOverlay;
    if (!win.WidgetBoardOverlay) return null;
    mjBoardOverlay = win.WidgetBoardOverlay.create({
      overlayId: 'mjBoardOverlay',
      titleId: 'mjOverlayTitle',
      messageId: 'mjOverlayMsg',
      actionsId: 'mjOverlayActions',
    });
    mjBoardOverlay.setGameRenderer(renderMjBoardOverlay);
    return mjBoardOverlay;
  }

  function mjOverlayDialogEl() {
    const overlay = $('mjBoardOverlay');
    return overlay ? overlay.querySelector('.widget-board-dialog') : null;
  }

  function renderMjLobbySeatsHtml(s, esc) {
    const seats = s.seats || [];
    const mySeat = resolveMySeat(s);
    let html = '<div class="mj-overlay-seats mj-lobby-seats">';
    for (let i = 0; i < 4; i++) {
      const st = seats[i];
      const cls = ['mj-seat-dot'];
      if (st) cls.push('mj-seat-dot--filled');
      if (st && st.ready) cls.push('mj-seat-dot--ready');
      if (i === mySeat) cls.push('mj-seat-dot--me');
      const initial = st ? playerInitial(st.name) : '';
      const name = st ? ((st.name || '—') + (st.ready ? ' ✓' : '')) : '空位';
      html += `<div class="${cls.join(' ')}">`
        + `<div class="mj-seat-dot-inner">${esc(initial)}</div>`
        + `<span class="mj-seat-dot-name">${esc(name)}</span>`
        + '</div>';
    }
    html += '</div>';
    return html;
  }

  function renderMjBoardOverlay(els, s, api) {
    if (!s || !s.code || !lobbyInRoom(s)) return false;
    const esc = api.escHtml;
    const btn = api.makeActionButton;
    els.actionsEl.innerHTML = '';
    els.titleEl.textContent = '';
    els.msgEl.innerHTML = '';
    const dialog = mjOverlayDialogEl();
    if (dialog) dialog.classList.remove('widget-board-dialog--wide');

    if (s.status === 'lobby') {
      const lobby = s.lobby || {};
      const minP = Number(s.min_players) || 2;
      const n = lobby.occupied_count != null
        ? lobby.occupied_count
        : (s.seats || []).filter(Boolean).length;
      els.titleEl.textContent = '等待开局';
      if (dialog) dialog.classList.add('widget-board-dialog--wide');
      const hint = '房间内 ' + n + ' 人 · 至少 ' + minP + ' 人全部准备后可开局'
        + (lobby.can_start ? '（可开局）' : '');
      els.msgEl.innerHTML = renderMjLobbySeatsHtml(s, esc)
        + `<p class="mj-overlay-hint">${esc(hint)}</p>`;
      const mySeat = resolveMySeat(s);
      const me = mySeat != null ? (s.seats || [])[mySeat] : null;
      if (mySeat != null) {
        els.actionsEl.appendChild(btn(
          me && me.ready ? '取消准备' : '准备',
          'btn-accent',
          () => { doReady().catch((err) => alert(err.message)); }
        ));
      }
      if (s.you_are_host && lobby.can_start) {
        els.actionsEl.appendChild(btn(
          '开局',
          'btn-accent',
          () => { doStart().catch((err) => alert(err.message)); }
        ));
      }
      return true;
    }

    if (s.status === 'dealer_roll') {
      const dr = s.dice_roll || {};
      const rolls = dr.rolls || [];
      els.titleEl.textContent = '投骰定庄';
      if (dialog) dialog.classList.add('widget-board-dialog--wide');
      const mySeat = resolveMySeat(s);
      let html = '<div class="mj-overlay-seats mj-lobby-seats mj-overlay-dice-seats">';
      rolls.forEach((r) => {
        const cls = ['mj-seat-dot', 'mj-seat-dot--filled'];
        if (r.rolled) cls.push('mj-seat-dot--ready');
        if (r.seat === mySeat) cls.push('mj-seat-dot--me');
        const inner = r.rolled ? (r.dice1 + '+' + r.dice2 + '=' + r.total) : '?';
        html += `<div class="${cls.join(' ')}">`
          + `<div class="mj-seat-dot-inner mj-seat-dot-inner--dice">${esc(inner)}</div>`
          + `<span class="mj-seat-dot-name">${esc(r.name || '—')}</span>`
          + '</div>';
      });
      html += '</div>';
      const pending = rolls.filter((r) => !r.rolled).length;
      let hint = pending ? ('还有 ' + pending + ' 人未掷骰 · 点数最大者坐庄') : '全员已掷骰，正在发牌…';
      if (dr.dealer_name && dr.all_done) {
        hint = '庄家：' + dr.dealer_name + '（合计 ' + (dr.total || '?') + '）· 正在发牌…';
      }
      html += `<p class="mj-overlay-hint">${esc(hint)}</p>`;
      els.msgEl.innerHTML = html;
      if (dr.need_my_roll) {
        els.actionsEl.appendChild(btn(
          '掷骰子',
          'btn-accent',
          () => { doRollDice().catch((err) => alert(err.message)); }
        ));
      }
      return true;
    }

    return false;
  }

  function updateBoardOverlay(s) {
    initMjBoardOverlay();
    if (!mjBoardOverlay || mjBoardOverlay.hasConfirm()) return;
    mjBoardOverlay.refresh(s);
  }

  function isBoardOverlayActive(s) {
    if (!s || !lobbyInRoom(s)) return false;
    return s.status === 'lobby' || s.status === 'dealer_roll';
  }

  function getAppBasePath() {
    if (win.SITJOY_BASE_PATH) {
      return String(win.SITJOY_BASE_PATH).replace(/\/$/, '');
    }
    const path = win.location.pathname || '/';
    const low = path.toLowerCase();
    let idx = low.indexOf('/widgets/mahjong/table');
    if (idx < 0) idx = low.indexOf('/widgets/mahjong');
    if (idx >= 0) return path.slice(0, idx);
    return null;
  }

  function resolveAppUrl(pathAndQuery) {
    const raw = String(pathAndQuery || '').trim();
    const qIdx = raw.indexOf('?');
    const pathPart = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
    const queryPart = qIdx >= 0 ? raw.slice(qIdx) : '';
    const normalized = pathPart.startsWith('/') ? pathPart : '/' + pathPart;
    const base = getAppBasePath();
    if (base !== null) return (base || '') + normalized + queryPart;
    const rel = normalized.startsWith('/') ? '..' + normalized + queryPart : raw;
    try {
      return new URL(rel, win.location.href).href;
    } catch (_) {
      return raw;
    }
  }

  function apiUrl(pathAndQuery) {
    return resolveAppUrl(pathAndQuery);
  }

  function fetchJson(url, options) {
    return fetch(url, Object.assign({ credentials: 'include' }, options || {})).then(async (r) => {
      const text = await r.text();
      let data = {};
      try {
        data = text ? JSON.parse(text) : {};
      } catch (_) {
        const snippet = String(text || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        throw new Error(r.status === 404 ? '接口未找到(404)，请重启应用服务后重试' : (snippet || `HTTP ${r.status}`));
      }
      if (data.status === 'error') throw new Error(data.message || '请求失败');
      if (!r.ok) throw new Error(data.message || `HTTP ${r.status}`);
      return data;
    });
  }

  function api(action, payload, method) {
    const m = method || 'POST';
    if (m === 'GET') {
      const qs = new URLSearchParams(Object.assign({ action }, payload || {}));
      return fetchJson(apiUrl('/api/mahjong-play?' + qs.toString()));
    }
    return fetchJson(apiUrl('/api/mahjong-play'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ action }, payload || {})),
    });
  }

  function tileLabel(t) {
    if (!t) return '?';
    const suit = t[0];
    const n = t.slice(1);
    if (suit === 'p') return n + '筒';
    if (suit === 's') return n + '条';
    const honor = { z1: '东', z2: '南', z3: '西', z4: '北', z5: '中', z6: '发', z7: '白' };
    return honor[t] || t;
  }

  function tileGlyph(t) {
    const key = String(t || '').trim();
    if (!key) return '?';
    const suit = key[0];
    if (suit === 'p') {
      const n = parseInt(key.slice(1), 10);
      if (n >= 1 && n <= 9) return String.fromCodePoint(0x1F019 + n - 1);
    }
    if (suit === 's') {
      const n = parseInt(key.slice(1), 10);
      if (n >= 1 && n <= 9) return String.fromCodePoint(0x1F010 + n - 1);
    }
    const honorCode = { z1: 0x1F000, z2: 0x1F001, z3: 0x1F002, z4: 0x1F003, z5: 0x1F004, z6: 0x1F005, z7: 0x1F006 };
    if (honorCode[key]) return String.fromCodePoint(honorCode[key]);
    return tileLabel(t);
  }

  function tileKindClasses(t) {
    const key = String(t || '').trim();
    if (key.startsWith('p')) return ['mj-tile--pin'];
    if (key.startsWith('s')) return ['mj-tile--sou'];
    if (key === 'z7') return ['mj-tile--honor', 'mj-tile--bai'];
    if (key === 'z5') return ['mj-tile--honor', 'mj-tile--zhong'];
    if (key === 'z6') return ['mj-tile--honor', 'mj-tile--fa'];
    if (/^z[1-4]$/.test(key)) return ['mj-tile--honor', 'mj-tile--wind'];
    if (key.startsWith('z')) return ['mj-tile--honor'];
    return ['mj-tile--unknown'];
  }

  function tileInnerHtml(glyph) {
    return '<span class="mj-tile-glyph-wrap"><span class="mj-tile-glyph">' + glyph + '</span></span>';
  }

  function tileFaceHtml(t, variant) {
    const key = String(t || '').trim();
    const label = tileLabel(key);
    const glyph = tileGlyph(key);
    const cls = ['mj-tile'].concat(tileKindClasses(key));
    if (variant === 'mini' || variant === 'table') cls.push('mj-tile--table');
    if (variant === 'hand') cls.push('mj-tile--hand');
    return `<span class="${cls.join(' ')}" role="img" aria-label="${esc(label)}" data-tile="${esc(key)}">`
      + tileInnerHtml(glyph)
      + '</span>';
  }

  function tileHandButtonHtml(t, canDiscard) {
    const key = String(t || '').trim();
    const label = tileLabel(key);
    const glyph = tileGlyph(key);
    const cls = ['mj-tile', 'mj-tile--hand'].concat(tileKindClasses(key));
    if (canDiscard) cls.push('mj-tile--clickable');
    const inner = tileInnerHtml(glyph);
    const attrs = ` class="${cls.join(' ')}" aria-label="${esc(label)}" data-tile="${esc(key)}"`;
    if (canDiscard) {
      return `<button type="button"${attrs} data-discard="1">${inner}</button>`;
    }
    return `<span${attrs} role="img">${inner}</span>`;
  }

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
  }

  function saveRoomCode(code) {
    try {
      if (code) localStorage.setItem(ROOM_KEY, String(code).trim().toUpperCase());
      else localStorage.removeItem(ROOM_KEY);
    } catch (_) {}
    if (mjPlayMode().isMain && win.WidgetRoom) win.WidgetRoom.setUrlRoomParam(code);
  }

  function loadRoomCode() {
    if (win.WidgetRoom) {
      const fromUrl = win.WidgetRoom.readUrlRoomParam();
      if (fromUrl) return fromUrl;
    }
    try { return localStorage.getItem(ROOM_KEY) || ''; } catch (_) { return ''; }
  }

  function initRoomChat() {
    if (roomChat || !win.WidgetRoom) return roomChat;
    const root = $('mjRoomChat');
    if (!root) return null;
    roomChat = win.WidgetRoom.createChat({
      root,
      layout: isPopup ? 'side' : 'below',
      isActive: () => lobbyInRoom(state),
      onSend: (text) => api('chat_send', { room_code: roomCode, text }).then((data) => {
        applyState(data);
      }),
    });
    return roomChat;
  }

  function syncRoomChat(s) {
    if (!roomChat) initRoomChat();
    if (!roomChat) return;
    const active = lobbyInRoom(s);
    roomChat.setVisible(active);
    if (active) roomChat.render((s && s.chat_messages) || []);
  }

  function pageUrl(path) {
    return resolveAppUrl(path);
  }

  function snapshotState() {
    return {
      roomCode,
      lastVersion,
      state: state ? JSON.parse(JSON.stringify(state)) : null,
    };
  }

  function postStateToPopup() {
    if (isPopup || !tablePopup || tablePopup.closed) return;
    try {
      tablePopup.postMessage({ type: 'mj-play-state', payload: snapshotState() }, win.location.origin);
    } catch (_) {}
  }

  function setWindowPlaceholderVisible(show) {
    const ph = $('mjWindowPlaceholder');
    if (!ph) return;
    ph.classList.toggle('pm-u-hidden', !show);
  }

  function updatePopoutBtnUi() {
    const btn = $('mjPopoutBtn');
    if (!btn) return;
    if (popupOpen && tablePopup && !tablePopup.closed) {
      btn.textContent = '关闭牌桌窗口';
      btn.classList.add('go-play-popout-btn--active');
    } else {
      btn.textContent = '牌桌独立窗口';
      btn.classList.remove('go-play-popout-btn--active');
    }
  }

  function onTableWindowClosed() {
    tablePopup = null;
    popupOpen = false;
    if (popupMonitorTimer) {
      win.clearInterval(popupMonitorTimer);
      popupMonitorTimer = null;
    }
    setWindowPlaceholderVisible(false);
    updatePopoutBtnUi();
    const wrap = $('mjTableWrap');
    if (wrap) wrap.classList.remove('pm-u-hidden');
  }

  function openTableWindow() {
    if (tablePopup && !tablePopup.closed) {
      tablePopup.focus();
      postStateToPopup();
      return true;
    }
    if (!roomCode) {
      alert('请先创建或加入房间');
      return false;
    }
    const url = pageUrl('/widgets/mahjong/table?room=' + encodeURIComponent(roomCode));
    tablePopup = win.open(url, TABLE_POPUP_NAME, 'popup=yes,width=520,height=580,resizable=yes,scrollbars=no');
    if (!tablePopup) {
      alert('无法打开新窗口：请允许本站「弹出式窗口」后重试');
      return false;
    }
    popupOpen = true;
    setWindowPlaceholderVisible(true);
    const wrap = $('mjTableWrap');
    if (wrap) wrap.classList.add('pm-u-hidden');
    updatePopoutBtnUi();
    popupMonitorTimer = win.setInterval(() => {
      if (!tablePopup || tablePopup.closed) onTableWindowClosed();
    }, 400);
    postStateToPopup();
    return true;
  }

  function closeTableWindow() {
    if (tablePopup && !tablePopup.closed) {
      try { tablePopup.close(); } catch (_) {}
    }
    onTableWindowClosed();
  }

  function seatAtIndex(seats, i) {
    const st = (seats || [])[i];
    if (!st) return null;
    const uid = Number(st.user_id);
    if (!uid) return st;
    for (let j = 0; j < i; j++) {
      const other = (seats || [])[j];
      if (other && Number(other.user_id) === uid) return null;
    }
    return st;
  }

  function resolveHostSeat(s) {
    if (!s) return null;
    const hostUid = Number(s.host_user_id || 0);
    if (hostUid) {
      const seats = s.seats || [];
      for (let i = 0; i < seats.length; i++) {
        const st = seatAtIndex(seats, i);
        if (st && Number(st.user_id) === hostUid) return i;
      }
    }
    const ds = Number(s.dealer_seat);
    return ds >= 0 && ds < 4 ? ds : null;
  }

  function resolveWindAnchor(s) {
    if (!s) return null;
    if (s.status === 'lobby') return resolveHostSeat(s);
    const ds = Number(s.dealer_seat);
    return ds >= 0 && ds < 4 ? ds : resolveHostSeat(s);
  }

  function windLabelForSeat(seatIdx, anchorSeat) {
    const labels = ['东', '南', '西', '北'];
    if (anchorSeat == null) return labels[seatIdx] || '—';
    return labels[(seatIdx - anchorSeat + 4) % 4];
  }

  function renderLobbySeats(s) {
    const lobby = s && s.lobby || {};
    const hint = $('mjRoomHint');
    if (hint && s && s.status === 'lobby' && s.code) {
      const seats = s.seats || [];
      const minP = Number(s.min_players) || 2;
      const n = lobby.occupied_count != null ? lobby.occupied_count : seats.filter(Boolean).length;
      hint.textContent = '房间内 ' + n + ' 人 · 至少 ' + minP + ' 人全部准备后可开局'
        + (lobby.can_start ? '（可开局）' : '');
    }
  }

  function lobbyInRoom(s) {
    return !!(s && s.code && resolveMySeat(s) != null);
  }

  function setVisible(el, on) {
    if (!el) return;
    el.classList.toggle('pm-u-hidden', !on);
    if (el.hasAttribute('hidden')) {
      if (on) el.removeAttribute('hidden');
      else el.setAttribute('hidden', '');
    }
  }

  function leaveConfirmMessage(s) {
    const host = s && s.you_are_host;
    const inGame = s && s.status && s.status !== 'lobby';
    if (host && inGame) {
      return '对局进行中，解散将立即结束本房间并踢出所有玩家。确定解散？';
    }
    if (host) return '确定解散房间？所有玩家将被移出。';
    if (inGame) return '确定离开房间？对局将继续（本局按缺席处理）。';
    return '确定离开房间？';
  }

  function updateLeaveButtons(s) {
    const label = (s && s.you_are_host) ? '解散房间' : '离开房间';
    const mainBtn = $('mjLeaveBtn');
    const popBtn = $('mjPopupLeaveBtn');
    const inRoom = lobbyInRoom(s);
    if (mainBtn) mainBtn.textContent = label;
    if (popBtn) popBtn.textContent = label;
    setVisible(mainBtn, inRoom);
    setVisible(popBtn, inRoom);
  }

  function renderRoomSidebar(s) {
    if (!s) return;
    const codeEl = $('mjRoomCode');
    if (codeEl) codeEl.textContent = s.code || '------';
    const statusEl = $('mjSideStatusLine');
    const playersEl = $('mjSidePlayersLine');
    const seats = s.seats || [];
    if (playersEl) {
      const names = [];
      const seen = new Set();
      seats.forEach((st) => {
        if (!st) return;
        const uid = Number(st.user_id);
        if (uid && seen.has(uid)) return;
        if (uid) seen.add(uid);
        names.push((st.name || '—') + (st.ready ? ' ✓' : ''));
      });
      playersEl.textContent = names.length ? names.join(' · ') : '等待玩家加入';
    }
    if (statusEl) {
      let label = '等待开局';
      if (s.status === 'dealer_roll') label = '投骰定庄';
      else if (s.status === 'playing') label = '对局中';
      else if (s.status === 'hand_end') label = '本局结束';
      statusEl.textContent = label;
    }
    const panel = $('mjRoomPanel');
    if (panel) panel.classList.toggle('pm-u-hidden', !lobbyInRoom(s));
  }

  function clearRoomUi(hint) {
    stopWatch();
    closeTableWindow();
    roomCode = '';
    saveRoomCode('');
    state = null;
    lastVersion = -1;
    if (!isPopup) postStateToPopup();
    const hintEl = $('mjRoomHint');
    if (hintEl) hintEl.textContent = hint || '创建或加入房间后开始。';
    setVisible($('mjReadyBtn'), false);
    setVisible($('mjStartBtn'), false);
    setVisible($('mjConfirmRollBtn'), false);
    setVisible($('mjNextHandBtn'), false);
    setVisible($('mjLeaveBtn'), false);
    setVisible($('mjBoardCard'), false);
    setVisible($('mjLobbyPanel'), false);
    $('mjRoomPanel') && $('mjRoomPanel').classList.add('pm-u-hidden');
    if (roomChat) roomChat.setVisible(false);
    const lobbySeats = $('mjLobbySeats');
    if (lobbySeats) {
      lobbySeats.innerHTML = '';
      lobbySeats.hidden = true;
    }
    const scores = $('mjSideScores');
    if (scores) {
      scores.classList.add('pm-u-hidden');
      scores.textContent = '';
    }
    const actions = $('mjActions');
    if (actions) actions.hidden = true;
    const hand = $('mjMyHand');
    if (hand) hand.innerHTML = '';
    for (let i = 0; i < 4; i++) {
      renderSeat(i, { seats: [], discards: [], melds: [], my_seat: null, dealer_seat: 0, current_seat: null });
    }
    const center = $('mjCenterInfo');
    if (center) {
      center.textContent = hint || '—';
      center.classList.remove('pm-u-hidden');
    }
    setVisible($('mjDiceRoll'), false);
    setWindowPlaceholderVisible(false);
    updatePopoutBtnUi();
    updateLeaveButtons(null);
    if (mjBoardOverlay) mjBoardOverlay.clear();
    if (isPopup && hint && center) center.textContent = hint;
  }

  function onRoomEnded(message, opts) {
    const o = opts || {};
    const msg = message || '房间已结束';
    if (isPopup) {
      clearRoomUi(msg);
      if (!o.skipOpenerNotify) {
        try {
          if (win.opener && !win.opener.closed) {
            win.opener.postMessage({ type: 'mj-play-room-ended', message: msg }, win.location.origin);
          }
        } catch (_) {}
      }
      return;
    }
    clearRoomUi(msg);
    if (!o.silent) alert(msg);
  }

  function renderDiceRoll(s) {
    setVisible($('mjDiceRoll'), false);
  }

  function renderScores(s) {
    const bar = $('mjSideScores');
    if (!bar || !s) return;
    bar.classList.add('pm-u-hidden');
    bar.textContent = '';
  }

  function seatScoreValue(s, logical) {
    if (logical < 0) return 0;
    const scores = s.scores || {};
    return Number(scores[String(logical)] ?? scores[logical] ?? 0);
  }

  function playerInitial(name) {
    const n = String(name || '').trim();
    if (!n || n === '-') return '？';
    return n.charAt(0);
  }

  function clearPlayerAvatarVisuals(img, fallback, plus) {
    if (img) {
      img.onload = null;
      img.onerror = null;
      img.hidden = true;
      img.classList.add('pm-u-hidden');
      img.removeAttribute('src');
    }
    if (fallback) {
      fallback.textContent = '';
      fallback.hidden = true;
      fallback.classList.add('pm-u-hidden');
    }
    plus?.classList.add('pm-u-hidden');
  }

  function renderPlayerRole(roleEl, isDealer, visible) {
    if (!roleEl) return;
    if (!visible) {
      roleEl.textContent = '';
      roleEl.classList.add('pm-u-hidden');
      roleEl.setAttribute('aria-hidden', 'true');
      roleEl.classList.remove('mj-role-tag--dealer', 'mj-role-tag--xian');
      return;
    }
    roleEl.textContent = isDealer ? '庄' : '闲';
    roleEl.classList.remove('pm-u-hidden');
    roleEl.setAttribute('aria-hidden', 'false');
    roleEl.classList.toggle('mj-role-tag--dealer', isDealer);
    roleEl.classList.toggle('mj-role-tag--xian', !isDealer);
  }

  function renderSeatWind(windEl, logical, s) {
    if (!windEl) return '';
    const anchor = resolveWindAnchor(s);
    if (anchor == null || logical < 0) {
      windEl.textContent = '';
      windEl.classList.add('pm-u-hidden');
      windEl.setAttribute('aria-hidden', 'true');
      return '';
    }
    const wind = windLabelForSeat(logical, anchor);
    windEl.textContent = wind;
    windEl.classList.remove('pm-u-hidden');
    windEl.setAttribute('aria-hidden', 'false');
    return wind;
  }

  function renderPlayerBadge(domIdx, s, logical) {
    const badge = $('mjPlayerBadge' + domIdx);
    const img = $('mjPlayerAvatarImg' + domIdx);
    const fallback = $('mjPlayerAvatarFallback' + domIdx);
    const plus = $('mjPlayerAvatarPlus' + domIdx);
    const nameEl = $('mjSeatName' + domIdx);
    const metaEl = $('mjSeatMeta' + domIdx);
    const roleEl = $('mjSeatRole' + domIdx);
    const windEl = $('mjSeatWind' + domIdx);
    const scoreEl = $('mjSeatScore' + domIdx);
    if (!badge || !nameEl) return;

    clearPlayerAvatarVisuals(img, fallback, plus);
    const st = logical >= 0 ? seatAtIndex(s.seats, logical) : null;
    const mySeat = resolveMySeat(s);
    const empty = !st;
    const canSwap = !!s.can_swap_seat && mySeat != null && empty && logical >= 0 && logical !== mySeat;

    badge.classList.toggle('is-empty', empty);
    badge.classList.toggle('is-me', !empty && mySeat === logical);
    badge.classList.toggle('is-dealer', !empty && s.dealer_seat === logical);
    badge.classList.toggle('is-actionable', canSwap);
    badge.tabIndex = canSwap ? 0 : -1;
    badge.setAttribute('aria-disabled', canSwap ? 'false' : 'true');
    if (logical >= 0) badge.dataset.logicalSeat = String(logical);
    else delete badge.dataset.logicalSeat;

    if (empty) {
      const wind = renderSeatWind(windEl, logical, s);
      nameEl.textContent = '空位';
      renderPlayerRole(roleEl, false, false);
      if (metaEl) metaEl.textContent = canSwap ? '点击换座' : '';
      if (scoreEl) scoreEl.textContent = '';
      plus?.classList.remove('pm-u-hidden');
      badge.setAttribute('aria-label', canSwap ? (wind ? `点击换到${wind}位` : '点击换到此空位') : (wind ? `${wind}位空位` : '空位'));
      return;
    }

    const name = st.name || '—';
    const wind = renderSeatWind(windEl, logical, s);
    nameEl.textContent = name;
    const isDealer = s.dealer_seat === logical;
    renderPlayerRole(roleEl, isDealer, s.status !== 'lobby');
    const meta = [];
    if (s.current_seat === logical && s.status === 'playing') meta.push('出牌');
    if (st.ready && s.status === 'lobby') meta.push('已准备');
    if (metaEl) metaEl.textContent = meta.join(' · ');
    if (scoreEl) {
      const sc = seatScoreValue(s, logical);
      const showScore = s.status && s.status !== 'lobby';
      scoreEl.textContent = showScore ? `${sc} 分` : '';
      scoreEl.classList.toggle('pm-u-hidden', !showScore);
    }
    badge.setAttribute('aria-label', wind ? `${wind} · ${name}` : name);

    const avatarUrl = st.avatar_url ? String(st.avatar_url) : '';
    if (avatarUrl && img) {
      img.alt = name;
      img.onerror = () => {
        img.hidden = true;
        img.classList.add('pm-u-hidden');
        img.removeAttribute('src');
        if (fallback) {
          fallback.textContent = playerInitial(name);
          fallback.hidden = false;
          fallback.classList.remove('pm-u-hidden');
        }
      };
      img.onload = () => {
        img.hidden = false;
        img.classList.remove('pm-u-hidden');
        if (fallback) {
          fallback.hidden = true;
          fallback.classList.add('pm-u-hidden');
        }
      };
      img.src = avatarUrl;
      if (img.complete && img.naturalWidth > 0) {
        img.hidden = false;
        img.classList.remove('pm-u-hidden');
      }
    } else if (fallback) {
      fallback.textContent = playerInitial(name);
      fallback.hidden = false;
      fallback.classList.remove('pm-u-hidden');
    }
  }

  function renderSeat(seatIdx, s) {
    const logical = s._view_seat != null ? s._view_seat : seatIdx;
    renderPlayerBadge(seatIdx, s, logical);
    const riverEl = $('mjRiver' + seatIdx);
    const meldsEl = $('mjMelds' + seatIdx);
    const st = logical >= 0 ? seatAtIndex(s.seats, logical) : null;
    if (!st) {
      if (riverEl) riverEl.innerHTML = '';
      if (meldsEl) meldsEl.innerHTML = '';
      return;
    }
    const river = (s.discards || [])[logical] || [];
    if (riverEl) {
      riverEl.innerHTML = river.map((t) => tileFaceHtml(t, 'mini')).join('');
    }
    const melds = (s.melds || [])[logical] || [];
    if (meldsEl) {
      meldsEl.innerHTML = melds.map((m) => {
        const tiles = (m.tiles || []).map((t) => tileLabel(t)).join('');
        return `<span class="mj-meld">${esc(m.type)}:${esc(tiles)}</span>`;
      }).join(' ');
    }
  }

  function syncHandTileLayout(handEl) {
    if (!handEl) return;
    const n = handEl.querySelectorAll('.mj-tile--hand').length;
    handEl.style.setProperty('--mj-hand-count', String(Math.max(n, 1)));
    const w = handEl.clientWidth;
    if (n > 0 && w > 0) {
      const rootPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
      const maxPx = 3.1 * rootPx;
      const perTile = Math.min(maxPx, (w / n) * 0.93);
      handEl.style.setProperty('--mj-hand-tile-size', perTile + 'px');
    }
  }

  let handLayoutBound = false;
  function ensureHandLayoutSync() {
    if (handLayoutBound) return;
    handLayoutBound = true;
    window.addEventListener('resize', () => {
      syncHandTileLayout($('mjMyHand'));
    });
  }

  function renderHand(s) {
    const handEl = $('mjMyHand');
    const stripEl = handEl && handEl.closest('.mj-hand-strip');
    if (!handEl) return;
    ensureHandLayoutSync();
    if (s.status === 'dealer_roll' || s.status === 'lobby') {
      handEl.innerHTML = '';
      if (stripEl) stripEl.classList.add('pm-u-hidden');
      return;
    }
    const hand = s.my_hand || [];
    const mySeat = resolveMySeat(s);
    const canDiscard = s.status === 'playing' && s.phase === 'discard' && s.current_seat === mySeat;
    if (stripEl) stripEl.classList.toggle('pm-u-hidden', !hand.length);
    handEl.innerHTML = hand.map((t) => tileHandButtonHtml(t, canDiscard)).join('');
    handEl.querySelectorAll('.mj-tile--hand.mj-tile--clickable').forEach((btn) => {
      btn.addEventListener('click', () => {
        const tile = btn.getAttribute('data-tile');
        if (tile) doDiscard(tile);
      });
    });
    syncHandTileLayout(handEl);
    window.requestAnimationFrame(() => syncHandTileLayout(handEl));
  }

  function renderActions(s) {
    const wrap = $('mjActions');
    const btns = $('mjActionBtns');
    if (!wrap || !btns) return;
    const list = [];
    if (s.pending_self_win) {
      list.push({ type: 'win', label: '自摸胡' });
      list.push({ type: 'pass', label: '不胡，出牌' });
    }
    const cr = s.claim_round;
    if (cr && cr.need_response && (cr.options || []).length) {
      (cr.options || []).forEach((opt) => {
        const labels = { win: '胡', pung: '碰', kong: '杠', pass: '过' };
        list.push({ type: opt, label: labels[opt] || opt });
      });
    }
    if (!list.length) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    btns.innerHTML = list.map((a) =>
      `<button type="button" class="btn-secondary mj-claim-btn" data-claim="${esc(a.type)}">${esc(a.label)}</button>`
    ).join('');
    btns.querySelectorAll('.mj-claim-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const t = btn.getAttribute('data-claim');
        if (t) doClaim(t);
      });
    });
  }

  function shouldRotateTableView(s) {
    return resolveMySeat(s) != null;
  }

  /** 按牌桌方位映射：本家下、对家上、下家左（南）、上家右（北） */
  function domSlotForSeat(logicalSeat, s) {
    if (!shouldRotateTableView(s)) {
      return logicalSeat >= 0 && logicalSeat < 4 ? logicalSeat : -1;
    }
    const my = resolveMySeat(s);
    if (my == null) return logicalSeat >= 0 && logicalSeat < 4 ? logicalSeat : -1;
    const diff = (logicalSeat - my + 4) % 4;
    const map = { 0: 0, 1: 2, 2: 1, 3: 3 };
    return map[diff] != null ? map[diff] : -1;
  }

  function logicalSeatForDomSlot(dom, s) {
    if (!shouldRotateTableView(s)) {
      return dom >= 0 && dom < 4 ? dom : -1;
    }
    for (let L = 0; L < 4; L++) {
      if (domSlotForSeat(L, s) === dom) return L;
    }
    return -1;
  }

  function renderTable(raw) {
    const s = withResolvedSeat(normalizeRoomState(raw));
    state = s;
    if (!s || !s.code) return;
    roomCode = s.code;
    saveRoomCode(roomCode);
    for (let dom = 0; dom < 4; dom++) {
      const logical = logicalSeatForDomSlot(dom, s);
      renderSeat(dom, Object.assign({}, s, {
        my_seat: resolveMySeat(s),
        _view_seat: logical,
        discards: s.discards,
        melds: s.melds,
        seats: s.seats,
        dealer_seat: s.dealer_seat,
        current_seat: s.current_seat,
      }));
    }
    const viewS = Object.assign({}, s);
    const mySeat = resolveMySeat(s);
    if (mySeat != null) {
      viewS.my_seat = mySeat;
      viewS.my_hand = s.my_hand;
    }
    renderHand(viewS);
    renderActions(s);
    renderScores(s);

    const center = $('mjCenterInfo');
    if (center) {
      let msg = `房间 ${s.code} · 第 ${s.hand_no || 1} 局`;
      if (s.status === 'lobby') {
        const lb = s.lobby || {};
        msg += ' · 等待开局（' + (lb.occupied_count || 0) + ' 人，至少 ' + (s.min_players || 2) + ' 人准备）';
      }
      else if (s.status === 'dealer_roll') {
        const dr = s.dice_roll || {};
        msg += ' · 投骰定庄';
        if (dr.dealer_name) msg += ' · 庄家 ' + dr.dealer_name;
      }
      else if (s.status === 'playing') msg += ` · 牌墙余 ${s.wall_remaining ?? '?'}`;
      else if (s.status === 'hand_end') {
        const r = s.last_hand_result || {};
        if (r.win_type === 'draw') msg += ' · 流局';
        else if (r.winner_seat != null) {
          const wn = ((s.seats || [])[r.winner_seat] || {}).name || '';
          msg += ` · ${wn} 胡（${r.win_type === 'tsumo' ? '自摸' : '点炮'}）`;
          if (r.win_type === 'tsumo' || r.win_type === 'ron') msg += ` · 下局 ${wn} 坐庄`;
        }
      }
      center.textContent = msg;
    }

    renderLobbySeats(s);
    renderDiceRoll(s);
    updateBoardOverlay(s);
    renderRoomSidebar(s);
    syncRoomChat(s);

    const overlayActive = isBoardOverlayActive(s);
    if (center) center.classList.toggle('pm-u-hidden', overlayActive);

    const inRoom = lobbyInRoom(s);
    setVisible($('mjBoardCard'), inRoom);
    const hideTable = isMain && popupOpen;
    setVisible($('mjTableWrap'), inRoom && !hideTable);
    setVisible($('mjReadyBtn'), s.status === 'lobby' && resolveMySeat(s) != null && !overlayActive);
    setVisible($('mjStartBtn'), s.status === 'lobby' && s.you_are_host && !overlayActive);
    setVisible($('mjConfirmRollBtn'), false);
    setVisible($('mjNextHandBtn'), s.status === 'hand_end' && s.you_are_host);
    setVisible($('mjLeaveBtn'), lobbyInRoom(s));
    updateLeaveButtons(s);

    const readyBtn = $('mjReadyBtn');
    if (readyBtn && s.status === 'lobby') {
      const me = mySeat != null ? (s.seats || [])[mySeat] : null;
      readyBtn.textContent = me && me.ready ? '取消准备' : '准备';
    }
    const popReady = $('mjPopupReadyBtn');
    if (popReady && s.status === 'lobby') {
      const me = mySeat != null ? (s.seats || [])[mySeat] : null;
      popReady.textContent = me && me.ready ? '取消准备' : '准备';
      setVisible(popReady, mySeat != null && !overlayActive);
    }
    if (isMain) updatePopoutBtnUi();
  }

  function applyState(data) {
    if (!data || data.status !== 'success') return false;
    const ver = Number(data.version) || 0;
    if (!data.unchanged && lastVersion >= 0 && ver > 0 && ver < lastVersion) {
      return false;
    }
    if (data.unchanged && lastVersion >= 0 && ver <= lastVersion) return true;
    lastVersion = ver;
    renderTable(data);
    if (!isPopup) postStateToPopup();
    return true;
  }

  function applyPayloadFromParent(payload) {
    if (!payload) return;
    if (payload.lastVersion != null) lastVersion = Number(payload.lastVersion);
    if (!payload.state || !payload.state.code) {
      clearRoomUi('房间已结束');
      return;
    }
    if (payload.roomCode) roomCode = String(payload.roomCode).toUpperCase();
    renderTable(payload.state);
  }

  function beaconLeave() {
    if (!roomCode || isPopup) return;
    try {
      fetch(apiUrl('/api/mahjong-play'), {
        method: 'POST',
        credentials: 'include',
        keepalive: true,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'leave', room_code: roomCode }),
      });
    } catch (_) {}
  }

  function mjToast(message, isError) {
    const msg = String(message || '').trim();
    if (!msg) return;
    if (win.showAppToast) win.showAppToast(msg, !!isError);
    else if (isError) alert(msg);
  }

  async function doCreate() {
    const btn = $('mjCreateBtn');
    if (btn && btn.disabled) return;
    if (btn) btn.disabled = true;
    try {
      const data = await api('create', {});
      if (!applyState(data)) {
        mjToast('房间已创建但界面更新失败，请刷新页面', true);
        return;
      }
      mjToast('房间已创建：' + roomCode, false);
      if (!isPopup) startWatch();
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function doJoin() {
    if (joinInFlight) return;
    const code = ($('mjJoinInput') && $('mjJoinInput').value || '').trim().toUpperCase();
    if (!code) return alert('请输入房间号');
    joinInFlight = true;
    try {
      const data = await api('join', { room_code: code });
      applyState(data);
      if (!isPopup) startWatch();
    } finally {
      joinInFlight = false;
    }
  }

  function requestLeaveRoom() {
    if (!roomCode) {
      clearRoomUi();
      return Promise.resolve();
    }
    initMjBoardOverlay();
    const msg = leaveConfirmMessage(state);
    const isHost = !!(state && state.you_are_host);
    if (!mjBoardOverlay) {
      return doLeaveConfirmed();
    }
    return new Promise((resolve, reject) => {
      mjBoardOverlay.showConfirm({
        title: isHost ? '解散房间' : '离开房间',
        message: msg,
        confirmLabel: isHost ? '解散' : '离开',
        cancelLabel: '取消',
        danger: true,
        onConfirm: () => {
          doLeaveConfirmed().then(resolve).catch(reject);
        },
        onCancel: () => resolve(),
      });
    });
  }

  async function doLeaveConfirmed() {
    const data = await api('leave', { room_code: roomCode });
    if (data.room_deleted || data.room_dissolved || data.left_room) {
      const endedMsg = data.message || (data.room_dissolved ? '房间已解散' : '已离开房间');
      onRoomEnded(endedMsg, isPopup ? {} : undefined);
      return data;
    }
    applyState(data);
    return data;
  }

  async function doReady() {
    const me = state && (state.seats || [])[state.my_seat];
    const next = !(me && me.ready);
    const data = await api('ready', { room_code: roomCode, ready: next });
    applyState(data);
  }

  async function doStart() {
    const data = await api('start', { room_code: roomCode });
    applyState(data);
  }

  async function doRollDice() {
    const data = await api('roll_dice', { room_code: roomCode });
    applyState(data);
  }

  async function doConfirmRoll() {
    const data = await api('confirm_roll', { room_code: roomCode });
    applyState(data);
  }

  async function doNextHand() {
    const data = await api('next_hand', { room_code: roomCode });
    applyState(data);
  }

  async function doDiscard(tile) {
    const data = await api('discard', { room_code: roomCode, tile });
    applyState(data);
  }

  async function doClaim(type) {
    const data = await api('claim', { room_code: roomCode, type });
    applyState(data);
  }

  async function doSwapSeat(preferSeat) {
    try {
      const data = await api('swap_seat', { room_code: roomCode, prefer_seat: preferSeat });
      let ok = applyState(data);
      if (!ok) {
        const fresh = await api('state', { room_code: roomCode }, 'GET');
        ok = applyState(fresh);
      }
      if (ok) {
        let msg = (data && data.message) || '已更换座位';
        if (state && state.status === 'lobby') {
          const my = resolveMySeat(state);
          const anchor = resolveWindAnchor(state);
          if (my != null && anchor != null) {
            msg += '（' + windLabelForSeat(my, anchor) + '位）';
          }
        }
        mjToast(msg, false);
      } else {
        mjToast('换座状态同步失败，请刷新页面', true);
      }
    } catch (err) {
      const msg = String((err && err.message) || '');
      const maybeTransient = /解散|过期|不存在|不在该房间|换座失败|刷新/.test(msg);
      if (maybeTransient) {
        try {
          const fresh = await api('state', { room_code: roomCode }, 'GET');
          if (applyState(fresh)) {
            mjToast('换座已完成', false);
            return;
          }
        } catch (_) {}
      }
      mjToast(msg || '换座失败', true);
    }
  }

  function onPlayerBadgeClick(domIdx) {
    const badge = $('mjPlayerBadge' + domIdx);
    if (!badge || !badge.classList.contains('is-actionable') || !state) return;
    const raw = badge.getAttribute('data-logical-seat');
    let target = raw != null && raw !== '' ? Number(raw) : logicalSeatForDomSlot(domIdx, state);
    if (!Number.isFinite(target) || target < 0) return;
    doSwapSeat(target);
  }

  function bindPlayerAvatarUi() {
    for (let dom = 0; dom < 4; dom++) {
      const badge = $('mjPlayerBadge' + dom);
      if (!badge || badge.dataset.bound === '1') continue;
      badge.dataset.bound = '1';
      const activate = () => onPlayerBadgeClick(dom);
      badge.addEventListener('click', activate);
      badge.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
        activate();
      });
    }
  }

  let roomSyncRecoveries = 0;

  async function recoverRoomStateAfterSyncError() {
    if (!roomCode || roomSyncRecoveries >= 2) return false;
    roomSyncRecoveries += 1;
    try {
      const data = await api('state', { room_code: roomCode }, 'GET');
      if (data && data.status === 'success' && applyState(data)) {
        roomSyncRecoveries = 0;
        return true;
      }
    } catch (_) {
      try {
        const data = await api('join', { room_code: roomCode });
        if (data && data.status === 'success' && applyState(data)) {
          roomSyncRecoveries = 0;
          return true;
        }
      } catch (_) {}
    }
    return false;
  }

  function stopWatch() {
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

  function streamUrl() {
    const qs = new URLSearchParams({
      action: 'stream',
      room_code: roomCode,
      since_version: String(lastVersion >= 0 ? lastVersion : 0),
    });
    return apiUrl('/api/mahjong-play?' + qs.toString());
  }

  function connectSse() {
    if (!roomCode || watchAbort || typeof EventSource === 'undefined') {
      startWaitWatch();
      return;
    }
    let es;
    try {
      es = new EventSource(streamUrl());
    } catch (_) {
      useSse = false;
      startWaitWatch();
      return;
    }
    eventSource = es;
    es.addEventListener('state', (ev) => {
      if (watchAbort || !ev.data) return;
      try {
        applyState(JSON.parse(ev.data));
      } catch (_) {}
    });
    const onRoomEndedEvent = (ev) => {
      if (watchAbort || !ev.data) return;
      try {
        const data = JSON.parse(ev.data);
        const msg = String(data.message || '');
        const maybeRecover = msg.indexOf('不在该房间') >= 0
          || msg.indexOf('解散') >= 0
          || msg.indexOf('过期') >= 0
          || msg.indexOf('不存在') >= 0;
        if (maybeRecover) {
          recoverRoomStateAfterSyncError().then((ok) => {
            if (!ok) onRoomEnded(msg || '房间已结束');
          });
          return;
        }
        onRoomEnded(msg || '房间已结束');
      } catch (_) {
        recoverRoomStateAfterSyncError().then((ok) => {
          if (!ok) onRoomEnded('房间已结束');
        });
      }
    };
    es.addEventListener('room_error', onRoomEndedEvent);
    es.addEventListener('room_dissolved', onRoomEndedEvent);
    es.onerror = () => {
      if (watchAbort) return;
      try { es.close(); } catch (_) {}
      if (eventSource === es) eventSource = null;
      win.setTimeout(() => {
        if (!watchAbort && roomCode) connectSse();
      }, 500);
    };
  }

  function startSseWatch() {
    connectSse();
  }

  function watchLoop() {
    if (watchAbort || !roomCode) return;
    watchCtrl = new AbortController();
    const signal = watchCtrl.signal;
    api('wait', { room_code: roomCode, since_version: String(lastVersion >= 0 ? lastVersion : 0) }, 'GET')
      .then((data) => {
        if (watchAbort || !roomCode) return;
        if (data && data.status === 'success' && !data.unchanged) applyState(data);
        if (!watchAbort && roomCode) watchLoop();
      })
      .catch((err) => {
        if (watchAbort || (err && err.name === 'AbortError')) return;
        const msg = String((err && err.message) || '');
        if (msg.indexOf('解散') >= 0 || msg.indexOf('不存在') >= 0 || msg.indexOf('过期') >= 0) {
          recoverRoomStateAfterSyncError().then((ok) => {
            if (!ok) onRoomEnded(msg.indexOf('解散') >= 0 ? msg : '房间已解散或已过期');
          });
          return;
        }
        if (msg.indexOf('不在该房间') >= 0) {
          recoverRoomStateAfterSyncError().then((ok) => {
            if (!ok) onRoomEnded(msg);
          });
          return;
        }
        if (!watchAbort && roomCode) win.setTimeout(watchLoop, 1500);
      });
  }

  function startWaitWatch() {
    watchAbort = false;
    watchLoop();
  }

  function startWatch() {
    if (isPopup) return;
    stopWatch();
    watchAbort = false;
    if (useSse) startSseWatch();
    else startWaitWatch();
  }

  async function tryResume() {
    let code = loadRoomCode();
    if (isPopup) {
      try {
        code = new URL(win.location.href).searchParams.get('room') || code;
      } catch (_) {}
    }
    if (!code) return;
    roomCode = String(code).toUpperCase();
    try {
      const data = await api('state', { room_code: roomCode }, 'GET');
      applyState(data);
    } catch (err) {
      try {
        const data = await api('join', { room_code: roomCode });
        applyState(data);
      } catch (err2) {
        saveRoomCode('');
        const msg = String((err2 && err2.message) || (err && err.message) || '');
        if (msg.indexOf('解散') >= 0 || msg.indexOf('不存在') >= 0 || msg.indexOf('过期') >= 0 || msg.indexOf('不在') >= 0) {
          clearRoomUi(msg.indexOf('解散') >= 0 ? msg : '房间已解散或已过期');
        }
        return;
      }
    }
    if (!isPopup) startWatch();
  }

  function bindMainMessageBridge() {
    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      const msg = e.data || {};
      if (msg.type === 'mj-play-request-state') postStateToPopup();
      if (msg.type === 'mj-play-room-ended') onRoomEnded(msg.message || '房间已结束', { silent: true });
    });
  }

  function initPopup() {
    initMjBoardOverlay();
    initRoomChat();
    bindPlayerAvatarUi();
    document.title = '麻将牌桌';
    tryResume();
    const syncFromOpener = () => {
      if (!win.opener || win.opener.closed) return;
      try {
        win.opener.postMessage({ type: 'mj-play-request-state' }, win.location.origin);
      } catch (_) {}
    };
    syncFromOpener();
    win.setInterval(syncFromOpener, 1200);
    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      if (e.data && e.data.type === 'mj-play-state') applyPayloadFromParent(e.data.payload);
    });
    try {
      win.opener && win.opener.postMessage({ type: 'mj-play-popup-ready' }, win.location.origin);
    } catch (_) {}
    const popReady = $('mjPopupReadyBtn');
    if (popReady) {
      popReady.addEventListener('click', () => doReady().catch((err) => alert(err.message)));
    }
    const popLeave = $('mjPopupLeaveBtn');
    if (popLeave) {
      popLeave.addEventListener('click', () => requestLeaveRoom().catch((err) => alert(err.message)));
    }
    win.addEventListener('beforeunload', () => {
      if (roomCode && state && state.my_seat != null && !state.you_are_host) beaconLeave();
    });
  }

  function initMain() {
    initMjBoardOverlay();
    initRoomChat();
    bindPlayerAvatarUi();
    bindMainMessageBridge();
    $('mjCreateBtn') && $('mjCreateBtn').addEventListener('click', () => doCreate().catch((e) => mjToast(e.message || '创建失败', true)));
    $('mjJoinBtn') && $('mjJoinBtn').addEventListener('click', () => doJoin().catch((e) => alert(e.message)));
    $('mjLeaveBtn') && $('mjLeaveBtn').addEventListener('click', () => requestLeaveRoom().catch((e) => alert(e.message)));
    $('mjReadyBtn') && $('mjReadyBtn').addEventListener('click', () => doReady().catch((e) => alert(e.message)));
    $('mjStartBtn') && $('mjStartBtn').addEventListener('click', () => doStart().catch((e) => alert(e.message)));
    $('mjConfirmRollBtn') && $('mjConfirmRollBtn').addEventListener('click', () => doConfirmRoll().catch((e) => alert(e.message)));
    $('mjNextHandBtn') && $('mjNextHandBtn').addEventListener('click', () => doNextHand().catch((e) => alert(e.message)));
    const popBtn = $('mjPopoutBtn');
    if (popBtn) {
      popBtn.addEventListener('click', () => {
        if (popupOpen && tablePopup && !tablePopup.closed) closeTableWindow();
        else openTableWindow();
      });
    }
    win.addEventListener('beforeunload', () => {
      if (!roomCode || !state || state.my_seat == null) return;
      if (state.you_are_host) return;
      beaconLeave();
    });
    tryResume();
  }

  function bootMahjongPlay() {
    const mode = mjPlayMode();
    if (mode.isPopup) initPopup();
    else if (mode.isMain) initMain();
    else tryResume();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootMahjongPlay);
  } else {
    bootMahjongPlay();
  }
})(typeof window !== 'undefined' ? window : this);
