/**
 * 麻将：主控页 + 牌桌独立窗口（postMessage 同步）；SSE / 长轮询。
 */
(function (global) {
  'use strict';
  const win = global || window;
  const ROOM_KEY = 'sitjoy.mahjong.room.v1';
  const TABLE_POPUP_NAME = 'sitjoy_mj_table_popup';

  const isPopup = document.body && document.body.dataset.mjPlayMode === 'popup';
  const isMain = document.body && document.body.dataset.mjPlayMode === 'main';

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

  const $ = (id) => document.getElementById(id);

  function initMjBoardOverlay() {
    if (mjBoardOverlay) return mjBoardOverlay;
    if (!win.WidgetBoardOverlay) return null;
    mjBoardOverlay = win.WidgetBoardOverlay.create({
      overlayId: 'mjBoardOverlay',
      titleId: 'mjOverlayTitle',
      messageId: 'mjOverlayMsg',
      actionsId: 'mjOverlayActions',
    });
    return mjBoardOverlay;
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

  function esc(s) {
    return String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;');
  }

  function saveRoomCode(code) {
    try {
      if (code) localStorage.setItem(ROOM_KEY, code);
      else localStorage.removeItem(ROOM_KEY);
    } catch (_) {}
  }

  function loadRoomCode() {
    try { return localStorage.getItem(ROOM_KEY) || ''; } catch (_) { return ''; }
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

  function renderLobbySeats(s) {
    const root = $('mjLobbySeats');
    const panel = $('mjLobbyPanel');
    if (!root) return;
    const inLobby = s && s.status === 'lobby' && s.code;
    if (panel) panel.classList.toggle('pm-u-hidden', !inLobby);
    root.hidden = !inLobby;
    if (!inLobby) return;
    const seats = s.seats || [];
    const minP = Number(s.min_players) || 2;
    const labels = ['东', '南', '西', '北'];
    root.innerHTML = [0, 1, 2, 3].map((i) => {
      const st = seats[i];
      const cls = ['mj-seat-dot'];
      if (!st) cls.push('mj-seat-dot--empty');
      else {
        cls.push('mj-seat-dot--filled');
        if (st.ready) cls.push('mj-seat-dot--ready');
        if (s.my_seat === i) cls.push('mj-seat-dot--me');
      }
      const check = st && st.ready ? '✓' : '';
      const name = st ? (st.name || '—') : '空位';
      return '<div class="' + cls.join(' ') + '" title="' + esc(labels[i] + ' · ' + name) + '">'
        + '<span class="mj-seat-dot-inner">' + check + '</span>'
        + '<span class="mj-seat-dot-name">' + esc(st ? name : '空') + '</span></div>';
    }).join('');
    const lobby = s.lobby || {};
    const hint = $('mjRoomHint');
    if (hint) {
      const n = lobby.occupied_count != null ? lobby.occupied_count : seats.filter(Boolean).length;
      hint.textContent = '房间内 ' + n + ' 人 · 至少 ' + minP + ' 人全部准备后可开局'
        + (lobby.can_start ? '（可开局）' : '');
    }
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
    const inRoom = !!(s && s.code && s.my_seat != null);
    if (mainBtn) mainBtn.textContent = label;
    if (popBtn) popBtn.textContent = label;
    setVisible(mainBtn, inRoom);
    setVisible(popBtn, inRoom);
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
    setVisible($('mjNextHandBtn'), false);
    setVisible($('mjLeaveBtn'), false);
    setVisible($('mjTableCard'), false);
    setVisible($('mjLobbyPanel'), false);
    const lobbySeats = $('mjLobbySeats');
    if (lobbySeats) {
      lobbySeats.innerHTML = '';
      lobbySeats.hidden = true;
    }
    const scores = $('mjScoresBar');
    if (scores) {
      scores.hidden = true;
      scores.innerHTML = '';
    }
    const actions = $('mjActions');
    if (actions) actions.hidden = true;
    const hand = $('mjMyHand');
    if (hand) hand.innerHTML = '';
    for (let i = 0; i < 4; i++) {
      renderSeat(i, { seats: [], discards: [], melds: [], my_seat: null, dealer_seat: 0, current_seat: null });
    }
    const center = $('mjCenterInfo');
    if (center) center.textContent = hint || '—';
    setWindowPlaceholderVisible(false);
    updatePopoutBtnUi();
    updateLeaveButtons(null);
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

  function renderScores(s) {
    const bar = $('mjScoresBar');
    if (!bar || !s) return;
    const scores = s.scores || {};
    const seats = s.seats || [];
    const parts = seats.filter(Boolean).map((st) => {
      const sc = scores[String(st.seat)] ?? 0;
      return `${esc(st.name)}: ${sc}`;
    });
    if (!parts.length) {
      bar.hidden = true;
      return;
    }
    bar.hidden = false;
    bar.innerHTML = '<strong>累计积分</strong> · ' + parts.join(' ｜ ');
  }

  function renderSeat(seatIdx, s) {
    const logical = s._view_seat != null ? s._view_seat : seatIdx;
    const nameEl = $('mjSeatName' + seatIdx);
    const metaEl = $('mjSeatMeta' + seatIdx);
    const riverEl = $('mjRiver' + seatIdx);
    const meldsEl = $('mjMelds' + seatIdx);
    const st = (s.seats || [])[logical];
    if (!nameEl) return;
    if (!st) {
      nameEl.textContent = '空位';
      if (metaEl) metaEl.textContent = '';
      if (riverEl) riverEl.innerHTML = '';
      if (meldsEl) meldsEl.innerHTML = '';
      return;
    }
    let meta = [];
    if (s.dealer_seat === logical) meta.push('庄');
    if (s.current_seat === logical) meta.push('出牌');
    if (st.ready) meta.push('已准备');
    nameEl.textContent = st.name || '—';
    if (metaEl) metaEl.textContent = meta.join(' · ');
    const river = (s.discards || [])[logical] || [];
    if (riverEl) {
      riverEl.innerHTML = river.map((t) => `<span class="mj-tile mj-tile--mini">${esc(tileLabel(t))}</span>`).join('');
    }
    const melds = (s.melds || [])[logical] || [];
    if (meldsEl) {
      meldsEl.innerHTML = melds.map((m) => {
        const tiles = (m.tiles || []).map((t) => tileLabel(t)).join('');
        return `<span class="mj-meld">${esc(m.type)}:${esc(tiles)}</span>`;
      }).join(' ');
    }
  }

  function renderHand(s) {
    const handEl = $('mjMyHand');
    if (!handEl) return;
    const hand = s.my_hand || [];
    const mySeat = s.my_seat;
    const canDiscard = s.status === 'playing' && s.phase === 'discard' && s.current_seat === mySeat;
    handEl.innerHTML = hand.map((t) => {
      const cls = 'mj-tile' + (canDiscard ? ' mj-tile--clickable' : '');
      return `<button type="button" class="${cls}" data-tile="${esc(t)}" ${canDiscard ? '' : 'disabled'}>${esc(tileLabel(t))}</button>`;
    }).join('');
    handEl.querySelectorAll('.mj-tile--clickable').forEach((btn) => {
      btn.addEventListener('click', () => {
        const tile = btn.getAttribute('data-tile');
        if (tile) doDiscard(tile);
      });
    });
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

  function domSlotForSeat(logicalSeat, s) {
    const my = s.my_seat;
    const active = (s.active_seats || []).slice().sort((a, b) => a - b);
    if (my == null || !active.length) return logicalSeat;
    const mi = active.indexOf(my);
    const si = active.indexOf(logicalSeat);
    if (si < 0) return logicalSeat;
    const diff = (si - mi + active.length) % active.length;
    const map3 = { 0: 0, 1: 3, 2: 1 };
    const map4 = { 0: 0, 1: 3, 2: 1, 3: 2 };
    const map = active.length === 3 ? map3 : map4;
    return map[diff] != null ? map[diff] : logicalSeat;
  }

  function renderTable(s) {
    state = s;
    if (!s || !s.code) return;
    roomCode = s.code;
    saveRoomCode(roomCode);
    for (let dom = 0; dom < 4; dom++) {
      let logical = dom;
      for (let L = 0; L < 4; L++) {
        if (domSlotForSeat(L, s) === dom) {
          logical = L;
          break;
        }
      }
      renderSeat(dom, Object.assign({}, s, {
        my_seat: s.my_seat,
        _view_seat: logical,
        discards: s.discards,
        melds: s.melds,
        seats: s.seats,
        dealer_seat: s.dealer_seat,
        current_seat: s.current_seat,
      }));
    }
    const viewS = Object.assign({}, s);
    if (s.my_seat != null) {
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
      else if (s.status === 'playing') msg += ` · 牌墙余 ${s.wall_remaining ?? '?'}`;
      else if (s.status === 'hand_end') {
        const r = s.last_hand_result || {};
        if (r.win_type === 'draw') msg += ' · 流局';
        else if (r.winner_seat != null) {
          const wn = ((s.seats || [])[r.winner_seat] || {}).name || '';
          msg += ` · ${wn} 胡（${r.win_type === 'tsumo' ? '自摸' : '点炮'}）`;
        }
      }
      center.textContent = msg;
    }

    renderLobbySeats(s);

    setVisible($('mjTableCard'), s.status !== 'lobby' && !(isMain && popupOpen));
    setVisible($('mjReadyBtn'), s.status === 'lobby' && s.my_seat != null);
    setVisible($('mjStartBtn'), s.status === 'lobby' && s.you_are_host);
    setVisible($('mjNextHandBtn'), s.status === 'hand_end' && s.you_are_host);
    setVisible($('mjLeaveBtn'), !!s.my_seat);
    updateLeaveButtons(s);

    const readyBtn = $('mjReadyBtn');
    if (readyBtn && s.status === 'lobby') {
      const me = (s.seats || [])[s.my_seat];
      readyBtn.textContent = me && me.ready ? '取消准备' : '准备';
    }
    const popReady = $('mjPopupReadyBtn');
    if (popReady && s.status === 'lobby') {
      const me = (s.seats || [])[s.my_seat];
      popReady.textContent = me && me.ready ? '取消准备' : '准备';
      setVisible(popReady, s.my_seat != null);
    }
    if (isMain) updatePopoutBtnUi();
  }

  function applyState(data) {
    if (!data || data.status !== 'success') return false;
    const ver = Number(data.version) || 0;
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
    applyState(payload.state);
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

  async function doCreate() {
    const data = await api('create', {});
    applyState(data);
    if (!isPopup) startWatch();
  }

  async function doJoin() {
    const code = ($('mjJoinInput') && $('mjJoinInput').value || '').trim().toUpperCase();
    if (!code) return alert('请输入房间号');
    const data = await api('join', { room_code: code });
    applyState(data);
    if (!isPopup) startWatch();
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
        onRoomEnded(data.message || '房间已结束');
      } catch (_) {
        onRoomEnded('房间已结束');
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
          onRoomEnded(msg.indexOf('解散') >= 0 ? msg : '房间已解散或已过期');
          return;
        }
        if (msg.indexOf('不在该房间') >= 0) {
          onRoomEnded(msg);
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
      if (!isPopup) startWatch();
    } catch (err) {
      saveRoomCode('');
      const msg = String((err && err.message) || '');
      if (msg.indexOf('解散') >= 0 || msg.indexOf('不存在') >= 0 || msg.indexOf('过期') >= 0) {
        clearRoomUi(msg);
      }
    }
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
    bindMainMessageBridge();
    $('mjCreateBtn') && $('mjCreateBtn').addEventListener('click', () => doCreate().catch((e) => alert(e.message)));
    $('mjJoinBtn') && $('mjJoinBtn').addEventListener('click', () => doJoin().catch((e) => alert(e.message)));
    $('mjLeaveBtn') && $('mjLeaveBtn').addEventListener('click', () => requestLeaveRoom().catch((e) => alert(e.message)));
    $('mjReadyBtn') && $('mjReadyBtn').addEventListener('click', () => doReady().catch((e) => alert(e.message)));
    $('mjStartBtn') && $('mjStartBtn').addEventListener('click', () => doStart().catch((e) => alert(e.message)));
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

  document.addEventListener('DOMContentLoaded', () => {
    if (isPopup) initPopup();
    else if (isMain) initMain();
    else tryResume();
  });
})(typeof window !== 'undefined' ? window : this);
