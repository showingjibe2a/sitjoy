/**
 * 麻将：主控页 + 牌桌独立窗口（postMessage 同步）；SSE / 长轮询。
 */
(function (global) {
  'use strict';
  const win = global || window;
  const ROOM_KEY = 'sitjoy.mahjong.room.v1';
  const TABLE_POPUP_NAME = 'sitjoy_mj_table_popup';
  const MJ_POPUP_BOUNDS_KEY = 'mahjong';
  const MJ_POPUP_DEFAULTS = { width: 520, height: 680, minWidth: 380, minHeight: 420 };
  const MJ_JOIN_LOCAL_ORIGIN = 'http://192.168.5.203:233';
  const MJ_JOIN_CLOUD_ORIGIN = 'http://812165.xyz:233';

  // -------------------------------------------------------------------------
  // 模式检测与模块级状态
  // -------------------------------------------------------------------------
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
  let lastChatSeq = -1;
  let watchAbort = false;
  let watchCtrl = null;
  let eventSource = null;
  let useSse = true;
  let tablePopup = null;
  let popupOpen = false;
  let popupMonitorTimer = null;
  let popupBoundsSaver = null;
  let mjBoardOverlay = null;
  let pendingChiPick = null;
  let selectedDiscardIndex = null;
  let joinInFlight = false;
  let roomChat = null;
  let dealerRevealTimer = null;
  let dealerRevealDealNudged = false;
  let rulePresetSyncing = false;
  let activeJokerTiles = new Set();
  let lastJoinNoticeVersion = -1;
  let mjToastStack = null;

  const MJ_PRESET_HINTS = {
    standard: '136 张；可点炮/自摸；仅平胡；庄闲双倍，无连庄加倍。',
    hangzhou: '白板财神；仅自摸；暴头/财飘/双财飘、杠开/杠暴/杠飘加倍；连庄 2→4→8 倍。',
  };

  function hzPatternText(r) {
    if (!r || !r.hand_pattern_label) return '';
    let t = r.hand_pattern_label;
    if (Number(r.pattern_mult) > 1) t += ' ×' + r.pattern_mult;
    if (Number(r.dealer_mult) > 1) t += '（连庄 ×' + r.dealer_mult + '）';
    return t;
  }

  const $ = (id) => document.getElementById(id);

  // -------------------------------------------------------------------------
  // 庄家揭示轮询与状态归一化
  // -------------------------------------------------------------------------
  function clearDealerRevealPoll() {
    if (dealerRevealTimer) {
      win.clearTimeout(dealerRevealTimer);
      dealerRevealTimer = null;
    }
  }

  function resetDealerRevealNudge() {
    dealerRevealDealNudged = false;
  }

  /** 投骰定庄展示期 version 不变，需主动拉 state 更新倒计时并在到时发牌。 */
  function needsDealerRevealPoll(s) {
    if (!s || s.status !== 'dealer_roll') return false;
    const dr = s.dice_roll || {};
    return dr.all_done && (Number(dr.reveal_remaining) > 0 || !!dr.dealer_name);
  }

  function syncDealerRevealPoll(s) {
    if (!s || s.status !== 'dealer_roll') {
      resetDealerRevealNudge();
      clearDealerRevealPoll();
      return;
    }
    if (!needsDealerRevealPoll(s) || !roomCode || watchAbort) {
      clearDealerRevealPoll();
      return;
    }
    const remain = Number((s.dice_roll || {}).reveal_remaining) || 0;
    if (remain <= 0 && !dealerRevealDealNudged) {
      dealerRevealDealNudged = true;
      api('state', { room_code: roomCode }, 'GET')
        .then((data) => { if (data) applyState(data); })
        .catch(() => { dealerRevealDealNudged = false; });
      if (s.you_are_host) {
        doConfirmRoll()
          .then((data) => { if (data) applyState(data); })
          .catch(() => { dealerRevealDealNudged = false; });
      }
    }
    clearDealerRevealPoll();
    const delay = remain > 0 ? Math.min(900, Math.max(250, remain * 450)) : 400;
    dealerRevealTimer = win.setTimeout(() => {
      dealerRevealTimer = null;
      if (watchAbort || !roomCode) return;
      api('state', { room_code: roomCode }, 'GET')
        .then((data) => { if (data) applyState(data); })
        .catch(() => {});
    }, delay);
  }

  function resolveMySeat(s) {
    if (!s) return null;
    const uid = s.my_user_id;
    if (uid != null) {
      const seats = s.seats || [];
      for (let i = 0; i < seats.length; i++) {
        const st = seatAtIndex(seats, i);
        if (st && Number(st.user_id) === Number(uid)) return i;
      }
    }
    const direct = s.my_seat;
    if (direct != null && direct >= 0) return direct;
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

  // -------------------------------------------------------------------------
  // 牌桌中央浮层
  // -------------------------------------------------------------------------
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

  function appendMjReadyButtons(els, s, btn) {
    const lobby = s.lobby || {};
    const mySeat = resolveMySeat(s);
    const me = mySeat != null ? (s.seats || [])[mySeat] : null;
    if (mySeat != null) {
      els.actionsEl.appendChild(btn(
        me && me.ready ? '取消准备' : '准备',
        'btn-accent',
        () => { doReady().catch((err) => alert(err.message)); }
      ));
    }
    if (s.you_are_host && lobby.can_start && s.status !== 'hand_end') {
      els.actionsEl.appendChild(btn(
        '开局',
        'btn-accent',
        () => { doStart().catch((err) => alert(err.message)); }
      ));
    }
  }

  function appendMjReadyOverlay(els, s, esc, btn) {
    const dialog = mjOverlayDialogEl();
    if (dialog) dialog.classList.add('widget-board-dialog--wide');
    els.msgEl.innerHTML = renderMjLobbySeatsHtml(s, esc);
    appendMjReadyButtons(els, s, btn);
  }

  function renderSeatHandEndReveal(domIdx, logical, s) {
    const el = $('mjSeatReveal' + domIdx);
    if (!el) return;
    if (s.status !== 'hand_end' || logical < 0) {
      el.innerHTML = '';
      el.hidden = true;
      el.classList.add('pm-u-hidden');
      return;
    }
    const reveal = ((s.last_hand_result || {}).reveal_hands || {}).seats;
    const row = reveal && reveal.find((r) => r.seat === logical);
    if (!row) {
      el.innerHTML = '';
      el.hidden = true;
      el.classList.add('pm-u-hidden');
      return;
    }
    const winnerSeat = (s.last_hand_result || {}).winner_seat;
    const meldsHtml = (row.melds || []).map((m) => renderMeldHtml(m)).join('');
    const handHtml = (row.hand || []).map((t) => tileFaceHtml(t, 'mini')).join('');
    el.className = 'mj-seat-reveal' + (logical === winnerSeat ? ' mj-seat-reveal--winner' : '');
    el.innerHTML = '<div class="mj-seat-reveal-tiles">'
      + meldsHtml
      + (handHtml ? `<span class="mj-seat-reveal-hand">${handHtml}</span>` : '')
      + '</div>';
    el.hidden = false;
    el.classList.remove('pm-u-hidden');
  }

  function mjHandEndResultLine(s) {
    const r = s.last_hand_result || {};
    if (r.win_type === 'draw') return '流局';
    if (r.winner_seat == null) return '';
    const wn = ((s.seats || [])[r.winner_seat] || {}).name || '';
    let line = wn + ' 胡（' + (r.win_type === 'tsumo' ? '自摸' : '点炮') + '）';
    const pat = hzPatternText(r);
    if (pat) line += ' · ' + pat;
    else if (r.dealer_mult) line += ' · 连庄 ' + r.dealer_mult + ' 倍';
    if (r.win_type === 'tsumo' || r.win_type === 'ron') line += ' · 下局 ' + wn + ' 坐庄';
    return line;
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
      els.titleEl.textContent = '等待开局';
      appendMjReadyOverlay(els, s, esc, btn);
      return true;
    }

    if (s.status === 'hand_end') {
      const r = s.last_hand_result || {};
      els.titleEl.textContent = '本局结束';
      const resultLine = mjHandEndResultLine(s);
      const dealerHint = r.win_type === 'draw' ? '流局庄家顺延，无需掷骰' : '上局赢家坐庄，无需掷骰';
      let html = '';
      if (resultLine) html += `<p class="mj-overlay-result">${esc(resultLine)}</p>`;
      html += `<p class="mj-overlay-hint">${esc('全员准备后自动开始下一局 · ' + dealerHint)}</p>`;
      html += renderMjLobbySeatsHtml(s, esc);
      els.msgEl.innerHTML = html;
      appendMjReadyButtons(els, s, btn);
      return true;
    }

    if (s.status === 'dealer_roll') {
      const dr = s.dice_roll || {};
      const rolls = dr.rolls || [];
      els.titleEl.textContent = '投骰定庄';
      if (dialog) dialog.classList.add('widget-board-dialog--wide');
      const mySeat = resolveMySeat(s);
      const allDone = dr.all_done && rolls.length > 0 && rolls.every((r) => r.rolled);
      const winnerSeat = allDone && dr.dealer_seat != null ? Number(dr.dealer_seat) : null;
      let html = '<div class="mj-overlay-seats mj-lobby-seats mj-overlay-dice-seats">';
      rolls.forEach((r) => {
        const cls = ['mj-seat-dot', 'mj-seat-dot--filled'];
        if (r.rolled) cls.push('mj-seat-dot--ready');
        if (winnerSeat != null && r.seat === winnerSeat) cls.push('mj-seat-dot--dice-winner');
        if (r.seat === mySeat) cls.push('mj-seat-dot--me');
        const inner = r.rolled ? (r.dice1 + '+' + r.dice2 + '=' + r.total) : '?';
        html += `<div class="${cls.join(' ')}">`
          + `<div class="mj-seat-dot-inner mj-seat-dot-inner--dice">${esc(inner)}</div>`
          + `<span class="mj-seat-dot-name">${esc(r.name || '—')}</span>`
          + '</div>';
      });
      html += '</div>';
      const pending = rolls.filter((r) => !r.rolled).length;
      let hint = pending ? ('还有 ' + pending + ' 人未掷骰 · 点数最大者坐庄') : '';
      if (!pending && dr.dealer_name) {
        const remain = Math.ceil(Number(dr.reveal_remaining) || 0);
        hint = '庄家：' + dr.dealer_name + '（' + (dr.total || '?') + ' 点）';
        if (remain > 0) hint += ' · ' + remain + ' 秒后发牌…';
        else hint += ' · 正在发牌…';
      } else if (!pending) {
        hint = '全员已掷骰，正在定庄…';
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
    if (pendingChiPick) return;
    if (!mjBoardOverlay || mjBoardOverlay.hasConfirm()) return;
    mjBoardOverlay.refresh(s);
  }

  function isBoardOverlayActive(s) {
    if (!s || !lobbyInRoom(s)) return false;
    return s.status === 'lobby' || s.status === 'dealer_roll' || s.status === 'hand_end';
  }

  // -------------------------------------------------------------------------
  // URL 解析与 API
  // -------------------------------------------------------------------------
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

  // -------------------------------------------------------------------------
  // 牌面渲染
  // -------------------------------------------------------------------------
  function tileLabel(t) {
    if (!t) return '?';
    const suit = t[0];
    const n = t.slice(1);
    if (suit === 'w') return n + '万';
    if (suit === 'p') return n + '筒';
    if (suit === 's') return n + '条';
    const honor = { z1: '东', z2: '南', z3: '西', z4: '北', z5: '中', z6: '發', z7: '白' };
    return honor[t] || t;
  }

  function tileTipLabel(key) {
    const label = tileLabel(key);
    if (activeJokerTiles.has(key)) return label + '（癞子）';
    return label;
  }

  function tileTipAttr(label) {
    return ` data-mj-tip="${esc(label)}"`;
  }

  let mjTileTipEl = null;

  function ensureMjTileTipEl() {
    if (mjTileTipEl) return mjTileTipEl;
    mjTileTipEl = document.createElement('div');
    mjTileTipEl.className = 'mj-tile-tip-float';
    mjTileTipEl.setAttribute('role', 'tooltip');
    mjTileTipEl.hidden = true;
    document.body.appendChild(mjTileTipEl);
    return mjTileTipEl;
  }

  function showMjTileTip(tileEl) {
    const text = tileEl && tileEl.getAttribute('data-mj-tip');
    if (!text) {
      hideMjTileTip();
      return;
    }
    const tip = ensureMjTileTipEl();
    tip.textContent = text;
    tip.hidden = false;
    const rect = tileEl.getBoundingClientRect();
    tip.style.left = `${rect.left + rect.width / 2}px`;
    tip.style.top = `${rect.top - 6}px`;
    tip.style.transform = 'translate(-50%, -100%)';
    requestAnimationFrame(() => {
      if (tip.hidden) return;
      const tr = tip.getBoundingClientRect();
      if (tr.left < 4) tip.style.left = `${4 + tr.width / 2}px`;
      if (tr.right > window.innerWidth - 4) tip.style.left = `${window.innerWidth - 4 - tr.width / 2}px`;
      if (tr.top < 4) {
        tip.style.top = `${rect.bottom + 6}px`;
        tip.style.transform = 'translate(-50%, 0)';
      }
    });
  }

  function hideMjTileTip() {
    if (mjTileTipEl) mjTileTipEl.hidden = true;
  }

  function bindMjTileTips() {
    if (document.body.dataset.mjTileTipsBound) return;
    document.body.dataset.mjTileTipsBound = '1';
    document.addEventListener('mouseover', (e) => {
      const tile = e.target.closest && e.target.closest('.mj-tile[data-mj-tip]');
      if (tile) showMjTileTip(tile);
    });
    document.addEventListener('mouseout', (e) => {
      const from = e.target.closest && e.target.closest('.mj-tile[data-mj-tip]');
      if (!from) return;
      const to = e.relatedTarget;
      if (to && from.contains(to)) return;
      hideMjTileTip();
    });
    document.addEventListener('focusin', (e) => {
      const tile = e.target.closest && e.target.closest('.mj-tile[data-mj-tip]');
      if (tile) showMjTileTip(tile);
    });
    document.addEventListener('focusout', (e) => {
      const from = e.target.closest && e.target.closest('.mj-tile[data-mj-tip]');
      if (!from) return;
      const to = e.relatedTarget;
      if (to && from.contains(to)) return;
      hideMjTileTip();
    });
    window.addEventListener('scroll', hideMjTileTip, true);
  }

  const MAN_NUM = ['', '一', '二', '三', '四', '五', '六', '七', '八', '九'];
  function pinDotHtml(color, big) {
    return `<span class="mj-tile-pin-dot${big ? ' is-big' : ''}" data-color="${color || 'k'}"></span>`;
  }

  function pinDotSlotHtml(color, big) {
    return `<span class="mj-tile-pin-slot${big ? ' is-big' : ''}">${pinDotHtml(color, big)}</span>`;
  }

  function pinColHtml(colors) {
    return `<span class="mj-tile-pin-col" style="--pin-rows:${colors.length}">${colors.map((c) => pinDotSlotHtml(c)).join('')}</span>`;
  }

  function pinColsFaceHtml(rank, left, right) {
    return `<span class="mj-tile-face mj-tile-face--pin mj-tile-face--pin-cols" data-rank="${rank}">`
      + `<span class="mj-tile-pin-board"><span class="mj-tile-pin-cols">${pinColHtml(left)}${pinColHtml(right)}</span></span></span>`;
  }

  function pin7FaceHtml() {
    const d = (c) => pinDotSlotHtml(c);
    return `<span class="mj-tile-face mj-tile-face--pin mj-tile-face--pin7" data-rank="7">`
      + '<span class="mj-tile-pin-board"><span class="mj-tile-pin7">'
      + `<span class="mj-tile-pin-diag">${d('g')}${d('r')}${d('g')}</span>`
      + `<span class="mj-tile-pin-quad">${d('k')}${d('k')}${d('g')}${d('g')}</span>`
      + '</span></span></span>';
  }

  function pinGridHtml(rank, cells) {
    let grid = '';
    for (let i = 1; i <= 9; i++) {
      const d = cells[i];
      if (d) {
        grid += `<span class="mj-tile-pin-cell is-on${d.big ? ' is-big' : ''}">${pinDotSlotHtml(d.c, d.big)}</span>`;
      } else {
        grid += '<span class="mj-tile-pin-cell"></span>';
      }
    }
    return `<span class="mj-tile-face mj-tile-face--pin" data-rank="${rank}"><span class="mj-tile-pin-board"><span class="mj-tile-pin-grid">${grid}</span></span></span>`;
  }

  /** 筒子牌面（国标常见配色）：r红 g绿 k黑 */
  function pinFaceHtml(rank) {
    const G = 'g'; const R = 'r'; const K = 'k';
    if (rank === 1) {
      return pinGridHtml(1, { 5: { c: G, big: true } });
    }
    if (rank === 2) {
      return pinGridHtml(2, { 1: { c: G }, 9: { c: K } });
    }
    if (rank === 3) {
      return pinGridHtml(3, { 1: { c: G }, 5: { c: R }, 9: { c: G } });
    }
    if (rank === 4) {
      return pinGridHtml(4, { 1: { c: R }, 3: { c: G }, 7: { c: G }, 9: { c: R } });
    }
    if (rank === 5) {
      return pinGridHtml(5, { 1: { c: R }, 3: { c: G }, 5: { c: K }, 7: { c: G }, 9: { c: R } });
    }
    if (rank === 6) {
      return pinColsFaceHtml(6, [G, G, K], [K, G, G]);
    }
    if (rank === 7) {
      return pin7FaceHtml();
    }
    if (rank === 8) {
      return pinColsFaceHtml(8, [K, K, K, K], [K, K, K, K]);
    }
    if (rank === 9) {
      return pinGridHtml(9, {
        1: { c: R }, 2: { c: R }, 3: { c: R }, 4: { c: G }, 5: { c: G }, 6: { c: G }, 7: { c: K }, 8: { c: K }, 9: { c: K },
      });
    }
    return pinGridHtml(rank, {});
  }

  function souStickHtml(color) {
    return `<span class="mj-tile-sou-stick" data-color="${color || 'g'}"></span>`;
  }

  function souColHtml(count, color) {
    let sticks = '';
    for (let i = 0; i < count; i++) sticks += souStickHtml(color);
    return `<span class="mj-tile-sou-col" style="--sou-rows:${count}">${sticks}</span>`;
  }

  function souColsFaceHtml(rank, left, right) {
    return `<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou-cols" data-rank="${rank}">`
      + `<span class="mj-tile-sou-cols">${souColHtml(left, 'g')}${souColHtml(right, 'g')}</span></span>`;
  }

  function souSticksStackHtml(colors) {
    return `<span class="mj-tile-sou-stack">${colors.map((c) => souStickHtml(c)).join('')}</span>`;
  }

  function sou3TriHtml() {
    return '<span class="mj-tile-sou-tri">'
      + `<span class="mj-tile-sou-tri-top">${souStickHtml('r')}</span>`
      + `<span class="mj-tile-sou-tri-bottom">${souStickHtml('g')}${souStickHtml('g')}</span>`
      + '</span>';
  }

  function sou4BlockHtml() {
    const row = (a, b) => `<span class="mj-tile-sou-row">${souStickHtml(a)}${souStickHtml(b)}</span>`;
    return '<span class="mj-tile-sou-2x2">'
      + row('g', 'g')
      + row('g', 'g')
      + '</span>';
  }

  function souBirdHtml() {
    return '<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou1" data-rank="1">'
      + '<svg class="mj-tile-sou-bird-svg" viewBox="0 0 32 40" aria-hidden="true" focusable="false">'
      + '<rect x="12.5" y="24" width="7" height="14" rx="2" fill="#248040" stroke="#145028" stroke-width="0.8"/>'
      + '<ellipse cx="9" cy="28" rx="3.5" ry="7" fill="#32a858" transform="rotate(-18 9 28)"/>'
      + '<ellipse cx="23" cy="28" rx="3.5" ry="7" fill="#32a858" transform="rotate(18 23 28)"/>'
      + '<ellipse cx="16" cy="14" rx="9" ry="8" fill="#e02820"/>'
      + '<ellipse cx="20" cy="13" rx="7" ry="5" fill="#c01818" transform="rotate(-25 20 13)"/>'
      + '<circle cx="12.5" cy="11" r="5.5" fill="#e02820"/>'
      + '<circle cx="11" cy="10" r="1.3" fill="#101010"/>'
      + '<circle cx="11.4" cy="9.6" r="0.45" fill="#fff"/>'
      + '<path d="M7.5 10.5 L4 12 L7.5 12.5 Z" fill="#e8a020"/>'
      + '<path d="M8 6 Q10 3 12 5 Q14 3 16 6 Q14 8 12 7 Q10 8 8 6" fill="#288848"/>'
      + '<path d="M22 16 Q26 18 24 22 Q20 20 22 16" fill="#208838"/>'
      + '<path d="M10 16 Q6 18 8 22 Q12 20 10 16" fill="#208838"/>'
      + '</svg></span>';
  }

  function souGridHtml(rank, cells) {
    let grid = '';
    for (let i = 1; i <= 9; i++) {
      const c = cells[i];
      if (c) grid += `<span class="mj-tile-sou-cell is-on">${souStickHtml(c)}</span>`;
      else grid += '<span class="mj-tile-sou-cell"></span>';
    }
    return `<span class="mj-tile-face mj-tile-face--sou" data-rank="${rank}"><span class="mj-tile-sou-grid">${grid}</span></span>`;
  }

  /** 条子牌面：仅 3/5/7/9 含红条（3 顶红、5/9 中心红、7 顶红） */
  function souFaceHtml(rank) {
    const G = 'g'; const R = 'r';
    if (rank === 1) return souBirdHtml();
    if (rank === 2) {
      return `<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou2" data-rank="2">${souSticksStackHtml([G, G])}</span>`;
    }
    if (rank === 3) {
      return `<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou3" data-rank="3">${sou3TriHtml()}</span>`;
    }
    if (rank === 4) {
      return `<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou4" data-rank="4">${sou4BlockHtml()}</span>`;
    }
    if (rank === 5) {
      return souGridHtml(5, { 1: G, 3: G, 5: R, 7: G, 9: G });
    }
    if (rank === 6) {
      return souColsFaceHtml(6, 3, 3);
    }
    if (rank === 7) {
      return `<span class="mj-tile-face mj-tile-face--sou mj-tile-face--sou7" data-rank="7">`
        + `<span class="mj-tile-sou7-top">${souStickHtml(R)}</span>`
        + `<span class="mj-tile-sou7-rows">`
        + `<span class="mj-tile-sou-row">${souStickHtml(G)}${souStickHtml(G)}${souStickHtml(G)}</span>`
        + `<span class="mj-tile-sou-row">${souStickHtml(G)}${souStickHtml(G)}${souStickHtml(G)}</span>`
        + '</span></span>';
    }
    if (rank === 8) {
      return souColsFaceHtml(8, 4, 4);
    }
    if (rank === 9) {
      return souGridHtml(9, {
        1: G, 2: G, 3: G, 4: G, 5: R, 6: G, 7: G, 8: G, 9: G,
      });
    }
    return souGridHtml(rank, {});
  }

  const HONOR_CHAR = { z1: '东', z2: '南', z3: '西', z4: '北', z5: '中', z6: '發', z7: '' };

  function manFaceHtml(rank) {
    return `<span class="mj-tile-face mj-tile-face--man" data-rank="${rank}">`
      + `<span class="mj-tile-man-num">${MAN_NUM[rank] || rank}</span>`
      + '<span class="mj-tile-man-suit">萬</span></span>';
  }

  function honorFaceHtml(key) {
    const ch = HONOR_CHAR[key] || '?';
    return `<span class="mj-tile-face mj-tile-face--honor mj-tile-face--${esc(key)}">`
      + (ch ? `<span class="mj-tile-honor-glyph">${esc(ch)}</span>` : '')
      + '</span>';
  }

  function tileInnerHtmlForTile(key) {
    const k = String(key || '').trim();
    const suit = k[0];
    const rank = parseInt(k.slice(1), 10);
    let face;
    if (suit === 'w' && rank >= 1 && rank <= 9) face = manFaceHtml(rank);
    else if (suit === 'p' && rank >= 1 && rank <= 9) face = pinFaceHtml(rank);
    else if (suit === 's' && rank >= 1 && rank <= 9) face = souFaceHtml(rank);
    else if (/^z[1-7]$/.test(k)) face = honorFaceHtml(k);
    else face = '<span class="mj-tile-face mj-tile-face--unknown">?</span>';
    return `<span class="mj-tile-glyph-wrap">${face}</span>`;
  }

  function tileKindClasses(t) {
    const key = String(t || '').trim();
    if (key.startsWith('w')) return ['mj-tile--man'];
    if (key.startsWith('p')) return ['mj-tile--pin'];
    if (key.startsWith('s')) return ['mj-tile--sou'];
    if (key === 'z7') return ['mj-tile--honor', 'mj-tile--bai'];
    if (key === 'z5') return ['mj-tile--honor', 'mj-tile--zhong'];
    if (key === 'z6') return ['mj-tile--honor', 'mj-tile--fa'];
    if (/^z[1-4]$/.test(key)) return ['mj-tile--honor', 'mj-tile--wind'];
    if (key.startsWith('z')) return ['mj-tile--honor'];
    return ['mj-tile--unknown'];
  }

  function tileFaceHtml(t, variant, mark) {
    const key = String(t || '').trim();
    const label = tileLabel(key);
    const cls = ['mj-tile'].concat(tileKindClasses(key));
    if (activeJokerTiles.has(key)) cls.push('mj-tile--joker');
    if (variant === 'mini' || variant === 'table') cls.push('mj-tile--table');
    if (variant === 'hand') cls.push('mj-tile--hand');
    if (variant === 'meld') cls.push('mj-tile--table', 'mj-tile--meld');
    if (mark === 'last-discard') cls.push('mj-tile--last-discard');
    if (mark === 'drawn') cls.push('mj-tile--drawn');
    if (mark === 'called') cls.push('mj-tile--called');
    return `<span class="${cls.join(' ')}" role="img" aria-label="${esc(label)}" data-tile="${esc(key)}"${tileTipAttr(tileTipLabel(key))}>`
      + tileInnerHtmlForTile(key)
      + '</span>';
  }

  function tileHandButtonHtml(t, canDiscard, mark, selected, handIdx) {
    const key = String(t || '').trim();
    const label = tileLabel(key);
    const cls = ['mj-tile', 'mj-tile--hand'].concat(tileKindClasses(key));
    if (activeJokerTiles.has(key)) cls.push('mj-tile--joker');
    if (canDiscard) cls.push('mj-tile--clickable');
    if (mark === 'drawn') cls.push('mj-tile--drawn');
    if (selected) cls.push('mj-tile--selected');
    const inner = tileInnerHtmlForTile(key);
    const tip = tileTipLabel(key);
    const idxAttr = canDiscard && handIdx != null ? ` data-hand-idx="${handIdx}"` : '';
    const attrs = ` class="${cls.join(' ')}" aria-label="${esc(label)}" data-tile="${esc(key)}"${tileTipAttr(tip)}${idxAttr}`;
    if (canDiscard) {
      const pressed = selected ? ' aria-pressed="true"' : ' aria-pressed="false"';
      return `<span role="button" tabindex="0"${attrs}${pressed} data-select="1">${inner}</span>`;
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

  // -------------------------------------------------------------------------
  // 房间聊天
  // -------------------------------------------------------------------------
  function initRoomChat() {
    if (roomChat || !win.WidgetRoom) return roomChat;
    const root = $('mjRoomChat');
    if (!root) return null;
    roomChat = win.WidgetRoom.createChat({
      root,
      layout: isPopup ? 'side' : 'below',
      isActive: () => lobbyInRoom(state),
      onSend: (text) => api('chat_send', { room_code: roomCode, text }).then((data) => {
        applyChatOnly(data);
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

  function copyTextToClipboard(text) {
    const value = String(text || '');
    if (!value) return Promise.resolve(false);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value).then(() => true).catch(() => false);
    }
    const ta = document.createElement('textarea');
    ta.value = value;
    ta.setAttribute('readonly', 'readonly');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    ta.style.pointerEvents = 'none';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try {
      ok = !!document.execCommand('copy');
    } catch (_) {
      ok = false;
    }
    if (ta.parentNode) ta.parentNode.removeChild(ta);
    return Promise.resolve(ok);
  }

  function buildMjRoomJoinUrl(origin, code) {
    const base = String(origin || '').replace(/\/$/, '');
    const c = encodeURIComponent(String(code || '').trim().toUpperCase());
    return `${base}/widgets/mahjong?room=${c}`;
  }

  function buildMjRoomShareText(code) {
    const c = String(code || roomCode || '').trim().toUpperCase();
    if (!c) return '';
    return [
      `网址（本地直接加入）：${buildMjRoomJoinUrl(MJ_JOIN_LOCAL_ORIGIN, c)}`,
      `网址（云端直接加入）：${buildMjRoomJoinUrl(MJ_JOIN_CLOUD_ORIGIN, c)}`,
      `房间号：${c}`,
    ].join('\n');
  }

  async function copyMjRoomShare() {
    const text = buildMjRoomShareText();
    if (!text) return;
    const ok = await copyTextToClipboard(text);
    mjToast(ok ? '已复制加入链接与房间号' : '复制失败', !ok);
    const btn = $('mjRoomCopyBtn');
    if (btn && ok) {
      const prev = btn.textContent;
      btn.textContent = '已复制';
      win.setTimeout(() => { btn.textContent = prev; }, 1200);
    }
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
    if (popupBoundsSaver) {
      popupBoundsSaver.save();
      popupBoundsSaver.stop();
      popupBoundsSaver = null;
    }
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
    const popupApi = win.SitjoyWidgetPopup;
    if (popupApi) {
      tablePopup = popupApi.openWithRememberedBounds(MJ_POPUP_BOUNDS_KEY, url, TABLE_POPUP_NAME, MJ_POPUP_DEFAULTS);
    } else {
      tablePopup = win.open(url, TABLE_POPUP_NAME, 'popup=yes,width=520,height=680,resizable=yes,scrollbars=no');
    }
    if (!tablePopup) {
      alert('无法打开新窗口：请允许本站「弹出式窗口」后重试');
      return false;
    }
    if (popupApi) {
      popupBoundsSaver = popupApi.attachBoundsSaver(MJ_POPUP_BOUNDS_KEY, tablePopup, MJ_POPUP_DEFAULTS);
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
    if (s.status === 'lobby') {
      const east = Number(s.east_seat);
      return Number.isFinite(east) && east >= 0 && east < 4 ? east : 0;
    }
    const ds = Number(s.dealer_seat);
    if (Number.isFinite(ds) && ds >= 0 && ds < 4) return ds;
    return resolveHostSeat(s);
  }

  function windLabelForSeat(seatIdx, anchorSeat) {
    const labels = ['东', '南', '西', '北'];
    if (anchorSeat == null) return labels[seatIdx] || '—';
    return labels[(seatIdx - anchorSeat + 4) % 4];
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
    const inGame = s && s.status && s.status !== 'lobby' && s.status !== 'hand_end';
    if (inGame) return '确定离开房间？对局将继续（本局按缺席处理）。';
    return '确定离开房间？';
  }

  function updateLeaveButtons(s) {
    const mainBtn = $('mjLeaveBtn');
    const inRoom = lobbyInRoom(s);
    if (mainBtn) mainBtn.textContent = '离开房间';
    setVisible(mainBtn, inRoom && !isPopup);
  }

  // -------------------------------------------------------------------------
  // 房间侧栏 UI
  // -------------------------------------------------------------------------
  function renderRoomSidebar(s) {
    if (!s) return;
    const codeEl = $('mjRoomCode');
    if (codeEl) codeEl.textContent = s.code || '------';
    const copyBtn = $('mjRoomCopyBtn');
    const inRoom = lobbyInRoom(s);
    if (copyBtn) copyBtn.classList.toggle('pm-u-hidden', !inRoom);
    const ruleEl = $('mjSideRuleLine');
    const inLobby = inRoom && s.status === 'lobby';
    if (ruleEl) {
      if (inRoom && !inLobby && (s.rule_summary || s.rule_label)) {
        ruleEl.textContent = s.rule_summary || ('规则：' + s.rule_label);
        ruleEl.classList.remove('pm-u-hidden');
      } else {
        ruleEl.classList.add('pm-u-hidden');
        ruleEl.textContent = '';
      }
    }
    const streakEl = $('mjSideStreakLine');
    if (streakEl) {
      if (s.rule_preset === 'hangzhou' && s.dealer_mult) {
        const streak = Number(s.dealer_streak) || 0;
        const labels = ['一庄（2倍）', '二连庄（4倍）', '三连庄（8倍）'];
        streakEl.textContent = '本局计分：' + (labels[Math.min(streak, 2)] || labels[0]);
        streakEl.classList.remove('pm-u-hidden');
      } else {
        streakEl.classList.add('pm-u-hidden');
        streakEl.textContent = '';
      }
    }
    syncRulePresetUi(s);
    const panel = $('mjRoomPanel');
    if (panel) panel.classList.toggle('pm-u-hidden', !inRoom);
  }

  function syncRulePresetUi(s) {
    const notice = $('mjRuleNotice');
    const sel = $('mjRulePreset');
    const hint = $('mjRulePresetHint');
    const inRoom = s && lobbyInRoom(s);
    const inLobby = inRoom && s.status === 'lobby';
    if (notice) notice.classList.toggle('pm-u-hidden', !inLobby);
    if (!sel) return;
    const preset = (s && s.rule_preset) || 'standard';
    rulePresetSyncing = true;
    sel.value = preset;
    rulePresetSyncing = false;
    if (hint) {
      const tip = (s && s.rule_summary)
        || MJ_PRESET_HINTS[preset]
        || MJ_PRESET_HINTS.standard;
      hint.setAttribute('data-tip', tip);
    }
    sel.disabled = !(inLobby && s && s.you_are_host);
  }

  function clearRoomUi(hint) {
    stopWatch();
    clearDealerRevealPoll();
    resetDealerRevealNudge();
    closeTableWindow();
    roomCode = '';
    saveRoomCode('');
    state = null;
    lastVersion = -1;
    lastChatSeq = -1;
    lastJoinNoticeVersion = -1;
    selectedDiscardIndex = null;
    if (!isPopup) postStateToPopup();
    setVisible($('mjLeaveBtn'), false);
    if (!isPopup) {
      setVisible($('mjBoardCard'), true);
      setVisible($('mjTableLayout'), false);
      setVisible($('mjTablePlaceholder'), true);
    } else {
      setVisible($('mjBoardCard'), false);
    }
    $('mjRoomPanel') && $('mjRoomPanel').classList.add('pm-u-hidden');
    const ruleNotice = $('mjRuleNotice');
    if (ruleNotice) ruleNotice.classList.add('pm-u-hidden');
    const copyBtn = $('mjRoomCopyBtn');
    if (copyBtn) copyBtn.classList.add('pm-u-hidden');
    if (roomChat) roomChat.setVisible(false);
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

    const viewLogical = logicalSeatForDomSlot(domIdx, s);
    const seatLogical = viewLogical >= 0 ? viewLogical : logical;

    clearPlayerAvatarVisuals(img, fallback, plus);
    const st = seatLogical >= 0 ? seatAtIndex(s.seats, seatLogical) : null;
    const mySeat = resolveMySeat(s);
    const empty = !st;
    const canSwap = !!s.can_swap_seat && mySeat != null && empty && seatLogical >= 0 && seatLogical !== mySeat;

    badge.classList.toggle('is-empty', empty);
    badge.classList.toggle('is-me', !empty && mySeat === seatLogical);
    badge.classList.toggle('is-dealer', !empty && s.dealer_seat === seatLogical);
    badge.classList.toggle('is-actionable', canSwap);
    badge.tabIndex = canSwap ? 0 : -1;
    badge.setAttribute('aria-disabled', canSwap ? 'false' : 'true');
    if (seatLogical >= 0) badge.dataset.logicalSeat = String(seatLogical);
    else delete badge.dataset.logicalSeat;

    if (empty) {
      const wind = renderSeatWind(windEl, seatLogical, s);
      nameEl.textContent = '空位';
      renderPlayerRole(roleEl, false, false);
      if (metaEl) metaEl.textContent = canSwap ? '点击换座' : '';
      if (scoreEl) scoreEl.textContent = '';
      renderSeatHandEndReveal(domIdx, seatLogical, s);
      plus?.classList.remove('pm-u-hidden');
      badge.setAttribute('aria-label', canSwap ? (wind ? `点击换到${wind}位` : '点击换到此空位') : (wind ? `${wind}位空位` : '空位'));
      return;
    }

    const name = st.name || '—';
    const wind = renderSeatWind(windEl, seatLogical, s);
    nameEl.textContent = name;
    const isDealer = s.dealer_seat === seatLogical;
    renderPlayerRole(roleEl, isDealer, s.status !== 'lobby');
    const meta = [];
    if (st.waits_next_hand && (s.status === 'playing' || s.status === 'dealer_roll')) meta.push('下局加入');
    if (s.current_seat === seatLogical && s.status === 'playing') meta.push('出牌');
    if (st.ready && (s.status === 'lobby' || s.status === 'hand_end')) meta.push('已准备');
    if (metaEl) metaEl.textContent = meta.join(' · ');
    if (scoreEl) {
      const sc = seatScoreValue(s, seatLogical);
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
    renderSeatHandEndReveal(domIdx, seatLogical, s);
  }

  function tileConcealedHtml(variant) {
    const cls = ['mj-tile', 'mj-tile--concealed'];
    if (variant === 'mini' || variant === 'table' || variant === 'meld') cls.push('mj-tile--table', 'mj-tile--meld');
    return `<span class="${cls.join(' ')}" role="img" aria-label="暗杠"${tileTipAttr('暗杠')}></span>`;
  }

  function meldTitle(m) {
    const t = m.type || '';
    if (t === 'kong') {
      if (m.kong_kind === 'concealed' || m.tiles_hidden) return '暗杠';
      if (m.kong_kind === 'added') return '明杠（补）';
      return '明杠';
    }
    if (t === 'pung') return '碰';
    if (t === 'chi') return '吃';
    return t;
  }

  function renderMeldHtml(m) {
    if (m.tiles_hidden) {
      const n = Number(m.tile_count) || 4;
      let html = '<span class="mj-meld-set mj-meld-set--concealed" title="' + esc(meldTitle(m)) + '">';
      for (let i = 0; i < n; i++) html += tileConcealedHtml('meld');
      html += '</span>';
      return html;
    }
    const tiles = m.tiles || [];
    const called = m.called_tile || null;
    return '<span class="mj-meld-set" title="' + esc(meldTitle(m)) + '">'
      + tiles.map((t) => tileFaceHtml(t, 'meld', called && t === called ? 'called' : null)).join('')
      + '</span>';
  }

  function meldsElForSeat(seatIdx) {
    let el = $('mjBadgeMelds' + seatIdx);
    if (el) return el;
    el = $('mjMelds' + seatIdx);
    if (el) {
      el.classList.add('mj-badge-melds');
      return el;
    }
    const badge = $('mjPlayerBadge' + seatIdx);
    if (!badge) return null;
    const side = badge.querySelector('.mj-player-side') || badge;
    el = document.createElement('div');
    el.className = 'mj-badge-melds';
    el.id = 'mjBadgeMelds' + seatIdx;
    el.setAttribute('aria-label', '副露');
    side.appendChild(el);
    return el;
  }

  // -------------------------------------------------------------------------
  // 座位、河牌与副露
  // -------------------------------------------------------------------------
  function renderSeat(seatIdx, s) {
    const logical = s._view_seat != null ? s._view_seat : seatIdx;
    renderPlayerBadge(seatIdx, s, logical);
    const riverEl = $('mjRiver' + seatIdx);
    const meldsEl = meldsElForSeat(seatIdx);
    const st = logical >= 0 ? seatAtIndex(s.seats, logical) : null;
    if (!st) {
      if (riverEl) riverEl.innerHTML = '';
      if (meldsEl) meldsEl.innerHTML = '';
      renderSeatHandEndReveal(seatIdx, logical, s);
      return;
    }
    const river = (s.discards || [])[logical] || [];
    const lastDisc = s.last_discard;
    if (riverEl) {
      riverEl.innerHTML = river.map((t, i) => {
        const isLast = lastDisc
          && Number(lastDisc.seat) === logical
          && i === river.length - 1
          && t === lastDisc.tile;
        return tileFaceHtml(t, 'mini', isLast ? 'last-discard' : null);
      }).join('');
    }
    const melds = (s.melds || [])[logical] || [];
    if (meldsEl) {
      meldsEl.innerHTML = melds.map((m) => renderMeldHtml(m)).join('');
    }
  }

  function syncHandTileLayout(handEl) {
    if (!handEl) return;
    const stripEl = handEl.closest('.mj-hand-strip');
    const n = handEl.querySelectorAll('.mj-tile--hand').length;
    handEl.style.setProperty('--mj-hand-count', String(Math.max(n, 1)));
    let w = handEl.clientWidth;
    if (stripEl && stripEl.clientWidth > 0) w = stripEl.clientWidth;
    if (n > 0 && w > 0) {
      const layout = handEl.closest('.mj-table-layout');
      const scaleRaw = layout && getComputedStyle(layout).getPropertyValue('--mj-ui-scale');
      const scale = scaleRaw ? parseFloat(scaleRaw) || 1 : 1;
      const rootPx = parseFloat(getComputedStyle(document.documentElement).fontSize) || 16;
      const maxPx = 3.1 * rootPx * scale;
      const gapPx = Math.max(2, Math.round(w * 0.008));
      const perTile = Math.min(maxPx, (w - gapPx * Math.max(n - 1, 0)) / Math.max(n, 1));
      handEl.style.setProperty('--mj-hand-tile-size', perTile + 'px');
      handEl.style.setProperty('--mj-hand-gap', gapPx + 'px');
      handEl.style.setProperty('--mj-tile-pack', '0px');
    }
  }

  const MJ_LAYOUT_REF_W = 500;
  const MJ_LAYOUT_REF_H = 640;

  function syncMjLayoutScale() {
    const layout = document.querySelector('.mj-table-layout');
    if (!layout) return;
    const wrap = layout.closest('.mj-table-wrap');
    const w = layout.clientWidth || MJ_LAYOUT_REF_W;
    let scale = Math.max(0.58, Math.min(1, w / MJ_LAYOUT_REF_W));
    if (isPopup) {
      const vh = win.innerHeight || document.documentElement.clientHeight || MJ_LAYOUT_REF_H;
      const hScale = Math.max(0.48, Math.min(1, (vh - 12) / MJ_LAYOUT_REF_H));
      scale = Math.min(scale, hScale);
    }
    layout.style.setProperty('--mj-ui-scale', scale.toFixed(3));
    const table = layout.querySelector('.mj-table');
    if (table) {
      const tw = table.clientWidth;
      const th = table.clientHeight;
      let tileRem = 1.52;
      if (tw > 0) {
        tileRem = Math.max(0.88, Math.min(1.52, (tw / 290) * 1.52));
      }
      let maxRiver = 0;
      for (let i = 0; i < 4; i++) {
        const el = document.getElementById('mjRiver' + i);
        if (el) maxRiver = Math.max(maxRiver, el.querySelectorAll('.mj-tile--table').length);
      }
      if (maxRiver > 5) {
        tileRem = Math.max(0.72, tileRem * Math.max(0.75, 1 - (maxRiver - 5) * 0.045));
      }
      table.style.setProperty('--mj-table-tile-size', tileRem.toFixed(3) + 'rem');
      if (th > 0) {
        table.style.setProperty('--mj-side-river-max-h', Math.round(th * 0.4) + 'px');
      }
    }
    syncHandTileLayout($('mjMyHand'));
  }

  let layoutScaleBound = false;
  function ensureLayoutScaleSync() {
    if (layoutScaleBound) return;
    const layout = document.querySelector('.mj-table-layout');
    if (!layout) return;
    layoutScaleBound = true;
    const ro = typeof ResizeObserver !== 'undefined'
      ? new ResizeObserver(() => syncMjLayoutScale())
      : null;
    if (ro) {
      ro.observe(layout);
      const wrap = layout.closest('.mj-table-wrap');
      if (wrap) ro.observe(wrap);
      const stage = layout.closest('.mj-play-popup-stage');
      if (stage) ro.observe(stage);
    }
    window.addEventListener('resize', syncMjLayoutScale);
    syncMjLayoutScale();
  }

  let handLayoutBound = false;
  function ensureHandLayoutSync() {
    if (handLayoutBound) return;
    handLayoutBound = true;
    window.addEventListener('resize', () => {
      syncMjLayoutScale();
    });
  }

  function syncDiscardSelection(s) {
    const hand = (s && s.my_hand) || [];
    if (selectedDiscardIndex == null || selectedDiscardIndex < 0 || selectedDiscardIndex >= hand.length) {
      selectedDiscardIndex = null;
    }
  }

  // -------------------------------------------------------------------------
  // 手牌
  // -------------------------------------------------------------------------
  function renderHand(s) {
    const handEl = $('mjMyHand');
    const stripEl = handEl && handEl.closest('.mj-hand-strip');
    if (!handEl) return;
    ensureHandLayoutSync();
    if (s.status === 'dealer_roll' || s.status === 'lobby' || s.status === 'hand_end') {
      handEl.innerHTML = '';
      selectedDiscardIndex = null;
      if (stripEl) stripEl.classList.add('pm-u-hidden');
      return;
    }
    const hand = s.my_hand || [];
    const mySeat = resolveMySeat(s);
    const canDiscard = s.status === 'playing'
      && s.phase === 'discard'
      && Number(s.current_seat) === Number(mySeat);
    syncDiscardSelection(s);
    if (!canDiscard) selectedDiscardIndex = null;
    const dt = s.drawn_tile;
    const drawnTile = (dt && Number(dt.seat) === mySeat) ? dt.tile : null;
    let drawnIdx = -1;
    if (drawnTile) {
      for (let i = hand.length - 1; i >= 0; i--) {
        if (hand[i] === drawnTile) { drawnIdx = i; break; }
      }
    }
    if (stripEl) stripEl.classList.toggle('pm-u-hidden', !hand.length);
    handEl.innerHTML = hand.map((t, i) =>
      tileHandButtonHtml(t, canDiscard, i === drawnIdx ? 'drawn' : null, canDiscard && i === selectedDiscardIndex, i)
    ).join('');
    handEl.querySelectorAll('.mj-tile--hand.mj-tile--clickable').forEach((tileEl) => {
      const toggle = () => {
        if (!canDiscard) return;
        const idx = Number(tileEl.getAttribute('data-hand-idx'));
        if (!Number.isFinite(idx)) return;
        selectedDiscardIndex = selectedDiscardIndex === idx ? null : idx;
        renderHand(s);
        renderHandActions(s);
      };
      tileEl.addEventListener('click', toggle);
      tileEl.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          toggle();
        }
      });
    });
    syncHandTileLayout(handEl);
    window.requestAnimationFrame(() => {
      syncMjLayoutScale();
      syncHandTileLayout(handEl);
    });
  }

  function sortedWinOptions(opts) {
    return (opts || []).slice().sort((a, b) => {
      const ma = Number(a.sort_mult != null ? a.sort_mult : (a.pattern_mult || 1) * (a.dealer_mult || 1));
      const mb = Number(b.sort_mult != null ? b.sort_mult : (b.pattern_mult || 1) * (b.dealer_mult || 1));
      return mb - ma;
    });
  }

  function currentWinOptions() {
    if (!state) return [];
    const cr = state.claim_round;
    if (cr && cr.need_response && (cr.options || []).includes('win')) {
      return sortedWinOptions(cr.win_options || []);
    }
    if (state.self_win_options && state.self_win_options.length) {
      return sortedWinOptions(state.self_win_options);
    }
    return [];
  }

  function winActionLabel(opts) {
    if (!opts || !opts.length) return '胡';
    const wt = opts[0].win_type || 'tsumo';
    if (wt === 'tsumo') return '自摸胡';
    return '胡';
  }

  function compactWinLabel(wo) {
    if (!wo) return '胡';
    let t = wo.pattern_label || '平胡';
    const pm = Number(wo.pattern_mult) || 1;
    const dm = Number(wo.dealer_mult) || 1;
    if (pm > 1) t += '×' + pm;
    if (dm > 1) t += '·庄×' + dm;
    return t;
  }

  function pushWinButtons(list, winOpts) {
    const opts = sortedWinOptions(winOpts);
    if (!opts.length) {
      list.push({ type: 'win', label: '自摸胡', style: 'win' });
      return;
    }
    if (opts.length === 1) {
      list.push({
        type: 'win',
        label: winActionLabel(opts),
        style: 'win',
        pattern_code: opts[0].pattern_code,
      });
      return;
    }
    opts.forEach((wo) => {
      list.push({
        type: 'win',
        label: compactWinLabel(wo),
        style: 'win',
        pattern_code: wo.pattern_code,
        compact: true,
      });
    });
  }

  function showChiChoiceOverlay(chiOptions) {
    initMjBoardOverlay();
    if (!mjBoardOverlay) return;
    pendingChiPick = chiOptions;
    const els = mjBoardOverlay.elements;
    if (!els) return;
    els.actionsEl.innerHTML = '';
    els.titleEl.textContent = '选择吃的组合';
    els.msgEl.innerHTML = '<div class="mj-chi-picker">'
      + chiOptions.map((tiles, idx) =>
        '<button type="button" class="mj-chi-pick-btn" data-chi-idx="' + idx + '">'
        + tiles.map((t) => tileFaceHtml(t, 'meld')).join('')
        + '</button>'
      ).join('')
      + '</div>';
    els.actionsEl.appendChild(mjBoardOverlay.makeActionButton('取消', 'btn-secondary', () => {
      pendingChiPick = null;
      mjBoardOverlay.refresh(state);
    }));
    els.overlay.classList.remove('pm-u-hidden');
    els.overlay.removeAttribute('hidden');
    els.msgEl.querySelectorAll('.mj-chi-pick-btn').forEach((btn) => {
      btn.addEventListener('click', () => {
        const idx = Number(btn.getAttribute('data-chi-idx'));
        const pick = chiOptions[idx];
        pendingChiPick = null;
        mjBoardOverlay.refresh(state);
        if (pick) doClaim('chi', pick).catch((err) => alert(err.message));
      });
    });
  }

  function hideActionPickerIfIdle() {
    if (pendingChiPick || !mjBoardOverlay) return;
    if (!mjBoardOverlay.hasConfirm() && !isBoardOverlayActive(state)) {
      mjBoardOverlay.refresh(state);
    }
  }

  function onClaimClick(type) {
    if (type === 'win') {
      const winOpts = currentWinOptions();
      if (winOpts.length === 1) {
        doClaim('win', null, winOpts[0].pattern_code || null).catch((err) => alert(err.message));
        return;
      }
      if (state && state.pending_self_win) {
        doClaim('win').catch((err) => alert(err.message));
        return;
      }
    }
    if (type === 'chi') {
      const cr = state && state.claim_round;
      const opts = (cr && cr.chi_options) || [];
      if (opts.length > 1) {
        showChiChoiceOverlay(opts);
        return;
      }
      if (opts.length === 1) {
        doClaim('chi', opts[0]).catch((err) => alert(err.message));
        return;
      }
    }
    doClaim(type).catch((err) => alert(err.message));
  }

  function renderHandActions(s) {
    const handWrap = $('mjHandActions');
    const handBtns = $('mjHandActionBtns');
    const legacyWrap = $('mjActions');
    const legacyBtns = $('mjActionBtns');
    const useLegacy = !handWrap || !handBtns;
    const wrap = useLegacy ? legacyWrap : handWrap;
    const btns = useLegacy ? legacyBtns : handBtns;
    if (legacyWrap && !useLegacy) setVisible(legacyWrap, false);
    if (!wrap || !btns) return;

    const mySeat = resolveMySeat(s);
    const canDiscard = s.status === 'playing'
      && s.phase === 'discard'
      && Number(s.current_seat) === Number(mySeat);
    syncDiscardSelection(s);

    const list = [];
    const cr = s.claim_round;
    if (cr && cr.need_response && (cr.options || []).length) {
      const order = ['win', 'pung', 'kong', 'chi', 'pass'];
      const opts = (cr.options || []).slice().sort((a, b) => {
        const ia = order.indexOf(a);
        const ib = order.indexOf(b);
        return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
      });
      const winOpts = cr.win_options || [];
      opts.forEach((opt) => {
        if (opt === 'win') {
          pushWinButtons(list, winOpts);
          return;
        }
        const labels = { pung: '碰', kong: '杠', chi: '吃', pass: '过' };
        const style = 'claim';
        list.push({ type: opt, label: labels[opt] || opt, style });
      });
    }
    if (canDiscard && !(cr && cr.need_response)) {
      const winOpts = s.self_win_options || [];
      if (winOpts.length || s.pending_self_win) {
        pushWinButtons(list, winOpts);
      }
      const sk = s.self_kong || {};
      (sk.concealed || []).forEach((tile) => {
        list.push({
          type: 'self_kong',
          kind: 'concealed',
          tile,
          label: '暗杠',
          style: 'claim',
        });
      });
      (sk.added || []).forEach((tile) => {
        list.push({
          type: 'self_kong',
          kind: 'added',
          tile,
          label: '明杠',
          style: 'claim',
        });
      });
      list.push({
        type: 'discard',
        label: '出牌',
        style: 'primary',
        disabled: selectedDiscardIndex == null,
      });
    }

    if (!list.length) {
      setVisible(wrap, false);
      wrap.classList.remove('is-active');
      btns.innerHTML = '';
      hideActionPickerIfIdle();
      return;
    }

    setVisible(wrap, true);
    wrap.classList.add('is-active');
    btns.innerHTML = list.map((a) => {
      const cls = ['mj-hand-action-btn'];
      if (a.style === 'primary') cls.push('mj-hand-action-btn--primary');
      else if (a.style === 'win') cls.push('mj-hand-action-btn--win');
      else if (a.style === 'claim') cls.push('mj-hand-action-btn--claim');
      if (a.compact) cls.push('mj-hand-action-btn--compact');
      const dis = a.disabled ? ' disabled' : '';
      const action = a.type === 'discard' ? 'discard' : a.type;
      const tileAttr = a.tile ? ` data-tile="${esc(a.tile)}"` : '';
      const kindAttr = a.kind ? ` data-kong-kind="${esc(a.kind)}"` : '';
      const patAttr = a.pattern_code ? ` data-pattern-code="${esc(a.pattern_code)}"` : '';
      return `<button type="button" class="${cls.join(' ')}" data-hand-action="${esc(action)}"${tileAttr}${kindAttr}${patAttr}${dis}>${esc(a.label)}</button>`;
    }).join('');

    btns.querySelectorAll('[data-hand-action]').forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.disabled) return;
        const t = btn.getAttribute('data-hand-action');
        if (t === 'discard') {
          if (selectedDiscardIndex == null) return;
          const hand = (state && state.my_hand) || [];
          const tile = hand[selectedDiscardIndex];
          if (!tile) return;
          selectedDiscardIndex = null;
          doDiscard(tile).catch((err) => alert(err.message));
          return;
        }
        if (t === 'self_kong') {
          const kind = btn.getAttribute('data-kong-kind') || 'concealed';
          const tile = btn.getAttribute('data-tile');
          if (!tile) return;
          doSelfKong(kind, tile).catch((err) => alert(err.message));
          return;
        }
        if (t === 'win') {
          const patternCode = btn.getAttribute('data-pattern-code');
          doClaim('win', null, patternCode || null).catch((err) => alert(err.message));
          return;
        }
        if (t) onClaimClick(t);
      });
    });
  }

  /** @deprecated 操作区已移至手牌上方 mjHandActions */
  function renderActions(s) {
    renderHandActions(s);
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
    activeJokerTiles = new Set((s && s.joker_tiles) || []);
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
    const overlayCoversTable = isBoardOverlayActive(s);
    if (center) {
      if (overlayCoversTable) {
        center.textContent = '';
        center.classList.add('pm-u-hidden');
      } else {
        center.classList.remove('pm-u-hidden');
        let msg = `房间 ${s.code} · 第 ${s.hand_no || 1} 局`;
        if (s.rule_label) msg += ' · ' + s.rule_label;
        if (s.status === 'playing') {
          msg += ` · 牌墙余 ${s.wall_remaining ?? '?'}`;
          if (s.rule_preset === 'hangzhou' && s.dealer_mult) {
            msg += ' · 连庄 ' + s.dealer_mult + ' 倍';
          }
        }
        center.textContent = msg;
      }
    }

    renderDiceRoll(s);
    updateBoardOverlay(s);
    renderRoomSidebar(s);
    syncRoomChat(s);

    const overlayCoversLobby = overlayCoversTable;

    const inRoom = lobbyInRoom(s);
    if (!isPopup) setVisible($('mjBoardCard'), true);
    const hideTable = isMain && popupOpen;
    setVisible($('mjTableLayout'), inRoom && !hideTable);
    setVisible($('mjTablePlaceholder'), (!inRoom || hideTable) && !isPopup);
    const canReady = s.status === 'lobby' || s.status === 'hand_end';
    setVisible($('mjLeaveBtn'), lobbyInRoom(s));
    updateLeaveButtons(s);

    const popReady = $('mjPopupReadyBtn');
    if (popReady && canReady) {
      const me = mySeat != null ? (s.seats || [])[mySeat] : null;
      popReady.textContent = me && me.ready ? '取消准备' : '准备';
      setVisible(popReady, isPopup && mySeat != null && !overlayCoversLobby);
    }
    if (isMain) updatePopoutBtnUi();
    ensureLayoutScaleSync();
    syncMjLayoutScale();
    syncDealerRevealPoll(s);
    maybeShowJoinNotice(s);
  }

  function ensureMjToastStack() {
    if (mjToastStack && document.body.contains(mjToastStack)) return mjToastStack;
    mjToastStack = document.getElementById('mjPlayToastStack');
    if (!mjToastStack) {
      mjToastStack = document.createElement('div');
      mjToastStack.id = 'mjPlayToastStack';
      mjToastStack.className = 'go-play-toast-stack';
      mjToastStack.setAttribute('aria-live', 'polite');
      document.body.appendChild(mjToastStack);
    }
    return mjToastStack;
  }

  function showMjPlayToast(message, isError, duration) {
    const stack = ensureMjToastStack();
    const isErr = !!isError;
    const ms = duration != null ? duration : (isErr ? 6000 : 3500);
    const el = document.createElement('div');
    el.className = 'go-play-toast ' + (isErr ? 'go-play-toast--error' : 'go-play-toast--success');
    const msgEl = document.createElement('div');
    msgEl.className = 'go-play-toast-message';
    msgEl.textContent = String(message || '');
    el.appendChild(msgEl);
    stack.appendChild(el);
    win.requestAnimationFrame(() => el.classList.add('is-show'));
    if (ms > 0) {
      win.setTimeout(() => {
        el.classList.remove('is-show');
        win.setTimeout(() => el.remove(), 220);
      }, ms);
    }
  }

  function mjToastToPopup(msg, isError, duration) {
    if (!tablePopup || tablePopup.closed) return;
    try {
      tablePopup.postMessage({
        type: 'mj-play-toast',
        msg: String(msg || ''),
        isError: !!isError,
        duration: duration != null ? duration : undefined,
      }, win.location.origin);
    } catch (_) {}
  }

  function maybeShowJoinNotice(s) {
    const notice = s && s.join_notice;
    if (!notice || notice.at_version == null) return;
    const ver = Number(notice.at_version);
    if (!Number.isFinite(ver) || ver <= lastJoinNoticeVersion) return;
    lastJoinNoticeVersion = ver;
    const text = String(notice.message || '').trim()
      || `${String(notice.name || '新玩家')} 已入座，将于下局加入对局`;
    showMjNoticeToast(text, false, 4000);
  }

  function showMjNoticeToast(message, isError, duration) {
    const err = !!isError;
    const dur = duration != null ? duration : (err ? 6000 : 3500);
    if (!isPopup && win.showAppToast) {
      win.showAppToast(String(message || ''), err, dur);
    } else {
      showMjPlayToast(message, err, dur);
    }
  }

  function applyChatOnly(data) {
    if (!data || data.status !== 'success') return false;
    const WR = win.WidgetRoom;
    const merge = WR && WR.mergeChatMessages ? WR.mergeChatMessages : (prev, inc) => (prev || []).concat(inc || []);
    const seq = Number(data.chat_seq) || 0;
    const incoming = data.chat_messages || [];
    if (!incoming.length && lastChatSeq >= 0 && seq > 0 && seq <= lastChatSeq) return false;
    lastChatSeq = Math.max(lastChatSeq, seq);
    const merged = merge(state ? (state.chat_messages || []) : [], incoming);
    if (state) {
      state = Object.assign({}, state, {
        chat_messages: merged,
        chat_seq: seq || state.chat_seq,
      });
    }
    if (!roomChat) initRoomChat();
    if (roomChat) roomChat.render(merged);
    if (!isPopup) postStateToPopup();
    return true;
  }

  function applyState(data) {
    if (!data || data.status !== 'success') return false;
    if (data.chat_only) return applyChatOnly(data);
    const ver = Number(data.version) || 0;
    if (!data.unchanged && lastVersion >= 0 && ver > 0 && ver < lastVersion) {
      return false;
    }
    if (data.unchanged && lastVersion >= 0 && ver <= lastVersion) {
      if (needsDealerRevealPoll(normalizeRoomState(data))) {
        renderTable(data);
        if (!isPopup) postStateToPopup();
      }
      return true;
    }
    lastVersion = ver;
    if (data.chat_seq != null) lastChatSeq = Math.max(lastChatSeq, Number(data.chat_seq) || 0);
    renderTable(data);
    if (!isPopup) postStateToPopup();
    return true;
  }

  function handleWatchPayload(data) {
    if (!data || data.status !== 'success') return;
    if (data.chat_only) {
      applyChatOnly(data);
      return;
    }
    if (data.unchanged) {
      if (data.chat_seq != null) lastChatSeq = Math.max(lastChatSeq, Number(data.chat_seq) || 0);
      if (needsDealerRevealPoll(normalizeRoomState(data))) applyState(data);
      return;
    }
    applyState(data);
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

  function mjToast(message, isError) {
    showMjNoticeToast(message, isError);
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
    if (!mjBoardOverlay) {
      return doLeaveConfirmed();
    }
    return new Promise((resolve, reject) => {
      mjBoardOverlay.showConfirm({
        title: '离开房间',
        message: msg,
        confirmLabel: '离开',
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
    if (data.room_deleted || data.room_dissolved) {
      onRoomEnded(data.message || '房间已解散', isPopup ? {} : undefined);
      return data;
    }
    if (data.left_room) {
      onRoomEnded(data.message || '已离开房间', isPopup ? {} : undefined);
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

  async function doClaim(type, chiTiles, patternCode) {
    const payload = { room_code: roomCode, type };
    if (chiTiles && type === 'chi') payload.chi_tiles = chiTiles;
    if (patternCode && type === 'win') payload.pattern_code = patternCode;
    const data = await api('claim', payload);
    pendingChiPick = null;
    applyState(data);
  }

  async function doSelfKong(kind, tile) {
    const data = await api('self_kong', { room_code: roomCode, kind, tile });
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
    clearDealerRevealPoll();
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
      since_chat_seq: String(lastChatSeq >= 0 ? lastChatSeq : 0),
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
        handleWatchPayload(JSON.parse(ev.data));
      } catch (_) {}
    });
    es.addEventListener('chat', (ev) => {
      if (watchAbort || !ev.data) return;
      try {
        handleWatchPayload(JSON.parse(ev.data));
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
    api('wait', {
      room_code: roomCode,
      since_version: String(lastVersion >= 0 ? lastVersion : 0),
      since_chat_seq: String(lastChatSeq >= 0 ? lastChatSeq : 0),
    }, 'GET')
      .then((data) => {
        if (watchAbort || !roomCode) return;
        handleWatchPayload(data);
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
        const data = await api('rejoin', { room_code: roomCode });
        applyState(data);
      } catch (errRejoin) {
        try {
          const data = await api('join', { room_code: roomCode });
          applyState(data);
        } catch (err2) {
          saveRoomCode('');
          const msg = String((err2 && err2.message) || (errRejoin && errRejoin.message) || (err && err.message) || '');
          if (msg.indexOf('解散') >= 0 || msg.indexOf('不存在') >= 0 || msg.indexOf('过期') >= 0 || msg.indexOf('不在') >= 0) {
            clearRoomUi(msg.indexOf('解散') >= 0 ? msg : '房间已解散或已过期');
          }
          return;
        }
      }
    }
    if (!isPopup) startWatch();
  }

  function bindMainMessageBridge() {
    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      const msg = e.data || {};
      if (msg.type === 'mj-play-request-state') postStateToPopup();
      if (msg.type === 'mj-play-popup-ready') {
        const popupApi = win.SitjoyWidgetPopup;
        if (popupApi && tablePopup && !tablePopup.closed) {
          popupApi.applyBounds(tablePopup, popupApi.resolveBounds(MJ_POPUP_BOUNDS_KEY, MJ_POPUP_DEFAULTS), MJ_POPUP_DEFAULTS);
        }
      }
      if (msg.type === 'mj-play-room-ended') onRoomEnded(msg.message || '房间已结束', { silent: true });
    });
  }

  function initPopup() {
    initMjBoardOverlay();
    initRoomChat();
    bindPlayerAvatarUi();
    document.title = '麻将牌桌';
    const popupApi = win.SitjoyWidgetPopup;
    if (popupApi) {
      popupApi.applyBounds(win, popupApi.resolveBounds(MJ_POPUP_BOUNDS_KEY, MJ_POPUP_DEFAULTS), MJ_POPUP_DEFAULTS);
      popupApi.attachBoundsSaver(MJ_POPUP_BOUNDS_KEY, win, MJ_POPUP_DEFAULTS);
    }
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
      const data = e.data || {};
      if (data.type === 'mj-play-state') applyPayloadFromParent(data.payload);
      if (data.type === 'mj-play-toast') {
        showMjPlayToast(data.msg, data.isError, data.duration);
      }
    });
    try {
      win.opener && win.opener.postMessage({ type: 'mj-play-popup-ready' }, win.location.origin);
    } catch (_) {}
    ensureLayoutScaleSync();
    syncMjLayoutScale();
    win.addEventListener('resize', syncMjLayoutScale);
    const popReady = $('mjPopupReadyBtn');
    if (popReady) {
      popReady.addEventListener('click', () => doReady().catch((err) => alert(err.message)));
    }
  }

  async function doSetRulePreset() {
    if (rulePresetSyncing || !roomCode || !state) return;
    if (state.status !== 'lobby' || !state.you_are_host) return;
    const preset = ($('mjRulePreset') && $('mjRulePreset').value) || 'standard';
    if (preset === (state.rule_preset || 'standard')) {
      syncRulePresetUi(state);
      return;
    }
    const data = await api('set_rule_preset', { room_code: roomCode, rule_preset: preset });
    applyState(data);
  }

  function syncRulePresetHint() {
    const sel = $('mjRulePreset');
    const hint = $('mjRulePresetHint');
    if (!sel || !hint) return;
    const key = sel.value || 'standard';
    hint.setAttribute('data-tip', MJ_PRESET_HINTS[key] || MJ_PRESET_HINTS.standard);
  }

  function onRulePresetChange() {
    syncRulePresetHint();
    if (rulePresetSyncing) return;
    doSetRulePreset().catch((err) => {
      alert(err.message || '规则更新失败');
      if (state) syncRulePresetUi(state);
    });
  }

  function initMain() {
    initMjBoardOverlay();
    initRoomChat();
    bindPlayerAvatarUi();
    bindMainMessageBridge();
    syncRulePresetHint();
    $('mjRulePreset') && $('mjRulePreset').addEventListener('change', onRulePresetChange);
    $('mjCreateBtn') && $('mjCreateBtn').addEventListener('click', () => doCreate().catch((e) => mjToast(e.message || '创建失败', true)));
    $('mjJoinBtn') && $('mjJoinBtn').addEventListener('click', () => doJoin().catch((e) => alert(e.message)));
    $('mjLeaveBtn') && $('mjLeaveBtn').addEventListener('click', () => requestLeaveRoom().catch((e) => alert(e.message)));
    $('mjRoomCopyBtn') && $('mjRoomCopyBtn').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      copyMjRoomShare();
    });
    const popBtn = $('mjPopoutBtn');
    if (popBtn) {
      popBtn.addEventListener('click', () => {
        if (popupOpen && tablePopup && !tablePopup.closed) closeTableWindow();
        else openTableWindow();
      });
    }
    tryResume();
  }

  function bootMahjongPlay() {
    bindMjTileTips();
    const mode = mjPlayMode();
    if (mode.isPopup) initPopup();
    else if (mode.isMain) initMain();
    else tryResume();
    ensureLayoutScaleSync();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootMahjongPlay);
  } else {
    bootMahjongPlay();
  }
})(typeof window !== 'undefined' ? window : this);
