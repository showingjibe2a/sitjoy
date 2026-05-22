/**
 * 围棋对弈：主控页 + 棋盘独立窗口（window.open，postMessage 同步）
 */
(function (global) {
  'use strict';
  const win = global || (typeof window !== 'undefined' ? window : typeof globalThis !== 'undefined' ? globalThis : {});
  const SIZE = 19;
  const BLACK = 1;
  const WHITE = 2;
  const EMPTY = 0;

  const isPopup = document.body && document.body.dataset.goPlayMode === 'popup';

  let roomCode = '';
  let yourColor = 0;
  let board = [];
  let currentPlayer = BLACK;
  let gameStatus = '';
  const ROOM_STORAGE_KEY = 'sitjoy.go-play.room.v1';
  let undoCount = 0;
  let undoLimit = 20;
  let watchActive = false;
  let watchAbort = false;
  let lastVersion = -1;
  let lastMoveKey = '';
  let lastMoveX = -1;
  let lastMoveY = -1;
  const BOARD_POPUP_NAME = 'sitjoy_go_board_popup';
  let popupOpen = false;
  let popupMonitorTimer = null;
  let watchAbortCtrl = null;

  const $ = (id) => document.getElementById(id);

  function getAppBasePath() {
    if (win.SITJOY_BASE_PATH) {
      return String(win.SITJOY_BASE_PATH).replace(/\/$/, '');
    }
    const path = win.location.pathname || '/';
    const m = path.match(/^(.*)\/widgets\/go-play\/?/i);
    if (m && m[1]) return m[1];
    return '';
  }

  function resolveAppUrl(pathAndQuery) {
    const raw = String(pathAndQuery || '').trim();
    const qIdx = raw.indexOf('?');
    const pathPart = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
    const queryPart = qIdx >= 0 ? raw.slice(qIdx) : '';
    const normalized = pathPart.startsWith('/') ? pathPart : '/' + pathPart;
    const base = getAppBasePath();
    if (base) {
      return base + normalized + queryPart;
    }
    const rel = normalized.startsWith('/') ? '..' + normalized + queryPart : raw;
    try {
      return new URL(rel, win.location.href).href;
    } catch (e) {
      return raw;
    }
  }

  function apiUrl(pathAndQuery) {
    return resolveAppUrl(pathAndQuery);
  }

  function pageUrl(path) {
    return resolveAppUrl(path);
  }

  function fetchJson(url, options) {
    const opts = Object.assign({ credentials: 'include' }, options || {});
    return fetch(url, opts).then(async (r) => {
      const text = await r.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : {};
      } catch (e) {
        const snippet = String(text || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        throw new Error(r.status === 404 ? '接口未找到(404)，请重启应用服务后重试' : (snippet || `HTTP ${r.status}`));
      }
      if (data && data.status === 'error') {
        throw new Error(data.message || '请求失败');
      }
      if (!r.ok) {
        throw new Error((data && data.message) || `HTTP ${r.status}`);
      }
      return data;
    });
  }

  function api(action, payload, method, signal) {
    const m = method || 'POST';
    const fetchOpts = signal ? { signal } : {};
    if (m === 'GET') {
      const qs = new URLSearchParams(Object.assign({ action }, payload || {}));
      return fetchJson(apiUrl('/api/go-play?' + qs.toString()), fetchOpts);
    }
    return fetchJson(apiUrl('/api/go-play'), Object.assign({
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ action }, payload || {})),
    }, fetchOpts));
  }

  function toast(msg, isError) {
    if (win.showAppToast) win.showAppToast(msg, !!isError, isError ? 6000 : 3500);
    else alert(msg);
  }

  function colorName(c) {
    if (c === BLACK) return '黑';
    if (c === WHITE) return '白';
    return '-';
  }

  function snapshotState() {
    return {
      roomCode,
      yourColor,
      board,
      currentPlayer,
      gameStatus,
      undoCount,
      undoLimit,
      lastMoveKey,
      lastMove: lastMoveX >= 0 ? { x: lastMoveX, y: lastMoveY } : null,
      canPlay: gameStatus === 'playing' && yourColor && yourColor === currentPlayer,
    };
  }

  function applyLastMoveFromData(data) {
    const lm = data && data.last_move;
    if (lm && Number.isFinite(Number(lm.x)) && Number.isFinite(Number(lm.y))) {
      lastMoveX = Number(lm.x);
      lastMoveY = Number(lm.y);
      lastMoveKey = `${lastMoveX},${lastMoveY}`;
      return;
    }
    if (!data || !Number(data.moves_count)) {
      lastMoveX = -1;
      lastMoveY = -1;
      lastMoveKey = '';
    }
  }

  let boardPopup = null;

  function postStateToPopup() {
    if (!boardPopup || boardPopup.closed) return;
    try {
      boardPopup.postMessage({ type: 'go-play-state', payload: snapshotState() }, win.location.origin);
    } catch (_) {}
  }

  function updatePopoutBtnUi() {
    const btn = $('goPopoutBtn');
    if (!btn) return;
    const alive = popupOpen && boardPopup && !boardPopup.closed;
    if (alive) {
      btn.textContent = '关闭棋盘窗口';
      btn.classList.add('go-play-popout-btn--active');
      btn.title = '关闭已打开的棋盘独立窗口';
    } else {
      btn.textContent = '棋盘独立窗口';
      btn.classList.remove('go-play-popout-btn--active');
      btn.title = '在新浏览器窗口中打开棋盘（需允许弹出窗口）';
    }
  }

  function setWindowPlaceholderVisible(show) {
    const ph = $('goWindowPlaceholder');
    if (!ph) return;
    ph.classList.toggle('pm-u-hidden', !show);
  }

  function stopPopupMonitor() {
    if (popupMonitorTimer) {
      win.clearInterval(popupMonitorTimer);
      popupMonitorTimer = null;
    }
  }

  function onBoardWindowClosed() {
    boardPopup = null;
    popupOpen = false;
    stopPopupMonitor();
    setWindowPlaceholderVisible(false);
    updatePopoutBtnUi();
  }

  function startPopupMonitor() {
    stopPopupMonitor();
    popupMonitorTimer = win.setInterval(() => {
      if (!boardPopup || boardPopup.closed) onBoardWindowClosed();
    }, 400);
  }

  /** 须在按钮 click 里同步调用，否则会被浏览器拦截 */
  function openBoardWindow() {
    if (!roomCode) {
      toast('请先创建或加入房间', true);
      return false;
    }
    if (boardPopup && !boardPopup.closed) {
      boardPopup.focus();
      postStateToPopup();
      return true;
    }
    const url = pageUrl('/widgets/go-play/board?room=' + encodeURIComponent(roomCode));
    boardPopup = win.open(
      url,
      BOARD_POPUP_NAME,
      'popup=yes,width=520,height=540,resizable=yes,scrollbars=no'
    );
    if (!boardPopup) {
      toast('无法打开新窗口：请在浏览器地址栏允许本站「弹出式窗口」后重试', true);
      return false;
    }
    popupOpen = true;
    setWindowPlaceholderVisible(true);
    updatePopoutBtnUi();
    startPopupMonitor();
    toast('棋盘已在独立窗口中打开，请保持本页开启以同步对局', false);
    return true;
  }

  function closeBoardWindow() {
    if (boardPopup && !boardPopup.closed) {
      try { boardPopup.close(); } catch (_) {}
    }
    onBoardWindowClosed();
  }

  function toggleBoardWindow() {
    if (popupOpen && boardPopup && !boardPopup.closed) {
      closeBoardWindow();
    } else {
      openBoardWindow();
    }
  }

  function turnStatusText(data) {
    let turnText = '等待对手加入';
    if (gameStatus === 'playing') {
      const mine = yourColor === currentPlayer;
      turnText = mine ? `轮到你（${colorName(currentPlayer)}）` : `对方思考中（${colorName(currentPlayer)}）`;
    } else if (gameStatus === 'ended') {
      const w = Number((data && data.winner) || 0);
      if (w === 0) turnText = (data && data.end_reason) || '对局结束';
      else turnText = `${colorName(w)}胜 — ${(data && data.end_reason) || ''}`;
    }
    return turnText;
  }

  function closeBoardPopup() {
    closeBoardWindow();
  }

  function applyState(data) {
    if (!data || data.status !== 'success') return false;
    const ver = Number(data.version || 0);
    if (lastVersion >= 0 && ver > 0 && ver < lastVersion) {
      return false;
    }
    roomCode = String(data.room_code || roomCode || '').toUpperCase();
    yourColor = Number(data.your_color || 0);
    board = data.board || [];
    currentPlayer = Number(data.current_player || BLACK);
    gameStatus = String(data.game_status || data.room_status || '');
    undoCount = Number(data.undo_count || 0);
    undoLimit = Number(data.undo_limit || 20);
    lastVersion = Number(data.version || 0);
    applyLastMoveFromData(data);

    if (!isPopup) {
      if ($('goRoomCode')) $('goRoomCode').textContent = roomCode || '------';
      if ($('goPlayersLine')) {
        $('goPlayersLine').textContent = `黑：${data.black_name || '-'} ｜ 白：${data.white_name || '等待对手'}`;
      }
      let turnText = '等待对手加入';
      if (gameStatus === 'playing') {
        const mine = yourColor === currentPlayer;
        turnText = mine ? `轮到你（${colorName(currentPlayer)}）` : `对方思考中（${colorName(currentPlayer)}）`;
      } else if (gameStatus === 'ended') {
        const w = Number(data.winner || 0);
        if (w === 0) turnText = data.end_reason || '对局结束';
        else turnText = `${colorName(w)}胜 — ${data.end_reason || ''}`;
      }
      if ($('goTurnLine')) $('goTurnLine').textContent = `状态：${turnText}`;
      if ($('goUndoLine')) $('goUndoLine').textContent = `悔棋：${undoCount} / ${undoLimit}`;

      const inRoom = !!roomCode;
      $('goRoomPanel')?.classList.toggle('pm-u-hidden', !inRoom);
      $('goLobbyHint')?.classList.toggle('pm-u-hidden', inRoom);
      const hintEl = $('goRoomHint');
      if (hintEl && !hintEl.textContent.trim()) {
        hintEl.classList.add('pm-u-hidden');
      }

      const canPlay = gameStatus === 'playing' && yourColor && yourColor === currentPlayer;
      if ($('goUndoBtn')) $('goUndoBtn').disabled = gameStatus !== 'playing' || undoCount >= undoLimit;
      if ($('goResignBtn')) $('goResignBtn').disabled = gameStatus !== 'playing' || !yourColor;
      if ($('goPassBtn')) $('goPassBtn').disabled = !canPlay;
      if ($('goPopoutBtn')) $('goPopoutBtn').disabled = !roomCode;

      persistRoomCode(roomCode);
    }

    renderBoard($('goBoard'));
    updatePopupStatusBar(data);
    postStateToPopup();
    return true;
  }

  function popupTurnText(data) {
    if (gameStatus === 'playing') {
      return yourColor === currentPlayer
        ? `轮到你 · ${colorName(currentPlayer)}`
        : `对方 · ${colorName(currentPlayer)}`;
    }
    if (gameStatus === 'ended') {
      return (data && data.end_reason) || '对局结束';
    }
    if (gameStatus === 'waiting') {
      return '等待对手加入';
    }
    return '等待对手';
  }

  function updatePopupDocumentTitle(data) {
    if (!isPopup || !roomCode) return;
    const turnText = popupTurnText(data);
    document.title = `围棋 ${roomCode} · ${turnText}`;
  }

  function updatePopupStatusBar(data) {
    updatePopupDocumentTitle(data);
  }

  function getBoardFrame(el) {
    if (!el) return null;
    return el.closest('.go-play-board-frame') || document.getElementById('goBoardFrame');
  }

  function bindBoardFrame(frame) {
    if (!frame || frame.dataset.goBound === '1') return;
    frame.dataset.goBound = '1';
    frame.addEventListener('click', onBoardFrameClick);
  }

  function coordFromPointer(e, frame) {
    const rect = frame.getBoundingClientRect();
    if (!rect.width || !rect.height) return null;
    let nx = (e.clientX - rect.left) / rect.width;
    let ny = (e.clientY - rect.top) / rect.height;
    nx = Math.max(0, Math.min(1, nx));
    ny = Math.max(0, Math.min(1, ny));
    const maxIdx = SIZE - 1;
    const x = Math.max(0, Math.min(maxIdx, Math.round(nx * maxIdx)));
    const y = Math.max(0, Math.min(maxIdx, Math.round(ny * maxIdx)));
    return { x, y };
  }

  function renderBoard(el) {
    if (!el) return;
    const frame = getBoardFrame(el);
    bindBoardFrame(frame);
    el.innerHTML = '';
    const markX = lastMoveX;
    const markY = lastMoveY;

    for (let y = 0; y < SIZE; y++) {
      for (let x = 0; x < SIZE; x++) {
        const v = (board[y] && board[y][x]) || EMPTY;
        if (!v) continue;
        const stone = document.createElement('span');
        stone.className = 'go-play-stone ' + (v === BLACK ? 'go-play-stone--black' : 'go-play-stone--white');
        stone.style.setProperty('--gx', String(x));
        stone.style.setProperty('--gy', String(y));
        if (markX >= 0 && markY >= 0 && x === markX && y === markY) {
          stone.classList.add('go-play-stone--last');
        }
        el.appendChild(stone);
      }
    }
  }

  function playMoveAt(x, y) {
    if (!roomCode) return;
    if (gameStatus !== 'playing' || yourColor !== currentPlayer) {
      toast('尚未轮到您落子', true);
      return;
    }
    api('move', { room_code: roomCode, x, y }).then((d) => {
      if (!applyState(d)) toast((d && d.message) || '落子失败', true);
    }).catch((err) => toast(err.message || '网络错误', true));
  }

  function onBoardFrameClick(e) {
    const frame = e.currentTarget;
    if (!frame || !roomCode) return;
    const coord = coordFromPointer(e, frame);
    if (!coord) return;
    if (isPopup) {
      if (!win.opener || win.opener.closed) {
        toast('主窗口已关闭', true);
        return;
      }
      try {
        win.opener.postMessage({
          type: 'go-play-move',
          x: coord.x,
          y: coord.y,
        }, win.location.origin);
      } catch (_) {
        toast('无法与主窗口通信', true);
      }
      return;
    }
    playMoveAt(coord.x, coord.y);
  }

  function handleMoveFromPopup(x, y) {
    playMoveAt(x, y);
  }

  function startWatch() {
    if (isPopup) return;
    stopWatch();
    watchAbort = false;
    watchActive = true;
    watchLoop();
  }

  function stopWatch() {
    watchAbort = true;
    watchActive = false;
    if (watchAbortCtrl) {
      try { watchAbortCtrl.abort(); } catch (_) {}
      watchAbortCtrl = null;
    }
  }

  function clearRoomFromUrl() {
    try {
      const u = new URL(win.location.href);
      u.searchParams.delete('room');
      win.history.replaceState({}, '', u);
    } catch (_) {}
  }

  function watchLoop() {
    if (watchAbort || !watchActive || !roomCode) return;
    watchAbortCtrl = new AbortController();
    const signal = watchAbortCtrl.signal;
    api('wait', { room_code: roomCode, since_version: lastVersion }, 'GET', signal)
      .then((d) => {
        if (watchAbort || !roomCode) return;
        if (d && d.status === 'success' && !d.unchanged) {
          applyState(d);
        }
        if (!watchAbort && roomCode) watchLoop();
      })
      .catch((err) => {
        if (watchAbort || (err && err.name === 'AbortError')) return;
        const msg = String((err && err.message) || '');
        if (msg.indexOf('不存在') >= 0 || msg.indexOf('不在该房间') >= 0) {
          resetLocalRoomUi();
          toast(msg.indexOf('不存在') >= 0 ? '房间已关闭' : msg, false);
          return;
        }
        if (!watchAbort && roomCode) {
          win.setTimeout(watchLoop, 1500);
        }
      });
  }

  function persistRoomCode(code) {
    const c = String(code || '').trim().toUpperCase();
    try {
      if (c) sessionStorage.setItem(ROOM_STORAGE_KEY, c);
      else sessionStorage.removeItem(ROOM_STORAGE_KEY);
    } catch (_) {}
  }

  function readStoredRoomCode() {
    try {
      return String(sessionStorage.getItem(ROOM_STORAGE_KEY) || '').trim().toUpperCase();
    } catch (_) {
      return '';
    }
  }

  function joinRoom(code) {
    const c = String(code || '').trim().toUpperCase();
    if (!c) {
      toast('请输入房间号', true);
      return Promise.resolve(false);
    }
    stopWatch();
    return api('join', { room_code: c }).then((d) => {
      if (!d || d.status !== 'success') {
        toast((d && d.message) || '加入房间失败', true);
        if (d && d.message && String(d.message).indexOf('不存在') >= 0) {
          persistRoomCode('');
        }
        return false;
      }
      if (!applyState(d)) {
        toast('加入成功但界面更新失败，请刷新页面', true);
        return false;
      }
      if ($('goJoinInput')) $('goJoinInput').value = c;
      try {
        const u = new URL(win.location.href);
        u.searchParams.set('room', c);
        win.history.replaceState({}, '', u);
      } catch (_) {}
      startWatch();
      toast('已加入房间 ' + c, false);
      return true;
    }).catch((err) => {
      toast(err.message || '网络错误', true);
      return false;
    });
  }

  function rejoinRoom(code, silent) {
    const c = String(code || '').trim().toUpperCase();
    if (!c) return Promise.resolve(false);
    stopWatch();
    return api('join', { room_code: c }).then((d) => {
      if (!d || d.status !== 'success') {
        if (!silent) toast((d && d.message) || '回到房间失败', true);
        if (d && d.message && String(d.message).indexOf('不存在') >= 0) {
          persistRoomCode('');
          clearRoomFromUrl();
        }
        return false;
      }
      if (!applyState(d)) {
        if (!silent) toast('回到房间失败', true);
        return false;
      }
      if ($('goJoinInput')) $('goJoinInput').value = c;
      try {
        const u = new URL(win.location.href);
        u.searchParams.set('room', c);
        win.history.replaceState({}, '', u);
      } catch (_) {}
      startWatch();
      if (!silent) toast('已进入房间 ' + c, false);
      return true;
    }).catch((err) => {
      if (!silent) toast(err.message || '网络错误', true);
      return false;
    });
  }

  function resetLocalRoomUi() {
    closeBoardPopup();
    roomCode = '';
    yourColor = 0;
    gameStatus = '';
    lastMoveX = -1;
    lastMoveY = -1;
    lastMoveKey = '';
    lastVersion = -1;
    persistRoomCode('');
    stopWatch();
    $('goRoomPanel')?.classList.add('pm-u-hidden');
    $('goLobbyHint')?.classList.remove('pm-u-hidden');
    if ($('goPopoutBtn')) $('goPopoutBtn').disabled = true;
    if ($('goRoomHint')) {
      $('goRoomHint').textContent = '';
      $('goRoomHint').classList.add('pm-u-hidden');
    }
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    renderBoard($('goBoard'));
    try {
      const u = new URL(win.location.href);
      u.searchParams.delete('room');
      win.history.replaceState({}, '', u);
    } catch (_) {}
  }

  function notifyServerLeave() {
    const code = String(roomCode || '').trim().toUpperCase();
    if (!code || yourColor !== WHITE) return;
    const body = JSON.stringify({ action: 'leave', room_code: code });
    const url = apiUrl('/api/go-play');
    try {
      fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
        credentials: 'include',
        keepalive: true,
      }).catch(() => {});
    } catch (_) {}
  }

  function leaveRoom() {
    const code = String(roomCode || '').trim().toUpperCase();
    if (!code) {
      resetLocalRoomUi();
      return Promise.resolve();
    }
    stopWatch();
    return api('leave', { room_code: code }).then((d) => {
      if (d && d.status !== 'success' && !(d && d.room_deleted)) {
        toast((d && d.message) || '离开房间失败', true);
      }
    }).catch(() => {}).finally(() => {
      resetLocalRoomUi();
    });
  }

  function bindMainUi() {
    $('goCreateBtn')?.addEventListener('click', () => {
      const btn = $('goCreateBtn');
      stopWatch();
      closeBoardWindow();
      if (btn) btn.disabled = true;
      api('create', {}).then((d) => {
        if (!d || d.status !== 'success') {
          toast((d && d.message) || '创建失败', true);
          return;
        }
        if (!applyState(d)) {
          toast('房间已创建但界面更新失败，请刷新页面', true);
          return;
        }
        toast('房间已创建：' + roomCode, false);
        persistRoomCode(roomCode);
        try {
          const u = new URL(win.location.href);
          u.searchParams.set('room', roomCode);
          win.history.replaceState({}, '', u);
        } catch (_) {}
        startWatch();
      }).catch((err) => {
        if (err && err.name !== 'AbortError') toast(err.message || '网络错误', true);
      }).finally(() => {
        if (btn) btn.disabled = false;
      });
    });

    $('goJoinBtn')?.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      joinRoom(String($('goJoinInput')?.value || ''));
    });

    $('goJoinInput')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        joinRoom(String($('goJoinInput')?.value || ''));
      }
    });

    $('goPassBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      api('pass', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '操作失败', true);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goUndoBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      if (!win.confirm('确认悔棋一手？（本局最多 ' + undoLimit + ' 次）')) return;
      api('undo', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '悔棋失败', true);
        else toast('已悔棋', false);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goResignBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      if (!win.confirm('确认认输？')) return;
      api('resign', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '操作失败', true);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goLeaveBtn')?.addEventListener('click', () => {
      leaveRoom();
    });

    $('goPopoutBtn')?.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      toggleBoardWindow();
    });
  }

  function bindPopupUi() {
    const boardEl = $('goBoard');
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    renderBoard(boardEl);
    bindBoardFrame(getBoardFrame(boardEl));

    document.title = '围棋棋盘';

    const syncFromOpener = () => {
      if (!win.opener || win.opener.closed) {
        document.title = '围棋 — 主窗口已关闭';
        return;
      }
      try {
        win.opener.postMessage({ type: 'go-play-request-state' }, win.location.origin);
      } catch (_) {}
    };

    syncFromOpener();
    win.setInterval(syncFromOpener, 1200);

    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      const msg = e.data || {};
      if (msg.type === 'go-play-state' && msg.payload) {
        const p = msg.payload;
        roomCode = p.roomCode || '';
        yourColor = p.yourColor || 0;
        board = p.board || board;
        currentPlayer = p.currentPlayer || BLACK;
        gameStatus = p.gameStatus || '';
        undoCount = p.undoCount || 0;
        undoLimit = p.undoLimit || 20;
        lastMoveKey = p.lastMoveKey || '';
        if (p.lastMove && Number.isFinite(Number(p.lastMove.x)) && Number.isFinite(Number(p.lastMove.y))) {
          lastMoveX = Number(p.lastMove.x);
          lastMoveY = Number(p.lastMove.y);
        } else {
          lastMoveX = -1;
          lastMoveY = -1;
        }
        renderBoard(boardEl);
        updatePopupDocumentTitle({});
      }
    });

    try {
      win.opener && win.opener.postMessage({ type: 'go-play-popup-ready' }, win.location.origin);
    } catch (_) {}
  }

  function bindMainMessageBridge() {
    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      const msg = e.data || {};
      if (msg.type === 'go-play-move') {
        handleMoveFromPopup(Number(msg.x), Number(msg.y));
      }
      if (msg.type === 'go-play-request-state' || msg.type === 'go-play-popup-ready') {
        postStateToPopup();
      }
    });
  }

  function tryAutoRejoin() {
    let code = '';
    try {
      code = new URL(win.location.href).searchParams.get('room') || '';
    } catch (_) {}
    code = String(code || readStoredRoomCode() || '').trim().toUpperCase();
    if (!code) return;
    if ($('goJoinInput')) $('goJoinInput').value = code;
    rejoinRoom(code, true).then((ok) => {
      if (!ok) {
        persistRoomCode('');
        clearRoomFromUrl();
        if ($('goRoomHint')) {
          $('goRoomHint').textContent = '无法自动回到房间（可能已过期或服务器已重启），请重新创建或加入。';
          $('goRoomHint').classList.remove('pm-u-hidden');
        }
      }
    });
  }

  document.addEventListener('DOMContentLoaded', () => {
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    if (isPopup) {
      bindPopupUi();
      return;
    }
    bindMainUi();
    bindMainMessageBridge();
    renderBoard($('goBoard'));
    bindBoardFrame(getBoardFrame($('goBoard')));
    tryAutoRejoin();
  });

  if (!isPopup) {
    win.addEventListener('pagehide', () => {
      notifyServerLeave();
      stopWatch();
      closeBoardPopup();
    });
  }

  win.SitjoyGoPlay = {
    openBoardWindow,
    closeBoardWindow,
    toggleBoardWindow,
    openBoardPopup: openBoardWindow,
    apiUrl,
  };
})(typeof window !== 'undefined' ? window : typeof globalThis !== 'undefined' ? globalThis : this);
