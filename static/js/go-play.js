/**
 * 围棋对弈：主控页 + 棋盘画中画（页面内浮动，置顶可固定）
 */
(function (global) {
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
  let pipOpen = false;
  let pipPinned = true;
  let pipDrag = null;

  const $ = (id) => document.getElementById(id);

  function resolveAppUrl(pathAndQuery) {
    const raw = String(pathAndQuery || '').trim();
    const rel = raw.startsWith('/') ? '..' + raw : raw;
    try {
      return new URL(rel, global.location.href).href;
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
    return fetch(url, Object.assign({ credentials: 'include' }, options || {})).then(async (r) => {
      const text = await r.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : {};
      } catch (e) {
        const snippet = String(text || '').replace(/\s+/g, ' ').trim().slice(0, 80);
        throw new Error(r.status === 404 ? '接口未找到(404)，请重启应用服务后重试' : (snippet || `HTTP ${r.status}`));
      }
      if (!r.ok && data && data.status !== 'success') {
        throw new Error(data.message || `HTTP ${r.status}`);
      }
      return data;
    });
  }

  function api(action, payload, method) {
    const m = method || 'POST';
    if (m === 'GET') {
      const qs = new URLSearchParams(Object.assign({ action }, payload || {}));
      return fetchJson(apiUrl('/api/go-play?' + qs.toString()));
    }
    return fetchJson(apiUrl('/api/go-play'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(Object.assign({ action }, payload || {})),
    });
  }

  function toast(msg, isError) {
    if (global.showAppToast) global.showAppToast(msg, !!isError, isError ? 6000 : 3500);
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
      canPlay: gameStatus === 'playing' && yourColor && yourColor === currentPlayer,
    };
  }

  function postStateToPopup() {
    syncPipBoard();
    if (!boardPopup || boardPopup.closed) return;
    try {
      boardPopup.postMessage({ type: 'go-play-state', payload: snapshotState() }, global.location.origin);
    } catch (_) {}
  }

  let boardPopup = null;

  function updatePopoutBtnUi() {
    const btn = $('goPopoutBtn');
    if (!btn) return;
    if (pipOpen) {
      btn.textContent = '关闭画中画';
      btn.classList.add('go-play-popout-btn--active');
      btn.title = '关闭页面右上角棋盘画中画';
    } else {
      btn.textContent = '棋盘画中画';
      btn.classList.remove('go-play-popout-btn--active');
      btn.title = '在页面顶部显示可固定的棋盘画中画';
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

  function updatePipChrome(data) {
    const title = $('goPipTitle');
    const status = $('goPipStatus');
    if (title) title.textContent = roomCode ? `围棋 · ${roomCode}` : '围棋棋盘';
    if (status) status.textContent = turnStatusText(data || {});
  }

  function syncPipBoard(data) {
    if (!pipOpen) return;
    const pipBoard = $('goPipBoard');
    if (pipBoard) renderBoard(pipBoard);
    updatePipChrome(data);
  }

  function applyPipPinnedUi() {
    const root = $('goPipRoot');
    const pinBtn = $('goPipPinBtn');
    if (!root) return;
    root.classList.toggle('is-pinned', pipPinned);
    if (pipPinned) {
      root.style.left = '';
      root.style.top = '';
      root.style.right = '';
      root.style.bottom = '';
    }
    if (pinBtn) {
      pinBtn.classList.toggle('is-active', pipPinned);
      pinBtn.setAttribute('aria-pressed', pipPinned ? 'true' : 'false');
      pinBtn.title = pipPinned ? '已固定右上角，点击后可拖动' : '点击固定到页面右上角';
    }
  }

  function openBoardPip() {
    if (!roomCode) {
      toast('请先创建或加入房间', true);
      return;
    }
    const root = $('goPipRoot');
    if (!root) return;
    pipOpen = true;
    pipPinned = true;
    root.classList.remove('pm-u-hidden');
    root.setAttribute('aria-hidden', 'false');
    applyPipPinnedUi();
    const pipBoard = $('goPipBoard');
    if (pipBoard) {
      renderBoard(pipBoard);
      bindBoardFrame($('goPipBoardFrame'));
    }
    updatePipChrome({});
    updatePopoutBtnUi();
    toast('棋盘画中画已打开，可置顶固定或拖动标题栏移动', false);
  }

  function closeBoardPip() {
    const root = $('goPipRoot');
    pipOpen = false;
    if (root) {
      root.classList.add('pm-u-hidden');
      root.setAttribute('aria-hidden', 'true');
      root.classList.remove('is-dragging');
    }
    pipDrag = null;
    updatePopoutBtnUi();
  }

  function toggleBoardPip() {
    if (pipOpen) closeBoardPip();
    else openBoardPip();
  }

  function closeBoardPopup() {
    closeBoardPip();
    if (boardPopup && !boardPopup.closed) {
      try { boardPopup.close(); } catch (_) {}
    }
    boardPopup = null;
  }

  function openBoardPopup() {
    toggleBoardPip();
  }

  function bindPipUi() {
    $('goPipCloseBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      closeBoardPip();
    });
    $('goPipPinBtn')?.addEventListener('click', (e) => {
      e.stopPropagation();
      pipPinned = !pipPinned;
      applyPipPinnedUi();
    });

    const root = $('goPipRoot');
    const chrome = root && root.querySelector('.go-play-pip-chrome');
    if (!chrome) return;

    chrome.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return;
      if (e.target.closest('button')) return;
      if (pipPinned || !root) return;
      e.preventDefault();
      const rect = root.getBoundingClientRect();
      root.style.right = 'auto';
      root.style.bottom = 'auto';
      root.style.left = `${rect.left}px`;
      root.style.top = `${rect.top}px`;
      pipDrag = { sx: e.clientX, sy: e.clientY, left: rect.left, top: rect.top };
      root.classList.add('is-dragging');
    });

    global.addEventListener('mousemove', (e) => {
      if (!pipDrag || !root) return;
      root.style.left = `${pipDrag.left + e.clientX - pipDrag.sx}px`;
      root.style.top = `${pipDrag.top + e.clientY - pipDrag.sy}px`;
    });

    global.addEventListener('mouseup', () => {
      if (pipDrag && root) root.classList.remove('is-dragging');
      pipDrag = null;
    });
  }

  function applyState(data) {
    if (!data || data.status !== 'success') return false;
    roomCode = String(data.room_code || roomCode || '').toUpperCase();
    yourColor = Number(data.your_color || 0);
    board = data.board || [];
    currentPlayer = Number(data.current_player || BLACK);
    gameStatus = String(data.game_status || data.room_status || '');
    undoCount = Number(data.undo_count || 0);
    undoLimit = Number(data.undo_limit || 20);
    lastVersion = Number(data.version || 0);

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
    syncPipBoard(data);
    postStateToPopup();
    return true;
  }

  function updatePopupStatusBar(data) {
    const bar = $('goPopupStatus');
    if (!bar) return;
    let turnText = '等待对手';
    if (gameStatus === 'playing') {
      turnText = yourColor === currentPlayer ? `轮到你 · ${colorName(currentPlayer)}` : `对方 · ${colorName(currentPlayer)}`;
    } else if (gameStatus === 'ended') {
      turnText = data.end_reason || '对局结束';
    }
    bar.textContent = `房间 ${roomCode} ｜ ${turnText}`;
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
    let lastX = -1;
    let lastY = -1;
    if (Array.isArray(board) && board.length === SIZE) {
      for (let y = 0; y < SIZE; y++) {
        for (let x = 0; x < SIZE; x++) {
          if (board[y][x]) {
            lastX = x;
            lastY = y;
          }
        }
      }
    }
    lastMoveKey = `${lastX},${lastY}`;

    for (let y = 0; y < SIZE; y++) {
      for (let x = 0; x < SIZE; x++) {
        const v = (board[y] && board[y][x]) || EMPTY;
        if (!v) continue;
        const stone = document.createElement('span');
        stone.className = 'go-play-stone ' + (v === BLACK ? 'go-play-stone--black' : 'go-play-stone--white');
        stone.style.setProperty('--gx', String(x));
        stone.style.setProperty('--gy', String(y));
        if (x === lastX && y === lastY) stone.classList.add('go-play-stone--last');
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
      if (!global.opener || global.opener.closed) {
        toast('主窗口已关闭', true);
        return;
      }
      try {
        global.opener.postMessage({
          type: 'go-play-move',
          x: coord.x,
          y: coord.y,
        }, global.location.origin);
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
    watchAbort = false;
    watchActive = true;
    watchLoop();
  }

  function stopWatch() {
    watchAbort = true;
    watchActive = false;
  }

  function watchLoop() {
    if (watchAbort || !watchActive || !roomCode) return;
    api('wait', { room_code: roomCode, since_version: lastVersion }, 'GET')
      .then((d) => {
        if (watchAbort || !roomCode) return;
        if (d && d.status === 'success' && !d.unchanged) {
          applyState(d);
        }
        if (!watchAbort && roomCode) watchLoop();
      })
      .catch(() => {
        if (!watchAbort && roomCode) {
          global.setTimeout(watchLoop, 1200);
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

  function rejoinRoom(code, silent) {
    const c = String(code || '').trim().toUpperCase();
    if (!c) return Promise.resolve(false);
    return api('join', { room_code: c }).then((d) => {
      if (!applyState(d)) {
        if (!silent) toast((d && d.message) || '回到房间失败', true);
        if (d && d.message && String(d.message).indexOf('不存在') >= 0) {
          persistRoomCode('');
        }
        return false;
      }
      if ($('goJoinInput')) $('goJoinInput').value = c;
      try {
        const u = new URL(global.location.href);
        u.searchParams.set('room', c);
        global.history.replaceState({}, '', u);
      } catch (_) {}
      startWatch();
      if (!silent) toast('已进入房间 ' + c, false);
      return true;
    }).catch((err) => {
      if (!silent) toast(err.message || '网络错误', true);
      return false;
    });
  }

  function bindMainUi() {
    $('goCreateBtn')?.addEventListener('click', () => {
      api('create', {}).then((d) => {
        if (!applyState(d)) {
          toast((d && d.message) || '创建失败', true);
          return;
        }
        toast('房间已创建：' + roomCode, false);
        persistRoomCode(roomCode);
        try {
          const u = new URL(global.location.href);
          u.searchParams.set('room', roomCode);
          global.history.replaceState({}, '', u);
        } catch (_) {}
        startWatch();
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goJoinBtn')?.addEventListener('click', () => {
      const code = String($('goJoinInput')?.value || '').trim().toUpperCase();
      if (!code) {
        toast('请输入房间号', true);
        return;
      }
      rejoinRoom(code, true).then((ok) => {
        if (ok) toast('已加入房间 ' + code, false);
      });
    });

    $('goPassBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      api('pass', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '操作失败', true);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goUndoBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      if (!global.confirm('确认悔棋一手？（本局最多 ' + undoLimit + ' 次）')) return;
      api('undo', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '悔棋失败', true);
        else toast('已悔棋', false);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goResignBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      if (!global.confirm('确认认输？')) return;
      api('resign', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '操作失败', true);
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goLeaveBtn')?.addEventListener('click', () => {
      closeBoardPopup();
      roomCode = '';
      yourColor = 0;
      gameStatus = '';
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
        const u = new URL(global.location.href);
        u.searchParams.delete('room');
        global.history.replaceState({}, '', u);
      } catch (_) {}
    });

    $('goPopoutBtn')?.addEventListener('click', toggleBoardPip);
    bindPipUi();
  }

  function bindPopupUi() {
    const boardEl = $('goBoard');
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    renderBoard(boardEl);
    bindBoardFrame(getBoardFrame(boardEl));

    const syncFromOpener = () => {
      if (!global.opener || global.opener.closed) {
        if ($('goPopupStatus')) $('goPopupStatus').textContent = '主窗口已关闭，可关闭本窗口';
        return;
      }
      try {
        global.opener.postMessage({ type: 'go-play-request-state' }, global.location.origin);
      } catch (_) {}
    };

    syncFromOpener();
    global.setInterval(syncFromOpener, 1200);

    global.addEventListener('message', (e) => {
      if (e.origin !== global.location.origin) return;
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
        renderBoard(boardEl);
        updatePopupStatusBar({ end_reason: $('goPopupStatus')?.textContent });
        if ($('goPopupStatus')) {
          let turnText = '同步中…';
          if (gameStatus === 'playing') {
            turnText = yourColor === currentPlayer ? `轮到你 · ${colorName(currentPlayer)}` : `对方 · ${colorName(currentPlayer)}`;
          } else if (gameStatus === 'ended') {
            turnText = '对局结束';
          } else if (gameStatus === 'waiting') {
            turnText = '等待对手加入';
          }
          $('goPopupStatus').textContent = `房间 ${roomCode} ｜ ${turnText}`;
        }
      }
    });

    try {
      global.opener && global.opener.postMessage({ type: 'go-play-popup-ready' }, global.location.origin);
    } catch (_) {}
  }

  function bindMainMessageBridge() {
    global.addEventListener('message', (e) => {
      if (e.origin !== global.location.origin) return;
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
      code = new URL(global.location.href).searchParams.get('room') || '';
    } catch (_) {}
    code = String(code || readStoredRoomCode() || '').trim().toUpperCase();
    if (!code) return;
    if ($('goJoinInput')) $('goJoinInput').value = code;
    rejoinRoom(code, true).then((ok) => {
      if (!ok && $('goRoomHint')) {
        $('goRoomHint').textContent = '无法自动回到房间（可能已过期或服务器已重启），请重新创建或加入。';
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
    global.addEventListener('beforeunload', () => {
      stopWatch();
      closeBoardPopup();
    });
  }

  global.SitjoyGoPlay = { openBoardPip, closeBoardPip, toggleBoardPip, openBoardPopup: toggleBoardPip, apiUrl };
})();
