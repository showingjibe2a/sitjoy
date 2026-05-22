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
  let pendingInfo = null;
  let pendingForYou = false;
  let youRequestedPending = false;
  let winner = 0;
  let endReason = '';
  let blackName = '';
  let whiteName = '';
  let rematchYou = false;
  let rematchOpponent = false;
  let koPoint = null;
  let youInPractice = false;
  let opponentInPractice = false;
  let practiceByColor = 0;
  let practiceLocal = null;
  let localBoardMode = false;
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
    const idx = path.toLowerCase().indexOf('/widgets/go-play');
    if (idx >= 0) {
      return path.slice(0, idx);
    }
    return null;
  }

  function resolveAppUrl(pathAndQuery) {
    const raw = String(pathAndQuery || '').trim();
    const qIdx = raw.indexOf('?');
    const pathPart = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
    const queryPart = qIdx >= 0 ? raw.slice(qIdx) : '';
    const normalized = pathPart.startsWith('/') ? pathPart : '/' + pathPart;
    const base = getAppBasePath();
    if (base !== null) {
      return (base || '') + normalized + queryPart;
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

  let goToastStack = null;

  function ensureGoToastStack() {
    if (goToastStack && document.body.contains(goToastStack)) return goToastStack;
    goToastStack = document.getElementById('goPlayToastStack');
    if (!goToastStack) {
      goToastStack = document.createElement('div');
      goToastStack.id = 'goPlayToastStack';
      goToastStack.className = 'go-play-toast-stack';
      goToastStack.setAttribute('aria-live', 'polite');
      document.body.appendChild(goToastStack);
    }
    return goToastStack;
  }

  function showGoPlayToast(message, isError, duration) {
    const stack = ensureGoToastStack();
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

  function toastToPopup(msg, isError) {
    if (!boardPopup || boardPopup.closed) return;
    try {
      boardPopup.postMessage({
        type: 'go-play-toast',
        msg: String(msg || ''),
        isError: !!isError,
      }, win.location.origin);
    } catch (_) {}
  }

  function toast(msg, isError) {
    const err = !!isError;
    const dur = err ? 6000 : 3500;
    if (!isPopup && win.showAppToast) {
      win.showAppToast(msg, err, dur);
    } else {
      showGoPlayToast(msg, err, dur);
    }
    if (!isPopup && err) toastToPopup(msg, true);
  }

  function colorName(c) {
    if (c === BLACK) return '黑';
    if (c === WHITE) return '白';
    return '-';
  }

  function undoRequestPlies(pending) {
    const n = Number(pending && pending.undo_plies) || 0;
    if (n === 2) return 2;
    if (n === 1) return 1;
    return 0;
  }

  function undoRequestDesc(pending) {
    const n = undoRequestPlies(pending);
    if (n === 2) {
      return '撤回对方上一手及您上次落子（共 2 手），回到您上次落子之前';
    }
    if (n === 1) {
      return '撤回您上一手落子';
    }
    return '撤回上一手';
  }

  function cloneBoard2d(src) {
    const b = [];
    for (let y = 0; y < SIZE; y++) {
      b.push((src[y] || []).slice());
    }
    return b;
  }

  function localGroupLiberties(board, x, y) {
    const color = board[y][x];
    if (!color) return { stones: [], liberties: new Set() };
    const stack = [[x, y]];
    const visited = new Set();
    const liberties = new Set();
    const stones = [];
    while (stack.length) {
      const [cx, cy] = stack.pop();
      const key = cx + ',' + cy;
      if (visited.has(key)) continue;
      visited.add(key);
      stones.push([cx, cy]);
      const dirs = [[-1, 0], [1, 0], [0, -1], [0, 1]];
      for (let i = 0; i < dirs.length; i++) {
        const nx = cx + dirs[i][0];
        const ny = cy + dirs[i][1];
        if (nx < 0 || nx >= SIZE || ny < 0 || ny >= SIZE) continue;
        const v = board[ny][nx];
        if (v === EMPTY) liberties.add(nx + ',' + ny);
        else if (v === color && !visited.has(nx + ',' + ny)) stack.push([nx, ny]);
      }
    }
    return { stones, liberties };
  }

  function localRemoveDead(board, color) {
    const removed = [];
    const checked = new Set();
    for (let y = 0; y < SIZE; y++) {
      for (let x = 0; x < SIZE; x++) {
        if (board[y][x] !== color || checked.has(x + ',' + y)) continue;
        const g = localGroupLiberties(board, x, y);
        g.stones.forEach(([sx, sy]) => checked.add(sx + ',' + sy));
        if (g.liberties.size) continue;
        g.stones.forEach(([sx, sy]) => {
          board[sy][sx] = EMPTY;
          removed.push({ x: sx, y: sy });
        });
      }
    }
    return removed;
  }

  function localTryPlay(board, x, y, color) {
    if (board[y][x] !== EMPTY) {
      return { ok: false, msg: '该点已有棋子', captured: [] };
    }
    const opp = color === BLACK ? WHITE : BLACK;
    board[y][x] = color;
    const captured = localRemoveDead(board, opp);
    const g = localGroupLiberties(board, x, y);
    if (!g.liberties.size) {
      board[y][x] = EMPTY;
      return {
        ok: false,
        msg: captured.length ? '禁着点（落子后己方无气）' : '禁着点（落子后己方无气且未提子）',
        captured: [],
      };
    }
    return { ok: true, msg: '', captured };
  }

  function syncPracticeFlagsFromData(data) {
    const d = data || {};
    practiceByColor = Number(d.practice_by_color || 0);
    const yc = Number(d.your_color != null ? d.your_color : yourColor) || 0;
    const pColor = practiceByColor;
    if (d.practice_active && pColor && yc) {
      youInPractice = pColor === yc;
      opponentInPractice = pColor !== yc;
      return;
    }
    youInPractice = !!d.you_in_practice;
    opponentInPractice = !!d.opponent_in_practice;
    if (!youInPractice && !opponentInPractice) {
      practiceByColor = 0;
    }
  }

  function ensurePracticeLocalReady() {
    if (!youInPractice || practiceLocal || !roomCode) return;
    startLocalPracticeFromServer();
  }

  function isLocalPracticeActive() {
    if (youInPractice && !practiceLocal && roomCode) {
      ensurePracticeLocalReady();
    }
    return youInPractice && !!practiceLocal;
  }

  function isFreeLocalBoard() {
    return localBoardMode && !roomCode && !!practiceLocal;
  }

  function isLocalBoardActive() {
    return isLocalPracticeActive() || isFreeLocalBoard();
  }

  function getViewBoard() {
    return isLocalBoardActive() ? practiceLocal.board : board;
  }

  function getViewKo() {
    return isLocalBoardActive() ? practiceLocal.ko : koPoint;
  }

  function getViewLastMove() {
    if (isLocalBoardActive()) {
      return { x: practiceLocal.lastMoveX, y: practiceLocal.lastMoveY };
    }
    return { x: lastMoveX, y: lastMoveY };
  }

  function enterFreeLocalBoard() {
    if (roomCode) return;
    localBoardMode = true;
    gameStatus = 'local';
    yourColor = 0;
    const empty = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    practiceLocal = {
      board: cloneBoard2d(empty),
      baseBoard: cloneBoard2d(empty),
      moves: [],
      currentPlayer: BLACK,
      baseCurrentPlayer: BLACK,
      ko: null,
      baseKo: null,
      lastMoveX: -1,
      lastMoveY: -1,
      baseLastMoveX: -1,
      baseLastMoveY: -1,
    };
    board = cloneBoard2d(practiceLocal.board);
    koPoint = null;
    lastMoveX = -1;
    lastMoveY = -1;
    lastMoveKey = '';
    if (!isPopup) {
      $('goLocalPanel')?.classList.remove('pm-u-hidden');
      $('goRoomPanel')?.classList.add('pm-u-hidden');
      $('goLobbyHint')?.classList.add('pm-u-hidden');
      if ($('goLocalHint')) {
        $('goLocalHint').textContent = '本地摆棋：点击棋盘落子，黑白轮流；虚手换手，悔一手撤销上一手。';
      }
      if ($('goPopoutBtn')) $('goPopoutBtn').disabled = false;
      updateLocalTurnHint();
    }
    renderBoard($('goBoard'));
    updatePracticeUi();
    updateBoardOverlay({});
    postStateToPopup();
  }

  function ensurePracticeLocalBaseSnapshot() {
    if (!practiceLocal) return;
    if (!practiceLocal.baseBoard) {
      practiceLocal.baseBoard = cloneBoard2d(practiceLocal.board);
      practiceLocal.baseCurrentPlayer = practiceLocal.currentPlayer;
      practiceLocal.baseKo = practiceLocal.ko
        ? { x: Number(practiceLocal.ko.x), y: Number(practiceLocal.ko.y) }
        : null;
      practiceLocal.baseLastMoveX = practiceLocal.lastMoveX;
      practiceLocal.baseLastMoveY = practiceLocal.lastMoveY;
    }
  }

  function cloneKoPoint(ko) {
    if (!ko) return null;
    return { x: Number(ko.x), y: Number(ko.y) };
  }

  function rebuildPracticeLocalFromMoves() {
    if (!practiceLocal) return;
    ensurePracticeLocalBaseSnapshot();

    if (!practiceLocal.moves.length) {
      practiceLocal.board = cloneBoard2d(practiceLocal.baseBoard);
      practiceLocal.currentPlayer = practiceLocal.baseCurrentPlayer;
      practiceLocal.ko = cloneKoPoint(practiceLocal.baseKo);
      practiceLocal.lastMoveX = practiceLocal.baseLastMoveX;
      practiceLocal.lastMoveY = practiceLocal.baseLastMoveY;
      return;
    }

    const b = cloneBoard2d(practiceLocal.baseBoard);
    let ko = cloneKoPoint(practiceLocal.baseKo);
    let lx = practiceLocal.baseLastMoveX;
    let ly = practiceLocal.baseLastMoveY;
    let cp = practiceLocal.baseCurrentPlayer;

    for (const m of practiceLocal.moves) {
      if (ko && (Number(ko.x) !== m.x || Number(ko.y) !== m.y)) {
        ko = null;
      }
      const res = localTryPlay(b, m.x, m.y, m.color);
      if (!res.ok) continue;
      if (res.captured.length === 1) {
        ko = { x: res.captured[0].x, y: res.captured[0].y };
      } else {
        ko = null;
      }
      lx = m.x;
      ly = m.y;
      cp = m.color === BLACK ? WHITE : BLACK;
    }
    practiceLocal.board = b;
    practiceLocal.ko = ko;
    practiceLocal.currentPlayer = cp;
    practiceLocal.lastMoveX = lx;
    practiceLocal.lastMoveY = ly;
  }

  function localPassMove() {
    if (!practiceLocal) return;
    practiceLocal.ko = null;
    practiceLocal.currentPlayer = practiceLocal.currentPlayer === BLACK ? WHITE : BLACK;
    renderBoard($('goBoard'));
    updateLocalTurnHint();
    postStateToPopup();
    updatePracticeUi();
  }

  function localUndoMove() {
    if (!practiceLocal || !practiceLocal.moves.length) {
      toast('没有可悔的手', true);
      return;
    }
    practiceLocal.moves.pop();
    rebuildPracticeLocalFromMoves();
    renderBoard($('goBoard'));
    updateLocalTurnHint();
    postStateToPopup();
    updatePracticeUi();
  }

  /** 在线对局演习：撤回本地试下的一手（最多撤到开启演习时） */
  function practiceUndoStep() {
    if (!youInPractice || !practiceLocal) {
      toast('当前未在演习中', true);
      return;
    }
    if (!practiceLocal.moves.length) {
      const msg = '已是开启演习时的局面，无法继续撤回';
      showGoPlayToast(msg, true);
      if (!isPopup) toastToPopup(msg, true);
      return;
    }
    practiceLocal.moves.pop();
    rebuildPracticeLocalFromMoves();
    renderBoard($('goBoard'));
    postStateToPopup();
    updatePracticeUi();
  }

  function notifyOpenerPracticeUndo() {
    if (!isPopup || !win.opener || win.opener.closed) return false;
    try {
      win.opener.postMessage({ type: 'go-play-practice-undo' }, win.location.origin);
      return true;
    } catch (_) {
      return false;
    }
  }

  function localClearBoard() {
    if (!isFreeLocalBoard()) return;
    const empty = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    practiceLocal = {
      board: cloneBoard2d(empty),
      baseBoard: cloneBoard2d(empty),
      moves: [],
      currentPlayer: BLACK,
      baseCurrentPlayer: BLACK,
      ko: null,
      baseKo: null,
      lastMoveX: -1,
      lastMoveY: -1,
      baseLastMoveX: -1,
      baseLastMoveY: -1,
    };
    board = cloneBoard2d(practiceLocal.board);
    renderBoard($('goBoard'));
    updateLocalTurnHint();
    postStateToPopup();
    updatePracticeUi();
    toast('棋盘已清空', false);
  }

  function updateLocalTurnHint() {
    const el = $('goLocalStatus');
    if (!el || !isFreeLocalBoard() || !practiceLocal) return;
    const n = practiceLocal.moves.length;
    el.textContent = `本地摆棋 · ${colorName(practiceLocal.currentPlayer)}行棋（${n} 手）`;
  }

  function notifyOpenerLocalAction(action) {
    if (!isPopup || !win.opener || win.opener.closed) return false;
    try {
      win.opener.postMessage({ type: action }, win.location.origin);
      return true;
    } catch (_) {
      return false;
    }
  }

  function startLocalPracticeFromServer() {
    const base = cloneBoard2d(board);
    const ko = koPoint ? { x: Number(koPoint.x), y: Number(koPoint.y) } : null;
    practiceLocal = {
      board: cloneBoard2d(base),
      baseBoard: base,
      moves: [],
      currentPlayer: currentPlayer,
      baseCurrentPlayer: currentPlayer,
      ko: ko ? { x: ko.x, y: ko.y } : null,
      baseKo: ko ? { x: ko.x, y: ko.y } : null,
      lastMoveX: lastMoveX,
      lastMoveY: lastMoveY,
      baseLastMoveX: lastMoveX,
      baseLastMoveY: lastMoveY,
    };
    youInPractice = true;
  }

  function stopLocalPractice() {
    practiceLocal = null;
    youInPractice = false;
    practiceByColor = 0;
  }

  function practicePlayAt(x, y) {
    if (!practiceLocal) return;
    if (practiceLocal.ko && Number(practiceLocal.ko.x) === x && Number(practiceLocal.ko.y) === y) {
      toast('禁着点（打劫，不可立即反提）', true);
      return;
    }
    if (practiceLocal.ko && (Number(practiceLocal.ko.x) !== x || Number(practiceLocal.ko.y) !== y)) {
      practiceLocal.ko = null;
    }
    const color = practiceLocal.currentPlayer;
    const b = cloneBoard2d(practiceLocal.board);
    const res = localTryPlay(b, x, y, color);
    if (!res.ok) {
      toast(res.msg, true);
      return;
    }
    practiceLocal.board = b;
    if (res.captured.length === 1) {
      practiceLocal.ko = { x: res.captured[0].x, y: res.captured[0].y };
    } else {
      practiceLocal.ko = null;
    }
    practiceLocal.moves.push({ x, y, color, captures: res.captured });
    practiceLocal.currentPlayer = color === BLACK ? WHITE : BLACK;
    practiceLocal.lastMoveX = x;
    practiceLocal.lastMoveY = y;
    renderBoard($('goBoard'));
    postStateToPopup();
    updateLocalTurnHint();
    updatePracticeUi();
  }

  function updatePracticeUi() {
    if (isFreeLocalBoard()) {
      const passBtns = ['goPassBtn', 'goPopupPassBtn', 'goLocalPassBtn'];
      const undoBtns = ['goUndoBtn', 'goPopupUndoBtn', 'goLocalUndoBtn'];
      const resignBtns = ['goResignBtn', 'goPopupResignBtn'];
      const practiceBtns = ['goPracticeBtn', 'goPopupPracticeBtn'];
      const practiceRevertBtns = ['goPracticeRevertBtn', 'goPopupPracticeRevertBtn'];
      const practiceEndBtns = ['goPracticeEndBtn', 'goPopupPracticeEndBtn'];
      const hasMoves = !!(practiceLocal && practiceLocal.moves.length);
      setToolbarBtns(passBtns, { disabled: false, hidden: false });
      setToolbarBtns(undoBtns, { disabled: !hasMoves, hidden: false });
      setToolbarBtns(resignBtns, { hidden: true });
      setToolbarBtns(practiceBtns, { hidden: true });
      setToolbarBtns(practiceRevertBtns, { hidden: true });
      setToolbarBtns(practiceEndBtns, { hidden: true });
      const banner = $('goPracticeBanner');
      if (banner && !isPopup) {
        banner.classList.remove('pm-u-hidden');
        banner.textContent = '本地摆棋：点击棋盘落子，黑白轮流；虚手换手，悔一手撤销上一手。';
      }
      if (isPopup) {
        document.title = `本地摆棋 · ${colorName(practiceLocal ? practiceLocal.currentPlayer : BLACK)}`;
      }
      return;
    }

    const practiceBtns = ['goPracticeBtn', 'goPopupPracticeBtn'];
    const practiceRevertBtns = ['goPracticeRevertBtn', 'goPopupPracticeRevertBtn'];
    const practiceEndBtns = ['goPracticeEndBtn', 'goPopupPracticeEndBtn'];
    const passBtns = ['goPassBtn', 'goPopupPassBtn'];
    const undoBtns = ['goUndoBtn', 'goPopupUndoBtn'];
    const resignBtns = ['goResignBtn', 'goPopupResignBtn'];
    const banner = $('goPracticeBanner');
    const roomBusy = youInPractice || opponentInPractice;
    const canStart = gameStatus === 'playing' && yourColor && yourColor === currentPlayer && !pendingInfo && !roomBusy;
    const practiceLabel = opponentInPractice ? '对方演习中' : '演习模式';
    const practiceLabelShort = opponentInPractice ? '对方演习' : '演习';

    if (youInPractice) {
      setToolbarBtns(practiceBtns, { hidden: true });
      setToolbarBtns(practiceRevertBtns, {
        hidden: false,
        text: isPopup ? '撤回' : '撤回一步',
        danger: false,
      });
      setToolbarBtns(practiceEndBtns, { hidden: false, danger: true });
    } else {
      setToolbarBtns(practiceBtns, {
        hidden: false,
        disabled: !canStart && !opponentInPractice,
        text: isPopup ? practiceLabelShort : practiceLabel,
      });
      setToolbarBtns(practiceRevertBtns, { hidden: true, danger: false });
      setToolbarBtns(practiceEndBtns, { hidden: true, danger: false });
    }

    if (banner && !isPopup) {
      if (youInPractice) {
        banner.classList.remove('pm-u-hidden');
        banner.textContent = `演习中：可本地模拟双方落子（已 ${practiceLocal ? practiceLocal.moves.length : 0} 手）。「撤回一步」仅撤销试下；「结束演习」恢复开局并继续正式对弈。`;
      } else if (opponentInPractice) {
        banner.classList.remove('pm-u-hidden');
        banner.textContent = '对方正在演习中，请稍候…';
      } else {
        banner.classList.add('pm-u-hidden');
        banner.textContent = '';
      }
    }

    const canPlay = gameStatus === 'playing' && yourColor && yourColor === currentPlayer && !pendingInfo && !roomBusy;
    const hasMoves = board.length > 0 && board.some((row) => row && row.some((v) => v));
    const undoDisabled = roomBusy || gameStatus !== 'playing' || !yourColor || !hasMoves || !!pendingInfo;
    const resignDisabled = roomBusy || gameStatus !== 'playing' || !yourColor || !!pendingInfo;
    setToolbarBtns(passBtns, { disabled: !canPlay });
    setToolbarBtns(undoBtns, { disabled: undoDisabled });
    setToolbarBtns(resignBtns, { disabled: resignDisabled });
  }

  function snapshotState() {
    return {
      roomCode,
      yourColor,
      board,
      currentPlayer,
      gameStatus,
      lastMoveKey,
      lastMove: lastMoveX >= 0 ? { x: lastMoveX, y: lastMoveY } : null,
      canPlay: gameStatus === 'playing' && yourColor && yourColor === currentPlayer && !pendingInfo,
      pending: pendingInfo,
      pendingForYou,
      youRequestedPending,
      winner,
      endReason,
      blackName,
      whiteName,
      rematchYou,
      rematchOpponent,
      ko: koPoint,
      youInPractice,
      opponentInPractice,
      practiceByColor,
      localBoardMode,
      freeLocalActive: isFreeLocalBoard(),
      practiceActive: isLocalBoardActive(),
      practiceBoard: isLocalBoardActive() ? practiceLocal.board : board,
      practiceBaseBoard: isLocalBoardActive() && practiceLocal.baseBoard
        ? practiceLocal.baseBoard
        : (isLocalBoardActive() ? practiceLocal.board : null),
      practiceBaseCurrentPlayer: isLocalBoardActive()
        ? practiceLocal.baseCurrentPlayer
        : currentPlayer,
      practiceBaseKo: isLocalBoardActive() ? practiceLocal.baseKo : koPoint,
      practiceBaseLastMove: isLocalBoardActive()
        ? { x: practiceLocal.baseLastMoveX, y: practiceLocal.baseLastMoveY }
        : null,
      practiceMoves: isLocalBoardActive()
        ? (practiceLocal.moves || []).map((m) => ({
          x: m.x,
          y: m.y,
          color: m.color,
        }))
        : [],
      practiceCurrentPlayer: isLocalBoardActive() ? practiceLocal.currentPlayer : currentPlayer,
      practiceKo: isLocalBoardActive() ? practiceLocal.ko : koPoint,
      practiceLastMove: isLocalBoardActive()
        ? { x: practiceLocal.lastMoveX, y: practiceLocal.lastMoveY }
        : (lastMoveX >= 0 ? { x: lastMoveX, y: lastMoveY } : null),
    };
  }

  function escHtml(text) {
    const d = document.createElement('div');
    d.textContent = String(text || '');
    return d.innerHTML;
  }

  function overlayBtn(label, className, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = className;
    b.textContent = label;
    b.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      onClick();
    });
    return b;
  }

  function refreshMainStateFromServer() {
    if (isPopup || !roomCode) return;
    api('state', { room_code: roomCode }, 'GET').then((d) => {
      if (d && d.status === 'success') applyState(d);
    }).catch(() => {});
  }

  function notifyOpenerRefresh() {
    if (!isPopup || !win.opener || win.opener.closed) return;
    try {
      win.opener.postMessage({ type: 'go-play-popup-changed' }, win.location.origin);
    } catch (_) {}
  }

  function applyApiResult(d, okMsg, opts) {
    const ok = applyState(d, opts);
    if (!ok) {
      toast((d && d.message) || '操作失败', true);
      return false;
    }
    if (isPopup) {
      notifyOpenerRefresh();
    }
    if (okMsg) toast(okMsg, false);
    return true;
  }

  function setToolbarBtns(ids, opts) {
    (ids || []).forEach((id) => {
      const el = $(id);
      if (!el) return;
      if (opts.disabled != null) el.disabled = !!opts.disabled;
      if (opts.text != null) el.textContent = opts.text;
      if (opts.hidden != null) el.classList.toggle('pm-u-hidden', !!opts.hidden);
      if (opts.danger != null) {
        const popup = el.classList.contains('go-play-popup-btn');
        if (popup) {
          el.classList.toggle('go-play-popup-btn--danger', !!opts.danger);
        } else {
          el.classList.toggle('btn-danger', !!opts.danger);
          if (opts.danger) {
            el.classList.remove('btn-secondary');
          } else if (!el.classList.contains('btn-accent')) {
            el.classList.add('btn-secondary');
          }
        }
      }
    });
  }

  function respondPending(accept) {
    if (!roomCode) return;
    api('respond', { room_code: roomCode, accept: !!accept }).then((d) => {
      applyApiResult(d, accept ? '已确认' : '已拒绝');
    }).catch((err) => toast(err.message || '网络错误', true));
  }

  function cancelPendingRequest() {
    if (!roomCode) return;
    api('cancel_request', { room_code: roomCode }).then((d) => {
      applyApiResult(d, null);
    }).catch((err) => toast(err.message || '网络错误', true));
  }

  function voteRematch() {
    if (!roomCode) return;
    api('rematch', { room_code: roomCode }).then((d) => {
      if (!applyApiResult(d, null)) return;
      if (d && d.game_status === 'playing') toast('已重开对局', false);
      else if (d && d.rematch_you) toast('已同意重开，等待对方确认', false);
    }).catch((err) => toast(err.message || '网络错误', true));
  }

  function updateBoardOverlay(data) {
    const overlay = $('goBoardOverlay');
    const titleEl = $('goOverlayTitle');
    const msgEl = $('goOverlayMsg');
    const actionsEl = $('goOverlayActions');
    if (!overlay || !titleEl || !msgEl || !actionsEl) return;

    actionsEl.innerHTML = '';
    titleEl.textContent = '';
    msgEl.textContent = '';
    let show = false;
    const d = data || {};

    if (pendingInfo && pendingInfo.type) {
      const fromName = pendingInfo.from_name || colorName(pendingInfo.from_color);
      if (pendingInfo.type === 'undo') {
        const undoDesc = undoRequestDesc(pendingInfo);
        if (pendingForYou) {
          show = true;
          titleEl.textContent = '悔棋请求';
          msgEl.textContent = `${fromName} 请求悔棋：${undoDesc}，是否同意？`;
          actionsEl.appendChild(overlayBtn('同意悔棋', 'btn-accent', () => respondPending(true)));
          actionsEl.appendChild(overlayBtn('拒绝', 'btn-secondary', () => respondPending(false)));
        } else if (youRequestedPending && !isPopup) {
          show = true;
          titleEl.textContent = '等待对方确认';
          msgEl.textContent = `您已请求悔棋（${undoDesc}），等待对方同意…`;
          actionsEl.appendChild(overlayBtn('取消请求', 'btn-secondary', cancelPendingRequest));
        }
      } else if (pendingInfo.type === 'resign') {
        if (pendingForYou) {
          show = true;
          titleEl.textContent = '认输确认';
          msgEl.textContent = `${fromName} 请求认输并结束对局，是否确认？`;
          actionsEl.appendChild(overlayBtn('确认认输', 'btn-accent', () => respondPending(true)));
          actionsEl.appendChild(overlayBtn('拒绝', 'btn-secondary', () => respondPending(false)));
        } else if (youRequestedPending && !isPopup) {
          show = true;
          titleEl.textContent = '等待对方确认';
          msgEl.textContent = '您已请求认输，等待对方确认…';
          actionsEl.appendChild(overlayBtn('取消请求', 'btn-secondary', cancelPendingRequest));
        }
      }
    } else if (gameStatus === 'ended' && yourColor) {
      show = true;
      const w = Number(d.winner != null ? d.winner : winner);
      const reason = String(d.end_reason || endReason || '').trim();
      titleEl.textContent = '对局结果';
      let html = '';
      if (w) {
        html += `<div class="go-play-board-dialog-result">${escHtml(colorName(w) + '胜')}</div>`;
      }
      if (reason) {
        html += `<span>${escHtml(reason)}</span>`;
      }
      if (!html) {
        html = '<span>对局结束</span>';
      }
      if (rematchYou && !rematchOpponent) {
        html += '<p style="margin:0.35rem 0 0;font-size:0.8rem;color:#6b6560;">等待对方同意重开…</p>';
      }
      msgEl.innerHTML = html;
      if (!rematchYou) {
        actionsEl.appendChild(overlayBtn('同意重开', 'btn-accent', voteRematch));
      }
    }

    overlay.classList.toggle('pm-u-hidden', !show);
    if (show) {
      overlay.removeAttribute('hidden');
    } else {
      overlay.setAttribute('hidden', '');
    }
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
    if (!roomCode && !localBoardMode) {
      enterFreeLocalBoard();
    }
    if (boardPopup && !boardPopup.closed) {
      boardPopup.focus();
      postStateToPopup();
      return true;
    }
    const url = roomCode
      ? pageUrl('/widgets/go-play/board?room=' + encodeURIComponent(roomCode))
      : pageUrl('/widgets/go-play/board?local=1');
    boardPopup = win.open(
      url,
      BOARD_POPUP_NAME,
      'popup=yes,width=580,height=540,resizable=yes,scrollbars=no'
    );
    if (!boardPopup) {
      toast('无法打开新窗口：请在浏览器地址栏允许本站「弹出式窗口」后重试', true);
      return false;
    }
    popupOpen = true;
    setWindowPlaceholderVisible(true);
    updatePopoutBtnUi();
    startPopupMonitor();
    toast(
      roomCode
        ? '棋盘已在独立窗口中打开，请保持本页开启以同步对局'
        : '本地棋盘窗口已打开，可与本页同步落子',
      false
    );
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

  function applyState(data, opts) {
    if (!data || data.status !== 'success') return false;
    const ver = Number(data.version || 0);
    const force = !!(opts && opts.force);
    if (!force && lastVersion >= 0 && ver > 0 && ver <= lastVersion) {
      return false;
    }
    roomCode = String(data.room_code || roomCode || '').toUpperCase();
    if (roomCode) {
      localBoardMode = false;
      $('goLocalPanel')?.classList.add('pm-u-hidden');
    }
    yourColor = Number(data.your_color || 0);
    currentPlayer = Number(data.current_player || BLACK);
    gameStatus = String(data.game_status || data.room_status || '');
    pendingInfo = data.pending || null;
    pendingForYou = !!data.pending_for_you;
    youRequestedPending = !!data.you_requested_pending;
    winner = Number(data.winner || 0);
    endReason = String(data.end_reason || '');
    blackName = String(data.black_name || '');
    whiteName = String(data.white_name || '');
    rematchYou = !!data.rematch_you;
    rematchOpponent = !!data.rematch_opponent;
    koPoint = data.ko || null;
    const prevYouPractice = youInPractice;
    syncPracticeFlagsFromData(data);

    if (!youInPractice) {
      stopLocalPractice();
      board = data.board || [];
      applyLastMoveFromData(data);
    } else {
      if (!prevYouPractice || !practiceLocal) {
        board = data.board || [];
        startLocalPracticeFromServer();
      }
      if (practiceLocal) {
        lastMoveX = practiceLocal.lastMoveX;
        lastMoveY = practiceLocal.lastMoveY;
        lastMoveKey = lastMoveX >= 0 ? `${lastMoveX},${lastMoveY}` : '';
      }
    }

    lastVersion = Number(data.version || 0);

    if (!isPopup) {
      if ($('goRoomCode')) $('goRoomCode').textContent = roomCode || '------';
      if ($('goPlayersLine')) {
        $('goPlayersLine').textContent = `黑：${data.black_name || '-'} ｜ 白：${data.white_name || '等待对手'}`;
      }
      let turnText = '等待对手加入';
      if (youInPractice) {
        turnText = `演习中 · 本地 ${colorName(practiceLocal ? practiceLocal.currentPlayer : currentPlayer)}行棋`;
      } else if (opponentInPractice) {
        turnText = '对方演习中';
      } else if (gameStatus === 'playing') {
        const mine = yourColor === currentPlayer;
        turnText = mine ? `轮到你（${colorName(currentPlayer)}）` : `对方思考中（${colorName(currentPlayer)}）`;
      } else if (gameStatus === 'ended') {
        const w = Number(data.winner || 0);
        if (w === 0) turnText = data.end_reason || '对局结束';
        else turnText = `${colorName(w)}胜 — ${data.end_reason || ''}`;
      }
      if ($('goTurnLine')) $('goTurnLine').textContent = `状态：${turnText}`;
      if ($('goUndoLine')) {
        $('goUndoLine').textContent = pendingInfo
          ? (youRequestedPending ? '悔棋：等待对方确认' : (pendingForYou ? '悔棋：待您确认' : '悔棋需对方同意'))
          : '悔棋需对方同意（对方已应手时默认撤回双方上一手）';
      }

      const inRoom = !!roomCode;
      $('goRoomPanel')?.classList.toggle('pm-u-hidden', !inRoom);
      $('goLocalPanel')?.classList.toggle('pm-u-hidden', inRoom || !localBoardMode);
      $('goLobbyHint')?.classList.add('pm-u-hidden');
      const hintEl = $('goRoomHint');
      if (hintEl && !hintEl.textContent.trim()) {
        hintEl.classList.add('pm-u-hidden');
      }

      if ($('goPopoutBtn')) $('goPopoutBtn').disabled = !roomCode && !localBoardMode;
      persistRoomCode(roomCode);
    }

    updatePracticeUi();
    renderBoard($('goBoard'));
    updateBoardOverlay(data);
    updatePopupStatusBar(data);
    postStateToPopup();
    return true;
  }

  function popupTurnText(data) {
    if (youInPractice) {
      return `演习 · ${colorName(practiceLocal ? practiceLocal.currentPlayer : currentPlayer)}`;
    }
    if (opponentInPractice) {
      return '对方演习中';
    }
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
    if (!isPopup) return;
    if (isFreeLocalBoard()) {
      document.title = `本地摆棋 · ${colorName(practiceLocal ? practiceLocal.currentPlayer : BLACK)}`;
      return;
    }
    if (!roomCode) return;
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
    const inset = 0.5 / SIZE;
    const span = 1 - 2 * inset;
    let nx = (e.clientX - rect.left) / rect.width;
    let ny = (e.clientY - rect.top) / rect.height;
    nx = (nx - inset) / span;
    ny = (ny - inset) / span;
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
    const viewBoard = getViewBoard();
    const viewKo = getViewKo();
    const lastMv = getViewLastMove();
    const markX = lastMv.x;
    const markY = lastMv.y;
    const showKoMark = viewKo && (isLocalBoardActive() || canPlayNow());

    for (let y = 0; y < SIZE; y++) {
      for (let x = 0; x < SIZE; x++) {
        const v = (viewBoard[y] && viewBoard[y][x]) || EMPTY;
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

    if (showKoMark) {
      const kx = Number(viewKo.x);
      const ky = Number(viewKo.y);
      if (Number.isFinite(kx) && Number.isFinite(ky) && kx >= 0 && ky >= 0 && kx < SIZE && ky < SIZE) {
        const empty = !(viewBoard[ky] && viewBoard[ky][kx]);
        if (empty) {
          const koMark = document.createElement('span');
          koMark.className = 'go-play-ko-mark';
          koMark.title = '打劫禁着点（不可立即反提）';
          koMark.setAttribute('aria-label', '打劫禁着点');
          koMark.style.setProperty('--gx', String(kx));
          koMark.style.setProperty('--gy', String(ky));
          el.appendChild(koMark);
        }
      }
    }
  }

  function canPlayNow() {
    if (isLocalBoardActive()) return true;
    return gameStatus === 'playing' && yourColor && yourColor === currentPlayer && !pendingInfo && !opponentInPractice;
  }

  function isKoForbidden(x, y) {
    const ko = getViewKo();
    if (!ko) return false;
    if (isLocalBoardActive()) {
      return Number(ko.x) === x && Number(ko.y) === y;
    }
    if (!canPlayNow() || youInPractice || opponentInPractice) return false;
    return Number(ko.x) === x && Number(ko.y) === y;
  }

  function getMoveBlockedReason(x, y) {
    if (isFreeLocalBoard()) {
      if (isKoForbidden(x, y)) return '禁着点（打劫，不可立即反提）';
      return null;
    }
    if (!roomCode) {
      return isPopup ? '未加入对局；请从主页面打开本地摆棋，或使用 ?local=1 独立棋盘' : null;
    }
    if (isLocalPracticeActive()) {
      if (isKoForbidden(x, y)) return '禁着点（打劫，不可立即反提）';
      return null;
    }
    if (opponentInPractice) return '对方正在演习，请稍候';
    if (pendingInfo) return '有待确认的请求，请先处理';
    if (gameStatus !== 'playing') return '对局未进行中';
    if (!yourColor) return '尚未加入对局';
    if (!canPlayNow()) return '尚未轮到您落子';
    if (isKoForbidden(x, y)) return '禁着点（打劫，不可立即反提）';
    return null;
  }

  function playMoveAt(x, y) {
    if (isLocalBoardActive()) {
      practicePlayAt(x, y);
      return;
    }
    if (!roomCode) return;
    const block = getMoveBlockedReason(x, y);
    if (block) {
      toast(block, true);
      return;
    }
    api('move', { room_code: roomCode, x, y }).then((d) => {
      if (!applyState(d)) toast((d && d.message) || '落子失败', true);
    }).catch((err) => toast(err.message || '网络错误', true));
  }

  function onBoardFrameClick(e) {
    const frame = e.currentTarget;
    if (!frame) return;
    if (!roomCode && !isFreeLocalBoard()) return;
    const coord = coordFromPointer(e, frame);
    if (!coord) return;
    if (isPopup) {
      if (isFreeLocalBoard() && (!win.opener || win.opener.closed)) {
        practicePlayAt(coord.x, coord.y);
        return;
      }
      if (!win.opener || win.opener.closed) {
        toast('主窗口已关闭', true);
        return;
      }
      const block = getMoveBlockedReason(coord.x, coord.y);
      if (block) {
        toast(block, true);
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
    if (isLocalBoardActive()) {
      const block = getMoveBlockedReason(x, y);
      if (block) {
        toast(block, true);
        return;
      }
      practicePlayAt(x, y);
      return;
    }
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
    pendingInfo = null;
    pendingForYou = false;
    youRequestedPending = false;
    winner = 0;
    endReason = '';
    rematchYou = false;
    rematchOpponent = false;
    koPoint = null;
    youInPractice = false;
    opponentInPractice = false;
    stopLocalPractice();
    lastMoveX = -1;
    lastMoveY = -1;
    lastMoveKey = '';
    lastVersion = -1;
    persistRoomCode('');
    stopWatch();
    $('goRoomPanel')?.classList.add('pm-u-hidden');
    $('goLocalPanel')?.classList.remove('pm-u-hidden');
    $('goLobbyHint')?.classList.add('pm-u-hidden');
    if ($('goPopoutBtn')) $('goPopoutBtn').disabled = false;
    if ($('goRoomHint')) {
      $('goRoomHint').textContent = '';
      $('goRoomHint').classList.add('pm-u-hidden');
    }
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    renderBoard($('goBoard'));
    updateBoardOverlay({});
    try {
      const u = new URL(win.location.href);
      u.searchParams.delete('room');
      win.history.replaceState({}, '', u);
    } catch (_) {}
    enterFreeLocalBoard();
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
      api('undo', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '悔棋请求失败', true);
        else {
          const plies = undoRequestPlies(d.pending || pendingInfo);
          toast(plies === 2 ? '已请求悔棋（将撤回双方上一手）' : '已向对方请求悔棋', false);
        }
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goResignBtn')?.addEventListener('click', () => {
      if (!roomCode) return;
      api('resign', { room_code: roomCode }).then((d) => {
        if (!applyState(d)) toast((d && d.message) || '认输请求失败', true);
        else toast('已向对方请求认输', false);
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

    $('goPracticeBtn')?.addEventListener('click', () => {
      if (!roomCode || opponentInPractice) return;
      api('practice_start', { room_code: roomCode }).then((d) => {
        if (!d || d.status !== 'success') {
          toast((d && d.message) || '无法开启演习', true);
          return;
        }
        applyState(d, { force: true });
        ensurePracticeLocalReady();
        toast('已进入演习模式', false);
        updatePracticeUi();
        renderBoard($('goBoard'));
        postStateToPopup();
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goPracticeRevertBtn')?.addEventListener('click', () => {
      practiceUndoStep();
    });

    $('goPracticeEndBtn')?.addEventListener('click', () => {
      if (!roomCode || !youInPractice) return;
      api('practice_end', { room_code: roomCode }).then((d) => {
        if (!applyApiResult(d, '演习已结束，请继续落子', { force: true })) return;
        updatePracticeUi();
        renderBoard($('goBoard'));
        postStateToPopup();
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goLocalPassBtn')?.addEventListener('click', () => localPassMove());
    $('goLocalUndoBtn')?.addEventListener('click', () => localUndoMove());
    $('goLocalClearBtn')?.addEventListener('click', () => localClearBoard());
  }

  function bindPopupToolbar() {
    $('goPopupPassBtn')?.addEventListener('click', () => {
      if (isFreeLocalBoard()) {
        if (!notifyOpenerLocalAction('go-play-local-pass')) localPassMove();
        return;
      }
      if (!roomCode || isLocalPracticeActive()) return;
      api('pass', { room_code: roomCode }).then((d) => {
        if (!applyApiResult(d, null)) return;
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goPopupUndoBtn')?.addEventListener('click', () => {
      if (isFreeLocalBoard()) {
        if (!notifyOpenerLocalAction('go-play-local-undo')) localUndoMove();
        return;
      }
      if (!roomCode || isLocalPracticeActive()) return;
      api('undo', { room_code: roomCode }).then((d) => {
        if (!applyApiResult(d, '已请求悔棋')) return;
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goPopupResignBtn')?.addEventListener('click', () => {
      if (!roomCode || isLocalPracticeActive()) return;
      api('resign', { room_code: roomCode }).then((d) => {
        if (!applyApiResult(d, '已请求认输')) return;
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goPopupPracticeBtn')?.addEventListener('click', () => {
      if (!roomCode || opponentInPractice) return;
      api('practice_start', { room_code: roomCode }).then((d) => {
        if (!d || d.status !== 'success') {
          toast((d && d.message) || '无法开启演习', true);
          return;
        }
        applyState(d, { force: true });
        ensurePracticeLocalReady();
        toast('已进入演习', false);
        notifyOpenerRefresh();
        renderBoard($('goBoard'));
      }).catch((err) => toast(err.message || '网络错误', true));
    });

    $('goPopupPracticeRevertBtn')?.addEventListener('click', () => {
      if (!notifyOpenerPracticeUndo()) practiceUndoStep();
    });

    $('goPopupPracticeEndBtn')?.addEventListener('click', () => {
      if (!roomCode || !youInPractice) return;
      api('practice_end', { room_code: roomCode }).then((d) => {
        if (!applyApiResult(d, '演习已结束', { force: true })) return;
        renderBoard($('goBoard'));
      }).catch((err) => toast(err.message || '网络错误', true));
    });
  }

  function bindPopupUi() {
    const boardEl = $('goBoard');
    board = Array.from({ length: SIZE }, () => Array(SIZE).fill(EMPTY));
    renderBoard(boardEl);
    bindBoardFrame(getBoardFrame(boardEl));
    updateBoardOverlay({});
    bindPopupToolbar();

    let urlLocal = false;
    try {
      urlLocal = new URL(win.location.href).searchParams.get('local') === '1';
    } catch (_) {}
    const hasOpener = !!(win.opener && !win.opener.closed);

    if (!hasOpener && urlLocal) {
      enterFreeLocalBoard();
    } else {
      updatePracticeUi();
    }

    document.title = '围棋棋盘';

    const syncFromOpener = () => {
      if (isFreeLocalBoard() && (!win.opener || win.opener.closed)) return;
      if (!win.opener || win.opener.closed) {
        if (!isFreeLocalBoard()) document.title = '围棋 — 主窗口已关闭';
        return;
      }
      try {
        win.opener.postMessage({ type: 'go-play-request-state' }, win.location.origin);
      } catch (_) {}
    };

    if (hasOpener || !urlLocal) {
      syncFromOpener();
      win.setInterval(syncFromOpener, 1200);
    }

    win.addEventListener('message', (e) => {
      if (e.origin !== win.location.origin) return;
      const msg = e.data || {};
      if (msg.type === 'go-play-toast') {
        showGoPlayToast(msg.msg, msg.isError);
        return;
      }
      if (msg.type === 'go-play-state' && msg.payload) {
        const p = msg.payload;
        roomCode = p.roomCode || '';
        yourColor = p.yourColor || 0;
        board = p.board || board;
        currentPlayer = p.currentPlayer || BLACK;
        gameStatus = p.gameStatus || '';
        pendingInfo = p.pending || null;
        pendingForYou = !!p.pendingForYou;
        youRequestedPending = !!p.youRequestedPending;
        winner = Number(p.winner || 0);
        endReason = String(p.endReason || '');
        rematchYou = !!p.rematchYou;
        rematchOpponent = !!p.rematchOpponent;
        koPoint = p.ko || null;
        syncPracticeFlagsFromData({
          you_in_practice: p.youInPractice,
          opponent_in_practice: p.opponentInPractice,
          practice_active: p.practiceActive,
          practice_by_color: p.practiceByColor,
          your_color: p.yourColor || yourColor,
        });
        if (youInPractice && !practiceLocal && roomCode) {
          ensurePracticeLocalReady();
        }
        localBoardMode = !!p.freeLocalActive;
        if (p.practiceActive && p.practiceBoard) {
          const baseSrc = p.practiceBaseBoard || p.practiceBoard;
          const baseKo = p.practiceBaseKo != null ? p.practiceBaseKo : p.practiceKo;
          const baseLm = p.practiceBaseLastMove || p.practiceLastMove;
          const ko = p.practiceKo || null;
          practiceLocal = {
            board: cloneBoard2d(p.practiceBoard),
            baseBoard: cloneBoard2d(baseSrc),
            moves: Array.isArray(p.practiceMoves)
              ? p.practiceMoves.map((m) => ({
                x: Number(m.x),
                y: Number(m.y),
                color: Number(m.color),
              }))
              : [],
            currentPlayer: p.practiceCurrentPlayer || BLACK,
            baseCurrentPlayer: p.practiceBaseCurrentPlayer || p.practiceCurrentPlayer || BLACK,
            ko: ko ? { x: Number(ko.x), y: Number(ko.y) } : null,
            baseKo: baseKo ? { x: Number(baseKo.x), y: Number(baseKo.y) } : null,
            lastMoveX: p.practiceLastMove ? Number(p.practiceLastMove.x) : -1,
            lastMoveY: p.practiceLastMove ? Number(p.practiceLastMove.y) : -1,
            baseLastMoveX: baseLm && Number.isFinite(Number(baseLm.x)) ? Number(baseLm.x) : -1,
            baseLastMoveY: baseLm && Number.isFinite(Number(baseLm.y)) ? Number(baseLm.y) : -1,
          };
          if (practiceLocal.moves.length) {
            rebuildPracticeLocalFromMoves();
          }
          board = cloneBoard2d(practiceLocal.board);
        } else if (!p.practiceActive) {
          practiceLocal = null;
          localBoardMode = false;
        }
        lastMoveKey = p.lastMoveKey || '';
        if (p.lastMove && Number.isFinite(Number(p.lastMove.x)) && Number.isFinite(Number(p.lastMove.y))) {
          lastMoveX = Number(p.lastMove.x);
          lastMoveY = Number(p.lastMove.y);
        } else {
          lastMoveX = -1;
          lastMoveY = -1;
        }
        renderBoard(boardEl);
        updateBoardOverlay({
          winner,
          end_reason: endReason,
        });
        updatePracticeUi();
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
      if (msg.type === 'go-play-local-pass') {
        localPassMove();
      }
      if (msg.type === 'go-play-local-undo') {
        localUndoMove();
      }
      if (msg.type === 'go-play-local-clear') {
        localClearBoard();
      }
      if (msg.type === 'go-play-practice-undo') {
        practiceUndoStep();
      }
      if (msg.type === 'go-play-popup-changed') {
        refreshMainStateFromServer();
        return;
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
        enterFreeLocalBoard();
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
    updateBoardOverlay({});
    let hasRoomTarget = false;
    try {
      hasRoomTarget = !!(new URL(win.location.href).searchParams.get('room') || readStoredRoomCode());
    } catch (_) {}
    if (hasRoomTarget) {
      tryAutoRejoin();
    } else {
      enterFreeLocalBoard();
    }
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
