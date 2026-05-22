"""在线围棋对弈（小组件）：文件持久化房间（多进程共享）、长轮询推送、19 路、最多悔棋 20 步。"""

import json
import os
import random
import string
import threading
import time
from contextlib import contextmanager
from urllib.parse import parse_qs

GO_BOARD_SIZE = 19
GO_EMPTY = 0
GO_BLACK = 1
GO_WHITE = 2
GO_MAX_UNDO = 20
GO_ROOM_TTL_SEC = 24 * 3600
GO_WAIT_TIMEOUT_SEC = 25
GO_WAIT_POLL_SEC = 0.35

_go_file_lock = threading.Lock()
_go_waiters = {}
_go_waiters_lock = threading.Lock()


def _go_signal_waiters(room_code):
    code = str(room_code or '').strip().upper()
    if not code:
        return
    with _go_waiters_lock:
        events = list(_go_waiters.get(code) or [])
    for ev in events:
        try:
            ev.set()
        except Exception:
            pass


def _go_register_waiter(room_code):
    code = str(room_code or '').strip().upper()
    ev = threading.Event()
    with _go_waiters_lock:
        _go_waiters.setdefault(code, []).append(ev)
    return ev


def _go_unregister_waiter(room_code, ev):
    code = str(room_code or '').strip().upper()
    with _go_waiters_lock:
        lst = _go_waiters.get(code)
        if not lst:
            return
        try:
            lst.remove(ev)
        except ValueError:
            pass
        if not lst:
            _go_waiters.pop(code, None)


class GoPlayMixin:
    """围棋对弈 API 与房间状态。"""

    def _go_rooms_dir(self):
        base = getattr(self, 'base_path', None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, 'var', 'go_play_rooms')
        os.makedirs(path, exist_ok=True)
        return path

    def _go_room_path(self, code):
        code = str(code or '').strip().upper()
        safe = ''.join(c for c in code if c.isalnum())
        return os.path.join(self._go_rooms_dir(), f'{safe}.json')

    def _go_flock(self, fh, exclusive):
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            return True
        except Exception:
            return False

    def _go_funlock(self, fh):
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    def _go_read_room_file(self, code):
        path = self._go_room_path(code)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                self._go_flock(fh, False)
                try:
                    data = json.load(fh)
                finally:
                    self._go_funlock(fh)
            if isinstance(data, dict):
                data['code'] = str(data.get('code') or code).strip().upper()
                return data
        except Exception:
            return None
        return None

    def _go_write_room_file(self, room):
        code = str(room.get('code') or '').strip().upper()
        if not code:
            return
        path = self._go_room_path(code)
        tmp = path + '.tmp'
        payload = json.dumps(room, ensure_ascii=False, separators=(',', ':'))
        with _go_file_lock:
            with open(tmp, 'w', encoding='utf-8') as fh:
                self._go_flock(fh, True)
                try:
                    fh.write(payload)
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except Exception:
                        pass
                finally:
                    self._go_funlock(fh)
            os.replace(tmp, path)
        _go_signal_waiters(code)

    def _go_delete_room_file(self, code):
        path = self._go_room_path(code)
        with _go_file_lock:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass

    @contextmanager
    def _go_room_store(self, code, create=False):
        code = str(code or '').strip().upper()
        with _go_file_lock:
            room = self._go_read_room_file(code) if code else None
            if room is None and not create:
                yield None, '房间不存在或已过期'
                return
            mutated = False
            try:
                yield room, None
            except _GoRoomMutated:
                mutated = True
            if mutated and room is not None:
                self._go_write_room_file(room)

    def _go_empty_board(self):
        return [[GO_EMPTY for _ in range(GO_BOARD_SIZE)] for _ in range(GO_BOARD_SIZE)]

    def _go_neighbors(self, x, y):
        for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < GO_BOARD_SIZE and 0 <= ny < GO_BOARD_SIZE:
                yield nx, ny

    def _go_group_and_liberties(self, board, x, y):
        color = board[y][x]
        if color == GO_EMPTY:
            return [], set()
        stack = [(x, y)]
        visited = set()
        liberties = set()
        stones = []
        while stack:
            cx, cy = stack.pop()
            if (cx, cy) in visited:
                continue
            visited.add((cx, cy))
            stones.append((cx, cy))
            for nx, ny in self._go_neighbors(cx, cy):
                v = board[ny][nx]
                if v == GO_EMPTY:
                    liberties.add((nx, ny))
                elif v == color and (nx, ny) not in visited:
                    stack.append((nx, ny))
        return stones, liberties

    def _go_remove_dead_groups(self, board, color):
        removed = []
        checked = set()
        for y in range(GO_BOARD_SIZE):
            for x in range(GO_BOARD_SIZE):
                if board[y][x] != color or (x, y) in checked:
                    continue
                stones, libs = self._go_group_and_liberties(board, x, y)
                checked.update(stones)
                if not libs:
                    for sx, sy in stones:
                        board[sy][sx] = GO_EMPTY
                        removed.append({'x': sx, 'y': sy})
        return removed

    def _go_try_play(self, board, x, y, color):
        if board[y][x] != GO_EMPTY:
            return False, '该点已有棋子', []
        opp = GO_WHITE if color == GO_BLACK else GO_BLACK
        board[y][x] = color
        captured = self._go_remove_dead_groups(board, opp)
        stones, libs = self._go_group_and_liberties(board, x, y)
        if not libs:
            board[y][x] = GO_EMPTY
            return False, '禁着点（无气且未提子）', []
        return True, '', captured

    def _go_replay_board(self, moves):
        board = self._go_empty_board()
        for mv in moves or []:
            x, y, color = int(mv['x']), int(mv['y']), int(mv['color'])
            if not (0 <= x < GO_BOARD_SIZE and 0 <= y < GO_BOARD_SIZE):
                continue
            board[y][x] = color
            opp = GO_WHITE if color == GO_BLACK else GO_BLACK
            self._go_remove_dead_groups(board, opp)
        return board

    def _go_user_display_name(self, user_id):
        uid = self._parse_int(user_id) or 0
        if not uid:
            return '访客'
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT username, name FROM users WHERE id=%s LIMIT 1', (uid,))
                    row = cur.fetchone() or {}
            return str(row.get('name') or row.get('username') or f'用户{uid}').strip() or f'用户{uid}'
        except Exception:
            return f'用户{uid}'

    def _go_cleanup_rooms(self):
        now = time.time()
        root = self._go_rooms_dir()
        try:
            names = os.listdir(root)
        except Exception:
            return
        for name in names:
            if not name.endswith('.json'):
                continue
            path = os.path.join(root, name)
            try:
                if now - os.path.getmtime(path) > GO_ROOM_TTL_SEC:
                    os.remove(path)
                    continue
            except Exception:
                continue
            room = self._go_read_room_file(name[:-5])
            if room and now - float(room.get('created_at') or 0) > GO_ROOM_TTL_SEC:
                self._go_delete_room_file(room.get('code'))

    def _go_new_room_code(self):
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(200):
            code = ''.join(random.choice(alphabet) for _ in range(6))
            if not os.path.isfile(self._go_room_path(code)):
                return code
        return ''.join(random.choice(alphabet) for _ in range(8))

    def _go_room_for_user(self, room, user_id):
        uid = self._parse_int(user_id) or 0
        color = 0
        if uid and uid == self._parse_int(room.get('black_user_id')):
            color = GO_BLACK
        elif uid and uid == self._parse_int(room.get('white_user_id')):
            color = GO_WHITE
        board = self._go_replay_board(room.get('moves'))
        return {
            'room_code': room.get('code'),
            'game_status': room.get('status'),
            'your_color': color,
            'current_player': room.get('current_player'),
            'board': board,
            'moves_count': len(room.get('moves') or []),
            'undo_count': int(room.get('undo_count') or 0),
            'undo_limit': GO_MAX_UNDO,
            'black_name': room.get('black_name') or '',
            'white_name': room.get('white_name') or '',
            'winner': int(room.get('winner') or 0),
            'end_reason': room.get('end_reason') or '',
            'version': int(room.get('version') or 0),
            'pass_streak': int(room.get('pass_streak') or 0),
        }

    def _go_get_room_locked(self, code):
        code = str(code or '').strip().upper()
        if not code:
            return None, '缺少房间号'
        room = self._go_read_room_file(code)
        if not room:
            return None, '房间不存在或已过期'
        return room, None

    def _go_save_room(self, room):
        raise _GoRoomMutated()

    def _go_user_in_room(self, room, user_id):
        uid = int(user_id)
        return uid in (
            self._parse_int(room.get('black_user_id')),
            self._parse_int(room.get('white_user_id')),
        )

    def handle_go_play_api(self, environ, method, start_response):
        user_id = self._get_session_user(environ)
        if not user_id:
            return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
        if not self._user_has_page_access(user_id, 'widgets_go_play'):
            return self.send_json({'status': 'error', 'message': '无权限访问围棋对弈'}, start_response)

        query = parse_qs(environ.get('QUERY_STRING', ''))
        data = (self._read_json_body(environ) or {}) if method != 'GET' else {}
        if method == 'GET':
            action = str((query.get('action') or [''])[0] or '').strip().lower()
        else:
            action = str(data.get('action') or '').strip().lower()

        self._go_cleanup_rooms()
        if action == 'create':
            return self._go_action_create(user_id, start_response)
        if action == 'join':
            return self._go_action_join(user_id, data, start_response)
        if action == 'state':
            return self._go_action_state(user_id, query, start_response)
        if action == 'wait':
            return self._go_action_wait(user_id, query, start_response)
        if action == 'move':
            return self._go_action_move(user_id, data, start_response)
        if action == 'pass':
            return self._go_action_pass(user_id, data, start_response)
        if action == 'undo':
            return self._go_action_undo(user_id, data, start_response)
        if action == 'resign':
            return self._go_action_resign(user_id, data, start_response)
        return self.send_json({'status': 'error', 'message': '未知操作'}, start_response)

    def _go_action_create(self, user_id, start_response):
        code = self._go_new_room_code()
        name = self._go_user_display_name(user_id)
        room = {
            'code': code,
            'created_at': time.time(),
            'black_user_id': int(user_id),
            'white_user_id': None,
            'black_name': name,
            'white_name': None,
            'current_player': GO_BLACK,
            'status': 'waiting',
            'winner': 0,
            'end_reason': '',
            'moves': [],
            'undo_count': 0,
            'pass_streak': 0,
            'version': 1,
        }
        self._go_write_room_file(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_join(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            uid = int(user_id)
            if uid == self._parse_int(room.get('black_user_id')):
                pass
            elif room.get('white_user_id'):
                if self._parse_int(room.get('white_user_id')) == uid:
                    pass
                else:
                    return self.send_json({'status': 'error', 'message': '房间已满'}, start_response)
            else:
                room['white_user_id'] = uid
                room['white_name'] = self._go_user_display_name(uid)
                room['status'] = 'playing'
                room['version'] = int(room.get('version') or 0) + 1
                self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_state(self, user_id, query, start_response):
        code = (query.get('room_code') or [''])[0]
        room, err = self._go_get_room_locked(code)
        if err:
            return self.send_json({'status': 'error', 'message': err}, start_response)
        if not self._go_user_in_room(room, user_id):
            return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_wait(self, user_id, query, start_response):
        """长轮询：version 变化后立刻返回最新局面（多进程通过文件 + 唤醒）。"""
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        try:
            since = int((query.get('since_version') or ['0'])[0] or 0)
        except Exception:
            since = 0
        if not code:
            return self.send_json({'status': 'error', 'message': '缺少房间号'}, start_response)

        waiter = _go_register_waiter(code)
        try:
            deadline = time.time() + GO_WAIT_TIMEOUT_SEC
            while time.time() < deadline:
                room, err = self._go_get_room_locked(code)
                if err:
                    return self.send_json({'status': 'error', 'message': err}, start_response)
                if not self._go_user_in_room(room, user_id):
                    return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
                ver = int(room.get('version') or 0)
                if ver > since:
                    out = self._go_room_for_user(room, user_id)
                    out['status'] = 'success'
                    return self.send_json(out, start_response)
                waiter.clear()
                remaining = max(0.05, deadline - time.time())
                waiter.wait(timeout=min(GO_WAIT_POLL_SEC, remaining))
        finally:
            _go_unregister_waiter(code, waiter)

        room, err = self._go_get_room_locked(code)
        if err:
            return self.send_json({'status': 'error', 'message': err}, start_response)
        if not self._go_user_in_room(room, user_id):
            return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        out['unchanged'] = True
        return self.send_json(out, start_response)

    def _go_action_move(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            uid = int(user_id)
            color = 0
            if uid == self._parse_int(room.get('black_user_id')):
                color = GO_BLACK
            elif uid == self._parse_int(room.get('white_user_id')):
                color = GO_WHITE
            else:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if int(room.get('current_player') or 0) != color:
                return self.send_json({'status': 'error', 'message': '尚未轮到您落子'}, start_response)
            try:
                x = int(data.get('x'))
                y = int(data.get('y'))
            except Exception:
                return self.send_json({'status': 'error', 'message': '坐标无效'}, start_response)
            if not (0 <= x < GO_BOARD_SIZE and 0 <= y < GO_BOARD_SIZE):
                return self.send_json({'status': 'error', 'message': '坐标超出棋盘'}, start_response)

            board = self._go_replay_board(room.get('moves'))
            ok, msg, captured = self._go_try_play(board, x, y, color)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)

            room['moves'].append({'x': x, 'y': y, 'color': color, 'captures': captured})
            room['current_player'] = GO_WHITE if color == GO_BLACK else GO_BLACK
            room['pass_streak'] = 0
            room['version'] = int(room.get('version') or 0) + 1
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_pass(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            uid = int(user_id)
            color = 0
            if uid == self._parse_int(room.get('black_user_id')):
                color = GO_BLACK
            elif uid == self._parse_int(room.get('white_user_id')):
                color = GO_WHITE
            else:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if int(room.get('current_player') or 0) != color:
                return self.send_json({'status': 'error', 'message': '尚未轮到您'}, start_response)

            room['pass_streak'] = int(room.get('pass_streak') or 0) + 1
            room['current_player'] = GO_WHITE if color == GO_BLACK else GO_BLACK
            room['version'] = int(room.get('version') or 0) + 1
            if room['pass_streak'] >= 2:
                room['status'] = 'ended'
                room['winner'] = 0
                room['end_reason'] = '双方连续虚手，对局结束（不计点）'
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_undo(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            if not self._go_user_in_room(room, user_id):
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if not room.get('moves'):
                return self.send_json({'status': 'error', 'message': '尚无棋步可悔'}, start_response)
            if int(room.get('undo_count') or 0) >= GO_MAX_UNDO:
                return self.send_json({'status': 'error', 'message': f'已达悔棋上限（{GO_MAX_UNDO} 步）'}, start_response)

            room['moves'].pop()
            room['undo_count'] = int(room.get('undo_count') or 0) + 1
            if room['moves']:
                last = room['moves'][-1]
                room['current_player'] = GO_WHITE if int(last['color']) == GO_BLACK else GO_BLACK
            else:
                room['current_player'] = GO_BLACK
            room['pass_streak'] = 0
            room['version'] = int(room.get('version') or 0) + 1
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_resign(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            uid = int(user_id)
            if uid == self._parse_int(room.get('black_user_id')):
                room['winner'] = GO_WHITE
                room['end_reason'] = f'{room.get("black_name") or "黑方"}认输'
            elif uid == self._parse_int(room.get('white_user_id')):
                room['winner'] = GO_BLACK
                room['end_reason'] = f'{room.get("white_name") or "白方"}认输'
            else:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            room['status'] = 'ended'
            room['version'] = int(room.get('version') or 0) + 1
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)


class _GoRoomMutated(Exception):
    """标记房间已在 context 内写盘。"""
