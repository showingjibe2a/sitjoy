"""在线围棋对弈（小组件）：文件持久化房间（多进程共享）、长轮询推送、19 路；悔棋/认输需对方确认。"""

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
GO_ROOM_TTL_SEC = 24 * 3600
GO_WAIT_TIMEOUT_SEC = 8
GO_WAIT_POLL_SEC = 0.3
GO_CLEANUP_ACTIONS = frozenset({
    'create', 'join', 'leave', 'state', 'move', 'pass',
    'undo', 'resign', 'respond', 'cancel_request', 'rematch',
    'practice_start', 'practice_cancel', 'practice_end',
})

_go_file_lock = threading.RLock()
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

    def _go_write_room_file_unlocked(self, room):
        code = str(room.get('code') or '').strip().upper()
        if not code:
            return
        path = self._go_room_path(code)
        tmp = path + '.tmp'
        payload = json.dumps(room, ensure_ascii=False, separators=(',', ':'))
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
        try:
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass
            os.rename(tmp, path)
        _go_signal_waiters(code)

    def _go_write_room_file(self, room):
        with _go_file_lock:
            self._go_write_room_file_unlocked(room)

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
        """读-改-写；持锁仅包裹磁盘读写，不包裹 yield 内业务逻辑（避免阻塞 create/wait）。"""
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
            with _go_file_lock:
                self._go_write_room_file_unlocked(room)

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

    def _go_ko_from_last_move(self, moves):
        """上一手恰好提一子时，该提子点为打劫禁着点（仅下一手禁止立即反提）。"""
        if not moves:
            return None
        last = moves[-1]
        caps = last.get('captures') or []
        if len(caps) != 1:
            return None
        c = caps[0]
        return {'x': int(c['x']), 'y': int(c['y'])}

    def _go_clear_ko(self, room):
        room['ko'] = None

    def _go_set_ko_after_move(self, room, captured):
        if len(captured) == 1:
            c = captured[0]
            room['ko'] = {'x': int(c['x']), 'y': int(c['y'])}
        else:
            self._go_clear_ko(room)

    def _go_check_ko_violation(self, room, x, y):
        ko = room.get('ko')
        if not isinstance(ko, dict):
            return True, ''
        kx, ky = int(ko.get('x', -1)), int(ko.get('y', -1))
        if kx == int(x) and ky == int(y):
            return False, '禁着点（打劫，不可立即反提）'
        return True, ''

    def _go_try_play(self, board, x, y, color):
        if board[y][x] != GO_EMPTY:
            return False, '该点已有棋子', []
        opp = GO_WHITE if color == GO_BLACK else GO_BLACK
        board[y][x] = color
        captured = self._go_remove_dead_groups(board, opp)
        stones, libs = self._go_group_and_liberties(board, x, y)
        if not libs:
            board[y][x] = GO_EMPTY
            if captured:
                return False, '禁着点（落子后己方无气）', []
            return False, '禁着点（落子后己方无气且未提子）', []
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

    def _go_clear_pending(self, room):
        room['pending'] = None

    def _go_pending_summary(self, room, user_id):
        pending = room.get('pending')
        if not isinstance(pending, dict) or not pending.get('type'):
            return {
                'pending': None,
                'pending_for_you': False,
                'you_requested_pending': False,
            }
        uid = int(user_id)
        from_uid = self._parse_int(pending.get('from_user_id'))
        return {
            'pending': {
                'type': pending.get('type'),
                'from_color': int(pending.get('from_color') or 0),
                'from_name': pending.get('from_name') or '',
                'undo_plies': int(pending.get('undo_plies') or 0) if pending.get('type') == 'undo' else 0,
            },
            'pending_for_you': from_uid and from_uid != uid,
            'you_requested_pending': from_uid == uid,
        }

    def _go_clear_practice(self, room):
        room['practice'] = None

    def _go_practice_summary(self, room, user_id):
        p = room.get('practice')
        if not isinstance(p, dict) or not self._parse_int(p.get('user_id')):
            return {
                'practice_active': False,
                'you_in_practice': False,
                'opponent_in_practice': False,
            }
        pid = self._parse_int(p.get('user_id'))
        uid = self._parse_int(user_id) or 0
        return {
            'practice_active': True,
            'practice_by_color': int(p.get('color') or 0),
            'you_in_practice': pid == uid,
            'opponent_in_practice': pid != uid,
        }

    def _go_practice_blocks_action(self, room, user_id):
        p = room.get('practice')
        if not isinstance(p, dict) or not self._parse_int(p.get('user_id')):
            return True, ''
        pid = self._parse_int(p.get('user_id'))
        if pid == int(user_id):
            return False, '请先结束或撤销演习'
        return False, '对方正在演习，请稍候'

    def _go_rematch_summary(self, room, user_id):
        uid = int(user_id)
        bu = self._parse_int(room.get('black_user_id'))
        wu = self._parse_int(room.get('white_user_id'))
        rb = bool(room.get('rematch_black'))
        rw = bool(room.get('rematch_white'))
        you = False
        opp = False
        if uid == bu:
            you, opp = rb, rw
        elif uid == wu:
            you, opp = rw, rb
        return {
            'rematch_you': you,
            'rematch_opponent': opp,
            'rematch_both_ready': rb and rw and bu and wu,
        }

    def _go_bump_version(self, room):
        room['version'] = int(room.get('version') or 0) + 1

    def _go_undo_pop_count(self, room, requester_color):
        """悔棋默认回到「己方上次落子」之前：末手为对方则撤双方各一手，末手为己方则撤一手。"""
        moves = room.get('moves') or []
        if not moves:
            return 0
        c = int(requester_color or 0)
        if not c:
            return 1
        last_c = int(moves[-1].get('color') or 0)
        if last_c == c:
            return 1
        if len(moves) >= 2 and int(moves[-2].get('color') or 0) == c:
            return 2
        return 1

    def _go_apply_undo_move(self, room, requester_color=None):
        if not room.get('moves'):
            return False, '尚无棋步可悔'
        if not requester_color:
            pending = room.get('pending')
            if isinstance(pending, dict) and pending.get('type') == 'undo':
                requester_color = int(pending.get('from_color') or 0)
        n = self._go_undo_pop_count(room, requester_color)
        if n <= 0:
            return False, '尚无棋步可悔'
        for _ in range(n):
            room['moves'].pop()
        if room['moves']:
            last = room['moves'][-1]
            room['current_player'] = GO_WHITE if int(last['color']) == GO_BLACK else GO_BLACK
        else:
            room['current_player'] = GO_BLACK
        room['pass_streak'] = 0
        room['ko'] = self._go_ko_from_last_move(room.get('moves'))
        return True, ''

    def _go_apply_resign(self, room, resign_color):
        if resign_color == GO_BLACK:
            room['winner'] = GO_WHITE
            room['end_reason'] = f'{room.get("black_name") or "黑方"}认输'
        else:
            room['winner'] = GO_BLACK
            room['end_reason'] = f'{room.get("white_name") or "白方"}认输'
        room['status'] = 'ended'
        room['rematch_black'] = False
        room['rematch_white'] = False

    def _go_reset_for_rematch(self, room):
        room['moves'] = []
        room['status'] = 'playing'
        room['winner'] = 0
        room['end_reason'] = ''
        room['current_player'] = GO_BLACK
        room['pass_streak'] = 0
        room['pending'] = None
        room['rematch_black'] = False
        room['rematch_white'] = False
        self._go_clear_ko(room)
        self._go_clear_practice(room)

    def _go_user_color(self, room, user_id):
        uid = self._parse_int(user_id) or 0
        if uid and uid == self._parse_int(room.get('black_user_id')):
            return GO_BLACK
        if uid and uid == self._parse_int(room.get('white_user_id')):
            return GO_WHITE
        return 0

    def _go_room_for_user(self, room, user_id):
        uid = self._parse_int(user_id) or 0
        color = self._go_user_color(room, user_id)
        board = self._go_replay_board(room.get('moves'))
        moves = room.get('moves') or []
        last_move = None
        if moves:
            m = moves[-1]
            last_move = {'x': int(m['x']), 'y': int(m['y'])}
        out = {
            'room_code': room.get('code'),
            'game_status': room.get('status'),
            'your_color': color,
            'current_player': room.get('current_player'),
            'board': board,
            'last_move': last_move,
            'moves_count': len(moves),
            'black_name': room.get('black_name') or '',
            'white_name': room.get('white_name') or '',
            'winner': int(room.get('winner') or 0),
            'end_reason': room.get('end_reason') or '',
            'version': int(room.get('version') or 0),
            'pass_streak': int(room.get('pass_streak') or 0),
            'ko': room.get('ko'),
        }
        out.update(self._go_pending_summary(room, user_id))
        out.update(self._go_rematch_summary(room, user_id))
        out.update(self._go_practice_summary(room, user_id))
        return out

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

        if action in GO_CLEANUP_ACTIONS:
            self._go_cleanup_rooms()
        if action == 'create':
            return self._go_action_create(user_id, start_response)
        if action == 'join':
            return self._go_action_join(user_id, data, start_response)
        if action == 'leave':
            return self._go_action_leave(user_id, data, start_response)
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
        if action == 'respond':
            return self._go_action_respond(user_id, data, start_response)
        if action == 'cancel_request':
            return self._go_action_cancel_request(user_id, data, start_response)
        if action == 'rematch':
            return self._go_action_rematch(user_id, data, start_response)
        if action == 'practice_start':
            return self._go_action_practice_start(user_id, data, start_response)
        if action == 'practice_cancel':
            return self._go_action_practice_cancel(user_id, data, start_response)
        if action == 'practice_end':
            return self._go_action_practice_end(user_id, data, start_response)
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
            'pass_streak': 0,
            'pending': None,
            'rematch_black': False,
            'rematch_white': False,
            'ko': None,
            'practice': None,
            'version': 1,
        }
        try:
            self._go_write_room_file(room)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': f'创建房间失败：{e}'}, start_response)
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

    def _go_action_leave(self, user_id, data, start_response):
        """离开房间：白方离开则回到等待；房主离开则删除房间文件。"""
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            uid = int(user_id)
            bu = self._parse_int(room.get('black_user_id'))
            wu = self._parse_int(room.get('white_user_id'))
            if uid == wu:
                room['white_user_id'] = None
                room['white_name'] = None
                if room.get('status') == 'playing':
                    room['status'] = 'waiting'
                room['pass_streak'] = 0
                self._go_clear_pending(room)
                self._go_clear_practice(room)
                room['rematch_black'] = False
                room['rematch_white'] = False
                self._go_bump_version(room)
                self._go_save_room(room)
            elif uid == bu:
                self._go_delete_room_file(code)
                return self.send_json({'status': 'success', 'room_deleted': True}, start_response)
            else:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
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
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '有待确认的请求，请先处理'}, start_response)
            ok, msg = self._go_practice_blocks_action(room, user_id)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)
            uid = int(user_id)
            color = self._go_user_color(room, user_id)
            if not color:
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

            ko_ok, ko_msg = self._go_check_ko_violation(room, x, y)
            if not ko_ok:
                return self.send_json({'status': 'error', 'message': ko_msg}, start_response)

            ko = room.get('ko')
            if isinstance(ko, dict) and (int(ko.get('x', -1)) != int(x) or int(ko.get('y', -1)) != int(y)):
                self._go_clear_ko(room)

            board = self._go_replay_board(room.get('moves'))
            ok, msg, captured = self._go_try_play(board, x, y, color)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)

            room['moves'].append({'x': x, 'y': y, 'color': color, 'captures': captured})
            self._go_set_ko_after_move(room, captured)
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
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '有待确认的请求，请先处理'}, start_response)
            ok, msg = self._go_practice_blocks_action(room, user_id)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)
            uid = int(user_id)
            color = self._go_user_color(room, user_id)
            if not color:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if int(room.get('current_player') or 0) != color:
                return self.send_json({'status': 'error', 'message': '尚未轮到您'}, start_response)

            room['pass_streak'] = int(room.get('pass_streak') or 0) + 1
            self._go_clear_ko(room)
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
        """发起悔棋请求，需对方同意后生效。"""
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            if not self._go_user_in_room(room, user_id):
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if not room.get('white_user_id'):
                return self.send_json({'status': 'error', 'message': '对手未加入，无法悔棋'}, start_response)
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '已有待确认的请求'}, start_response)
            ok, msg = self._go_practice_blocks_action(room, user_id)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)
            color = self._go_user_color(room, user_id)
            if not color:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            undo_plies = self._go_undo_pop_count(room, color)
            if undo_plies <= 0:
                return self.send_json({'status': 'error', 'message': '尚无棋步可悔'}, start_response)
            room['pending'] = {
                'type': 'undo',
                'from_user_id': int(user_id),
                'from_color': color,
                'from_name': room.get('black_name') if color == GO_BLACK else room.get('white_name'),
                'undo_plies': undo_plies,
            }
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_resign(self, user_id, data, start_response):
        """发起认输请求，需对方确认后结束对局。"""
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            if not room.get('white_user_id'):
                return self.send_json({'status': 'error', 'message': '对手未加入'}, start_response)
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '已有待确认的请求'}, start_response)
            ok, msg = self._go_practice_blocks_action(room, user_id)
            if not ok:
                return self.send_json({'status': 'error', 'message': msg}, start_response)
            color = self._go_user_color(room, user_id)
            if not color:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            room['pending'] = {
                'type': 'resign',
                'from_user_id': int(user_id),
                'from_color': color,
                'from_name': room.get('black_name') if color == GO_BLACK else room.get('white_name'),
            }
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_respond(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        accept = bool(data.get('accept'))
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            pending = room.get('pending')
            if not isinstance(pending, dict) or not pending.get('type'):
                return self.send_json({'status': 'error', 'message': '没有待处理的请求'}, start_response)
            uid = int(user_id)
            if self._parse_int(pending.get('from_user_id')) == uid:
                return self.send_json({'status': 'error', 'message': '不能确认自己的请求'}, start_response)
            if not self._go_user_in_room(room, user_id):
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            ptype = pending.get('type')
            if accept:
                if ptype == 'undo':
                    req_color = int(pending.get('from_color') or 0)
                    ok, msg = self._go_apply_undo_move(room, req_color)
                    if not ok:
                        return self.send_json({'status': 'error', 'message': msg}, start_response)
                elif ptype == 'resign':
                    self._go_apply_resign(room, int(pending.get('from_color') or 0))
                else:
                    return self.send_json({'status': 'error', 'message': '未知请求类型'}, start_response)
            self._go_clear_pending(room)
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_cancel_request(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            pending = room.get('pending')
            if not isinstance(pending, dict):
                return self.send_json({'status': 'error', 'message': '没有可取消的请求'}, start_response)
            if self._parse_int(pending.get('from_user_id')) != int(user_id):
                return self.send_json({'status': 'error', 'message': '只能取消自己发起的请求'}, start_response)
            self._go_clear_pending(room)
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_rematch(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'ended':
                return self.send_json({'status': 'error', 'message': '对局未结束，无法重开'}, start_response)
            if not room.get('white_user_id'):
                return self.send_json({'status': 'error', 'message': '对手未在房间内'}, start_response)
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '有待确认的请求'}, start_response)
            uid = int(user_id)
            if uid == self._parse_int(room.get('black_user_id')):
                room['rematch_black'] = True
            elif uid == self._parse_int(room.get('white_user_id')):
                room['rematch_white'] = True
            else:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if room.get('rematch_black') and room.get('rematch_white'):
                self._go_reset_for_rematch(room)
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_practice_start(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'playing':
                return self.send_json({'status': 'error', 'message': '对局未开始或已结束'}, start_response)
            if not room.get('white_user_id'):
                return self.send_json({'status': 'error', 'message': '对手未加入'}, start_response)
            if room.get('pending'):
                return self.send_json({'status': 'error', 'message': '有待确认的请求'}, start_response)
            existing = room.get('practice')
            uid = self._parse_int(user_id) or 0
            if isinstance(existing, dict):
                pid = self._parse_int(existing.get('user_id'))
                if pid and pid == uid:
                    out = self._go_room_for_user(room, user_id)
                    out['status'] = 'success'
                    return self.send_json(out, start_response)
                return self.send_json({'status': 'error', 'message': '已有玩家在演习'}, start_response)
            color = self._go_user_color(room, user_id)
            if not color:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if int(room.get('current_player') or 0) != color:
                return self.send_json({'status': 'error', 'message': '仅轮到己方时可开启演习'}, start_response)
            room['practice'] = {
                'user_id': uid,
                'color': color,
                'moves_count_at_start': len(room.get('moves') or []),
                'current_player_at_start': int(room.get('current_player') or GO_BLACK),
                'ko_at_start': room.get('ko'),
            }
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_practice_cancel(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            p = room.get('practice')
            if not isinstance(p, dict):
                return self.send_json({'status': 'error', 'message': '当前没有进行中的演习'}, start_response)
            if self._parse_int(p.get('user_id')) != int(user_id):
                return self.send_json({'status': 'error', 'message': '只能撤销自己的演习'}, start_response)
            self._go_clear_practice(room)
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)

    def _go_action_practice_end(self, user_id, data, start_response):
        """结束演习：丢弃本地试下手顺，恢复开启演习前的对局状态，轮到己方继续。"""
        code = str(data.get('room_code') or '').strip().upper()
        with self._go_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            p = room.get('practice')
            if not isinstance(p, dict):
                return self.send_json({'status': 'error', 'message': '当前没有进行中的演习'}, start_response)
            if self._parse_int(p.get('user_id')) != int(user_id):
                return self.send_json({'status': 'error', 'message': '只能结束自己的演习'}, start_response)
            room['current_player'] = int(p.get('current_player_at_start') or GO_BLACK)
            if isinstance(p.get('ko_at_start'), dict):
                room['ko'] = p.get('ko_at_start')
            else:
                self._go_clear_ko(room)
            self._go_clear_practice(room)
            self._go_bump_version(room)
            self._go_save_room(room)
        out = self._go_room_for_user(room, user_id)
        out['status'] = 'success'
        return self.send_json(out, start_response)


class _GoRoomMutated(Exception):
    """标记房间已在 context 内写盘。"""
