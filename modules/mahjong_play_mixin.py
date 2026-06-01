"""在线麻将（小组件）：三人起局、仅平胡；积分与员工昵称；房间文件 + 长轮询。"""

from modules.widget_room_chat_mixin import WidgetRoomChatMixin

import json
import os
import random
import string
import threading
import time
from collections import Counter
from contextlib import contextmanager
from urllib.parse import parse_qs

MJ_SEATS = 4
MJ_MIN_PLAYERS = 2
MJ_ROOM_TTL_SEC = 24 * 3600
MJ_WAIT_TIMEOUT_SEC = 8
MJ_WAIT_POLL_SEC = 0.3
MJ_STREAM_SESSION_SEC = 90
MJ_STREAM_PING_SEC = 12
MJ_TILE_COPIES = 4

# 三人麻将：条(s)、筒(p)、字(z1-7 东南西北中发白)，共 100 张
MJ_SUITS = ('p', 's')
MJ_HONORS = tuple(f'z{i}' for i in range(1, 8))

MJ_CLEANUP_ACTIONS = frozenset({
    'create', 'join', 'leave', 'ready', 'start', 'confirm_roll', 'state', 'wait',
    'discard', 'claim', 'next_hand', 'chat_send', 'swap_seat',
})

_mj_file_lock = threading.RLock()
_mj_waiters = {}
_mj_waiters_lock = threading.Lock()


class _MjRoomMutated(Exception):
    pass


def _mj_signal_waiters(room_code):
    code = str(room_code or '').strip().upper()
    if not code:
        return
    with _mj_waiters_lock:
        events = list(_mj_waiters.get(code) or [])
    for ev in events:
        try:
            ev.set()
        except Exception:
            pass


def _mj_register_waiter(room_code):
    code = str(room_code or '').strip().upper()
    ev = threading.Event()
    with _mj_waiters_lock:
        _mj_waiters.setdefault(code, []).append(ev)
    return ev


def _mj_unregister_waiter(room_code, ev):
    code = str(room_code or '').strip().upper()
    with _mj_waiters_lock:
        lst = _mj_waiters.get(code)
        if not lst:
            return
        try:
            lst.remove(ev)
        except ValueError:
            pass
        if not lst:
            _mj_waiters.pop(code, None)


class MahjongPlayMixin(WidgetRoomChatMixin):
    """麻将 API 与房间状态（简化平胡）。"""

    def _mj_rooms_dir(self):
        base = getattr(self, 'base_path', None) or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, 'var', 'mahjong_rooms')
        os.makedirs(path, exist_ok=True)
        return path

    def _mj_room_path(self, code):
        code = str(code or '').strip().upper()
        safe = ''.join(c for c in code if c.isalnum())
        return os.path.join(self._mj_rooms_dir(), f'{safe}.json')

    def _mj_flock(self, fh, exclusive):
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            return True
        except Exception:
            return False

    def _mj_funlock(self, fh):
        try:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass

    def _mj_read_room_file(self, code):
        path = self._mj_room_path(code)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                self._mj_flock(fh, False)
                try:
                    data = json.load(fh)
                finally:
                    self._mj_funlock(fh)
            if isinstance(data, dict):
                data['code'] = str(data.get('code') or code).strip().upper()
                return data
        except Exception:
            return None
        return None

    def _mj_write_room_file_unlocked(self, room):
        code = str(room.get('code') or '').strip().upper()
        if not code:
            return
        path = self._mj_room_path(code)
        tmp = path + '.tmp'
        payload = json.dumps(room, ensure_ascii=False, separators=(',', ':'))
        with open(tmp, 'w', encoding='utf-8') as fh:
            self._mj_flock(fh, True)
            try:
                fh.write(payload)
                fh.flush()
                try:
                    os.fsync(fh.fileno())
                except Exception:
                    pass
            finally:
                self._mj_funlock(fh)
        try:
            os.replace(tmp, path)
        except Exception:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass
            os.rename(tmp, path)
        _mj_signal_waiters(code)

    def _mj_write_room_file(self, room):
        with _mj_file_lock:
            self._mj_write_room_file_unlocked(room)

    def _mj_delete_room_file(self, code):
        path = self._mj_room_path(code)
        with _mj_file_lock:
            try:
                if os.path.isfile(path):
                    os.remove(path)
            except Exception:
                pass

    def _mj_dissolve_room(self, code):
        """删除房间文件并唤醒长轮询 / SSE 等待者。"""
        code = str(code or '').strip().upper()
        if not code:
            return
        self._mj_delete_room_file(code)
        _mj_signal_waiters(code)

    @contextmanager
    def _mj_room_store(self, code, create=False):
        code = str(code or '').strip().upper()
        with _mj_file_lock:
            room = self._mj_read_room_file(code) if code else None
            if room is None and not create:
                yield None, '房间不存在或已过期'
                return
            mutated = False
            try:
                yield room, None
            except _MjRoomMutated:
                mutated = True
            if mutated and room is not None:
                self._mj_write_room_file_unlocked(room)

    def _mj_read_room_normalized(self, code):
        """读取房间并去重座位；若有修正则写回。"""
        code = str(code or '').strip().upper()
        with _mj_file_lock:
            room = self._mj_read_room_file(code) if code else None
            if not room:
                return None
            if self._mj_normalize_seats(room):
                self._mj_write_room_file_unlocked(room)
            return room

    def _mj_read_room_retry(self, code, attempts=3):
        """读取房间文件，短暂重试以避免并发写入时误判房间不存在。"""
        code = str(code or '').strip().upper()
        if not code:
            return None
        last = None
        for i in range(max(1, int(attempts or 1))):
            last = self._mj_read_room_normalized(code)
            if last is not None:
                return last
            if i + 1 < attempts:
                time.sleep(0.05)
        return last

    def _mj_save_room(self, room):
        raise _MjRoomMutated()

    def _mj_bump_version(self, room):
        room['version'] = int(room.get('version') or 0) + 1

    def _mj_user_display_name(self, user_id):
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

    def _mj_user_avatar_url(self, user_id):
        uid = self._parse_int(user_id) or 0
        if not uid:
            return None
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT avatar_path FROM users WHERE id=%s LIMIT 1', (uid,))
                    row = cur.fetchone() or {}
            path = str(row.get('avatar_path') or '').strip()
            return f'/api/profile/avatar?user_id={uid}' if path else None
        except Exception:
            return None

    def _mj_can_swap_seat(self, room):
        return str(room.get('status') or '') == 'lobby'

    def _mj_relocate_seat_player(self, room, from_seat, to_seat):
        """将玩家从 from_seat 移到 to_seat，并同步积分与牌局数组索引。"""
        fs = int(from_seat)
        ts = int(to_seat)
        if fs < 0 or fs >= MJ_SEATS or ts < 0 or ts >= MJ_SEATS or fs == ts:
            return False
        seats = list(room.get('seats') or [None] * MJ_SEATS)
        while len(seats) < MJ_SEATS:
            seats.append(None)
        player = seats[fs]
        if not isinstance(player, dict):
            return False
        if isinstance(seats[ts], dict):
            return False
        uid = self._parse_int(player.get('user_id'))
        if not uid:
            return False
        seats[ts] = {
            'user_id': int(uid),
            'name': str(player.get('name') or self._mj_user_display_name(uid)).strip() or self._mj_user_display_name(uid),
            'ready': bool(player.get('ready')),
        }
        seats[fs] = None
        room['seats'] = seats[:MJ_SEATS]

        scores = dict(room.get('scores') or {})
        for i in range(MJ_SEATS):
            scores.setdefault(str(i), 0)
        scores[str(ts)] = int(scores.pop(str(fs), scores.get(str(ts), 0)) or 0)
        room['scores'] = scores

        if int(room.get('dealer_seat') or 0) == fs:
            room['dealer_seat'] = ts
        if room.get('current_seat') == fs:
            room['current_seat'] = ts

        for key in ('hands', 'melds', 'discards'):
            arr = list(room.get(key) or [])
            while len(arr) < MJ_SEATS:
                arr.append([])
            from_val = arr[fs] if fs < len(arr) else []
            to_val = arr[ts] if ts < len(arr) else []
            arr[fs] = to_val if isinstance(to_val, list) else []
            arr[ts] = from_val if isinstance(from_val, list) else []
            room[key] = arr[:MJ_SEATS]
        return True

    def _mj_new_room_code(self):
        alphabet = string.ascii_uppercase + string.digits
        for _ in range(200):
            code = ''.join(random.choice(alphabet) for _ in range(6))
            if not os.path.isfile(self._mj_room_path(code)):
                return code
        return ''.join(random.choice(alphabet) for _ in range(8))

    def _mj_cleanup_rooms(self):
        now = time.time()
        root = self._mj_rooms_dir()
        try:
            names = os.listdir(root)
        except Exception:
            return
        for name in names:
            if not name.endswith('.json'):
                continue
            path = os.path.join(root, name)
            try:
                if now - os.path.getmtime(path) > MJ_ROOM_TTL_SEC:
                    os.remove(path)
            except Exception:
                pass

    def _mj_build_wall(self):
        wall = []
        for suit in MJ_SUITS:
            for n in range(1, 10):
                t = f'{suit}{n}'
                wall.extend([t] * MJ_TILE_COPIES)
        for t in MJ_HONORS:
            wall.extend([t] * MJ_TILE_COPIES)
        random.shuffle(wall)
        return wall

    def _mj_tile_sort_key(self, t):
        if not t or len(t) < 2:
            return (9, 9, t)
        suit = t[0]
        try:
            num = int(t[1:])
        except Exception:
            num = 0
        suit_ord = 0 if suit == 'p' else (1 if suit == 's' else 2)
        return (suit_ord, num, t)

    def _mj_sort_tiles(self, tiles):
        return sorted(tiles, key=self._mj_tile_sort_key)

    def _mj_active_seats(self, room):
        seats = room.get('seats') or []
        out = []
        seen_uids = set()
        for i in range(MJ_SEATS):
            s = seats[i] if i < len(seats) else None
            if not isinstance(s, dict):
                continue
            uid = self._parse_int(s.get('user_id'))
            if uid and uid not in seen_uids:
                seen_uids.add(uid)
                out.append(i)
        return out

    def _mj_seat_of_user(self, room, user_id):
        uid = int(user_id)
        found = None
        for i in range(MJ_SEATS):
            s = (room.get('seats') or [None] * MJ_SEATS)[i]
            if isinstance(s, dict) and self._parse_int(s.get('user_id')) == uid:
                if found is None:
                    found = i
        return found

    def _mj_normalize_seats(self, room):
        """同一账号只保留一个座位，避免登出重进重复占位。"""
        seats = list(room.get('seats') or [])
        while len(seats) < MJ_SEATS:
            seats.append(None)
        seats = seats[:MJ_SEATS]
        seen = {}
        changed = False
        for i in range(MJ_SEATS):
            s = seats[i]
            if not isinstance(s, dict):
                if s is not None:
                    seats[i] = None
                    changed = True
                continue
            uid = self._parse_int(s.get('user_id'))
            if not uid:
                seats[i] = None
                changed = True
                continue
            if uid in seen:
                seats[i] = None
                changed = True
                continue
            seen[uid] = i
            name = self._mj_user_display_name(uid)
            if name and s.get('name') != name:
                s['name'] = name
                changed = True
            seats[i] = s
        if room.get('seats') != seats:
            room['seats'] = seats
            changed = True
        return changed

    def _mj_lobby_ready_summary(self, room):
        seats = room.get('seats') or []
        active = self._mj_active_seats(room)
        occ_count = len(active)
        all_ready = occ_count >= MJ_MIN_PLAYERS and all(
            isinstance((seats[i] if i < len(seats) else None), dict) and (seats[i] or {}).get('ready')
            for i in active
        )
        return {
            'occupied_count': occ_count,
            'all_ready': all_ready,
            'can_start': all_ready and occ_count >= MJ_MIN_PLAYERS,
        }

    def _mj_next_seat(self, room, seat):
        active = self._mj_active_seats(room)
        if not active:
            return seat
        if seat not in active:
            return active[0]
        idx = active.index(seat)
        return active[(idx + 1) % len(active)]

    def _mj_counter_after_remove(self, counter, tile, n):
        c = counter.copy()
        c[tile] -= n
        if c[tile] <= 0:
            del c[tile]
        return c

    def _mj_can_form_melds(self, counter):
        if not counter:
            return True
        tile = min(counter.keys(), key=self._mj_tile_sort_key)
        n = counter[tile]
        if n >= 3:
            if self._mj_can_form_melds(self._mj_counter_after_remove(counter, tile, 3)):
                return True
        suit = tile[0]
        if suit in MJ_SUITS and len(tile) >= 2:
            try:
                num = int(tile[1:])
            except Exception:
                num = -1
            if 1 <= num <= 7:
                t2 = f'{suit}{num + 1}'
                t3 = f'{suit}{num + 2}'
                if counter.get(t2, 0) > 0 and counter.get(t3, 0) > 0:
                    c = counter.copy()
                    for tt in (tile, t2, t3):
                        c[tt] -= 1
                        if c[tt] <= 0:
                            del c[tt]
                    if self._mj_can_form_melds(c):
                        return True
        return False

    def _mj_can_win(self, tiles):
        if len(tiles) % 3 != 2:
            return False
        c = Counter(tiles)
        for pair_tile in list(c.keys()):
            if c[pair_tile] < 2:
                continue
            rest = self._mj_counter_after_remove(c, pair_tile, 2)
            if self._mj_can_form_melds(rest):
                return True
        return False

    def _mj_hand_tile_list(self, room, seat):
        hands = room.get('hands') or [[], [], [], []]
        if seat < 0 or seat >= len(hands):
            return []
        return list(hands[seat] or [])

    def _mj_meld_tiles_flat(self, room, seat):
        melds = (room.get('melds') or [[], [], [], []])[seat] or []
        out = []
        for m in melds:
            out.extend(m.get('tiles') or [])
        return out

    def _mj_all_tiles_for_win(self, room, seat, extra=None):
        tiles = self._mj_hand_tile_list(room, seat) + self._mj_meld_tiles_flat(room, seat)
        if extra:
            tiles = tiles + [extra]
        return tiles

    def _mj_can_win_seat(self, room, seat, extra_tile=None):
        return self._mj_can_win(self._mj_all_tiles_for_win(room, seat, extra_tile))

    def _mj_draw_from_wall(self, room):
        pos = int(room.get('wall_pos') or 0)
        wall = room.get('wall') or []
        if pos >= len(wall):
            return None
        tile = wall[pos]
        room['wall_pos'] = pos + 1
        return tile

    def _mj_hand_scores(self, winner_seat, dealer_seat, active_seats):
        deltas = {str(s): 0 for s in active_seats}
        for s in active_seats:
            if s == winner_seat:
                continue
            pay = 1
            if winner_seat == dealer_seat:
                pay = 2
            elif s == dealer_seat:
                pay = 2
            deltas[str(s)] = int(deltas.get(str(s), 0)) - pay
            deltas[str(winner_seat)] = int(deltas.get(str(winner_seat), 0)) + pay
        return deltas

    def _mj_apply_hand_scores(self, room, winner_seat, win_type):
        dealer = int(room.get('dealer_seat') or 0)
        active = self._mj_active_seats(room)
        deltas = self._mj_hand_scores(winner_seat, dealer, active)
        scores = room.get('scores') or {}
        for k, v in deltas.items():
            scores[k] = int(scores.get(k, 0)) + int(v)
        room['scores'] = scores
        room['last_hand_result'] = {
            'winner_seat': winner_seat,
            'dealer_seat': dealer,
            'win_type': win_type,
            'deltas': deltas,
            'hand_no': int(room.get('hand_no') or 1),
        }
        room['status'] = 'hand_end'
        room['phase'] = 'hand_end'

    def _mj_roll_dealer_from_dice(self, room):
        """掷两枚骰子，按点数和在在座玩家中确定庄家座位。"""
        active = self._mj_active_seats(room)
        if not active:
            return 0
        d1 = random.randint(1, 6)
        d2 = random.randint(1, 6)
        total = d1 + d2
        idx = (total - 2) % len(active)
        dealer = active[idx]
        return d1, d2, total, dealer

    def _mj_begin_dealer_roll(self, room):
        active = self._mj_active_seats(room)
        if len(active) < MJ_MIN_PLAYERS:
            raise ValueError(f'至少需要 {MJ_MIN_PLAYERS} 人才能开局')
        d1, d2, total, dealer = self._mj_roll_dealer_from_dice(room)
        room['dealer_seat'] = dealer
        room['dice_roll'] = {
            'dice1': d1,
            'dice2': d2,
            'total': total,
            'dealer_seat': dealer,
        }
        room['status'] = 'dealer_roll'
        room['phase'] = 'dealer_roll'

    def _mj_start_hand(self, room):
        active = self._mj_active_seats(room)
        if len(active) < MJ_MIN_PLAYERS:
            raise ValueError(f'至少需要 {MJ_MIN_PLAYERS} 人才能开局')
        wall = self._mj_build_wall()
        hands = [[], [], [], []]
        dealer = int(room.get('dealer_seat') or 0)
        if dealer not in active:
            dealer = active[0]
        room['dealer_seat'] = dealer
        pos = 0
        for _ in range(13):
            for s in active:
                hands[s].append(wall[pos])
                pos += 1
        hands[dealer].append(wall[pos])
        pos += 1
        for s in range(MJ_SEATS):
            hands[s] = self._mj_sort_tiles(hands[s])
        room['wall'] = wall
        room['wall_pos'] = pos
        room['hands'] = hands
        room['melds'] = [[], [], [], []]
        room['discards'] = [[], [], [], []]
        room['last_discard'] = None
        room['claim_round'] = None
        room['current_seat'] = dealer
        room['phase'] = 'discard' if len(hands[dealer]) % 3 == 2 else 'draw'
        room['status'] = 'playing'
        room['last_hand_result'] = None
        room.pop('dice_roll', None)
        if room['phase'] == 'draw':
            self._mj_do_draw(room, dealer)

    def _mj_do_draw(self, room, seat):
        tile = self._mj_draw_from_wall(room)
        if tile is None:
            room['status'] = 'hand_end'
            room['phase'] = 'hand_end'
            room['last_hand_result'] = {'winner_seat': None, 'win_type': 'draw', 'deltas': {}}
            return
        hands = room.get('hands') or [[], [], [], []]
        hands[seat].append(tile)
        hands[seat] = self._mj_sort_tiles(hands[seat])
        room['hands'] = hands
        room['current_seat'] = seat
        if self._mj_can_win_seat(room, seat):
            room['pending_self_win'] = True
        room['phase'] = 'discard'

    def _mj_resolve_claims(self, room):
        cr = room.get('claim_round')
        if not isinstance(cr, dict):
            return
        discard_seat = int(cr.get('discard_seat', -1))
        tile = cr.get('tile')
        responses = cr.get('responses') or {}
        active = self._mj_active_seats(room)
        waiting = [s for s in active if s != discard_seat]
        if any(s not in responses for s in waiting):
            return

        def order_key(s):
            active_order = active
            base = active_order.index(discard_seat) if discard_seat in active_order else 0
            idx = (active_order.index(s) - base) % len(active_order)
            return idx

        priority = {'win': 3, 'kong': 2, 'pung': 1, 'pass': 0}
        best = None
        best_pri = -1
        best_ord = 99
        for s in waiting:
            act = responses.get(s) or 'pass'
            pri = priority.get(act, 0)
            if pri <= 0:
                continue
            ordv = order_key(s)
            if pri > best_pri or (pri == best_pri and ordv < best_ord):
                best_pri = pri
                best_ord = ordv
                best = (s, act)

        room['claim_round'] = None
        if not best:
            nxt = self._mj_next_seat(room, discard_seat)
            room['current_seat'] = nxt
            self._mj_do_draw(room, nxt)
            return

        seat, act = best
        if act == 'win':
            self._mj_apply_hand_scores(room, seat, 'ron')
            return
        hands = room.get('hands') or [[], [], [], []]
        melds = room.get('melds') or [[], [], [], []]
        discards = room.get('discards') or [[], [], [], []]
        if discard_seat >= 0 and discards[discard_seat]:
            discards[discard_seat].pop()
        if act == 'pung':
            removed = 0
            new_hand = []
            for t in hands[seat]:
                if t == tile and removed < 2:
                    removed += 1
                    continue
                new_hand.append(t)
            hands[seat] = self._mj_sort_tiles(new_hand)
            melds[seat].append({'type': 'pung', 'tiles': [tile] * 3, 'from_seat': discard_seat, 'open': True})
            room['hands'] = hands
            room['melds'] = melds
            room['discards'] = discards
            room['current_seat'] = seat
            room['phase'] = 'discard'
            return
        if act == 'kong':
            removed = 0
            new_hand = []
            for t in hands[seat]:
                if t == tile and removed < 3:
                    removed += 1
                    continue
                new_hand.append(t)
            hands[seat] = self._mj_sort_tiles(new_hand)
            melds[seat].append({'type': 'kong', 'tiles': [tile] * 4, 'from_seat': discard_seat, 'open': True})
            room['hands'] = hands
            room['melds'] = melds
            room['discards'] = discards
            room['current_seat'] = seat
            kong_draw = self._mj_draw_from_wall(room)
            if kong_draw:
                hands[seat].append(kong_draw)
                hands[seat] = self._mj_sort_tiles(hands[seat])
                room['hands'] = hands
            room['phase'] = 'discard'
            return

    def _mj_room_public(self, room, user_id):
        self._mj_normalize_seats(room)
        uid = int(user_id)
        my_seat = self._mj_seat_of_user(room, user_id)
        seats_pub = []
        for i in range(MJ_SEATS):
            s = (room.get('seats') or [None] * MJ_SEATS)[i]
            if not isinstance(s, dict):
                seats_pub.append(None)
                continue
            seats_pub.append({
                'seat': i,
                'user_id': self._parse_int(s.get('user_id')),
                'name': s.get('name') or '',
                'ready': bool(s.get('ready')),
                'is_host': self._parse_int(s.get('user_id')) == self._parse_int(room.get('host_user_id')),
                'avatar_url': self._mj_user_avatar_url(s.get('user_id')),
            })
        hands = room.get('hands') or [[], [], [], []]
        hand_counts = [len(hands[i] or []) for i in range(MJ_SEATS)]
        my_hand = self._mj_sort_tiles(list(hands[my_seat] or [])) if my_seat is not None else []
        claim = room.get('claim_round')
        claim_view = None
        if isinstance(claim, dict) and my_seat is not None:
            waiting = [s for s in self._mj_active_seats(room) if s != int(claim.get('discard_seat', -1))]
            claim_view = {
                'discard_seat': claim.get('discard_seat'),
                'tile': claim.get('tile'),
                'need_response': my_seat in waiting and my_seat not in (claim.get('responses') or {}),
                'options': [],
            }
            if claim_view['need_response']:
                tile = claim.get('tile')
                opts = ['pass']
                if self._mj_can_win_seat(room, my_seat, tile):
                    opts.append('win')
                hc = Counter(self._mj_hand_tile_list(room, my_seat))
                if hc.get(tile, 0) >= 2:
                    opts.append('pung')
                if hc.get(tile, 0) >= 3:
                    opts.append('kong')
                claim_view['options'] = opts
        dice_roll = None
        if room.get('status') == 'dealer_roll':
            dr = room.get('dice_roll') or {}
            ds = int(dr.get('dealer_seat', room.get('dealer_seat') or 0))
            dealer_name = ''
            for sp in seats_pub:
                if sp and int(sp.get('seat', -1)) == ds:
                    dealer_name = sp.get('name') or ''
                    break
            dice_roll = {
                'dice1': int(dr.get('dice1') or 0),
                'dice2': int(dr.get('dice2') or 0),
                'total': int(dr.get('total') or 0),
                'dealer_seat': ds,
                'dealer_name': dealer_name,
            }
        chat, chat_seq = self._wrc_chat_public(room, user_id)
        return {
            'code': room.get('code'),
            'version': int(room.get('version') or 0),
            'status': room.get('status'),
            'phase': room.get('phase'),
            'host_user_id': self._parse_int(room.get('host_user_id')),
            'seats': seats_pub,
            'my_seat': my_seat,
            'my_user_id': uid,
            'active_seats': self._mj_active_seats(room),
            'min_players': MJ_MIN_PLAYERS,
            'dealer_seat': int(room.get('dealer_seat') or 0),
            'current_seat': room.get('current_seat'),
            'scores': room.get('scores') or {},
            'hand_no': int(room.get('hand_no') or 1),
            'hand_counts': hand_counts,
            'my_hand': my_hand,
            'melds': room.get('melds') or [[], [], [], []],
            'discards': room.get('discards') or [[], [], [], []],
            'last_discard': room.get('last_discard'),
            'wall_remaining': max(0, len(room.get('wall') or []) - int(room.get('wall_pos') or 0)),
            'claim_round': claim_view,
            'pending_self_win': bool(room.get('pending_self_win')) and my_seat == room.get('current_seat'),
            'last_hand_result': room.get('last_hand_result'),
            'you_are_host': uid == self._parse_int(room.get('host_user_id')),
            'can_swap_seat': self._mj_can_swap_seat(room),
            'lobby': self._mj_lobby_ready_summary(room) if room.get('status') == 'lobby' else None,
            'dice_roll': dice_roll,
            'chat_messages': chat,
            'chat_seq': chat_seq,
        }

    def handle_mahjong_play_api(self, environ, method, start_response):
        user_id = self._get_session_user(environ)
        if not user_id:
            return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
        if not self._user_has_page_access(user_id, 'widgets_mahjong'):
            return self.send_json({'status': 'error', 'message': '无权限访问麻将'}, start_response)

        query = parse_qs(environ.get('QUERY_STRING', ''))
        data = (self._read_json_body(environ) or {}) if method != 'GET' else {}
        if method == 'GET':
            action = str((query.get('action') or [''])[0] or '').strip().lower()
        else:
            action = str(data.get('action') or '').strip().lower()

        if action in MJ_CLEANUP_ACTIONS:
            self._mj_cleanup_rooms()

        if action == 'create':
            return self._mj_action_create(user_id, start_response)
        if action == 'join':
            return self._mj_action_join(user_id, data, start_response)
        if action == 'leave':
            return self._mj_action_leave(user_id, data, start_response)
        if action == 'ready':
            return self._mj_action_ready(user_id, data, start_response)
        if action == 'start':
            return self._mj_action_start(user_id, data, start_response)
        if action == 'confirm_roll':
            return self._mj_action_confirm_roll(user_id, data, start_response)
        if action == 'state':
            return self._mj_action_state(user_id, query, start_response)
        if action == 'stream':
            return self._mj_action_stream(user_id, query, start_response)
        if action == 'wait':
            return self._mj_action_wait(user_id, query, start_response)
        if action == 'discard':
            return self._mj_action_discard(user_id, data, start_response)
        if action == 'claim':
            return self._mj_action_claim(user_id, data, start_response)
        if action == 'next_hand':
            return self._mj_action_next_hand(user_id, data, start_response)
        if action == 'chat_send':
            return self._mj_action_chat_send(user_id, data, start_response)
        if action == 'swap_seat':
            return self._mj_action_swap_seat(user_id, data, start_response)
        return self.send_json({'status': 'error', 'message': '未知操作'}, start_response)

    def _mj_action_chat_send(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if self._mj_seat_of_user(room, user_id) is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            name = self._mj_user_display_name(user_id)
            _, err_msg = self._wrc_chat_append(room, user_id, name, data.get('text'))
            if err_msg:
                return self.send_json({'status': 'error', 'message': err_msg}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_json_room(self, room, user_id, start_response, message=None):
        out = self._mj_room_public(room, user_id)
        out['status'] = 'success'
        if message:
            out['message'] = message
        return self.send_json(out, start_response)

    def _mj_action_create(self, user_id, start_response):
        code = self._mj_new_room_code()
        name = self._mj_user_display_name(user_id)
        seats = [None] * MJ_SEATS
        seats[0] = {'user_id': int(user_id), 'name': name, 'ready': True}
        room = {
            'code': code,
            'created_at': time.time(),
            'host_user_id': int(user_id),
            'status': 'lobby',
            'version': 1,
            'seats': seats,
            'scores': {str(i): 0 for i in range(MJ_SEATS)},
            'dealer_seat': 0,
            'hand_no': 1,
        }
        try:
            self._mj_write_room_file(room)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': f'创建房间失败：{e}'}, start_response)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_swap_seat(self, user_id, data, start_response):
        """大厅内点击空位可换座（仅空位）。"""
        code = str(data.get('room_code') or '').strip().upper()
        try:
            want = int(data.get('prefer_seat') if data.get('prefer_seat') is not None else data.get('seat'))
        except Exception:
            want = -1
        if want < 0 or want >= MJ_SEATS:
            return self.send_json({'status': 'error', 'message': '无效座位'}, start_response)
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if not self._mj_can_swap_seat(room):
                return self.send_json({'status': 'error', 'message': '对局已开始，无法换座'}, start_response)
            my_seat = self._mj_seat_of_user(room, user_id)
            if my_seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if my_seat == want:
                return self._mj_json_room(room, user_id, start_response, message='您已在该座位')
            if not self._mj_relocate_seat_player(room, my_seat, want):
                return self.send_json({'status': 'error', 'message': '该座位已有人或无法换座'}, start_response)
            self._mj_normalize_seats(room)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        with _mj_file_lock:
            room = self._mj_read_room_file(code)
        if not room:
            return self.send_json({'status': 'error', 'message': '房间已解散或已过期', 'room_dissolved': True}, start_response)
        if self._mj_seat_of_user(room, user_id) is None:
            return self.send_json({'status': 'error', 'message': '换座失败，请刷新后重试'}, start_response)
        return self._mj_json_room(room, user_id, start_response, message='已更换座位')

    def _mj_action_join(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'lobby':
                return self.send_json({'status': 'error', 'message': '对局已开始，无法加入'}, start_response)
            self._mj_normalize_seats(room)
            existing = self._mj_seat_of_user(room, user_id)
            seats = room.get('seats') or [None] * MJ_SEATS
            if existing is not None:
                seats[existing]['name'] = self._mj_user_display_name(user_id)
                self._mj_clear_user_duplicate_seats(seats, user_id, keep_seat=existing)
            else:
                self._mj_clear_user_duplicate_seats(seats, user_id, keep_seat=None)
                slot = None
                for i in range(MJ_SEATS):
                    if seats[i] is None:
                        slot = i
                        break
                if slot is None:
                    return self.send_json({'status': 'error', 'message': '房间座位已满'}, start_response)
                seats[slot] = {
                    'user_id': int(user_id),
                    'name': self._mj_user_display_name(user_id),
                    'ready': False,
                }
            room['seats'] = seats
            self._mj_normalize_seats(room)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_clear_user_duplicate_seats(self, seats, user_id, keep_seat=None):
        uid = int(user_id)
        for i in range(MJ_SEATS):
            if i == keep_seat:
                continue
            s = seats[i] if i < len(seats) else None
            if isinstance(s, dict) and self._parse_int(s.get('user_id')) == uid:
                seats[i] = None

    def _mj_vacate_seat_in_room(self, room, seat):
        """移出指定座位玩家；对局中会清空其手牌并必要时轮转当前出牌位。"""
        seats = list(room.get('seats') or [None] * MJ_SEATS)
        while len(seats) < MJ_SEATS:
            seats.append(None)
        seats[seat] = None
        room['seats'] = seats[:MJ_SEATS]
        if room.get('status') in ('playing', 'hand_end'):
            hands = list(room.get('hands') or [[], [], [], []])
            melds = list(room.get('melds') or [[], [], [], []])
            discards = list(room.get('discards') or [[], [], [], []])
            while len(hands) < MJ_SEATS:
                hands.append([])
            while len(melds) < MJ_SEATS:
                melds.append([])
            while len(discards) < MJ_SEATS:
                discards.append([])
            hands[seat] = []
            melds[seat] = []
            discards[seat] = []
            room['hands'] = hands
            room['melds'] = melds
            room['discards'] = discards
            if room.get('status') == 'playing':
                was_current = room.get('current_seat') == seat
                if room.get('pending_self_win') and was_current:
                    room['pending_self_win'] = False
                if was_current:
                    room['current_seat'] = self._mj_next_seat(room, seat)
                claim = room.get('claim_round')
                if isinstance(claim, dict):
                    resp = dict(claim.get('responses') or {})
                    resp.pop(seat, None)
                    claim['responses'] = resp
                    room['claim_round'] = claim

    def _mj_action_leave(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            is_host = int(user_id) == self._parse_int(room.get('host_user_id'))
            if is_host:
                self._mj_dissolve_room(code)
                return self.send_json({
                    'status': 'success',
                    'room_deleted': True,
                    'room_dissolved': True,
                    'left_room': True,
                    'message': '房间已解散',
                }, start_response)
            self._mj_vacate_seat_in_room(room, seat)
            if not self._mj_active_seats(room):
                self._mj_dissolve_room(code)
                return self.send_json({
                    'status': 'success',
                    'room_deleted': True,
                    'left_room': True,
                    'message': '已离开房间（房间已关闭）',
                }, start_response)
            if len(self._mj_active_seats(room)) < MJ_MIN_PLAYERS:
                self._mj_dissolve_room(code)
                return self.send_json({
                    'status': 'success',
                    'room_deleted': True,
                    'left_room': True,
                    'message': '已离开房间（人数不足，房间已关闭）',
                }, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self.send_json({
            'status': 'success',
            'left_room': True,
            'message': '已离开房间',
        }, start_response)

    def _mj_action_ready(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            seats = room.get('seats') or [None] * MJ_SEATS
            s = seats[seat]
            s['ready'] = bool(data.get('ready', True))
            seats[seat] = s
            room['seats'] = seats
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_start(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if int(user_id) != self._parse_int(room.get('host_user_id')):
                return self.send_json({'status': 'error', 'message': '仅房主可开局'}, start_response)
            if room.get('status') != 'lobby':
                return self.send_json({'status': 'error', 'message': '已在游戏中'}, start_response)
            active = self._mj_active_seats(room)
            if len(active) < MJ_MIN_PLAYERS:
                return self.send_json({'status': 'error', 'message': f'至少需要 {MJ_MIN_PLAYERS} 人'}, start_response)
            seats = room.get('seats') or []
            if not all(isinstance(seats[i], dict) and seats[i].get('ready') for i in active):
                return self.send_json({'status': 'error', 'message': '在座玩家须全部准备'}, start_response)
            try:
                self._mj_begin_dealer_roll(room)
            except ValueError as ex:
                return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_confirm_roll(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if int(user_id) != self._parse_int(room.get('host_user_id')):
                return self.send_json({'status': 'error', 'message': '仅房主可确认发牌'}, start_response)
            if room.get('status') != 'dealer_roll':
                return self.send_json({'status': 'error', 'message': '当前不在定庄阶段'}, start_response)
            try:
                self._mj_start_hand(room)
            except ValueError as ex:
                return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_state(self, user_id, query, start_response):
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        room = self._mj_read_room_retry(code)
        if not room:
            return self.send_json({
                'status': 'error',
                'message': '房间已解散或已过期',
                'room_dissolved': True,
            }, start_response)
        if self._mj_seat_of_user(room, user_id) is None:
            return self.send_json({
                'status': 'error',
                'message': '您不在该房间中',
                'left_room': True,
            }, start_response)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_wait(self, user_id, query, start_response):
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        try:
            since = int((query.get('since_version') or ['0'])[0] or 0)
        except Exception:
            since = 0
        waiter = _mj_register_waiter(code)
        try:
            deadline = time.time() + MJ_WAIT_TIMEOUT_SEC
            while time.time() < deadline:
                room = self._mj_read_room_retry(code)
                if not room:
                    return self.send_json({
                        'status': 'error',
                        'message': '房间已解散或已过期',
                        'room_dissolved': True,
                    }, start_response)
                if self._mj_seat_of_user(room, user_id) is None:
                    return self.send_json({
                        'status': 'error',
                        'message': '您不在该房间中',
                        'left_room': True,
                    }, start_response)
                ver = int(room.get('version') or 0)
                if ver > since:
                    return self._mj_json_room(room, user_id, start_response)
                waiter.clear()
                remaining = max(0.05, deadline - time.time())
                waiter.wait(timeout=min(MJ_WAIT_POLL_SEC, remaining))
        finally:
            _mj_unregister_waiter(code, waiter)
        room = self._mj_read_room_retry(code)
        if not room:
            return self.send_json({
                'status': 'error',
                'message': '房间已解散或已过期',
                'room_dissolved': True,
            }, start_response)
        if self._mj_seat_of_user(room, user_id) is None:
            return self.send_json({
                'status': 'error',
                'message': '您不在该房间中',
                'left_room': True,
            }, start_response)
        out = self._mj_room_public(room, user_id)
        out['status'] = 'success'
        out['unchanged'] = True
        return self.send_json(out, start_response)

    def _mj_action_stream(self, user_id, query, start_response):
        """SSE：房间 version 变化时推送 state 事件；客户端断线后自动重连。"""
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        try:
            since = int((query.get('since_version') or ['0'])[0] or 0)
        except Exception:
            since = 0
        if not code:
            return self.send_json({'status': 'error', 'message': '缺少房间号'}, start_response)

        room = self._mj_read_room_retry(code)
        if not room:
            return self.send_json({'status': 'error', 'message': '房间不存在或已过期'}, start_response)
        if self._mj_seat_of_user(room, user_id) is None:
            return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)

        uid = int(user_id)

        def generate():
            yield b': connected\n\n'
            waiter = _mj_register_waiter(code)
            since_local = since
            started = time.time()
            last_ping = started
            try:
                while time.time() - started < MJ_STREAM_SESSION_SEC:
                    room_now = self._mj_read_room_retry(code)
                    if not room_now:
                        yield self._sse_event('room_dissolved', {
                            'status': 'error',
                            'message': '房间已解散或已过期',
                            'room_dissolved': True,
                        })
                        return
                    if self._mj_seat_of_user(room_now, uid) is None:
                        # 换座等操作后可能短暂不同步，再读一次再判定
                        room_retry = self._mj_read_room_retry(code, attempts=2)
                        if room_retry and self._mj_seat_of_user(room_retry, uid) is not None:
                            room_now = room_retry
                        else:
                            yield self._sse_event('room_error', {'status': 'error', 'message': '您不在该房间中'})
                            return
                    ver = int(room_now.get('version') or 0)
                    if ver > since_local:
                        payload = self._mj_room_public(room_now, uid)
                        payload['status'] = 'success'
                        payload['version'] = ver
                        yield self._sse_event('state', payload)
                        since_local = ver
                    now = time.time()
                    if now - last_ping >= MJ_STREAM_PING_SEC:
                        yield self._sse_event('ping', {'t': int(now)})
                        last_ping = now
                    waiter.clear()
                    remaining = max(0.05, MJ_STREAM_SESSION_SEC - (now - started))
                    waiter.wait(timeout=min(MJ_WAIT_POLL_SEC, remaining))
            finally:
                _mj_unregister_waiter(code, waiter)

        return self.send_sse_stream(start_response, generate())

    def _mj_action_discard(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        tile = str(data.get('tile') or '').strip()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if room.get('status') != 'playing' or room.get('phase') != 'discard':
                return self.send_json({'status': 'error', 'message': '当前不能打牌'}, start_response)
            if int(room.get('current_seat', -1)) != seat:
                return self.send_json({'status': 'error', 'message': '未轮到您出牌'}, start_response)
            hands = room.get('hands') or [[], [], [], []]
            if tile not in (hands[seat] or []):
                return self.send_json({'status': 'error', 'message': '手牌中没有该牌'}, start_response)
            hands[seat].remove(tile)
            hands[seat] = self._mj_sort_tiles(hands[seat])
            discards = room.get('discards') or [[], [], [], []]
            discards[seat].append(tile)
            room['hands'] = hands
            room['discards'] = discards
            room['last_discard'] = {'seat': seat, 'tile': tile}
            room['pending_self_win'] = False
            active = self._mj_active_seats(room)
            waiting = [s for s in active if s != seat]
            if not waiting:
                return self.send_json({'status': 'error', 'message': '玩家不足'}, start_response)
            room['claim_round'] = {
                'discard_seat': seat,
                'tile': tile,
                'responses': {},
            }
            room['phase'] = 'claim'
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_claim(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        claim_type = str(data.get('type') or '').strip().lower()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)

            if room.get('pending_self_win') and int(room.get('current_seat', -1)) == seat:
                if claim_type == 'win':
                    if not self._mj_can_win_seat(room, seat):
                        return self.send_json({'status': 'error', 'message': '不能胡牌'}, start_response)
                    self._mj_apply_hand_scores(room, seat, 'tsumo')
                    room['pending_self_win'] = False
                    self._mj_bump_version(room)
                    self._mj_save_room(room)
                    return self._mj_json_room(room, user_id, start_response)
                if claim_type == 'pass':
                    room['pending_self_win'] = False
                    self._mj_bump_version(room)
                    self._mj_save_room(room)
                    return self._mj_json_room(room, user_id, start_response)
                return self.send_json({'status': 'error', 'message': '请先选择胡或过'}, start_response)

            cr = room.get('claim_round')
            if not isinstance(cr, dict) or room.get('phase') != 'claim':
                return self.send_json({'status': 'error', 'message': '当前无碰杠胡请求'}, start_response)
            discard_seat = int(cr.get('discard_seat', -1))
            if seat == discard_seat:
                return self.send_json({'status': 'error', 'message': '出牌者不能响应'}, start_response)
            if claim_type not in ('win', 'pung', 'kong', 'pass'):
                return self.send_json({'status': 'error', 'message': '无效操作'}, start_response)
            tile = cr.get('tile')
            if claim_type == 'win' and not self._mj_can_win_seat(room, seat, tile):
                return self.send_json({'status': 'error', 'message': '不能胡牌'}, start_response)
            hc = Counter(self._mj_hand_tile_list(room, seat))
            if claim_type == 'pung' and hc.get(tile, 0) < 2:
                return self.send_json({'status': 'error', 'message': '不能碰'}, start_response)
            if claim_type == 'kong' and hc.get(tile, 0) < 3:
                return self.send_json({'status': 'error', 'message': '不能杠'}, start_response)
            responses = cr.get('responses') or {}
            responses[seat] = claim_type
            cr['responses'] = responses
            room['claim_round'] = cr
            self._mj_resolve_claims(room)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_next_hand(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if int(user_id) != self._parse_int(room.get('host_user_id')):
                return self.send_json({'status': 'error', 'message': '仅房主可开下一局'}, start_response)
            if room.get('status') not in ('hand_end',):
                return self.send_json({'status': 'error', 'message': '本局未结束'}, start_response)
            last = room.get('last_hand_result') or {}
            w = last.get('winner_seat')
            if w is not None and last.get('win_type') in ('ron', 'tsumo'):
                room['dealer_seat'] = int(w)
            else:
                room['dealer_seat'] = self._mj_next_seat(room, int(room.get('dealer_seat') or 0))
            room['hand_no'] = int(room.get('hand_no') or 1) + 1
            room['pending_self_win'] = False
            room['claim_round'] = None
            try:
                self._mj_start_hand(room)
            except ValueError as ex:
                return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)
