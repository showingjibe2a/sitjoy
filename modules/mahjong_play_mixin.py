"""在线麻将（小组件）：规则预设、三人起局；积分与员工昵称；房间文件 + 长轮询。"""

from modules.mahjong_rules import (
    MJ_PRESET_HANGZHOU,
    MJ_PRESET_STANDARD,
    mj_dealer_streak_multiplier,
    mj_hz_pattern_code,
    mj_hz_pattern_label,
    mj_hz_pattern_multiplier,
    mj_normalize_preset,
    mj_preset_public_list,
    mj_rules_for_preset,
)
from modules.widget_room_chat_mixin import WidgetRoomChatMixin

import json
import os
import random
import shutil
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
MJ_WAIT_POLL_SEC = 0.08
MJ_STREAM_SESSION_SEC = 300
MJ_STREAM_PING_SEC = 12
MJ_DEALER_REVEAL_SEC = 2
MJ_TILE_COPIES = 4
MJ_TOTAL_TILES = 136

# 万(w)、筒(p)、条(s)、字(z1-7 东南西北中发白)，共 136 张
MJ_SUITS = ('w', 'p', 's')
MJ_HONORS = tuple(f'z{i}' for i in range(1, 8))

MJ_CLEANUP_ACTIONS = frozenset({
    'create', 'join', 'leave', 'ready', 'start', 'confirm_roll', 'roll_dice', 'rejoin', 'state', 'wait',
    'discard', 'claim', 'self_kong', 'next_hand', 'chat_send', 'swap_seat', 'set_rule_preset',
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
        if isinstance(room, dict) and room.get('status') == 'playing':
            self._mj_sync_pending_self_win(room)
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
            # 网络盘/SMB 上 replace 可能失败：禁止先删原文件，避免房间「消失」
            copied = False
            try:
                shutil.copy2(tmp, path)
                copied = True
            except Exception:
                pass
            try:
                os.remove(tmp)
            except Exception:
                pass
            if not copied:
                try:
                    os.rename(tmp, path)
                except Exception:
                    pass
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
        """读取房间并去重座位；若有修正则写回（读路径不写庄家位，避免换座后频繁覆写文件）。"""
        code = str(code or '').strip().upper()
        with _mj_file_lock:
            room = self._mj_read_room_file(code) if code else None
            if not room:
                return None
            if self._mj_normalize_seats(room):
                self._mj_write_room_file_unlocked(room)
            elif room.get('status') == 'playing':
                old = room.get('pending_self_win')
                self._mj_sync_pending_self_win(room)
                if room.get('pending_self_win') != old:
                    self._mj_write_room_file_unlocked(room)
            return room

    def _mj_read_room_retry(self, code, attempts=5):
        """读取房间文件，短暂重试以避免并发写入时误判房间不存在。"""
        code = str(code or '').strip().upper()
        if not code:
            return None
        last = None
        tries = max(1, int(attempts or 1))
        for i in range(tries):
            last = self._mj_read_room_normalized(code)
            if last is not None:
                return last
            if i + 1 < tries:
                time.sleep(0.06 * (i + 1))
        return last

    def _mj_read_room_for_user(self, code, user_id, attempts=5):
        """读取房间并确认用户仍在座；换座/SSE 同步时避免短暂误判不在房间。"""
        code = str(code or '').strip().upper()
        uid = self._parse_int(user_id) or 0
        if not code or not uid:
            return None
        tries = max(1, int(attempts or 1))
        last = None
        for i in range(tries):
            last = self._mj_read_room_retry(code, attempts=3)
            if last and self._mj_seat_of_user(last, uid) is not None:
                return last
            if i + 1 < tries:
                time.sleep(0.06 * (i + 1))
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

    def _mj_host_seat(self, room):
        return self._mj_seat_of_user(room, room.get('host_user_id'))

    def _mj_sync_lobby_dealer_seat(self, room):
        """大厅阶段庄家位跟随房主（首局仍由骰子重新定庄）。"""
        if str(room.get('status') or '') != 'lobby':
            return False
        host_seat = self._mj_host_seat(room)
        if host_seat is None:
            return False
        if int(room.get('dealer_seat') or -1) == int(host_seat):
            return False
        room['dealer_seat'] = int(host_seat)
        return True

    def _mj_pick_join_seat(self, room, seats=None):
        """从房主顺时针找第一个空位，避免新玩家落到旧东位/空庄位。"""
        if seats is None:
            seats = list(room.get('seats') or [None] * MJ_SEATS)
        else:
            seats = list(seats)
        while len(seats) < MJ_SEATS:
            seats.append(None)
        host_seat = self._mj_host_seat(room)
        order = []
        if host_seat is not None:
            for k in range(1, MJ_SEATS):
                order.append((int(host_seat) + k) % MJ_SEATS)
        else:
            order = list(range(MJ_SEATS))
        for i in order:
            if not isinstance(seats[i], dict):
                return i
        return None

    def _mj_after_lobby_seating_change(self, room):
        """入座/换座/清理后：去重座位并同步大厅庄家位。"""
        changed = self._mj_normalize_seats(room)
        if self._mj_sync_lobby_dealer_seat(room):
            changed = True
        return changed

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

        in_lobby = str(room.get('status') or '') == 'lobby'
        if not in_lobby:
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
        suit_ord = {'w': 0, 'p': 1, 's': 2}.get(suit, 3)
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

    def _mj_seat_waits_next_hand(self, room, seat):
        if room.get('status') not in ('playing', 'dealer_roll'):
            return False
        s = (room.get('seats') or [None] * MJ_SEATS)[seat]
        return isinstance(s, dict) and bool(s.get('waits_next_hand'))

    def _mj_playing_seats(self, room):
        active = self._mj_active_seats(room)
        if room.get('status') not in ('playing', 'dealer_roll'):
            return active
        playing = [s for s in active if not self._mj_seat_waits_next_hand(room, s)]
        return playing if playing else active

    def _mj_set_join_notice(self, room, seat, user_id, name):
        self._mj_bump_version(room)
        display = str(name or '').strip() or '新玩家'
        room['join_notice'] = {
            'seat': int(seat),
            'user_id': int(user_id),
            'name': display,
            'message': f'{display} 已入座，将于下局加入对局',
            'at_version': int(room.get('version') or 0),
        }

    def _mj_put_user_in_seat(self, room, user_id, slot, *, waits_next=False):
        uid = int(user_id)
        name = self._mj_user_display_name(uid)
        seats = list(room.get('seats') or [None] * MJ_SEATS)
        while len(seats) < MJ_SEATS:
            seats.append(None)
        entry = {
            'user_id': uid,
            'name': name,
            'ready': False,
        }
        if waits_next:
            entry['waits_next_hand'] = True
        seats[int(slot)] = entry
        room['seats'] = seats[:MJ_SEATS]
        return name

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
        active = self._mj_playing_seats(room)
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

    def _mj_is_hangzhou(self, room):
        return mj_normalize_preset((room or {}).get('rule_preset')) == MJ_PRESET_HANGZHOU

    def _mj_hz_seat_state(self, room, seat):
        if not self._mj_is_hangzhou(room):
            return None
        meta = room.setdefault('hz_meta', {})
        key = str(seat)
        if key not in meta:
            meta[key] = {'joker_disc_streak': 0, 'after_kong_draw': False}
        return meta[key]

    def _mj_hz_on_discard(self, room, seat, tile):
        st = self._mj_hz_seat_state(room, seat)
        if st is None:
            return
        jokers = self._mj_joker_tiles(room)
        if tile in jokers:
            st['joker_disc_streak'] = int(st.get('joker_disc_streak') or 0) + 1
        else:
            st['joker_disc_streak'] = 0
        st['after_kong_draw'] = False

    def _mj_hz_on_normal_draw(self, room, seat):
        st = self._mj_hz_seat_state(room, seat)
        if st is not None:
            st['after_kong_draw'] = False

    def _mj_hz_on_kong_draw(self, room, seat):
        st = self._mj_hz_seat_state(room, seat)
        if st is not None:
            st['after_kong_draw'] = True

    def _mj_is_baotou_wait(self, room, seat, exclude_drawn=None):
        """摸牌前：1 财神 + 4 组面子（12 张），摸任意牌可胡。"""
        if not self._mj_is_hangzhou(room):
            return False
        hand = list(self._mj_hand_tile_list(room, seat))
        if exclude_drawn and exclude_drawn in hand:
            hand.remove(exclude_drawn)
        tiles = hand + self._mj_meld_tiles_flat(room, seat)
        jokers = self._mj_joker_tiles(room)
        counter, j = self._mj_counter_jokers(Counter(tiles), jokers)
        if j != 1:
            return False
        if not counter:
            return False
        return sum(counter.values()) % 3 == 0 and self._mj_can_form_melds_joker(counter, 0)

    def _mj_hz_classify_tsumo(self, room, seat):
        dt = room.get('drawn_tile') or {}
        exclude = dt.get('tile') if int(dt.get('seat', -1)) == seat else None
        is_baotou = self._mj_is_baotou_wait(room, seat, exclude_drawn=exclude)
        st = self._mj_hz_seat_state(room, seat) or {}
        streak = int(st.get('joker_disc_streak') or 0)
        after_kong = bool(st.get('after_kong_draw'))
        mult = mj_hz_pattern_multiplier(is_baotou, streak, after_kong)
        code = mj_hz_pattern_code(is_baotou, streak, after_kong)
        return code, mult, mj_hz_pattern_label(code)

    def _mj_win_option_entry(self, room, win_type, pattern_code, pattern_mult, pattern_label):
        rules = self._mj_rules(room)
        streak = int(room.get('dealer_streak') or 0)
        dealer_mult = mj_dealer_streak_multiplier(streak) if rules.get('dealer_streak_scoring') else None
        pm = int(pattern_mult or 1)
        if win_type == 'tsumo':
            label = '自摸'
        else:
            label = '胡'
        if rules.get('hz_special_patterns') and pattern_label:
            label += ' · ' + pattern_label
        elif win_type == 'tsumo':
            label = '自摸胡'
        if pm > 1:
            label += ' ×' + str(pm)
        if dealer_mult and int(dealer_mult) > 1:
            label += '（连庄 ×' + str(int(dealer_mult)) + '）'
        return {
            'type': 'win',
            'win_type': win_type,
            'pattern_code': pattern_code or '',
            'pattern_label': pattern_label or '',
            'pattern_mult': pm,
            'dealer_mult': dealer_mult,
            'sort_mult': pm * (int(dealer_mult) if dealer_mult else 1),
            'label': label,
        }

    def _mj_sort_win_options(self, options):
        return sorted(
            list(options or []),
            key=lambda o: int(o.get('sort_mult') or o.get('pattern_mult') or 1),
            reverse=True,
        )

    def _mj_hz_tsumo_pattern_pick(self, room, seat, pattern_code=None):
        options = self._mj_sort_win_options(self._mj_hz_tsumo_win_options(room, seat))
        code = str(pattern_code or '').strip()
        if code:
            for o in options:
                if o.get('pattern_code') == code:
                    return o['pattern_code'], int(o['pattern_mult'] or 1), o.get('pattern_label') or ''
        if options:
            o = options[0]
            return o['pattern_code'], int(o['pattern_mult'] or 1), o.get('pattern_label') or ''
        return self._mj_hz_classify_tsumo(room, seat)

    def _mj_hz_tsumo_win_options(self, room, seat):
        dt = room.get('drawn_tile') or {}
        exclude = dt.get('tile') if int(dt.get('seat', -1)) == seat else None
        st = self._mj_hz_seat_state(room, seat) or {}
        streak = int(st.get('joker_disc_streak') or 0)
        after_kong = bool(st.get('after_kong_draw'))
        options = []
        seen_codes = set()
        for is_baotou in (True, False):
            if is_baotou:
                if not self._mj_is_baotou_wait(room, seat, exclude_drawn=exclude):
                    continue
            elif self._mj_is_baotou_wait(room, seat, exclude_drawn=exclude):
                continue
            code = mj_hz_pattern_code(is_baotou, streak, after_kong)
            if code in seen_codes:
                continue
            seen_codes.add(code)
            mult = mj_hz_pattern_multiplier(is_baotou, streak, after_kong)
            options.append(self._mj_win_option_entry(
                room, 'tsumo', code, mult, mj_hz_pattern_label(code),
            ))
        if not options:
            code, mult, plabel = self._mj_hz_classify_tsumo(room, seat)
            options.append(self._mj_win_option_entry(room, 'tsumo', code, mult, plabel))
        return self._mj_sort_win_options(options)

    def _mj_self_win_options(self, room, seat):
        if seat is None or not self._mj_can_win_seat(room, seat):
            return []
        rules = self._mj_rules(room)
        if rules.get('hz_special_patterns'):
            return self._mj_hz_tsumo_win_options(room, seat)
        return self._mj_sort_win_options([
            self._mj_win_option_entry(room, 'tsumo', 'pinghu', 1, '平胡'),
        ])

    def _mj_ron_win_options(self, room, seat, tile):
        if not self._mj_can_win_seat(room, seat, tile):
            return []
        return self._mj_sort_win_options([
            self._mj_win_option_entry(room, 'ron', 'pinghu', 1, '平胡'),
        ])

    def _mj_snapshot_reveal_hands(self, room):
        hands = room.get('hands') or [[], [], [], []]
        melds = room.get('melds') or [[], [], [], []]
        seats_raw = room.get('seats') or [None] * MJ_SEATS
        rows = []
        for i in range(MJ_SEATS):
            sp = seats_raw[i] if i < len(seats_raw) else None
            if not isinstance(sp, dict):
                continue
            seat_melds = []
            for m in (melds[i] if i < len(melds) else []) or []:
                if not isinstance(m, dict):
                    continue
                md = dict(m)
                md.pop('tiles_hidden', None)
                seat_melds.append(md)
            rows.append({
                'seat': i,
                'name': sp.get('name') or '',
                'hand': self._mj_sort_tiles(list((hands[i] if i < len(hands) else []) or [])),
                'melds': seat_melds,
            })
        return {'seats': rows}

    def _mj_attach_hand_reveal(self, room):
        last = room.get('last_hand_result')
        if not isinstance(last, dict) or last.get('reveal_hands'):
            return
        last['reveal_hands'] = self._mj_snapshot_reveal_hands(room)
        room['last_hand_result'] = last

    def _mj_scale_deltas(self, deltas, factor):
        f = int(factor or 1)
        if f <= 1:
            return dict(deltas or {})
        return {k: int(v) * f for k, v in (deltas or {}).items()}

    def _mj_rules(self, room):
        preset = mj_normalize_preset((room or {}).get('rule_preset'))
        rules = mj_rules_for_preset(preset)
        rules['joker_tiles'] = frozenset(rules.get('joker_tiles') or ())
        return rules

    def _mj_joker_tiles(self, room):
        return self._mj_rules(room).get('joker_tiles') or frozenset()

    def _mj_can_win(self, tiles, joker_tiles=None):
        jokers = frozenset(joker_tiles or ())
        if not jokers:
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
        return self._mj_can_win_with_jokers(tiles, jokers)

    def _mj_counter_jokers(self, counter, joker_tiles):
        c = counter.copy()
        j = 0
        for t in joker_tiles:
            j += int(c.pop(t, 0) or 0)
        return c, j

    def _mj_try_sequence_joker(self, counter, jokers, seq_tiles):
        c = counter.copy()
        j = jokers
        for t in seq_tiles:
            if c.get(t, 0) > 0:
                c[t] -= 1
                if c[t] <= 0:
                    del c[t]
            elif j > 0:
                j -= 1
            else:
                return False
        return self._mj_can_form_melds_joker(c, j)

    def _mj_can_form_melds_joker(self, counter, jokers):
        total = sum(counter.values()) + jokers
        if total == 0:
            return True
        if total % 3 != 0:
            return False
        if not counter:
            return jokers >= 0 and jokers % 3 == 0
        tile = min(counter.keys(), key=self._mj_tile_sort_key)
        n = counter[tile]
        for j_use in range(0, min(3, jokers) + 1):
            need = 3 - j_use
            if n >= need:
                c = counter.copy()
                c[tile] -= need
                if c[tile] <= 0:
                    del c[tile]
                if self._mj_can_form_melds_joker(c, jokers - j_use):
                    return True
        suit = tile[0]
        if suit in MJ_SUITS and len(tile) >= 2:
            try:
                num = int(tile[1:])
            except Exception:
                num = -1
            if 1 <= num <= 9:
                for start in (num - 2, num - 1, num):
                    if start < 1 or start > 7:
                        continue
                    seq = [f'{suit}{start}', f'{suit}{start + 1}', f'{suit}{start + 2}']
                    if self._mj_try_sequence_joker(counter, jokers, seq):
                        return True
        return False

    def _mj_can_win_with_jokers(self, tiles, joker_tiles):
        if len(tiles) % 3 != 2:
            return False
        counter, jokers = self._mj_counter_jokers(Counter(tiles), joker_tiles)
        if jokers >= 2 and self._mj_can_form_melds_joker(counter, jokers - 2):
            return True
        for pair_tile in list(counter.keys()):
            n = counter[pair_tile]
            if n >= 2:
                rest = self._mj_counter_after_remove(counter, pair_tile, 2)
                if self._mj_can_form_melds_joker(rest, jokers):
                    return True
            if n >= 1 and jokers >= 1:
                rest = self._mj_counter_after_remove(counter, pair_tile, 1)
                if self._mj_can_form_melds_joker(rest, jokers - 1):
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

    def _mj_meld_for_viewer(self, meld, viewer_seat, owner_seat):
        """暗杠仅对本人返回牌面，他人只见牌背。"""
        if not isinstance(meld, dict):
            return meld
        if meld.get('type') == 'kong' and not meld.get('open', True):
            if viewer_seat is None or int(viewer_seat) != int(owner_seat):
                tiles = meld.get('tiles') or []
                return {
                    'type': 'kong',
                    'open': False,
                    'kong_kind': meld.get('kong_kind') or 'concealed',
                    'tiles_hidden': True,
                    'tile_count': len(tiles) or 4,
                }
        return dict(meld)

    def _mj_melds_for_viewer(self, room, viewer_seat):
        raw = room.get('melds') or [[], [], [], []]
        out = []
        for seat_idx in range(MJ_SEATS):
            seat_melds = (raw[seat_idx] if seat_idx < len(raw) else None) or []
            out.append([
                self._mj_meld_for_viewer(m, viewer_seat, seat_idx)
                for m in seat_melds
            ])
        return out

    def _mj_self_kong_options(self, room, seat):
        """当前回合可声明的暗杠（四张在手）与补杠（已碰 + 第四张在手）。"""
        hands = room.get('hands') or [[], [], [], []]
        if seat < 0 or seat >= len(hands):
            return {'concealed': [], 'added': []}
        hand = list(hands[seat] or [])
        hc = Counter(hand)
        concealed = sorted(
            [t for t, n in hc.items() if n >= 4],
            key=self._mj_tile_sort_key,
        )
        added = []
        melds = (room.get('melds') or [[], [], [], []])[seat] or []
        seen = set()
        for m in melds:
            if m.get('type') != 'pung':
                continue
            tile = m.get('called_tile') or (m.get('tiles') or [None])[0]
            if not tile or tile in seen:
                continue
            if hc.get(tile, 0) >= 1:
                added.append(tile)
                seen.add(tile)
        added.sort(key=self._mj_tile_sort_key)
        return {'concealed': concealed, 'added': added}

    def _mj_finish_kong_turn(self, room, seat):
        """杠后补牌，进入出牌阶段（可自摸胡）。"""
        self._mj_hz_on_kong_draw(room, seat)
        kong_draw = self._mj_draw_from_wall(room)
        hands = room.get('hands') or [[], [], [], []]
        room.pop('pending_self_win', None)
        if kong_draw:
            hands[seat].append(kong_draw)
            hands[seat] = self._mj_sort_tiles(hands[seat])
            room['hands'] = hands
            room['drawn_tile'] = {'seat': seat, 'tile': kong_draw}
            if self._mj_can_win_seat(room, seat):
                room['pending_self_win'] = True
        room['current_seat'] = seat
        room['phase'] = 'discard'

    def _mj_all_tiles_for_win(self, room, seat, extra=None):
        tiles = self._mj_hand_tile_list(room, seat) + self._mj_meld_tiles_flat(room, seat)
        if extra:
            tiles = tiles + [extra]
        return tiles

    def _mj_meld_group_count(self, room, seat):
        melds = (room.get('melds') or [[], [], [], []])[seat] or []
        return len(melds)

    def _mj_hand_tiles_for_win(self, room, seat, extra_tile=None):
        hand = list(self._mj_hand_tile_list(room, seat))
        if extra_tile:
            hand.append(extra_tile)
        return hand

    def _mj_can_win_seat(self, room, seat, extra_tile=None):
        """胡牌判定：仅对手牌（及点炮牌）做 3n+2 分解，副露组数计入 4 组面子。"""
        hand = self._mj_hand_tiles_for_win(room, seat, extra_tile)
        meld_groups = self._mj_meld_group_count(room, seat)
        if meld_groups > 4:
            return False
        expected_len = (4 - meld_groups) * 3 + 2
        if len(hand) != expected_len:
            return False
        jokers = self._mj_joker_tiles(room)
        return self._mj_can_win(hand, jokers)

    def _mj_my_turn_can_self_win(self, room, seat):
        if seat is None:
            return False
        if room.get('status') != 'playing' or room.get('phase') != 'discard':
            return False
        if room.get('claim_round'):
            return False
        if int(room.get('current_seat', -1)) != int(seat):
            return False
        return self._mj_can_win_seat(room, seat)

    def _mj_sync_pending_self_win(self, room):
        seat = room.get('current_seat')
        if seat is None or not self._mj_my_turn_can_self_win(room, int(seat)):
            room.pop('pending_self_win', None)
            return
        room['pending_self_win'] = True

    def _mj_hand_scores(self, winner_seat, dealer_seat, active_seats, rules=None, dealer_streak=0):
        rules = rules or mj_rules_for_preset(MJ_PRESET_STANDARD)
        if rules.get('dealer_streak_scoring'):
            mult = mj_dealer_streak_multiplier(dealer_streak)
            deltas = {str(s): 0 for s in active_seats}
            for s in active_seats:
                if s == winner_seat:
                    continue
                if winner_seat == dealer_seat:
                    pay = mult
                elif s == dealer_seat:
                    pay = mult
                else:
                    pay = 1
                deltas[str(s)] = int(deltas.get(str(s), 0)) - pay
                deltas[str(winner_seat)] = int(deltas.get(str(winner_seat), 0)) + pay
            return deltas
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

    def _mj_apply_kong_score(self, room, kong_seat, kong_kind):
        """杠牌即时计分：明杠（含补杠、点杠）每家付 1 分，暗杠每家付 2 分。"""
        active = self._mj_playing_seats(room)
        if kong_seat not in active:
            return
        pay = 2 if str(kong_kind or '').strip().lower() == 'concealed' else 1
        scores = dict(room.get('scores') or {})
        gain = 0
        for s in active:
            if s == kong_seat:
                continue
            key = str(s)
            scores[key] = int(scores.get(key, 0)) - pay
            gain += pay
        if gain:
            kkey = str(kong_seat)
            scores[kkey] = int(scores.get(kkey, 0)) + gain
            room['scores'] = scores

    def _mj_apply_hand_scores(self, room, winner_seat, win_type, pattern_code=None):
        dealer = int(room.get('dealer_seat') or 0)
        active = self._mj_playing_seats(room)
        rules = self._mj_rules(room)
        streak = int(room.get('dealer_streak') or 0)
        mult = mj_dealer_streak_multiplier(streak) if rules.get('dealer_streak_scoring') else None
        deltas = self._mj_hand_scores(winner_seat, dealer, active, rules, streak)
        pattern_label = ''
        pattern_mult = 1
        picked_code = ''
        if rules.get('hz_special_patterns') and win_type == 'tsumo':
            picked_code, pattern_mult, pattern_label = self._mj_hz_tsumo_pattern_pick(
                room, winner_seat, pattern_code,
            )
            deltas = self._mj_scale_deltas(deltas, pattern_mult)
        else:
            picked_code = str(pattern_code or '').strip() or 'pinghu'
            if picked_code == 'pinghu':
                pattern_label = '平胡'
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
            'dealer_streak': streak,
            'dealer_mult': mult,
            'hand_pattern': picked_code,
            'hand_pattern_label': pattern_label,
            'pattern_mult': pattern_mult,
        }
        self._mj_enter_hand_end_lobby(room)

    def _mj_draw_from_wall(self, room):
        pos = int(room.get('wall_pos') or 0)
        wall = room.get('wall') or []
        if pos >= len(wall):
            return None
        tile = wall[pos]
        room['wall_pos'] = pos + 1
        return tile

    def _mj_enter_hand_end_lobby(self, room):
        """本局结束：清牌桌、全员取消准备，等待下局。"""
        self._mj_attach_hand_reveal(room)
        last = room.get('last_hand_result') or {}
        w = last.get('winner_seat')
        rules = self._mj_rules(room)
        dealer = int(room.get('dealer_seat') or 0)
        streak = int(room.get('dealer_streak') or 0)
        win_type = last.get('win_type')
        if win_type == 'draw':
            if rules.get('dealer_streak_on_draw'):
                room['dealer_streak'] = min(2, streak + 1)
            else:
                room['dealer_seat'] = self._mj_next_seat(room, dealer)
                room['dealer_streak'] = 0
        elif w is not None and win_type == 'tsumo':
            if int(w) == dealer and rules.get('dealer_streak_on_dealer_win'):
                room['dealer_streak'] = min(2, streak + 1)
            else:
                room['dealer_seat'] = int(w)
                room['dealer_streak'] = 0
        elif w is not None and win_type == 'ron':
            room['dealer_seat'] = int(w)
            room['dealer_streak'] = 0
        room.pop('join_notice', None)
        seats = room.get('seats') or [None] * MJ_SEATS
        for i in range(MJ_SEATS):
            s = seats[i]
            if isinstance(s, dict):
                s.pop('waits_next_hand', None)
                s['ready'] = False
                seats[i] = s
        room['seats'] = seats
        room['hands'] = [[], [], [], []]
        room['melds'] = [[], [], [], []]
        room['discards'] = [[], [], [], []]
        room.pop('last_discard', None)
        room.pop('drawn_tile', None)
        room.pop('claim_round', None)
        room.pop('pending_self_win', None)
        room.pop('current_seat', None)
        room.pop('wall', None)
        room.pop('wall_pos', None)
        room.pop('dice_rolls', None)
        room.pop('dice_roll', None)
        room.pop('hz_meta', None)
        room['status'] = 'hand_end'
        room['phase'] = 'hand_end'

    def _mj_count_tiles_accounted(self, room):
        total = 0
        wall = room.get('wall') or []
        pos = int(room.get('wall_pos') or 0)
        total += max(0, len(wall) - pos)
        hands = room.get('hands') or [[], [], [], []]
        for h in hands:
            total += len(h or [])
        discards = room.get('discards') or [[], [], [], []]
        for d in discards:
            total += len(d or [])
        melds = room.get('melds') or [[], [], [], []]
        for seat_melds in melds:
            for m in (seat_melds or []):
                total += len(m.get('tiles') or [])
        return total

    def _mj_assert_tile_conservation(self, room):
        if room.get('status') != 'playing':
            return
        accounted = self._mj_count_tiles_accounted(room)
        if accounted > MJ_TOTAL_TILES:
            raise ValueError('牌数异常（超出牌墙总量）')

    def _mj_chi_options(self, room, seat, discard_seat, tile):
        """仅下家可吃；返回所有合法顺子组合（每项为排序后的三张牌）。"""
        if self._mj_next_seat(room, discard_seat) != seat:
            return []
        if not tile or tile[0] not in MJ_SUITS or len(tile) < 2:
            return []
        suit = tile[0]
        try:
            num = int(tile[1:])
        except Exception:
            return []
        hand = Counter(self._mj_hand_tile_list(room, seat))
        options = []
        seen = set()

        def try_seq(nums):
            if any(n < 1 or n > 9 for n in nums):
                return
            tiles = [f'{suit}{n}' for n in nums]
            key = tuple(sorted(tiles, key=self._mj_tile_sort_key))
            if key in seen:
                return
            need = [t for t in tiles if t != tile]
            c = hand.copy()
            for t in need:
                if c.get(t, 0) < 1:
                    return
                c[t] -= 1
            seen.add(key)
            options.append(list(key))

        if num >= 3:
            try_seq([num - 2, num - 1, num])
        if 2 <= num <= 8:
            try_seq([num - 1, num, num + 1])
        if num <= 7:
            try_seq([num, num + 1, num + 2])
        return options

    def _mj_claim_options_for_seat(self, room, seat, tile, discard_seat=None):
        """碰/杠优先于吃；吃仅下家。"""
        opts = []
        rules = self._mj_rules(room)
        if rules.get('allow_ron') and self._mj_can_win_seat(room, seat, tile):
            opts.append('win')
        hc = Counter(self._mj_hand_tile_list(room, seat))
        if hc.get(tile, 0) >= 2:
            opts.append('pung')
        if hc.get(tile, 0) >= 3:
            opts.append('kong')
        if discard_seat is not None and self._mj_chi_options(room, seat, discard_seat, tile):
            opts.append('chi')
        return opts

    def _mj_any_claim_possible(self, room, discard_seat, tile):
        for s in self._mj_playing_seats(room):
            if s == discard_seat:
                continue
            if self._mj_claim_options_for_seat(room, s, tile, discard_seat):
                return True
        return False

    def _mj_clear_drawn_tile(self, room, seat=None):
        dt = room.get('drawn_tile')
        if not isinstance(dt, dict):
            room.pop('drawn_tile', None)
            return
        if seat is None or int(dt.get('seat', -1)) == seat:
            room.pop('drawn_tile', None)

    def _mj_autofill_pass_claims(self, room):
        cr = room.get('claim_round')
        if not isinstance(cr, dict):
            return
        discard_seat = int(cr.get('discard_seat', -1))
        tile = cr.get('tile')
        waiting = [s for s in self._mj_playing_seats(room) if s != discard_seat]
        responses = dict(cr.get('responses') or {})
        for s in waiting:
            if s in responses:
                continue
            if not self._mj_claim_options_for_seat(room, s, tile, discard_seat):
                responses[s] = 'pass'
        cr['responses'] = responses
        room['claim_round'] = cr

    def _mj_finalize_dealer_from_rolls(self, room):
        active = self._mj_playing_seats(room)
        rolls = room.get('dice_rolls') or {}
        best_seat = None
        best_total = -1
        for s in active:
            r = rolls.get(str(s)) or rolls.get(s)
            if not isinstance(r, dict):
                return False
            total = int(r.get('total') or 0)
            if total > best_total or (total == best_total and (best_seat is None or s < best_seat)):
                best_total = total
                best_seat = s
        if best_seat is None:
            return False
        winner = rolls.get(str(best_seat)) or rolls.get(best_seat) or {}
        room['dealer_seat'] = best_seat
        room['dice_roll'] = {
            'dice1': int(winner.get('dice1') or 0),
            'dice2': int(winner.get('dice2') or 0),
            'total': int(winner.get('total') or 0),
            'dealer_seat': best_seat,
            'all_rolls': {str(s): (rolls.get(str(s)) or rolls.get(s)) for s in active},
        }
        return True

    def _mj_begin_dealer_roll(self, room):
        active = self._mj_active_seats(room)
        if len(active) < MJ_MIN_PLAYERS:
            raise ValueError(f'至少需要 {MJ_MIN_PLAYERS} 人才能开局')
        room['status'] = 'dealer_roll'
        room['phase'] = 'dealer_roll'
        room['dice_rolls'] = {}
        room.pop('dice_roll', None)
        room.pop('dealer_deal_at', None)

    def _mj_schedule_dealer_reveal(self, room):
        if not self._mj_finalize_dealer_from_rolls(room):
            raise ValueError('定庄失败')
        room['dealer_deal_at'] = time.time() + MJ_DEALER_REVEAL_SEC

    def _mj_all_dice_rolled(self, room):
        active = self._mj_playing_seats(room)
        rolls = room.get('dice_rolls') or {}
        return bool(active) and len(rolls) >= len(active)

    def _mj_dealer_reveal_ready_to_deal(self, room):
        """全员已掷骰且展示计时结束（或定时器丢失但已定庄）时可发牌。"""
        if str(room.get('status') or '') != 'dealer_roll':
            return False
        if not self._mj_all_dice_rolled(room):
            return False
        if not room.get('dice_roll') and not self._mj_finalize_dealer_from_rolls(room):
            return False
        deal_at = float(room.get('dealer_deal_at') or 0)
        if deal_at:
            return time.time() >= deal_at
        return bool(room.get('dice_roll'))

    def _mj_try_deal_after_reveal(self, room):
        """投骰展示结束后自动发牌（在 room_store 内调用并 raise _MjRoomMutated）。"""
        if not self._mj_dealer_reveal_ready_to_deal(room):
            return False
        self._mj_start_hand(room)
        self._mj_bump_version(room)
        room.pop('dealer_deal_at', None)
        raise _MjRoomMutated()

    def _mj_read_room_tick(self, code):
        """读房间并在投骰展示计时结束后推进发牌。"""
        code = str(code or '').strip().upper()
        room = self._mj_read_room_retry(code)
        if not room or str(room.get('status') or '') != 'dealer_roll':
            return room
        if self._mj_all_dice_rolled(room) and not float(room.get('dealer_deal_at') or 0):
            try:
                with self._mj_room_store(code) as (room_now, err):
                    if err or not room_now:
                        return self._mj_read_room_retry(code)
                    if (
                        str(room_now.get('status') or '') == 'dealer_roll'
                        and self._mj_all_dice_rolled(room_now)
                        and not float(room_now.get('dealer_deal_at') or 0)
                    ):
                        self._mj_schedule_dealer_reveal(room_now)
                        self._mj_bump_version(room_now)
                        raise _MjRoomMutated()
            except _MjRoomMutated:
                pass
            room = self._mj_read_room_retry(code) or room
        if not self._mj_dealer_reveal_ready_to_deal(room):
            return room
        try:
            with self._mj_room_store(code) as (room_now, err):
                if err or not room_now:
                    return self._mj_read_room_retry(code)
                try:
                    self._mj_try_deal_after_reveal(room_now)
                except _MjRoomMutated:
                    pass
        except _MjRoomMutated:
            pass
        return self._mj_read_room_retry(code)

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
        dealer_drawn = wall[pos]
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
        room['drawn_tile'] = {'seat': dealer, 'tile': dealer_drawn}
        room['current_seat'] = dealer
        room['phase'] = 'discard' if len(hands[dealer]) % 3 == 2 else 'draw'
        room['status'] = 'playing'
        room['last_hand_result'] = None
        room.pop('dice_roll', None)
        room.pop('dice_rolls', None)
        room.pop('dealer_deal_at', None)
        room.pop('hz_meta', None)
        if room['phase'] == 'draw':
            self._mj_do_draw(room, dealer)

    def _mj_do_draw(self, room, seat, *, from_kong=False):
        if not from_kong:
            self._mj_hz_on_normal_draw(room, seat)
        tile = self._mj_draw_from_wall(room)
        if tile is None:
            room['last_hand_result'] = {
                'winner_seat': None,
                'win_type': 'draw',
                'deltas': {},
                'hand_no': int(room.get('hand_no') or 1),
            }
            self._mj_enter_hand_end_lobby(room)
            return
        hands = room.get('hands') or [[], [], [], []]
        hands[seat].append(tile)
        hands[seat] = self._mj_sort_tiles(hands[seat])
        room['hands'] = hands
        room['current_seat'] = seat
        room['drawn_tile'] = {'seat': seat, 'tile': tile}
        if self._mj_can_win_seat(room, seat):
            room['pending_self_win'] = True
        room['phase'] = 'discard'
        self._mj_assert_tile_conservation(room)

    def _mj_resolve_claims(self, room):
        cr = room.get('claim_round')
        if not isinstance(cr, dict):
            return
        discard_seat = int(cr.get('discard_seat', -1))
        tile = cr.get('tile')
        responses = cr.get('responses') or {}
        active = self._mj_playing_seats(room)
        waiting = [s for s in active if s != discard_seat]
        if any(s not in responses for s in waiting):
            return

        def order_key(s):
            active_order = active
            base = active_order.index(discard_seat) if discard_seat in active_order else 0
            idx = (active_order.index(s) - base) % len(active_order)
            return idx

        priority = {'win': 4, 'kong': 3, 'pung': 2, 'chi': 1, 'pass': 0}
        best = None
        best_pri = -1
        best_ord = 99
        for s in waiting:
            act = responses.get(s) or responses.get(str(s)) or 'pass'
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
            if not self._mj_rules(room).get('allow_ron'):
                nxt = self._mj_next_seat(room, discard_seat)
                room['current_seat'] = nxt
                self._mj_do_draw(room, nxt)
                return
            self._mj_apply_hand_scores(room, seat, 'ron')
            return
        hands = room.get('hands') or [[], [], [], []]
        melds = room.get('melds') or [[], [], [], []]
        discards = room.get('discards') or [[], [], [], []]
        if discard_seat >= 0 and discards[discard_seat]:
            discards[discard_seat].pop()
        self._mj_clear_drawn_tile(room, seat)
        if act == 'pung':
            removed = 0
            new_hand = []
            for t in hands[seat]:
                if t == tile and removed < 2:
                    removed += 1
                    continue
                new_hand.append(t)
            hands[seat] = self._mj_sort_tiles(new_hand)
            melds[seat].append({'type': 'pung', 'tiles': [tile] * 3, 'from_seat': discard_seat, 'called_tile': tile, 'open': True})
            room['hands'] = hands
            room['melds'] = melds
            room['discards'] = discards
            room['current_seat'] = seat
            room['phase'] = 'discard'
            return
        if act == 'chi':
            chi_picks = cr.get('chi_picks') or {}
            chi_tiles = chi_picks.get(seat) or chi_picks.get(str(seat))
            if not isinstance(chi_tiles, list) or tile not in chi_tiles:
                nxt = self._mj_next_seat(room, discard_seat)
                room['current_seat'] = nxt
                self._mj_do_draw(room, nxt)
                return
            valid = self._mj_chi_options(room, seat, discard_seat, tile)
            norm = tuple(sorted(chi_tiles, key=self._mj_tile_sort_key))
            if not any(tuple(sorted(v, key=self._mj_tile_sort_key)) == norm for v in valid):
                nxt = self._mj_next_seat(room, discard_seat)
                room['current_seat'] = nxt
                self._mj_do_draw(room, nxt)
                return
            for t in chi_tiles:
                if t == tile:
                    continue
                if t in hands[seat]:
                    hands[seat].remove(t)
            hands[seat] = self._mj_sort_tiles(hands[seat])
            melds[seat].append({
                'type': 'chi',
                'tiles': sorted(chi_tiles, key=self._mj_tile_sort_key),
                'from_seat': discard_seat,
                'called_tile': tile,
                'open': True,
            })
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
            melds[seat].append({
                'type': 'kong',
                'tiles': [tile] * 4,
                'from_seat': discard_seat,
                'called_tile': tile,
                'open': True,
                'kong_kind': 'open',
            })
            room['hands'] = hands
            room['melds'] = melds
            room['discards'] = discards
            self._mj_apply_kong_score(room, seat, 'open')
            self._mj_finish_kong_turn(room, seat)
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
                'waits_next_hand': bool(s.get('waits_next_hand')),
                'is_host': self._parse_int(s.get('user_id')) == self._parse_int(room.get('host_user_id')),
                'avatar_url': self._mj_user_avatar_url(s.get('user_id')),
            })
        hands = room.get('hands') or [[], [], [], []]
        hand_counts = [len(hands[i] or []) for i in range(MJ_SEATS)]
        my_hand = self._mj_sort_tiles(list(hands[my_seat] or [])) if my_seat is not None else []
        claim = room.get('claim_round')
        claim_view = None
        if isinstance(claim, dict) and my_seat is not None:
            waiting = [s for s in self._mj_playing_seats(room) if s != int(claim.get('discard_seat', -1))]
            claim_view = {
                'discard_seat': claim.get('discard_seat'),
                'tile': claim.get('tile'),
                'need_response': my_seat in waiting and my_seat not in (claim.get('responses') or {}),
                'options': [],
            }
            if claim_view['need_response']:
                tile = claim.get('tile')
                discard_seat = int(claim.get('discard_seat', -1))
                opts = ['pass'] + self._mj_claim_options_for_seat(room, my_seat, tile, discard_seat)
                claim_view['options'] = opts
                if 'win' in opts:
                    claim_view['win_options'] = self._mj_ron_win_options(room, my_seat, tile)
                chi_opts = self._mj_chi_options(room, my_seat, discard_seat, tile)
                if chi_opts:
                    claim_view['chi_options'] = chi_opts
        dice_roll = None
        if room.get('status') == 'dealer_roll':
            active = self._mj_playing_seats(room)
            rolls_map = room.get('dice_rolls') or {}
            rolls_list = []
            for s in active:
                sp = seats_pub[s] if s < len(seats_pub) else None
                r = rolls_map.get(str(s)) or rolls_map.get(s)
                rolls_list.append({
                    'seat': s,
                    'name': (sp or {}).get('name') or '',
                    'rolled': isinstance(r, dict),
                    'dice1': int(r.get('dice1') or 0) if isinstance(r, dict) else 0,
                    'dice2': int(r.get('dice2') or 0) if isinstance(r, dict) else 0,
                    'total': int(r.get('total') or 0) if isinstance(r, dict) else 0,
                })
            need_my_roll = (
                my_seat is not None
                and my_seat in active
                and str(my_seat) not in rolls_map
            )
            dr = room.get('dice_roll') or {}
            ds = int(dr.get('dealer_seat', room.get('dealer_seat') or 0))
            dealer_name = ''
            for sp in seats_pub:
                if sp and int(sp.get('seat', -1)) == ds:
                    dealer_name = sp.get('name') or ''
                    break
            dice_roll = {
                'rolls': rolls_list,
                'need_my_roll': need_my_roll,
                'all_done': len(rolls_map) >= len(active),
                'dice1': int(dr.get('dice1') or 0),
                'dice2': int(dr.get('dice2') or 0),
                'total': int(dr.get('total') or 0),
                'dealer_seat': ds,
                'dealer_name': dealer_name,
            }
            deal_at = float(room.get('dealer_deal_at') or 0)
            if deal_at > 0:
                dice_roll['reveal_remaining'] = max(0.0, deal_at - time.time())
            else:
                dice_roll['reveal_remaining'] = 0
        chat, chat_seq = self._wrc_chat_public(room, user_id)
        rules = self._mj_rules(room)
        preset = mj_normalize_preset(room.get('rule_preset'))
        streak = int(room.get('dealer_streak') or 0)
        can_self_win = self._mj_my_turn_can_self_win(room, my_seat)
        return {
            'code': room.get('code'),
            'version': int(room.get('version') or 0),
            'room_status': room.get('status'),
            'phase': room.get('phase'),
            'host_user_id': self._parse_int(room.get('host_user_id')),
            'seats': seats_pub,
            'my_seat': my_seat,
            'my_user_id': uid,
            'active_seats': self._mj_active_seats(room),
            'min_players': MJ_MIN_PLAYERS,
            'dealer_seat': int(room.get('dealer_seat') or 0),
            'dealer_streak': streak,
            'dealer_mult': mj_dealer_streak_multiplier(streak) if rules.get('dealer_streak_scoring') else None,
            'rule_preset': preset,
            'rule_label': rules.get('label') or preset,
            'rule_summary': rules.get('summary') or '',
            'joker_tiles': list(self._mj_joker_tiles(room)),
            'allow_ron': bool(rules.get('allow_ron')),
            'current_seat': room.get('current_seat'),
            'scores': room.get('scores') or {},
            'hand_no': int(room.get('hand_no') or 1),
            'hand_counts': hand_counts,
            'my_hand': my_hand,
            'melds': self._mj_melds_for_viewer(room, my_seat),
            'discards': room.get('discards') or [[], [], [], []],
            'last_discard': room.get('last_discard'),
            'drawn_tile': room.get('drawn_tile'),
            'wall_remaining': max(0, len(room.get('wall') or []) - int(room.get('wall_pos') or 0)),
            'claim_round': claim_view,
            'pending_self_win': can_self_win,
            'self_win_options': (
                self._mj_self_win_options(room, my_seat) if can_self_win else []
            ),
            'self_kong': (
                self._mj_self_kong_options(room, my_seat)
                if (
                    my_seat is not None
                    and room.get('status') == 'playing'
                    and room.get('phase') == 'discard'
                    and int(room.get('current_seat', -1)) == my_seat
                    and not room.get('claim_round')
                )
                else None
            ),
            'last_hand_result': room.get('last_hand_result'),
            'join_notice': room.get('join_notice'),
            'you_are_host': uid == self._parse_int(room.get('host_user_id')),
            'can_swap_seat': self._mj_can_swap_seat(room),
            'lobby': self._mj_lobby_ready_summary(room) if room.get('status') in ('lobby', 'hand_end') else None,
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
            return self._mj_action_create(user_id, data, start_response)
        if action == 'presets':
            return self.send_json({'status': 'success', 'presets': mj_preset_public_list()}, start_response)
        if action == 'join':
            return self._mj_action_join(user_id, data, start_response)
        if action == 'leave':
            return self._mj_action_leave(user_id, data, start_response)
        if action == 'rejoin':
            return self._mj_action_rejoin(user_id, data, start_response)
        if action == 'ready':
            return self._mj_action_ready(user_id, data, start_response)
        if action == 'start':
            return self._mj_action_start(user_id, data, start_response)
        if action == 'confirm_roll':
            return self._mj_action_confirm_roll(user_id, data, start_response)
        if action == 'roll_dice':
            return self._mj_action_roll_dice(user_id, data, start_response)
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
        if action == 'self_kong':
            return self._mj_action_self_kong(user_id, data, start_response)
        if action == 'next_hand':
            return self._mj_action_next_hand(user_id, data, start_response)
        if action == 'chat_send':
            return self._mj_action_chat_send(user_id, data, start_response)
        if action == 'swap_seat':
            return self._mj_action_swap_seat(user_id, data, start_response)
        if action == 'set_rule_preset':
            return self._mj_action_set_rule_preset(user_id, data, start_response)
        return self.send_json({'status': 'error', 'message': '未知操作'}, start_response)

    def _mj_action_chat_send(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if self._mj_seat_of_user(room, user_id) is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            name = self._mj_user_display_name(user_id)
            entry, err_msg = self._wrc_chat_append(room, user_id, name, data.get('text'))
            if err_msg:
                return self.send_json({'status': 'error', 'message': err_msg}, start_response)
            self._mj_save_room(room)
        return self.send_json(self._wrc_chat_send_json(room, user_id, entry), start_response)

    def _mj_json_room(self, room, user_id, start_response, message=None):
        out = self._mj_room_public(room, user_id)
        out['status'] = 'success'
        if message:
            out['message'] = message
        return self.send_json(out, start_response)

    def _mj_action_create(self, user_id, data, start_response):
        preset = mj_normalize_preset((data or {}).get('rule_preset'))
        rules = mj_rules_for_preset(preset)
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
            'dealer_streak': 0,
            'hand_no': 1,
            'rule_preset': preset,
            'rule_label': rules.get('label') or preset,
        }
        try:
            self._mj_write_room_file(room)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': f'创建房间失败：{e}'}, start_response)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_set_rule_preset(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        preset = mj_normalize_preset((data or {}).get('rule_preset'))
        rules = mj_rules_for_preset(preset)
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if int(user_id) != self._parse_int(room.get('host_user_id')):
                return self.send_json({'status': 'error', 'message': '仅房主可修改规则'}, start_response)
            if room.get('status') != 'lobby':
                return self.send_json({'status': 'error', 'message': '对局已开始，无法修改规则'}, start_response)
            if mj_normalize_preset(room.get('rule_preset')) == preset:
                return self._mj_json_room(room, user_id, start_response)
            room['rule_preset'] = preset
            room['rule_label'] = rules.get('label') or preset
            self._mj_bump_version(room)
            self._mj_save_room(room)
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
            self._mj_after_lobby_seating_change(room)
            if self._mj_seat_of_user(room, user_id) is None:
                return self.send_json({'status': 'error', 'message': '换座失败，请刷新后重试'}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response, message='已更换座位')

    def _mj_action_join(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            status = room.get('status')
            if status not in ('lobby', 'hand_end', 'playing', 'dealer_roll'):
                return self.send_json({'status': 'error', 'message': '对局已开始，无法加入'}, start_response)
            waits_next = status in ('playing', 'dealer_roll')
            self._mj_normalize_seats(room)
            existing = self._mj_seat_of_user(room, user_id)
            if existing is not None:
                seats = list(room.get('seats') or [None] * MJ_SEATS)
                while len(seats) < MJ_SEATS:
                    seats.append(None)
                seats[existing]['name'] = self._mj_user_display_name(user_id)
                self._mj_clear_user_duplicate_seats(seats, user_id, keep_seat=existing)
                room['seats'] = seats[:MJ_SEATS]
                self._mj_bump_version(room)
            else:
                seats = list(room.get('seats') or [None] * MJ_SEATS)
                while len(seats) < MJ_SEATS:
                    seats.append(None)
                self._mj_clear_user_duplicate_seats(seats, user_id, keep_seat=None)
                room['seats'] = seats[:MJ_SEATS]
                slot = self._mj_pick_join_seat(room, seats)
                if slot is None:
                    return self.send_json({'status': 'error', 'message': '房间座位已满'}, start_response)
                name = self._mj_put_user_in_seat(room, user_id, slot, waits_next=waits_next)
                if waits_next:
                    self._mj_set_join_notice(room, slot, user_id, name)
                else:
                    self._mj_bump_version(room)
            self._mj_after_lobby_seating_change(room)
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
            self._mj_vacate_seat_in_room(room, seat)
            if is_host:
                active = self._mj_active_seats(room)
                for i in active:
                    seats = room.get('seats') or []
                    s = seats[i] if i < len(seats) else None
                    if isinstance(s, dict):
                        uid = self._parse_int(s.get('user_id'))
                        if uid:
                            room['host_user_id'] = uid
                            break
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

    def _mj_action_rejoin(self, user_id, data, start_response):
        """刷新页面后重新入座（不创建新房间）。"""
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            self._mj_normalize_seats(room)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is not None:
                return self._mj_json_room(room, user_id, start_response, message='已在房间中')
            uid = int(user_id)
            is_host = uid == self._parse_int(room.get('host_user_id'))
            status = room.get('status')
            if status == 'lobby':
                slot = self._mj_pick_join_seat(room, room.get('seats') or [])
                if slot is None:
                    return self.send_json({'status': 'error', 'message': '房间座位已满'}, start_response)
                self._mj_put_user_in_seat(room, uid, slot, waits_next=False)
                if is_host:
                    seats = room.get('seats') or []
                    if isinstance(seats[slot], dict):
                        seats[slot]['ready'] = True
                        room['seats'] = seats
            elif status == 'hand_end':
                slot = self._mj_pick_join_seat(room, room.get('seats') or [])
                if slot is None:
                    return self.send_json({'status': 'error', 'message': '房间座位已满，无法重连'}, start_response)
                self._mj_put_user_in_seat(room, uid, slot, waits_next=False)
            elif status in ('playing', 'dealer_roll'):
                slot = self._mj_pick_join_seat(room, room.get('seats') or [])
                if slot is None and is_host:
                    for i in range(MJ_SEATS):
                        if (room.get('seats') or [None] * MJ_SEATS)[i] is None:
                            slot = i
                            break
                if slot is None:
                    return self.send_json({'status': 'error', 'message': '房间座位已满，无法重连'}, start_response)
                name = self._mj_put_user_in_seat(room, uid, slot, waits_next=True)
                self._mj_set_join_notice(room, slot, uid, name)
            else:
                return self.send_json({'status': 'error', 'message': '对局已开始，无法重新加入'}, start_response)
            self._mj_after_lobby_seating_change(room)
            if status not in ('playing', 'dealer_roll'):
                self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response, message='已重新加入房间')

    def _mj_try_auto_start_hand_if_all_ready(self, room):
        """hand_end：在座全员准备后自动开下一局，无需房主二次确认。"""
        if room.get('status') != 'hand_end':
            return False
        active = self._mj_active_seats(room)
        if len(active) < MJ_MIN_PLAYERS:
            return False
        seats = room.get('seats') or []
        if not all(isinstance(seats[i], dict) and seats[i].get('ready') for i in active):
            return False
        room['hand_no'] = int(room.get('hand_no') or 1) + 1
        room.pop('last_hand_result', None)
        self._mj_start_hand(room)
        return True

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
            if s['ready'] and room.get('status') == 'hand_end':
                try:
                    self._mj_try_auto_start_hand_if_all_ready(room)
                except ValueError as ex:
                    return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
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
            if room.get('status') not in ('lobby', 'hand_end'):
                return self.send_json({'status': 'error', 'message': '已在游戏中'}, start_response)
            active = self._mj_active_seats(room)
            if len(active) < MJ_MIN_PLAYERS:
                return self.send_json({'status': 'error', 'message': f'至少需要 {MJ_MIN_PLAYERS} 人'}, start_response)
            seats = room.get('seats') or []
            if not all(isinstance(seats[i], dict) and seats[i].get('ready') for i in active):
                return self.send_json({'status': 'error', 'message': '在座玩家须全部准备'}, start_response)
            if room.get('status') == 'hand_end':
                room['hand_no'] = int(room.get('hand_no') or 1) + 1
                room.pop('last_hand_result', None)
                try:
                    self._mj_start_hand(room)
                except ValueError as ex:
                    return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            else:
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
            active = self._mj_active_seats(room)
            rolls = room.get('dice_rolls') or {}
            if len(rolls) < len(active):
                return self.send_json({'status': 'error', 'message': '尚有玩家未掷骰'}, start_response)
            deal_at = float(room.get('dealer_deal_at') or 0)
            if deal_at and time.time() < deal_at:
                remain = max(1, int(deal_at - time.time() + 0.999))
                return self.send_json({
                    'status': 'error',
                    'message': f'请等待 {remain} 秒看清庄家后再发牌',
                }, start_response)
            try:
                if not room.get('dice_roll') and not self._mj_finalize_dealer_from_rolls(room):
                    return self.send_json({'status': 'error', 'message': '定庄失败'}, start_response)
                self._mj_start_hand(room)
            except ValueError as ex:
                return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            room.pop('dealer_deal_at', None)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_roll_dice(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            if room.get('status') != 'dealer_roll':
                return self.send_json({'status': 'error', 'message': '当前不在投骰阶段'}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if self._mj_seat_waits_next_hand(room, seat):
                return self.send_json({'status': 'error', 'message': '您将于下局加入，无需掷骰'}, start_response)
            rolls = dict(room.get('dice_rolls') or {})
            if str(seat) in rolls:
                return self.send_json({'status': 'error', 'message': '您已掷过骰子'}, start_response)
            d1 = random.randint(1, 6)
            d2 = random.randint(1, 6)
            rolls[str(seat)] = {'dice1': d1, 'dice2': d2, 'total': d1 + d2, 'seat': seat}
            room['dice_rolls'] = rolls
            active = self._mj_playing_seats(room)
            if len(rolls) >= len(active):
                try:
                    self._mj_schedule_dealer_reveal(room)
                except ValueError as ex:
                    return self.send_json({'status': 'error', 'message': str(ex)}, start_response)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_state(self, user_id, query, start_response):
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        room = self._mj_read_room_tick(code)
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
        since = self._wrc_query_int(query, 'since_version', 0)
        since_chat = self._wrc_query_int(query, 'since_chat_seq', 0)
        result = self._wrc_wait_for_update(
            code,
            user_id,
            since,
            since_chat,
            timeout_sec=MJ_WAIT_TIMEOUT_SEC,
            poll_sec=MJ_WAIT_POLL_SEC,
            register_waiter=_mj_register_waiter,
            unregister_waiter=_mj_unregister_waiter,
            read_room=lambda c: self._mj_read_room_tick(c),
            user_in_room=lambda room, uid: self._mj_seat_of_user(room, uid) is not None,
            build_state_response=lambda room, uid: {
                'status': 'success',
                **self._mj_room_public(room, uid),
            },
            build_unchanged_response=lambda room, uid: {
                'status': 'success',
                'unchanged': True,
                **self._mj_room_public(room, uid),
            },
            room_missing_response=lambda: {
                'status': 'error',
                'message': '房间已解散或已过期',
                'room_dissolved': True,
            },
            not_member_response=lambda: {
                'status': 'error',
                'message': '您不在该房间中',
                'left_room': True,
            },
        )
        return self.send_json(result, start_response)

    def _mj_action_stream(self, user_id, query, start_response):
        """SSE：对局 version 变化推送 state；聊天 chat_seq 变化推送 chat 增量。"""
        code = str((query.get('room_code') or [''])[0] or '').strip().upper()
        since = self._wrc_query_int(query, 'since_version', 0)
        since_chat = self._wrc_query_int(query, 'since_chat_seq', 0)
        if not code:
            return self.send_json({'status': 'error', 'message': '缺少房间号'}, start_response)

        room = self._mj_read_room_tick(code)
        if not room:
            return self.send_json({'status': 'error', 'message': '房间不存在或已过期'}, start_response)
        if self._mj_seat_of_user(room, user_id) is None:
            return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)

        uid = int(user_id)
        generate = self._wrc_stream_generate(
            code,
            uid,
            since,
            since_chat,
            session_sec=MJ_STREAM_SESSION_SEC,
            ping_sec=MJ_STREAM_PING_SEC,
            poll_sec=MJ_WAIT_POLL_SEC,
            register_waiter=_mj_register_waiter,
            unregister_waiter=_mj_unregister_waiter,
            read_room=lambda c, u: self._mj_read_room_tick(c),
            user_in_room=lambda room_now, u: self._mj_seat_of_user(room_now, u) is not None,
            build_state_payload=lambda room_now, u: self._mj_room_public(room_now, u),
        )
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
            hand_n = len(hands[seat] or [])
            if hand_n % 3 != 2:
                return self.send_json({'status': 'error', 'message': '手牌数量异常'}, start_response)
            if tile not in (hands[seat] or []):
                return self.send_json({'status': 'error', 'message': '手牌中没有该牌'}, start_response)
            self._mj_hz_on_discard(room, seat, tile)
            hands[seat].remove(tile)
            hands[seat] = self._mj_sort_tiles(hands[seat])
            discards = room.get('discards') or [[], [], [], []]
            discards[seat].append(tile)
            room['hands'] = hands
            room['discards'] = discards
            room['last_discard'] = {'seat': seat, 'tile': tile}
            room['pending_self_win'] = False
            self._mj_clear_drawn_tile(room, seat)
            active = self._mj_active_seats(room)
            waiting = [s for s in active if s != seat]
            if not waiting:
                return self.send_json({'status': 'error', 'message': '玩家不足'}, start_response)
            if not self._mj_any_claim_possible(room, seat, tile):
                room['claim_round'] = None
                nxt = self._mj_next_seat(room, seat)
                self._mj_do_draw(room, nxt)
            else:
                room['claim_round'] = {
                    'discard_seat': seat,
                    'tile': tile,
                    'responses': {},
                }
                room['phase'] = 'claim'
                self._mj_autofill_pass_claims(room)
                cr = room.get('claim_round') or {}
                responses = cr.get('responses') or {}
                if all(s in responses for s in waiting):
                    self._mj_resolve_claims(room)
            self._mj_assert_tile_conservation(room)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_self_kong(self, user_id, data, start_response):
        code = str(data.get('room_code') or '').strip().upper()
        kind = str(data.get('kind') or 'concealed').strip().lower()
        tile = str(data.get('tile') or '').strip()
        with self._mj_room_store(code) as (room, err):
            if err:
                return self.send_json({'status': 'error', 'message': err}, start_response)
            seat = self._mj_seat_of_user(room, user_id)
            if seat is None:
                return self.send_json({'status': 'error', 'message': '您不在该房间中'}, start_response)
            if room.get('status') != 'playing' or room.get('phase') != 'discard':
                return self.send_json({'status': 'error', 'message': '当前不能杠牌'}, start_response)
            if int(room.get('current_seat', -1)) != seat:
                return self.send_json({'status': 'error', 'message': '未轮到您出牌'}, start_response)
            if room.get('claim_round'):
                return self.send_json({'status': 'error', 'message': '请先响应碰杠胡'}, start_response)
            if not tile:
                return self.send_json({'status': 'error', 'message': '缺少牌张'}, start_response)
            opts = self._mj_self_kong_options(room, seat)
            hands = room.get('hands') or [[], [], [], []]
            melds = room.get('melds') or [[], [], [], []]
            hand_n = len(hands[seat] or [])
            if hand_n % 3 != 2:
                return self.send_json({'status': 'error', 'message': '手牌数量异常'}, start_response)
            if kind == 'concealed':
                if tile not in opts.get('concealed') or []:
                    return self.send_json({'status': 'error', 'message': '不能暗杠'}, start_response)
                removed = 0
                new_hand = []
                for t in hands[seat]:
                    if t == tile and removed < 4:
                        removed += 1
                        continue
                    new_hand.append(t)
                hands[seat] = self._mj_sort_tiles(new_hand)
                melds[seat].append({
                    'type': 'kong',
                    'tiles': [tile] * 4,
                    'open': False,
                    'kong_kind': 'concealed',
                })
            elif kind == 'added':
                if tile not in opts.get('added') or []:
                    return self.send_json({'status': 'error', 'message': '不能补杠'}, start_response)
                pung_idx = None
                for i, m in enumerate(melds[seat] or []):
                    if m.get('type') != 'pung':
                        continue
                    ct = m.get('called_tile') or (m.get('tiles') or [None])[0]
                    if ct == tile:
                        pung_idx = i
                        break
                if pung_idx is None:
                    return self.send_json({'status': 'error', 'message': '没有可补杠的碰'}, start_response)
                pung = melds[seat].pop(pung_idx)
                if tile not in hands[seat]:
                    return self.send_json({'status': 'error', 'message': '手牌中没有该牌'}, start_response)
                hands[seat].remove(tile)
                hands[seat] = self._mj_sort_tiles(hands[seat])
                melds[seat].append({
                    'type': 'kong',
                    'tiles': [tile] * 4,
                    'from_seat': pung.get('from_seat'),
                    'called_tile': tile,
                    'open': True,
                    'kong_kind': 'added',
                })
            else:
                return self.send_json({'status': 'error', 'message': '无效杠类型'}, start_response)
            room['hands'] = hands
            room['melds'] = melds
            self._mj_apply_kong_score(room, seat, kind)
            self._mj_clear_drawn_tile(room, seat)
            self._mj_finish_kong_turn(room, seat)
            self._mj_assert_tile_conservation(room)
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

            if self._mj_my_turn_can_self_win(room, seat):
                if claim_type == 'win':
                    if not self._mj_can_win_seat(room, seat):
                        return self.send_json({'status': 'error', 'message': '不能胡牌'}, start_response)
                    pattern_code = str(data.get('pattern_code') or '').strip() or None
                    self._mj_apply_hand_scores(room, seat, 'tsumo', pattern_code=pattern_code)
                    room.pop('pending_self_win', None)
                    self._mj_bump_version(room)
                    self._mj_save_room(room)
                    return self._mj_json_room(room, user_id, start_response)
                if claim_type == 'pass':
                    room.pop('pending_self_win', None)
                    self._mj_bump_version(room)
                    self._mj_save_room(room)
                    return self._mj_json_room(room, user_id, start_response)
                return self.send_json({'status': 'error', 'message': '当前只能胡牌或过'}, start_response)

            cr = room.get('claim_round')
            if not isinstance(cr, dict) or room.get('phase') != 'claim':
                return self.send_json({'status': 'error', 'message': '当前无碰杠胡请求'}, start_response)
            discard_seat = int(cr.get('discard_seat', -1))
            if seat == discard_seat:
                return self.send_json({'status': 'error', 'message': '出牌者不能响应'}, start_response)
            if claim_type not in ('win', 'pung', 'kong', 'chi', 'pass'):
                return self.send_json({'status': 'error', 'message': '无效操作'}, start_response)
            tile = cr.get('tile')
            if claim_type == 'win':
                if not self._mj_rules(room).get('allow_ron'):
                    return self.send_json({'status': 'error', 'message': '本规则不可点炮胡'}, start_response)
                if not self._mj_can_win_seat(room, seat, tile):
                    return self.send_json({'status': 'error', 'message': '不能胡牌'}, start_response)
            hc = Counter(self._mj_hand_tile_list(room, seat))
            if claim_type == 'pung' and hc.get(tile, 0) < 2:
                return self.send_json({'status': 'error', 'message': '不能碰'}, start_response)
            if claim_type == 'kong' and hc.get(tile, 0) < 3:
                return self.send_json({'status': 'error', 'message': '不能杠'}, start_response)
            if claim_type == 'chi':
                chi_opts = self._mj_chi_options(room, seat, discard_seat, tile)
                if not chi_opts:
                    return self.send_json({'status': 'error', 'message': '不能吃'}, start_response)
                chi_tiles = data.get('chi_tiles')
                if isinstance(chi_tiles, str):
                    chi_tiles = [x.strip() for x in chi_tiles.split(',') if x.strip()]
                if not chi_tiles:
                    if len(chi_opts) == 1:
                        chi_tiles = list(chi_opts[0])
                    else:
                        return self.send_json({'status': 'error', 'message': '请选择吃法'}, start_response)
                norm = tuple(sorted(chi_tiles, key=self._mj_tile_sort_key))
                if not any(tuple(sorted(v, key=self._mj_tile_sort_key)) == norm for v in chi_opts):
                    return self.send_json({'status': 'error', 'message': '无效的吃法'}, start_response)
                chi_picks = dict(cr.get('chi_picks') or {})
                chi_picks[str(seat)] = list(chi_tiles)
                cr['chi_picks'] = chi_picks
            responses = cr.get('responses') or {}
            responses[seat] = claim_type
            cr['responses'] = responses
            room['claim_round'] = cr
            self._mj_autofill_pass_claims(room)
            self._mj_resolve_claims(room)
            self._mj_assert_tile_conservation(room)
            self._mj_bump_version(room)
            self._mj_save_room(room)
        return self._mj_json_room(room, user_id, start_response)

    def _mj_action_next_hand(self, user_id, data, start_response):
        """已废弃：下局改由全员准备 + 房主开局。"""
        return self.send_json({
            'status': 'error',
            'message': '请全员准备后，由房主点击开局',
        }, start_response)
