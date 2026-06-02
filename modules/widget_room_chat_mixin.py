"""小组件多人房间：通用聊天消息存储与 SSE/长轮询增量推送辅助。"""

import time

WIDGET_ROOM_CHAT_MAX = 120
WIDGET_ROOM_CHAT_MAX_TEXT = 400
WRC_STREAM_POLL_SEC = 0.08
WRC_STREAM_SESSION_SEC = 300
WRC_STREAM_PING_SEC = 12


class WidgetRoomChatMixin:
    """房间 JSON 内嵌 chat_messages / chat_seq 的通用读写。"""

    def _wrc_query_int(self, query, key, default=0):
        try:
            return int((query.get(key) or [str(default)])[0] or default)
        except Exception:
            return default

    def _wrc_chat_public(self, room, user_id=None):
        uid = int(user_id) if user_id else None
        msgs = room.get('chat_messages')
        if not isinstance(msgs, list):
            msgs = []
        out = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            muid = self._parse_int(m.get('user_id'))
            out.append({
                'id': int(m.get('id') or 0),
                'user_id': muid,
                'name': str(m.get('name') or '').strip(),
                'text': str(m.get('text') or ''),
                'ts': float(m.get('ts') or 0),
                'mine': bool(uid and muid == uid),
            })
        seq = int(room.get('chat_seq') or 0)
        return out, seq

    def _wrc_chat_append(self, room, user_id, name, text):
        body = str(text or '').strip()
        if not body:
            return None, '消息不能为空'
        if len(body) > WIDGET_ROOM_CHAT_MAX_TEXT:
            body = body[:WIDGET_ROOM_CHAT_MAX_TEXT]
        msgs = room.get('chat_messages')
        if not isinstance(msgs, list):
            msgs = []
        seq = int(room.get('chat_seq') or 0) + 1
        room['chat_seq'] = seq
        entry = {
            'id': seq,
            'user_id': int(user_id),
            'name': str(name or '').strip() or f'用户{user_id}',
            'text': body,
            'ts': time.time(),
        }
        msgs.append(entry)
        if len(msgs) > WIDGET_ROOM_CHAT_MAX:
            msgs = msgs[-WIDGET_ROOM_CHAT_MAX:]
        room['chat_messages'] = msgs
        return entry, None

    def _wrc_chat_delta(self, room, user_id, since_seq):
        since_seq = int(since_seq or 0)
        chat_seq = int(room.get('chat_seq') or 0)
        if chat_seq <= since_seq:
            return None
        msgs, seq = self._wrc_chat_public(room, user_id)
        new_msgs = [m for m in msgs if int(m.get('id') or 0) > since_seq]
        if not new_msgs:
            return None
        return {
            'status': 'success',
            'chat_only': True,
            'version': int(room.get('version') or 0),
            'chat_seq': seq,
            'chat_messages': new_msgs,
        }

    def _wrc_chat_send_json(self, room, user_id, entry):
        msgs, seq = self._wrc_chat_public(room, user_id)
        entry_id = int((entry or {}).get('id') or 0)
        new_msg = next((m for m in msgs if int(m.get('id') or 0) == entry_id), None)
        payload = {
            'status': 'success',
            'chat_only': True,
            'version': int(room.get('version') or 0),
            'chat_seq': seq,
            'chat_messages': [new_msg] if new_msg else [],
        }
        return payload

    def _wrc_wait_for_update(
        self,
        code,
        user_id,
        since_version,
        since_chat_seq,
        *,
        timeout_sec,
        poll_sec,
        register_waiter,
        unregister_waiter,
        read_room,
        user_in_room,
        build_state_response,
        build_unchanged_response,
        room_missing_response,
        not_member_response,
    ):
        waiter = register_waiter(code)
        try:
            deadline = time.time() + timeout_sec
            while time.time() < deadline:
                room = read_room(code)
                if not room:
                    return room_missing_response()
                if not user_in_room(room, user_id):
                    return not_member_response()
                ver = int(room.get('version') or 0)
                if ver > since_version:
                    return build_state_response(room, user_id)
                delta = self._wrc_chat_delta(room, user_id, since_chat_seq)
                if delta:
                    delta['unchanged'] = True
                    return delta
                waiter.clear()
                remaining = max(0.05, deadline - time.time())
                waiter.wait(timeout=min(poll_sec, remaining))
        finally:
            unregister_waiter(code, waiter)

        room = read_room(code)
        if not room:
            return room_missing_response()
        if not user_in_room(room, user_id):
            return not_member_response()
        return build_unchanged_response(room, user_id)

    def _wrc_stream_generate(
        self,
        code,
        user_id,
        since_version,
        since_chat_seq,
        *,
        session_sec,
        ping_sec,
        poll_sec,
        register_waiter,
        unregister_waiter,
        read_room,
        user_in_room,
        build_state_payload,
        dissolved_event='room_dissolved',
    ):
        uid = int(user_id)

        def generate():
            yield b': connected\n\n'
            waiter = register_waiter(code)
            since_ver_local = int(since_version or 0)
            since_chat_local = int(since_chat_seq or 0)
            started = time.time()
            last_ping = started
            try:
                while time.time() - started < session_sec:
                    room_now = read_room(code, uid)
                    if not room_now:
                        yield self._sse_event(dissolved_event, {
                            'status': 'error',
                            'message': '房间已解散或已过期',
                            'room_dissolved': True,
                        })
                        return
                    if not user_in_room(room_now, uid):
                        yield self._sse_event('room_error', {
                            'status': 'error',
                            'message': '您不在该房间中',
                        })
                        return
                    ver = int(room_now.get('version') or 0)
                    chat_seq = int(room_now.get('chat_seq') or 0)
                    if ver > since_ver_local:
                        payload = build_state_payload(room_now, uid)
                        payload['status'] = 'success'
                        payload['version'] = ver
                        yield self._sse_event('state', payload)
                        since_ver_local = ver
                        since_chat_local = chat_seq
                    elif chat_seq > since_chat_local:
                        delta = self._wrc_chat_delta(room_now, uid, since_chat_local)
                        if delta:
                            yield self._sse_event('chat', delta)
                            since_chat_local = chat_seq
                    now = time.time()
                    if now - last_ping >= ping_sec:
                        yield self._sse_event('ping', {'t': int(now)})
                        last_ping = now
                    waiter.clear()
                    remaining = max(0.05, session_sec - (now - started))
                    waiter.wait(timeout=min(poll_sec, remaining))
            finally:
                unregister_waiter(code, waiter)

        return generate
