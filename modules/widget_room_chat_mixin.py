"""小组件多人房间：通用聊天消息存储与 API 辅助。"""

import time

WIDGET_ROOM_CHAT_MAX = 120
WIDGET_ROOM_CHAT_MAX_TEXT = 400


class WidgetRoomChatMixin:
    """房间 JSON 内嵌 chat_messages / chat_seq 的通用读写。"""

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
