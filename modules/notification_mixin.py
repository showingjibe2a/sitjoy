# -*- coding: utf-8 -*-
"""站内通知：列表、未读数、标记已读；业务侧通过辅助方法写入。"""

import threading
from datetime import datetime
from urllib.parse import parse_qs


class NotificationMixin:
    """站内通知 Mixin：用户通知 CRUD、管理员广播与业务事件写入。"""

    _NOTIFICATIONS_MIGRATION_HINT = 'scripts/sql/20260529_01_user_notifications.sql'

    # -------------------------------------------------------------------------
    # 表检测与序列化
    # -------------------------------------------------------------------------
    def _notification_is_missing_table_error(self, exc):
        """判断异常是否因 user_notifications 表尚未迁移导致。"""
        message = str(exc or '').lower()
        return (
            "doesn't exist" in message
            or 'does not exist' in message
            or 'unknown table' in message
        )

    def _notification_table_missing_json_response(self, exc, start_response):
        if not self._notification_is_missing_table_error(exc):
            return None
        return self.send_json({
            'status': 'error',
            'message': f'通知表未初始化，请先执行 {self._NOTIFICATIONS_MIGRATION_HINT}',
        }, start_response)

    def _notification_now_text(self):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def _serialize_notification_row(self, row):
        if not row:
            return None
        created = row.get('created_at')
        read_at = row.get('read_at')
        return {
            'id': int(row.get('id') or 0),
            'user_id': int(row.get('user_id') or 0),
            'notification_type': row.get('notification_type') or 'system',
            'title': row.get('title') or '',
            'body': row.get('body') or '',
            'link_url': row.get('link_url') or '',
            'link_label': row.get('link_label') or '',
            'is_read': int(row.get('is_read') or 0),
            'read_at': str(read_at) if read_at is not None else '',
            'created_at': str(created) if created is not None else '',
        }

    # -------------------------------------------------------------------------
    # 业务侧写入（异步 INSERT，表缺失时静默跳过）
    # -------------------------------------------------------------------------

    def _create_user_notification(
        self,
        user_id,
        notification_type,
        title,
        body=None,
        link_url=None,
        link_label=None,
    ):
        uid = self._parse_int(user_id)
        if not uid:
            return None
        title_text = (title or '').strip()[:255]
        if not title_text:
            return None
        body_text = (body or '').strip() or None
        if body_text:
            body_text = body_text[:2000]
        link = (link_url or '').strip() or None
        if link:
            link = link[:512]
        link_text = (link_label or '').strip() or None
        if link_text:
            link_text = link_text[:128]
        ntype = (notification_type or 'system').strip()[:64] or 'system'
        payload = (uid, ntype, title_text, body_text, link, link_text)

        def _insert():
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO user_notifications (
                                user_id, notification_type, title, body, link_url, link_label
                            ) VALUES (%s, %s, %s, %s, %s, %s)
                            """,
                            payload,
                        )
            except Exception as e:
                if not self._notification_is_missing_table_error(e):
                    print('Create user notification error: ' + str(e))

        threading.Thread(target=_insert, daemon=True).start()
        return True

    def _notify_admin_users(
        self,
        notification_type,
        title,
        body=None,
        link_url=None,
        link_label=None,
        exclude_user_id=None,
    ):
        exclude = self._parse_int(exclude_user_id) or 0
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id FROM users
                        WHERE COALESCE(is_admin, 0) = 1
                          AND COALESCE(is_approved, 1) = 1
                        """
                    )
                    rows = cur.fetchall() or []
        except Exception as e:
            if self._notification_is_missing_table_error(e):
                return
            print('Notify admin users lookup error: ' + str(e))
            return
        for row in rows:
            uid = self._parse_int(row.get('id'))
            if not uid or uid == exclude:
                continue
            self._create_user_notification(
                uid,
                notification_type,
                title,
                body=body,
                link_url=link_url,
                link_label=link_label,
            )

    # -------------------------------------------------------------------------
    # 业务事件通知（注册、待办指派）
    # -------------------------------------------------------------------------
    def _notify_registration_pending(self, username, name=None):
        display = (name or '').strip() or (username or '').strip() or '新用户'
        account = (username or '').strip() or '—'
        self._notify_admin_users(
            'registration_pending',
            '有新的注册申请待审核',
            body=f'账号：{account}；姓名：{display}',
            link_url='/system-employee-management',
            link_label='前往员工账号管理',
        )

    def _notify_registration_approved(self, user_id, username=None):
        uid = self._parse_int(user_id)
        if not uid:
            return
        account = (username or '').strip() or '您的账号'
        self._create_user_notification(
            uid,
            'registration_approved',
            '注册申请已通过',
            body=f'{account} 现已可以登录系统。',
            link_url='/login',
            link_label='前往登录',
        )

    def _notify_todo_assigned(self, assignee_ids, todo_title, todo_id=None, actor_user_id=None):
        title = (todo_title or '').strip() or '待办事项'
        actor_id = self._parse_int(actor_user_id) or 0
        link = '/'
        link_label = '前往首页待办'
        body = f'您被指派了待办：{title}'
        if todo_id:
            body = f'您被指派了待办「{title}」（#{int(todo_id)}）'
        for raw_id in assignee_ids or []:
            uid = self._parse_int(raw_id)
            if not uid or uid == actor_id:
                continue
            self._create_user_notification(
                uid,
                'todo_assigned',
                '新的待办指派',
                body=body,
                link_url=link,
                link_label=link_label,
            )

    # -------------------------------------------------------------------------
    # 用户通知 API
    # -------------------------------------------------------------------------

    def _notification_parse_mark_read_ids(self, data):
        """解析 mark_read 请求的 id / ids 列表。"""
        payload = data if isinstance(data, dict) else {}
        ids = []
        raw = payload.get('ids')
        if isinstance(raw, list):
            for x in raw:
                nid = self._parse_int(x)
                if nid:
                    ids.append(int(nid))
        single = self._parse_int(payload.get('id'))
        if single:
            ids.append(int(single))
        return sorted(set(ids))

    def handle_notification_api(self, environ, method, start_response):
        """当前用户通知：列表、未读数、单条/全部标记已读。"""
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            query = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query.get('action', [''])[0] or '').strip().lower()

            if method == 'POST' and action == 'mark_read':
                data = self._read_json_body(environ)
                ids = self._notification_parse_mark_read_ids(data)
                if not ids:
                    return self.send_json({'status': 'error', 'message': '缺少通知 ID'}, start_response)
                placeholders = ','.join(['%s'] * len(ids))
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            UPDATE user_notifications
                            SET is_read=1, read_at=COALESCE(read_at, %s)
                            WHERE user_id=%s AND id IN ({placeholders})
                            """,
                            (self._notification_now_text(), int(user_id)) + tuple(ids),
                        )
                return self.send_json({'status': 'success', 'updated': len(ids)}, start_response)

            if method == 'POST' and action == 'mark_all_read':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE user_notifications
                            SET is_read=1, read_at=COALESCE(read_at, %s)
                            WHERE user_id=%s AND is_read=0
                            """,
                            (self._notification_now_text(), int(user_id)),
                        )
                        updated = int(cur.rowcount or 0)
                return self.send_json({'status': 'success', 'updated': updated}, start_response)

            if method != 'GET':
                return self.send_json({'status': 'error', 'message': '不支持的请求'}, start_response)

            if action == 'unread_count':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            'SELECT COUNT(*) AS cnt FROM user_notifications WHERE user_id=%s AND is_read=0',
                            (int(user_id),),
                        )
                        row = cur.fetchone() or {}
                return self.send_json({
                    'status': 'success',
                    'unread_count': int(row.get('cnt') or 0),
                }, start_response)

            page = max(1, self._parse_int(query.get('page', ['1'])[0]) or 1)
            page_size = self._parse_int(query.get('page_size', ['20'])[0]) or 20
            page_size = max(5, min(50, page_size))
            offset = (page - 1) * page_size
            unread_only = str(query.get('unread_only', ['0'])[0] or '').strip().lower() in ('1', 'true', 'yes')

            where = ['user_id=%s']
            params = [int(user_id)]
            if unread_only:
                where.append('is_read=0')
            where_sql = ' AND '.join(where)

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f'SELECT COUNT(*) AS cnt FROM user_notifications WHERE {where_sql}',
                        tuple(params),
                    )
                    total_row = cur.fetchone() or {}
                    total = int(total_row.get('cnt') or 0)
                    cur.execute(
                        f"""
                        SELECT id, user_id, notification_type, title, body,
                               link_url, link_label, is_read, read_at, created_at
                        FROM user_notifications
                        WHERE {where_sql}
                        ORDER BY id DESC
                        LIMIT %s OFFSET %s
                        """,
                        tuple(params) + (page_size, offset),
                    )
                    rows = cur.fetchall() or []
                    cur.execute(
                        'SELECT COUNT(*) AS cnt FROM user_notifications WHERE user_id=%s AND is_read=0',
                        (int(user_id),),
                    )
                    unread_row = cur.fetchone() or {}

            items = [self._serialize_notification_row(row) for row in rows]
            return self.send_json({
                'status': 'success',
                'items': items,
                'total': total,
                'page': page,
                'page_size': page_size,
                'unread_count': int(unread_row.get('cnt') or 0),
            }, start_response)
        except Exception as e:
            missing = self._notification_table_missing_json_response(e, start_response)
            if missing:
                return missing
            print('Notification API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
