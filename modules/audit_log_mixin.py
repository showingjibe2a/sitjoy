# -*- coding: utf-8 -*-
"""访问与操作审计日志：页面访问、数据库相关 API 写操作；可授权管理员可查询与清理。"""

import json
import re
import threading
from io import BytesIO
from urllib.parse import parse_qs

_AUDIT_MUTATING = frozenset({'POST', 'PUT', 'PATCH', 'DELETE'})
_AUDIT_BODY_MAX = 48 * 1024
_AUDIT_SUMMARY_MAX = 4000
_AUDIT_SKIP_OPERATION_PREFIXES = (
    '/api/auth',
    '/api/audit-log',
    '/api/notification',
    '/api/go-play',
    '/api/mahjong-play',
    '/api/hello',
)
_AUDIT_REDACT_KEYS = frozenset({
    'password', 'password_hash', 'old_password', 'new_password',
    'confirm_phrase', 'confirm_username',
})

_AUDIT_HTTP_VERB_LABELS = {
    'POST': '新增',
    'PUT': '更新',
    'PATCH': '更新',
    'DELETE': '删除',
}

_AUDIT_API_RESOURCE_LABELS = {
    '/api/employee': '员工账号',
    '/api/profile': '个人资料',
    '/api/todo': '待办',
    '/api/todo-type': '待办类型',
    '/api/auth': '登录认证',
}

_AUDIT_COMMON_FIELD_LABELS = {
    'id': 'ID',
    'username': '账号',
    'name': '姓名',
    'phone': '手机',
    'birthday': '生日',
    'hire_date': '入职时间',
    'job_title': '岗位',
    'direct_supervisor_id': '直属上级',
    'is_admin': '管理员',
    'can_grant_admin': '管理员授权',
    'page_permissions': '页面访问权限',
    'factory_scope_mode': '工厂范围模式',
    'factory_scope_ids': '工厂范围',
    'title': '标题',
    'detail': '详情',
    'due_date': '截止日期',
    'start_date': '开始日期',
    'priority': '优先级',
    'is_recurring': '循环任务',
    'reminder_interval_days': '提醒间隔(天)',
}

_AUDIT_MIGRATION_HINT = '审计表未初始化，请先执行 scripts/sql/20260522_01_audit_logs.sql'


class AuditLogMixin:
    """审计日志写入与超级管理员查询 API。"""

    def _is_super_admin_user(self, user_id):
        try:
            return int(user_id or 0) == 1
        except Exception:
            return False

    @staticmethod
    def _audit_client_ip(environ):
        forwarded = (environ.get('HTTP_X_FORWARDED_FOR') or '').strip()
        if forwarded:
            return forwarded.split(',')[0].strip()[:64]
        return (environ.get('REMOTE_ADDR') or '')[:64]

    @staticmethod
    def _audit_user_agent(environ):
        return (environ.get('HTTP_USER_AGENT') or '')[:255]

    def _audit_user_snapshot(self, user_id):
        record = self._get_user_permission_record(user_id) if user_id else None
        if not record:
            return {
                'user_id': int(user_id or 0),
                'username': '',
                'user_name': '',
            }
        return {
            'user_id': int(record.get('id') or user_id or 0),
            'username': str(record.get('username') or ''),
            'user_name': str(record.get('name') or ''),
        }

    @staticmethod
    def _audit_is_missing_table_error(exc):
        message = str(exc or '').lower()
        return (
            "doesn't exist" in message
            or 'does not exist' in message
            or 'unknown table' in message
        )

    @staticmethod
    def _audit_is_missing_column_error(exc, column_name=None):
        message = str(exc or '').lower()
        if 'unknown column' not in message:
            return False
        if column_name:
            return str(column_name).lower() in message
        return True

    def _audit_table_missing_json_response(self, start_response):
        return self.send_json({'status': 'error', 'message': _AUDIT_MIGRATION_HINT}, start_response)

    def _audit_page_label(self, page_key, page_path):
        labels = getattr(self, 'PAGE_PERMISSION_LABELS', None) or {}
        if page_key and labels.get(page_key):
            return labels[page_key]
        return page_path or page_key or ''

    # -------------------------------------------------------------------------
    # 写入：页面访问 / API 写操作（异步 INSERT）
    # -------------------------------------------------------------------------

    def _audit_try_log_page_access(self, environ, user_id, page_path, page_key=None):
        if not user_id:
            return
        snap = self._audit_user_snapshot(user_id)
        page_path = str(page_path or environ.get('PATH_INFO') or '')[:255]
        page_key = str(page_key or '')[:64] or None
        page_label = self._audit_page_label(page_key, page_path)[:128]
        payload = (
            snap['user_id'],
            snap['username'],
            snap['user_name'] or None,
            page_path,
            page_key,
            page_label,
            self._audit_client_ip(environ),
            self._audit_user_agent(environ),
        )

        def _insert():
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO access_logs (
                                user_id, username, user_name,
                                page_path, page_key, page_label,
                                client_ip, user_agent
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            payload,
                        )
            except Exception as e:
                if not self._audit_is_missing_table_error(e):
                    print('Audit page access log error: ' + str(e))

        threading.Thread(target=_insert, daemon=True).start()

    def _audit_should_log_operation(self, path, method):
        m = (method or 'GET').upper()
        if m not in _AUDIT_MUTATING:
            return False
        p = str(path or '')
        for prefix in _AUDIT_SKIP_OPERATION_PREFIXES:
            if p == prefix or p.startswith(prefix + '/'):
                return False
        return p.startswith('/api/')

    def _audit_cache_request_body(self, environ, path, method):
        if not self._audit_should_log_operation(path, method):
            return
        if environ.get('sitjoy.audit_body_cached'):
            return
        content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
        if content_length <= 0:
            environ['sitjoy.audit_body_cached'] = 1
            environ['sitjoy.audit_request_body'] = b''
            return
        if content_length > _AUDIT_BODY_MAX:
            environ['sitjoy.audit_body_cached'] = 1
            environ['sitjoy.audit_request_body'] = None
            environ['sitjoy.audit_body_skipped'] = 'large'
            return
        try:
            stream = environ['wsgi.input']
            body = stream.read(content_length)
            if len(body) < content_length:
                body = body + stream.read(content_length - len(body))
            environ['wsgi.input'] = BytesIO(body)
            environ['sitjoy.audit_request_body'] = body
            environ['sitjoy.audit_body_cached'] = 1
        except Exception:
            environ['sitjoy.audit_body_cached'] = 1
            environ['sitjoy.audit_request_body'] = None

    @staticmethod
    def _audit_redact_json(obj):
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                key = str(k)
                if key.lower() in _AUDIT_REDACT_KEYS:
                    out[key] = '***'
                else:
                    out[key] = AuditLogMixin._audit_redact_json(v)
            return out
        if isinstance(obj, list):
            return [AuditLogMixin._audit_redact_json(item) for item in obj[:50]]
        return obj

    def _audit_build_request_summary(self, environ, path, method):
        parts = [method or 'GET', path or '']
        qs = (environ.get('QUERY_STRING') or '').strip()
        if qs:
            parts.append('?' + qs[:500])
        ctype = (environ.get('CONTENT_TYPE') or '').lower()
        if 'multipart/form-data' in ctype:
            parts.append('[multipart]')
            return ' '.join(parts)[:_AUDIT_SUMMARY_MAX]

        if environ.get('sitjoy.audit_body_skipped') == 'large':
            parts.append('[body>48KB]')
            return ' '.join(parts)[:_AUDIT_SUMMARY_MAX]

        body = environ.get('sitjoy.audit_request_body')
        if body is None and int(environ.get('CONTENT_LENGTH', 0) or 0) > 0:
            parts.append('[body未缓存]')
            return ' '.join(parts)[:_AUDIT_SUMMARY_MAX]

        if not body:
            return ' '.join(parts)[:_AUDIT_SUMMARY_MAX]

        try:
            text = body.decode('utf-8', errors='replace')
            data = json.loads(text)
            redacted = self._audit_redact_json(data)
            snippet = json.dumps(redacted, ensure_ascii=False, separators=(',', ':'))
            parts.append(snippet)
        except Exception:
            text = body.decode('utf-8', errors='replace')
            text = re.sub(r'(password|password_hash)\s*[:=]\s*\S+', r'\1=***', text, flags=re.I)
            parts.append(text[:2000])
        summary = ' '.join(parts)
        return summary[:_AUDIT_SUMMARY_MAX]

    def _audit_module_key_for_path(self, path):
        permission_map = getattr(self, 'API_PERMISSION_MAP', None) or {}
        key = permission_map.get(path)
        if key:
            return key
        if str(path or '').startswith('/api/go-play'):
            return 'widgets_go_play'
        if str(path or '').startswith('/api/mahjong-play'):
            return 'widgets_mahjong'
        return None

    @staticmethod
    def _audit_format_display_value(value):
        if value is None:
            return '（空）'
        if isinstance(value, bool):
            return '是' if value else '否'
        if isinstance(value, (int, float)) and value in (0, 1):
            return '是' if int(value) == 1 else '否'
        if isinstance(value, (dict, list, tuple, set)):
            try:
                text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))
            except Exception:
                text = str(value)
            if len(text) > 180:
                return text[:177] + '…'
            return text
        text = str(value).strip()
        return text if text else '（空）'

    def _audit_field_label(self, field_name, field_labels=None):
        key = str(field_name or '').strip()
        if not key:
            return '字段'
        labels = field_labels or {}
        if key in labels:
            return labels[key]
        if key in _AUDIT_COMMON_FIELD_LABELS:
            return _AUDIT_COMMON_FIELD_LABELS[key]
        return key

    def _audit_compute_field_changes(self, before, after, field_labels=None, fields=None):
        before_map = before if isinstance(before, dict) else {}
        after_map = after if isinstance(after, dict) else {}
        keys = list(fields or [])
        if not keys:
            keys = sorted(set(before_map.keys()) | set(after_map.keys()))
        changes = []
        for key in keys:
            old_raw = before_map.get(key)
            new_raw = after_map.get(key)
            if key == 'page_permissions':
                old_norm = self._normalize_page_permissions(old_raw) if hasattr(self, '_normalize_page_permissions') else old_raw
                new_norm = self._normalize_page_permissions(new_raw) if hasattr(self, '_normalize_page_permissions') else new_raw
                if json.dumps(old_norm, ensure_ascii=False, sort_keys=True) == json.dumps(new_norm, ensure_ascii=False, sort_keys=True):
                    continue
                old_display = '（空）'
                new_display = '已调整'
            else:
                old_display = self._audit_format_display_value(old_raw)
                new_display = self._audit_format_display_value(new_raw)
                if old_display == new_display:
                    continue
            changes.append({
                'field': str(key),
                'label': self._audit_field_label(key, field_labels),
                'old': old_display,
                'new': new_display,
            })
        return changes

    def _audit_stage_entity_changes(
        self,
        environ,
        entity_type,
        entity_id,
        entity_label,
        before,
        after,
        field_labels=None,
        fields=None,
        action=None,
    ):
        if not environ:
            return
        changes = self._audit_compute_field_changes(before, after, field_labels=field_labels, fields=fields)
        if not changes:
            return
        environ['sitjoy.audit_entity'] = {
            'action': (action or environ.get('REQUEST_METHOD') or 'PUT').strip().lower(),
            'entity_type': str(entity_type or '')[:64],
            'entity_id': int(entity_id) if entity_id is not None else None,
            'entity_label': str(entity_label or '')[:255],
            'changes': changes,
        }

    def _audit_resource_label_for_path(self, path):
        p = str(path or '').strip()
        if p in _AUDIT_API_RESOURCE_LABELS:
            return _AUDIT_API_RESOURCE_LABELS[p]
        labels = getattr(self, 'PAGE_PERMISSION_LABELS', None) or {}
        module_key = self._audit_module_key_for_path(p)
        if module_key and labels.get(module_key):
            return labels[module_key]
        return p or 'API'

    def _audit_build_intuitive_summary(self, path, method, body_data=None, entity_meta=None):
        verb = _AUDIT_HTTP_VERB_LABELS.get((method or 'GET').upper(), method or 'GET')
        resource = self._audit_resource_label_for_path(path)
        lines = []

        if entity_meta:
            action = str(entity_meta.get('action') or '').lower()
            verb = _AUDIT_HTTP_VERB_LABELS.get(action.upper(), verb)
            entity_label = str(entity_meta.get('entity_label') or '').strip()
            entity_id = entity_meta.get('entity_id')
            head = verb + ' · ' + resource
            if entity_label:
                head += f'「{entity_label}」'
            if entity_id:
                head += f'(#{entity_id})'
            lines.append(head)
            for item in entity_meta.get('changes') or []:
                label = item.get('label') or item.get('field') or '字段'
                old_v = item.get('old', '（空）')
                new_v = item.get('new', '（空）')
                lines.append(f'{label}：{old_v} → {new_v}')
            return '\n'.join(lines)[:_AUDIT_SUMMARY_MAX]

        lines.append(f'{verb} · {resource}')
        if isinstance(body_data, dict) and body_data:
            preview_keys = []
            for key in body_data.keys():
                if str(key).lower() in _AUDIT_REDACT_KEYS:
                    continue
                preview_keys.append(key)
            preview_keys = preview_keys[:12]
            for key in preview_keys:
                label = self._audit_field_label(key)
                value = self._audit_format_display_value(body_data.get(key))
                if len(value) > 120:
                    value = value[:117] + '…'
                lines.append(f'{label}：{value}')
            if len(body_data.keys()) > len(preview_keys):
                lines.append(f'… 另有 {len(body_data.keys()) - len(preview_keys)} 项')
        return '\n'.join(lines)[:_AUDIT_SUMMARY_MAX]

    def _audit_try_log_operation(self, environ, path, method):
        user_id = self._get_session_user(environ)
        if not user_id or not self._audit_should_log_operation(path, method):
            return
        snap = self._audit_user_snapshot(user_id)
        entity_meta = environ.get('sitjoy.audit_entity')
        body_data = None
        body = environ.get('sitjoy.audit_request_body')
        if body and not environ.get('sitjoy.audit_body_skipped'):
            try:
                body_data = json.loads(body.decode('utf-8', errors='replace'))
                if isinstance(body_data, dict):
                    body_data = self._audit_redact_json(body_data)
            except Exception:
                body_data = None
        if entity_meta:
            summary = self._audit_build_intuitive_summary(path, method, body_data=body_data, entity_meta=entity_meta)
        else:
            summary = self._audit_build_intuitive_summary(path, method, body_data=body_data)
            if not summary or summary.count('\n') <= 1:
                summary = self._audit_build_request_summary(environ, path, method)
        changes_json = None
        if entity_meta:
            try:
                changes_json = json.dumps(entity_meta, ensure_ascii=False, separators=(',', ':'))
            except Exception:
                changes_json = None
        module_key = self._audit_module_key_for_path(path)
        payload = (
            snap['user_id'],
            snap['username'],
            snap['user_name'] or None,
            str(path or '')[:255],
            (method or 'GET').upper()[:16],
            (str(module_key)[:64] if module_key else None),
            summary,
            changes_json,
            self._audit_client_ip(environ),
        )

        def _insert():
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO operation_logs (
                                user_id, username, user_name,
                                api_path, http_method, module_key,
                                request_summary, changes_json, client_ip
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            payload,
                        )
            except Exception as e:
                if self._audit_is_missing_table_error(e):
                    try:
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    """
                                    INSERT INTO operation_logs (
                                        user_id, username, user_name,
                                        api_path, http_method, module_key,
                                        request_summary, client_ip
                                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                                    """,
                                    payload[:7] + (payload[8],),
                                )
                    except Exception as e2:
                        if not self._audit_is_missing_table_error(e2):
                            print('Audit operation log fallback error: ' + str(e2))
                    return
                print('Audit operation log error: ' + str(e))

        threading.Thread(target=_insert, daemon=True).start()

    # -------------------------------------------------------------------------
    # 管理端 API：分页查询与按保留天数清理
    # -------------------------------------------------------------------------

    def handle_audit_log_api(self, environ, method, start_response):
        try:
            user_id = self._get_session_user(environ)
            can_view = getattr(self, '_can_view_audit_logs', None)
            if not callable(can_view) or not can_view(user_id):
                return self.send_json({'status': 'error', 'message': '仅可授权管理员可查看审计日志'}, start_response)

            query = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query.get('action', [''])[0] or '').strip().lower()

            if method == 'POST' and action == 'cleanup':
                data = self._read_json_body(environ)
                log_type = (data.get('type') or 'all').strip().lower()
                days = self._parse_int(data.get('keep_days') or data.get('days'))
                if days is None or days < 1:
                    days = 90
                if days > 3650:
                    days = 3650
                deleted_access = 0
                deleted_operation = 0
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if log_type in ('access', 'all'):
                            cur.execute(
                                "DELETE FROM access_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
                                (days,),
                            )
                            deleted_access = int(cur.rowcount or 0)
                        if log_type in ('operation', 'all'):
                            cur.execute(
                                "DELETE FROM operation_logs WHERE created_at < DATE_SUB(NOW(), INTERVAL %s DAY)",
                                (days,),
                            )
                            deleted_operation = int(cur.rowcount or 0)
                return self.send_json({
                    'status': 'success',
                    'deleted_access': deleted_access,
                    'deleted_operation': deleted_operation,
                    'keep_days': days,
                }, start_response)

            if method != 'GET':
                return self.send_json({'status': 'error', 'message': '不支持的请求'}, start_response)

            log_type = (query.get('type', ['access'])[0] or 'access').strip().lower()
            keyword = (query.get('q', [''])[0] or '').strip()
            date_from = (query.get('date_from', [''])[0] or '').strip()
            date_to = (query.get('date_to', [''])[0] or '').strip()
            page = max(1, self._parse_int(query.get('page', ['1'])[0]) or 1)
            page_size = self._parse_int(query.get('page_size', ['50'])[0]) or 50
            page_size = max(10, min(200, page_size))
            offset = (page - 1) * page_size

            if log_type not in ('access', 'operation'):
                return self.send_json({'status': 'error', 'message': 'type 须为 access 或 operation'}, start_response)

            table = 'access_logs' if log_type == 'access' else 'operation_logs'
            where = ['1=1']
            params = []

            if keyword:
                if log_type == 'access':
                    where.append(
                        '(username LIKE %s OR user_name LIKE %s OR page_path LIKE %s OR page_label LIKE %s OR page_key LIKE %s)'
                    )
                    like = f'%{keyword}%'
                    params.extend([like, like, like, like, like])
                else:
                    where.append(
                        '(username LIKE %s OR user_name LIKE %s OR api_path LIKE %s OR request_summary LIKE %s OR module_key LIKE %s)'
                    )
                    like = f'%{keyword}%'
                    params.extend([like, like, like, like, like])

            if date_from:
                where.append('created_at >= %s')
                params.append(date_from + ' 00:00:00')
            if date_to:
                where.append('created_at <= %s')
                params.append(date_to + ' 23:59:59')

            where_sql = ' AND '.join(where)

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(f'SELECT COUNT(*) AS cnt FROM {table} WHERE {where_sql}', tuple(params))
                    total_row = cur.fetchone() or {}
                    total = int(total_row.get('cnt') or 0)

                    if log_type == 'access':
                        cur.execute(
                            f"""
                            SELECT id, user_id, username, user_name, page_path, page_key, page_label,
                                   client_ip, user_agent, created_at
                            FROM {table}
                            WHERE {where_sql}
                            ORDER BY id DESC
                            LIMIT %s OFFSET %s
                            """,
                            tuple(params) + (page_size, offset),
                        )
                        rows = cur.fetchall() or []
                    else:
                        try:
                            cur.execute(
                                f"""
                                SELECT id, user_id, username, user_name, api_path, http_method, module_key,
                                       request_summary, changes_json, client_ip, created_at
                                FROM {table}
                                WHERE {where_sql}
                                ORDER BY id DESC
                                LIMIT %s OFFSET %s
                                """,
                                tuple(params) + (page_size, offset),
                            )
                            rows = cur.fetchall() or []
                        except Exception as list_exc:
                            if not self._audit_is_missing_column_error(list_exc, 'changes_json'):
                                raise
                            cur.execute(
                                f"""
                                SELECT id, user_id, username, user_name, api_path, http_method, module_key,
                                       request_summary, client_ip, created_at
                                FROM {table}
                                WHERE {where_sql}
                                ORDER BY id DESC
                                LIMIT %s OFFSET %s
                                """,
                                tuple(params) + (page_size, offset),
                            )
                            rows = cur.fetchall() or []

            for row in rows:
                if row.get('created_at') is not None:
                    row['created_at'] = str(row['created_at'])

            return self.send_json({
                'status': 'success',
                'type': log_type,
                'items': rows,
                'total': total,
                'page': page,
                'page_size': page_size,
            }, start_response)
        except Exception as e:
            if self._audit_is_missing_table_error(e):
                return self._audit_table_missing_json_response(start_response)
            print('Audit log API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
