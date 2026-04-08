import json


class PagePermissionMixin:
    """页面权限辅助能力。"""

    def _permission_keys(self):
        keys = getattr(self, 'PAGE_PERMISSION_KEYS', None)
        if keys:
            return list(keys)
        return []

    def _default_page_permissions(self):
        return {key: 1 for key in self._permission_keys()}

    def _normalize_page_permissions(self, raw_permissions, default_all=True):
        keys = self._permission_keys()
        normalized = {key: (1 if default_all else 0) for key in keys}
        if raw_permissions is None or raw_permissions == '':
            return normalized

        payload = raw_permissions
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                return normalized

        if isinstance(payload, dict):
            for key in keys:
                if key in payload:
                    normalized[key] = 1 if payload.get(key) else 0
            return normalized

        if isinstance(payload, (list, tuple, set)):
            allowed = {str(item) for item in payload}
            return {key: (1 if key in allowed else 0) for key in keys}

        return normalized

    def _serialize_page_permissions(self, raw_permissions, default_all=True):
        normalized = self._normalize_page_permissions(raw_permissions, default_all=default_all)
        return json.dumps(normalized, ensure_ascii=False)

    def _get_user_permission_record(self, user_id):
        if not user_id:
            return None
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, username, name, is_admin,
                           COALESCE(can_grant_admin, 0) AS can_grant_admin,
                           page_permissions
                    FROM users
                    WHERE id=%s
                    """,
                    (user_id,)
                )
                row = cur.fetchone()
        if not row:
            return None
        row['page_permissions'] = self._normalize_page_permissions(row.get('page_permissions'))
        return row

    def _can_manage_admin_permission(self, actor_record):
        if not actor_record:
            return False
        if int(actor_record.get('id') or 0) == 1:
            return True
        return bool(actor_record.get('is_admin')) and bool(actor_record.get('can_grant_admin'))

    def _user_has_page_access(self, user_id, permission_key):
        if not user_id:
            return False
        if not permission_key:
            return True
        record = self._get_user_permission_record(user_id)
        if not record:
            return False
        return bool(record.get('page_permissions', {}).get(permission_key, 1))

    def _serve_protected_page(self, environ, start_response, template_path, permission_key=None):
        user_id = self._get_session_user(environ)
        if not user_id:
            start_response('302 Found', [('Location', '/login')])
            return [b'']
        if permission_key and not self._user_has_page_access(user_id, permission_key):
            start_response('302 Found', [('Location', '/')])
            return [b'']
        return self.serve_file(template_path, 'text/html', start_response)

    def _get_user_factory_scope_ids(self, user_id):
        """Return allowed factory ids for a user.

        - `None`: unrestricted (typically admin or table not initialized)
        - `[]`: no factory access
        - `[id, ...]`: restricted to these factories
        """
        if not user_id:
            return []
        record = self._get_user_permission_record(user_id)
        if record and bool(record.get('is_admin')):
            return None
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT factory_id FROM user_factory_scopes WHERE user_id=%s ORDER BY factory_id ASC",
                        (user_id,)
                    )
                    rows = cur.fetchall() or []
        except Exception as e:
            message = str(e).lower()
            if "doesn't exist" in message or 'does not exist' in message or 'unknown table' in message:
                return None
            raise
        ids = []
        for row in rows:
            try:
                value = int(row.get('factory_id') or 0)
            except Exception:
                value = 0
            if value > 0:
                ids.append(value)
        return sorted(set(ids))

    def _factory_scope_clause(self, column_sql, user_id, prefix='AND'):
        scope_ids = self._get_user_factory_scope_ids(user_id)
        if scope_ids is None:
            return ('', tuple())
        if not scope_ids:
            return (f' {prefix} 1=0', tuple())
        placeholders = ','.join(['%s'] * len(scope_ids))
        return (f' {prefix} {column_sql} IN ({placeholders})', tuple(scope_ids))

    def _factory_scope_contains(self, user_id, factory_id):
        scope_ids = self._get_user_factory_scope_ids(user_id)
        if scope_ids is None:
            return True
        try:
            target = int(factory_id or 0)
        except Exception:
            target = 0
        return target > 0 and target in set(scope_ids)



