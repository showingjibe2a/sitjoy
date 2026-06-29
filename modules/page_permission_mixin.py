# -*- coding: utf-8 -*-
"""页面权限：解析 page_permissions、访问校验、受保护页面与工厂数据范围。"""

import json


class PagePermissionMixin:
    """页面权限辅助能力。"""

    _PAGE_PERMISSION_LEGACY_ALIASES = {
        'amazon_ad_delivery_management': ('amazon_ad_target_management',),
        'amazon_ad_target_management': ('amazon_ad_delivery_management',),
        'spec_main_image_management': ('gallery',),
    }

    # -------------------------------------------------------------------------
    # 权限字典：解析 / 序列化 / 管理员默认授权
    # -------------------------------------------------------------------------

    def _permission_keys(self):
        keys = getattr(self, 'PAGE_PERMISSION_KEYS', None)
        if keys:
            return list(keys)
        return []

    def _default_page_permissions(self):
        return {key: 1 for key in self._permission_keys()}

    def _denied_permission_keys(self):
        denied = getattr(self, 'PAGE_PERMISSION_DEFAULT_DENIED', None)
        if not denied:
            return set()
        return set(denied)

    @staticmethod
    def _user_is_admin(record):
        """统一解析 users.is_admin（兼容 int / str / bool）。"""
        if not record:
            return False
        try:
            if int(record.get('id') or 0) == 1:
                return True
        except (TypeError, ValueError):
            pass
        value = record.get('is_admin')
        if value is True:
            return True
        if value is False or value is None:
            return False
        try:
            return int(value) == 1
        except (TypeError, ValueError):
            return str(value).strip().lower() in ('1', 'true', 'yes')

    def _apply_admin_permission_grants(self, record, permissions):
        """管理员默认拥有系统管理等受限模块权限（用于 API 返回与导航）。"""
        if not permissions or not self._user_is_admin(record):
            return permissions
        merged = dict(permissions)
        for key in self._denied_permission_keys():
            if key == 'system_audit_log_management':
                if self._can_manage_admin_permission(record):
                    merged[key] = 1
                continue
            merged[key] = 1
        return merged

    def _can_view_audit_logs(self, user_id):
        record = self._get_user_permission_record(user_id)
        if not record:
            return False
        return self._can_manage_admin_permission(record)

    def _normalize_page_permissions(self, raw_permissions, default_all=True):
        keys = self._permission_keys()
        denied = self._denied_permission_keys()
        normalized = {key: (1 if default_all else 0) for key in keys}
        for key in denied:
            normalized[key] = 0
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
            for key in denied:
                if key not in payload:
                    normalized[key] = 0
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
                    (user_id,),
                )
                row = cur.fetchone()
        if not row:
            return None
        row['page_permissions'] = self._normalize_page_permissions(row.get('page_permissions'))
        row['page_permissions'] = self._apply_admin_permission_grants(row, row['page_permissions'])
        return row

    def _can_manage_admin_permission(self, actor_record):
        if not actor_record:
            return False
        if int(actor_record.get('id') or 0) == 1:
            return True
        return bool(actor_record.get('is_admin')) and bool(actor_record.get('can_grant_admin'))

    # -------------------------------------------------------------------------
    # 页面 / API 访问校验
    # -------------------------------------------------------------------------

    def _user_has_page_access(self, user_id, permission_key):
        if not user_id:
            return False
        if not permission_key:
            return True
        record = self._get_user_permission_record(user_id)
        if not record:
            return False
        denied = self._denied_permission_keys()
        if permission_key in denied and self._user_is_admin(record):
            return True
        default = 0 if permission_key in denied else 1
        perms = record.get('page_permissions', {})
        if bool(perms.get(permission_key, default)):
            return True
        for legacy_key in self._PAGE_PERMISSION_LEGACY_ALIASES.get(permission_key, ()):
            if bool(perms.get(legacy_key, default)):
                return True
        return False

    def _serve_protected_page(self, environ, start_response, template_path, permission_key=None):
        user_id = self._get_session_user(environ)
        if not user_id:
            start_response('302 Found', [('Location', '/login')])
            return [b'']
        if permission_key and not self._user_has_page_access(user_id, permission_key):
            start_response('302 Found', [('Location', '/')])
            return [b'']
        page_path = self._normalize_request_path(environ.get('PATH_INFO'))
        log_page = getattr(self, '_audit_try_log_page_access', None)
        if callable(log_page):
            log_page(environ, user_id, page_path, permission_key)
        return self.serve_file(template_path, 'text/html', start_response)

    # -------------------------------------------------------------------------
    # 工厂范围 / 下单产品关联
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_missing_table_error(exc):
        message = str(exc or '').lower()
        return (
            "doesn't exist" in message
            or 'does not exist' in message
            or 'unknown table' in message
        )

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
                        (user_id,),
                    )
                    rows = cur.fetchall() or []
        except Exception as e:
            if self._is_missing_table_error(e):
                return None
            raise
        ids = []
        for row in rows:
            n = self._parse_int(row.get('factory_id'))
            if n and n > 0:
                ids.append(n)
        scoped = sorted(set(ids))
        return scoped if scoped else None

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
        target = self._parse_int(factory_id)
        return target and target in set(scope_ids)

    def _get_linked_order_product_ids(self, factory_ids=None):
        """Return order_product ids linked to factories via mapping table.

        - None: mapping table missing or no mapping rows (unrestricted)
        - []: mapping table exists but no sku linked for requested factories
        - [id, ...]: restricted sku ids
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT COUNT(1) AS c FROM order_product_factory_links")
                    count_row = cur.fetchone() or {}
                    total = int(count_row.get('c') or 0)
                    if total <= 0:
                        return None
                    if factory_ids is None:
                        cur.execute("SELECT DISTINCT order_product_id FROM order_product_factory_links")
                    else:
                        valid_ids = [int(v) for v in (factory_ids or []) if int(v or 0) > 0]
                        if not valid_ids:
                            return []
                        placeholders = ','.join(['%s'] * len(valid_ids))
                        cur.execute(
                            f"SELECT DISTINCT order_product_id FROM order_product_factory_links WHERE factory_id IN ({placeholders})",
                            tuple(valid_ids),
                        )
                    rows = cur.fetchall() or []
        except Exception as e:
            if self._is_missing_table_error(e):
                return None
            raise
        ids = []
        for row in rows:
            n = self._parse_int(row.get('order_product_id'))
            if n and n > 0:
                ids.append(n)
        return sorted(set(ids))

    def _order_product_allowed_for_factory(self, order_product_id, factory_id):
        linked = self._get_linked_order_product_ids([factory_id])
        if linked is None:
            return True
        target = self._parse_int(order_product_id)
        return target and target in set(linked)

