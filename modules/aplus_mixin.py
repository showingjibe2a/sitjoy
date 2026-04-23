# -*- coding: utf-8 -*-
"""A+ 管理 Mixin - 版本/素材/布局（模板化渲染支持）"""

import os
import re
import io
import cgi
import json
import time
import hashlib
from urllib.parse import parse_qs


class AplusMixin:
    def _sanitize_folder_component(self, text, max_len=80):
        s = str(text or '').strip()
        if not s:
            return ''
        s = s.replace('\\', '-').replace('/', '-').replace('\x00', '')
        for ch in ['<', '>', ':', '"', '|', '?', '*']:
            s = s.replace(ch, '-')
        s = re.sub(r'\s+', ' ', s).strip()
        if max_len and len(s) > max_len:
            s = s[:max_len].rstrip()
        return s

    def _ensure_aplus_tables(self, conn):
        """
        Intentionally NO-OP.
        Database schema must be managed via scripts/sql/*.sql only.
        Do not create/alter/check schema at runtime.
        """
        return

    def _aplus_version_folder_abs(self, conn, sku_family_id, version_name):
        """Return absolute bytes path: <货号>/A+/<版本名>/ ."""
        sku_family_id = int(sku_family_id or 0)
        if sku_family_id <= 0:
            return b''
        with conn.cursor() as cur:
            cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
            row = cur.fetchone() or {}
        sku_family = str(row.get('sku_family') or '').strip()
        if not sku_family:
            return b''
        base = self._join_resources('')
        sku_root = os.path.join(base, self._safe_fsencode(sku_family))
        aplus_root = os.path.join(sku_root, self._safe_fsencode('A+'))
        ver = self._sanitize_folder_component(version_name, 80) or 'version'
        ver_root = os.path.join(aplus_root, self._safe_fsencode(ver))
        return ver_root

    def _ensure_aplus_version_folder(self, conn, sku_family_id, version_name):
        folder = self._aplus_version_folder_abs(conn, sku_family_id, version_name)
        if not folder:
            return b''
        try:
            os.makedirs(folder, exist_ok=True)
        except Exception:
            pass
        return folder

    def _sha256_hex(self, data):
        h = hashlib.sha256()
        h.update(data or b'')
        return h.hexdigest()

    def _get_image_type_id_for_aplus(self, conn, image_type_name, platform_type_id):
        """Validate image type is enabled, applies_aplus=1, and platform matches (or generic)."""
        name = str(image_type_name or '').strip()
        if not name:
            return 0
        platform_type_id = int(platform_type_id or 0)
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id
                FROM image_types
                WHERE name=%s AND is_enabled=1 AND applies_aplus=1
                LIMIT 1
                """,
                (name,),
            )
            row = cur.fetchone() or {}
            tid = int(row.get('id') or 0)
        if tid <= 0:
            return 0

        # platform filter: if mapping table exists and this type has rows, must match platform_type_id
        if platform_type_id > 0:
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.TABLES
                        WHERE TABLE_SCHEMA=DATABASE()
                          AND TABLE_NAME='image_type_platform_types'
                        """,
                    )
                    has_map = int((cur.fetchone() or {}).get('cnt') or 0) > 0
                if has_map:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM image_type_platform_types WHERE image_type_id=%s LIMIT 1", (tid,))
                        has_any = bool(cur.fetchone())
                    if has_any:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT 1 FROM image_type_platform_types WHERE image_type_id=%s AND platform_type_id=%s LIMIT 1",
                                (tid, platform_type_id),
                            )
                            if not cur.fetchone():
                                return 0
            except Exception:
                # If table missing or check fails, be permissive (runtime compatibility)
                pass

        return tid

    def handle_aplus_version_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query = parse_qs(environ.get('QUERY_STRING', '') or '')
                platform_type_id = self._parse_int(query.get('platform_type_id', [''])[0])
                sku_family_id = self._parse_int(query.get('sku_family_id', [''])[0])
                keyword = str(query.get('q', [''])[0] or '').strip()
                with self._get_db_connection() as conn:
                    where = []
                    params = []
                    if platform_type_id:
                        where.append("v.platform_type_id=%s")
                        params.append(int(platform_type_id))
                    if sku_family_id:
                        where.append("v.sku_family_id=%s")
                        params.append(int(sku_family_id))
                    if keyword:
                        where.append("(v.version_name LIKE %s)")
                        params.append(f"%{keyword}%")
                    where_sql = ("WHERE " + " AND ".join(where)) if where else ""
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT v.id, v.version_name, v.platform_type_id, v.sku_family_id,
                                   v.created_at, v.updated_at,
                                   pf.sku_family,
                                   pt.name AS platform_type_name
                            FROM aplus_versions v
                            LEFT JOIN product_families pf ON pf.id=v.sku_family_id
                            LEFT JOIN platform_types pt ON pt.id=v.platform_type_id
                            {where_sql}
                            ORDER BY v.updated_at DESC, v.id DESC
                            LIMIT 500
                            """,
                            tuple(params),
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                version_name = str(data.get('version_name') or '').strip()
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                if not version_name or not platform_type_id or not sku_family_id:
                    return self.send_json({'status': 'error', 'message': 'Missing version_name/platform_type_id/sku_family_id'}, start_response)
                if len(version_name) > 128:
                    return self.send_json({'status': 'error', 'message': '版本名称过长'}, start_response)
                user_id = None
                try:
                    user_id = self._get_session_user(environ)
                except Exception:
                    user_id = None
                with self._get_db_connection() as conn:
                    self._ensure_aplus_version_folder(conn, sku_family_id, version_name)
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO aplus_versions (version_name, platform_type_id, sku_family_id, created_by)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (version_name, int(platform_type_id), int(sku_family_id), int(user_id) if user_id else None),
                        )
                        vid = cur.lastrowid
                return self.send_json({'status': 'success', 'id': int(vid)}, start_response)

            if method in ('PATCH', 'PUT'):
                data = self._read_json_body(environ)
                vid = self._parse_int(data.get('id'))
                if not vid:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                sets = []
                vals = []
                if 'version_name' in data:
                    name = str(data.get('version_name') or '').strip()
                    if not name:
                        return self.send_json({'status': 'error', 'message': '版本名称不能为空'}, start_response)
                    if len(name) > 128:
                        return self.send_json({'status': 'error', 'message': '版本名称过长'}, start_response)
                    sets.append("version_name=%s")
                    vals.append(name)
                if not sets:
                    return self.send_json({'status': 'error', 'message': 'No updatable fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(f"UPDATE aplus_versions SET {', '.join(sets)} WHERE id=%s", tuple(vals + [int(vid)]))
                return self.send_json({'status': 'success', 'id': int(vid)}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                vid = self._parse_int(data.get('id'))
                if not vid:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM aplus_version_assets WHERE aplus_version_id=%s", (int(vid),))
                        cur.execute("DELETE FROM aplus_versions WHERE id=%s", (int(vid),))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_aplus_version_layout_api(self, environ, method, start_response):
        # Deprecated route: layout JSON now lives on image_types.aplus_layout_json_{mobile,desktop}
        return self.send_json({'status': 'error', 'message': 'Deprecated: use /api/image-type to read/write A+ layout JSON'}, start_response)

    def handle_aplus_version_assets_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query = parse_qs(environ.get('QUERY_STRING', '') or '')
                vid = self._parse_int(query.get('aplus_version_id', [''])[0] or query.get('id', [''])[0])
                device = str(query.get('device', [''])[0] or '').strip().lower()
                image_type_id = self._parse_int(query.get('image_type_id', [''])[0])
                if not vid:
                    return self.send_json({'status': 'error', 'message': 'Missing aplus_version_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        where = ["a.aplus_version_id=%s"]
                        params = [int(vid)]
                        if device in ('mobile', 'desktop'):
                            where.append("a.device=%s")
                            params.append(device)
                        if image_type_id:
                            where.append("a.image_type_id=%s")
                            params.append(int(image_type_id))
                        where_sql = "WHERE " + " AND ".join(where)
                        cur.execute(
                            """
                            SELECT a.id, a.aplus_version_id, a.image_asset_id, a.image_type_id, a.sort_order, a.device,
                                   ia.storage_path, ia.description
                            FROM aplus_version_assets a
                            LEFT JOIN image_assets ia ON ia.id=a.image_asset_id
                            {where_sql}
                            ORDER BY a.sort_order ASC, a.id ASC
                            """.format(where_sql=where_sql),
                            tuple(params),
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                vid = self._parse_int(data.get('aplus_version_id'))
                aid = self._parse_int(data.get('image_asset_id'))
                sort_order = self._parse_int(data.get('sort_order')) or 1
                device = str(data.get('device') or '').strip().lower() or 'desktop'
                if device not in ('mobile', 'desktop'):
                    device = 'desktop'
                if not vid or not aid:
                    return self.send_json({'status': 'error', 'message': 'Missing aplus_version_id/image_asset_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        image_type_id = self._parse_int(data.get('image_type_id'))
                        if not image_type_id:
                            cur.execute("SELECT image_type_id FROM image_assets WHERE id=%s LIMIT 1", (int(aid),))
                            arow = cur.fetchone() or {}
                            image_type_id = self._parse_int(arow.get('image_type_id'))
                        if not image_type_id:
                            return self.send_json({'status': 'error', 'message': 'Missing image_type_id'}, start_response)
                        cur.execute(
                            """
                            INSERT INTO aplus_version_assets (aplus_version_id, image_asset_id, image_type_id, sort_order, device)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (int(vid), int(aid), int(image_type_id), max(1, int(sort_order)), device),
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                vid = self._parse_int(data.get('aplus_version_id'))
                aid = self._parse_int(data.get('image_asset_id'))
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if item_id:
                            cur.execute("DELETE FROM aplus_version_assets WHERE id=%s", (int(item_id),))
                        elif vid and aid:
                            cur.execute("DELETE FROM aplus_version_assets WHERE aplus_version_id=%s AND image_asset_id=%s", (int(vid), int(aid)))
                        else:
                            return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_aplus_upload_api(self, environ, start_response):
        """Upload images into A+ version folder and register into image_assets + aplus_version_assets."""
        try:
            if environ.get('REQUEST_METHOD') != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)
            form = cgi.FieldStorage(fp=environ.get('wsgi.input'), environ=environ, keep_blank_values=True)
            vid = self._parse_int(form.getfirst('aplus_version_id', '') or form.getfirst('id', ''))
            if not vid:
                return self.send_json({'status': 'error', 'message': 'Missing aplus_version_id'}, start_response)
            image_type_name = str(form.getfirst('image_type_name', '') or '').strip()
            if not image_type_name:
                return self.send_json({'status': 'error', 'message': 'Missing image_type_name'}, start_response)
            device = str(form.getfirst('device', '') or 'desktop').strip().lower()
            if device not in ('mobile', 'desktop'):
                device = 'desktop'
            if 'file' not in form:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            files_field = form['file']
            files_list = files_field if isinstance(files_field, list) else [files_field]

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT platform_type_id, sku_family_id, version_name FROM aplus_versions WHERE id=%s LIMIT 1", (int(vid),))
                    vrow = cur.fetchone() or {}
                if not vrow:
                    return self.send_json({'status': 'error', 'message': 'A+版本不存在'}, start_response)
                platform_type_id = int(vrow.get('platform_type_id') or 0)
                sku_family_id = int(vrow.get('sku_family_id') or 0)
                version_name = str(vrow.get('version_name') or '').strip()

                type_id = self._get_image_type_id_for_aplus(conn, image_type_name, platform_type_id)
                if not type_id:
                    return self.send_json({'status': 'error', 'message': '图片类型不可用于当前平台A+'}, start_response)

                folder_abs = self._ensure_aplus_version_folder(conn, sku_family_id, version_name)
                if not folder_abs:
                    return self.send_json({'status': 'error', 'message': '无法定位A+目录（请确认货号）'}, start_response)

                created = 0
                asset_ids = []
                for item in files_list:
                    if not getattr(item, 'filename', None):
                        continue
                    filename = os.path.basename(str(item.filename))
                    if not self._is_image_name(filename):
                        continue
                    try:
                        content = item.file.read() or b''
                    except Exception:
                        content = b''
                    if not content:
                        continue
                    sha = self._sha256_hex(content)
                    ext = os.path.splitext(filename)[1].lower() or '.jpg'
                    base = os.path.splitext(filename)[0]
                    base = self._sanitize_folder_component(base, 80) or sha[:12]
                    safe_name = f"{self._sanitize_folder_component(image_type_name, 32) or 'A+'}-{base}{ext}"
                    abs_path = os.path.join(folder_abs, self._safe_fsencode(safe_name))
                    # ensure unique
                    if os.path.exists(abs_path):
                        safe_name = f"{self._sanitize_folder_component(image_type_name, 32) or 'A+'}-{base}_{int(time.time())}{ext}"
                        abs_path = os.path.join(folder_abs, self._safe_fsencode(safe_name))
                    with open(abs_path, 'wb') as f:
                        f.write(content)

                    storage_path = self._storage_path_from_abs(abs_path) if hasattr(self, '_storage_path_from_abs') else ''
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO image_assets (sha256, storage_path, image_type_id) VALUES (%s, %s, %s)",
                            (sha, storage_path, int(type_id)),
                        )
                        new_aid = int(cur.lastrowid or 0)
                        if new_aid:
                            asset_ids.append(new_aid)
                            created += 1
                            # attach to version
                            cur.execute(
                                "INSERT INTO aplus_version_assets (aplus_version_id, image_asset_id, image_type_id, sort_order, device) VALUES (%s, %s, %s, %s, %s)",
                                (int(vid), int(new_aid), int(type_id), 1, device),
                            )

                return self.send_json({'status': 'success', 'created': created, 'asset_ids': asset_ids}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

