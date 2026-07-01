# -*- coding: utf-8 -*-
"""A+ 管理 Mixin - 版本/栏目布局/素材组与上传替换"""

import os
import re
import cgi
import json
import time
import hashlib
from urllib.parse import parse_qs


class AplusMixin:
    """A+ 页面：版本目录、栏目布局、素材绑定、上传与替换。"""

    # -------------------------------------------------------------------------
    # 工具
    # -------------------------------------------------------------------------

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
        return

    def _aplus_parse_bool(self, value, default=False):
        if hasattr(self, '_parse_bool_flag'):
            return bool(self._parse_bool_flag(value, default=default))
        if value is None:
            return bool(default)
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'on', 'y'):
            return True
        if text in ('0', 'false', 'no', 'off', 'n'):
            return False
        return bool(default)

    def _aplus_version_folder_abs(self, conn, sku_family_id, version_name):
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
        return os.path.join(aplus_root, self._safe_fsencode(ver))

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

    def _aplus_validate_version_name(self, raw):
        name = str(raw or '').strip()
        if not name:
            return None, '版本名称不能为空'
        if len(name) > 128:
            return None, '版本名称过长'
        return name, None

    def _aplus_image_type_allowed_for_platform(self, conn, image_type_row, platform_type_id):
        if not image_type_row:
            return False
        if int(image_type_row.get('is_enabled') or 0) != 1:
            return False
        if int(image_type_row.get('applies_aplus') or 0) != 1:
            return False
        platform_type_id = int(platform_type_id or 0)
        if hasattr(self, '_image_type_matches_platform'):
            return self._image_type_matches_platform(image_type_row.get('platform_type_ids'), platform_type_id)
        csv = str(image_type_row.get('platform_type_ids') or '').strip()
        if not csv:
            return True
        if not platform_type_id:
            return True
        parts = [p.strip() for p in csv.split(',') if p.strip()]
        return str(platform_type_id) in parts

    def _aplus_asset_ref_count(self, conn, asset_id, exclude_link_id=None):
        aid = int(asset_id or 0)
        if aid <= 0:
            return 0
        total = 0
        with conn.cursor() as cur:
            if exclude_link_id:
                cur.execute(
                    "SELECT COUNT(1) AS c FROM aplus_version_assets WHERE image_asset_id=%s AND id<>%s",
                    (aid, int(exclude_link_id)),
                )
            else:
                cur.execute("SELECT COUNT(1) AS c FROM aplus_version_assets WHERE image_asset_id=%s", (aid,))
            total += int((cur.fetchone() or {}).get('c') or 0)
        for table in ('fabric_image_mappings', 'sales_variant_image_mappings'):
            if not self._has_required_tables([table]):
                continue
            try:
                with conn.cursor() as cur:
                    cur.execute(f"SELECT COUNT(1) AS c FROM {table} WHERE image_asset_id=%s", (aid,))
                    total += int((cur.fetchone() or {}).get('c') or 0)
            except Exception:
                continue
        return total

    def _aplus_recycle_asset_file_if_orphan(self, conn, asset_id, exclude_link_id=None, reason='替换'):
        aid = int(asset_id or 0)
        if aid <= 0:
            return True, ''
        refs = self._aplus_asset_ref_count(conn, aid, exclude_link_id=exclude_link_id)
        if refs > 0:
            return True, '仍有其他引用，保留原文件'
        storage_path = ''
        with conn.cursor() as cur:
            cur.execute("SELECT storage_path FROM image_assets WHERE id=%s LIMIT 1", (aid,))
            storage_path = str((cur.fetchone() or {}).get('storage_path') or '').strip()
        if storage_path:
            abs_path = self._join_resources(self._safe_fsencode(storage_path))
            if abs_path and os.path.exists(abs_path) and hasattr(self, '_move_file_to_listing_recycle_bin'):
                moved_ok, _dst, err = self._move_file_to_listing_recycle_bin(abs_path, reason)
                if not moved_ok:
                    return False, str(err or '移入回收站失败')
        with conn.cursor() as cur:
            cur.execute("DELETE FROM image_assets WHERE id=%s", (aid,))
        return True, ''

    def _resolve_aplus_image_type(self, conn, image_type_id=None, image_type_name=None, platform_type_id=0):
        tid = self._parse_int(image_type_id)
        if tid > 0:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id, name, is_enabled, applies_aplus, platform_type_ids
                    FROM image_types WHERE id=%s LIMIT 1
                    """,
                    (int(tid),),
                )
                row = cur.fetchone() or {}
            if row.get('id') and self._aplus_image_type_allowed_for_platform(conn, row, platform_type_id):
                return int(row['id']), str(row.get('name') or '')
            return 0, ''
        name = str(image_type_name or '').strip()
        if not name:
            return 0, ''
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, is_enabled, applies_aplus, platform_type_ids
                FROM image_types
                WHERE name=%s AND is_enabled=1 AND applies_aplus=1
                LIMIT 1
                """,
                (name,),
            )
            row = cur.fetchone() or {}
        if row.get('id') and self._aplus_image_type_allowed_for_platform(conn, row, platform_type_id):
            return int(row['id']), str(row.get('name') or '')
        return 0, ''

    # -------------------------------------------------------------------------
    # API：A+ 版本 CRUD
    # -------------------------------------------------------------------------

    def handle_aplus_version_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query = parse_qs(environ.get('QUERY_STRING', '') or '')
                platform_type_id = self._parse_int(query.get('platform_type_id', [''])[0])
                sku_family_id = self._parse_int(query.get('sku_family_id', [''])[0])
                keyword = str(query.get('q', [''])[0] or '').strip()
                detail_id = self._parse_int(query.get('id', [''])[0])
                with self._get_db_connection() as conn:
                    if detail_id:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                SELECT v.id, v.version_name, v.platform_type_id, v.sku_family_id,
                                       v.created_at, v.updated_at,
                                       pf.sku_family, pt.name AS platform_type_name
                                FROM aplus_versions v
                                LEFT JOIN product_families pf ON pf.id=v.sku_family_id
                                LEFT JOIN platform_types pt ON pt.id=v.platform_type_id
                                WHERE v.id=%s LIMIT 1
                                """,
                                (int(detail_id),),
                            )
                            row = cur.fetchone() or {}
                        if not row.get('id'):
                            return self.send_json({'status': 'error', 'message': '版本不存在'}, start_response)
                        return self.send_json({'status': 'success', 'item': row}, start_response)

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
                                   pf.sku_family, pt.name AS platform_type_name
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
                version_name, ver_err = self._aplus_validate_version_name(data.get('version_name'))
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                if ver_err:
                    return self.send_json({'status': 'error', 'message': ver_err}, start_response)
                if not platform_type_id or not sku_family_id:
                    return self.send_json({'status': 'error', 'message': 'Missing version_name/platform_type_id/sku_family_id'}, start_response)
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
                    version_name, ver_err = self._aplus_validate_version_name(data.get('version_name'))
                    if ver_err:
                        return self.send_json({'status': 'error', 'message': ver_err}, start_response)
                    sets.append("version_name=%s")
                    vals.append(version_name)
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
        return self.send_json({'status': 'error', 'message': 'Deprecated: use PATCH /api/image-type for A+ layout JSON'}, start_response)

    # -------------------------------------------------------------------------
    # API：版本素材
    # -------------------------------------------------------------------------

    def handle_aplus_version_assets_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query = parse_qs(environ.get('QUERY_STRING', '') or '')
                vid = self._parse_int(query.get('aplus_version_id', [''])[0] or query.get('id', [''])[0])
                sort_order = self._parse_int(query.get('sort_order', [''])[0])
                device = str(query.get('device', [''])[0] or '').strip().lower()
                if not vid:
                    return self.send_json({'status': 'error', 'message': 'Missing aplus_version_id'}, start_response)
                with self._get_db_connection() as conn:
                    where = ["a.aplus_version_id=%s"]
                    params = [int(vid)]
                    if sort_order:
                        where.append("a.sort_order=%s")
                        params.append(int(sort_order))
                    if device == 'mobile':
                        where.append("a.apply_mobile=1")
                    elif device == 'desktop':
                        where.append("a.apply_desktop=1")
                    where_sql = "WHERE " + " AND ".join(where)
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT a.id, a.aplus_version_id, a.image_asset_id,
                                   a.sort_order, a.item_sort_order,
                                   a.apply_mobile, a.apply_desktop,
                                   ia.storage_path, ia.description, ia.image_type_id,
                                   it.name AS image_type_name,
                                   it.aplus_layout_json_mobile, it.aplus_layout_json_desktop,
                                   it.aplus_share_images
                            FROM aplus_version_assets a
                            LEFT JOIN image_assets ia ON ia.id=a.image_asset_id
                            LEFT JOIN image_types it ON it.id=ia.image_type_id
                            {where_sql}
                            ORDER BY a.sort_order ASC, a.item_sort_order ASC, a.id ASC
                            """,
                            tuple(params),
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                vid = self._parse_int(data.get('aplus_version_id'))
                aid = self._parse_int(data.get('image_asset_id'))
                sort_order = max(1, self._parse_int(data.get('sort_order')) or 1)
                item_sort_order = max(1, self._parse_int(data.get('item_sort_order')) or 1)
                apply_mobile = int(self._aplus_parse_bool(data.get('apply_mobile'), default=True))
                apply_desktop = int(self._aplus_parse_bool(data.get('apply_desktop'), default=True))
                if not vid or not aid:
                    return self.send_json({'status': 'error', 'message': 'Missing aplus_version_id/image_asset_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO aplus_version_assets
                                (aplus_version_id, image_asset_id, sort_order, apply_mobile, apply_desktop, item_sort_order)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            """,
                            (int(vid), int(aid), sort_order, apply_mobile, apply_desktop, item_sort_order),
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method in ('PATCH', 'PUT'):
                data = self._read_json_body(environ)
                items = data.get('items')
                if not isinstance(items, list) or not items:
                    item_id = self._parse_int(data.get('id'))
                    if not item_id:
                        return self.send_json({'status': 'error', 'message': 'Missing items'}, start_response)
                    items = [data]
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        for it in items:
                            item_id = self._parse_int((it or {}).get('id'))
                            if not item_id:
                                continue
                            sets = []
                            vals = []
                            if 'sort_order' in it:
                                sets.append('sort_order=%s')
                                vals.append(max(1, self._parse_int(it.get('sort_order')) or 1))
                            if 'item_sort_order' in it:
                                sets.append('item_sort_order=%s')
                                vals.append(max(1, self._parse_int(it.get('item_sort_order')) or 1))
                            if 'apply_mobile' in it:
                                sets.append('apply_mobile=%s')
                                vals.append(int(self._aplus_parse_bool(it.get('apply_mobile'), default=True)))
                            if 'apply_desktop' in it:
                                sets.append('apply_desktop=%s')
                                vals.append(int(self._aplus_parse_bool(it.get('apply_desktop'), default=True)))
                            if not sets:
                                continue
                            cur.execute(
                                f"UPDATE aplus_version_assets SET {', '.join(sets)} WHERE id=%s",
                                tuple(vals + [int(item_id)]),
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
                            cur.execute("SELECT image_asset_id FROM aplus_version_assets WHERE id=%s LIMIT 1", (int(item_id),))
                            row = cur.fetchone() or {}
                            cur.execute("DELETE FROM aplus_version_assets WHERE id=%s", (int(item_id),))
                            orphan_aid = self._parse_int(row.get('image_asset_id'))
                            if orphan_aid:
                                self._aplus_recycle_asset_file_if_orphan(conn, orphan_aid, reason='移除')
                        elif vid and aid:
                            cur.execute(
                                "DELETE FROM aplus_version_assets WHERE aplus_version_id=%s AND image_asset_id=%s",
                                (int(vid), int(aid)),
                            )
                            self._aplus_recycle_asset_file_if_orphan(conn, aid, reason='移除')
                        else:
                            return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    # -------------------------------------------------------------------------
    # API：上传 / 替换
    # -------------------------------------------------------------------------

    def handle_aplus_upload_api(self, environ, start_response):
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
            sort_order = max(1, self._parse_int(form.getfirst('sort_order', '') or '1') or 1)
            requested_item_sort = self._parse_int(form.getfirst('item_sort_order', ''))
            apply_mobile = int(self._aplus_parse_bool(form.getfirst('apply_mobile', '1'), default=True))
            apply_desktop = int(self._aplus_parse_bool(form.getfirst('apply_desktop', '1'), default=True))
            image_type_id = self._parse_int(form.getfirst('image_type_id', ''))
            image_type_name = str(form.getfirst('image_type_name', '') or '').strip()
            replace_link_id = self._parse_int(form.getfirst('replace_link_id', ''))
            if 'file' not in form:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            files_field = form['file']
            files_list = files_field if isinstance(files_field, list) else [files_field]

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT platform_type_id, sku_family_id, version_name FROM aplus_versions WHERE id=%s LIMIT 1",
                        (int(vid),),
                    )
                    vrow = cur.fetchone() or {}
                if not vrow:
                    return self.send_json({'status': 'error', 'message': 'A+版本不存在'}, start_response)
                platform_type_id = int(vrow.get('platform_type_id') or 0)
                sku_family_id = int(vrow.get('sku_family_id') or 0)
                version_name = str(vrow.get('version_name') or '').strip()
                folder_abs = self._ensure_aplus_version_folder(conn, sku_family_id, version_name)
                if not folder_abs:
                    return self.send_json({'status': 'error', 'message': '无法定位A+目录（请确认货号）'}, start_response)

                if replace_link_id:
                    return self._aplus_replace_linked_asset(
                        conn, int(vid), int(replace_link_id), files_list, folder_abs, start_response,
                    )

                if requested_item_sort > 0:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id FROM aplus_version_assets
                            WHERE aplus_version_id=%s AND sort_order=%s AND item_sort_order=%s
                            LIMIT 1
                            """,
                            (int(vid), int(sort_order), int(requested_item_sort)),
                        )
                        slot_row = cur.fetchone() or {}
                    slot_link_id = self._parse_int(slot_row.get('id'))
                    if slot_link_id:
                        return self._aplus_replace_linked_asset(
                            conn, int(vid), int(slot_link_id), files_list, folder_abs, start_response,
                        )

                type_id, _type_name = self._resolve_aplus_image_type(
                    conn, image_type_id=image_type_id, image_type_name=image_type_name, platform_type_id=platform_type_id,
                )
                if not type_id and not replace_link_id:
                    # 若组内已有素材，沿用该组首张图的图片类型
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT ia.image_type_id
                            FROM aplus_version_assets a
                            JOIN image_assets ia ON ia.id=a.image_asset_id
                            WHERE a.aplus_version_id=%s AND a.sort_order=%s AND ia.image_type_id IS NOT NULL
                            ORDER BY a.item_sort_order ASC, a.id ASC
                            LIMIT 1
                            """,
                            (int(vid), int(sort_order)),
                        )
                        inherit = cur.fetchone() or {}
                    inherit_id = self._parse_int(inherit.get('image_type_id'))
                    if inherit_id:
                        type_id, _ = self._resolve_aplus_image_type(
                            conn, image_type_id=inherit_id, platform_type_id=platform_type_id,
                        )
                if not type_id:
                    return self.send_json({'status': 'error', 'message': '请选择有效的A+图片类型'}, start_response)

                with conn.cursor() as cur:
                    if requested_item_sort > 0:
                        next_item_sort = int(requested_item_sort)
                    else:
                        cur.execute(
                            "SELECT COALESCE(MAX(item_sort_order), 0) AS mx FROM aplus_version_assets WHERE aplus_version_id=%s AND sort_order=%s",
                            (int(vid), int(sort_order)),
                        )
                        next_item_sort = int((cur.fetchone() or {}).get('mx') or 0)

                created = 0
                asset_ids = []
                link_ids = []
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
                    if requested_item_sort <= 0:
                        next_item_sort += 1
                    item_sort_order = int(next_item_sort)
                    sha = self._sha256_hex(content)
                    ext = os.path.splitext(filename)[1].lower() or '.jpg'
                    base = os.path.splitext(filename)[0]
                    base = self._sanitize_folder_component(base, 80) or sha[:12]
                    safe_name = f"A+-{base}{ext}"
                    abs_path = os.path.join(folder_abs, self._safe_fsencode(safe_name))
                    if os.path.exists(abs_path):
                        safe_name = f"A+-{base}_{int(time.time())}{ext}"
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
                            cur.execute(
                                """
                                INSERT INTO aplus_version_assets
                                    (aplus_version_id, image_asset_id, sort_order, apply_mobile, apply_desktop, item_sort_order)
                                VALUES (%s, %s, %s, %s, %s, %s)
                                """,
                                (int(vid), int(new_aid), int(sort_order), apply_mobile, apply_desktop, int(item_sort_order)),
                            )
                            link_ids.append(int(cur.lastrowid or 0))

                return self.send_json({
                    'status': 'success',
                    'created': created,
                    'asset_ids': asset_ids,
                    'link_ids': link_ids,
                }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _aplus_replace_linked_asset(self, conn, vid, link_id, files_list, folder_abs, start_response):
        file_item = None
        for item in files_list:
            if getattr(item, 'filename', None):
                file_item = item
                break
        if not file_item:
            return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
        try:
            content = file_item.file.read() or b''
        except Exception:
            content = b''
        if not content:
            return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT a.id, a.image_asset_id, ia.storage_path, ia.image_type_id
                FROM aplus_version_assets a
                LEFT JOIN image_assets ia ON ia.id=a.image_asset_id
                WHERE a.id=%s AND a.aplus_version_id=%s LIMIT 1
                """,
                (int(link_id), int(vid)),
            )
            link_row = cur.fetchone() or {}
        if not link_row.get('id'):
            return self.send_json({'status': 'error', 'message': '素材记录不存在'}, start_response)

        old_aid = int(link_row.get('image_asset_id') or 0)
        old_type_id = self._parse_int(link_row.get('image_type_id'))
        old_path = str(link_row.get('storage_path') or '').strip()
        sha = self._sha256_hex(content)
        filename = os.path.basename(str(file_item.filename))
        ext = os.path.splitext(filename)[1].lower() or '.jpg'
        other_refs = self._aplus_asset_ref_count(conn, old_aid, exclude_link_id=link_id)

        if old_path and other_refs <= 0:
            abs_old = self._join_resources(self._safe_fsencode(old_path))
            if os.path.exists(abs_old) and hasattr(self, '_move_file_to_listing_recycle_bin'):
                moved_ok, _dst, err = self._move_file_to_listing_recycle_bin(abs_old, '替换')
                if not moved_ok:
                    return self.send_json({'status': 'error', 'message': err or '旧图移入回收站失败'}, start_response)
            try:
                parent = os.path.dirname(abs_old)
                if parent and not os.path.exists(parent):
                    os.makedirs(parent, exist_ok=True)
                with open(abs_old, 'wb') as f:
                    f.write(content)
            except Exception as e:
                return self.send_json({'status': 'error', 'message': f'写入失败: {e}'}, start_response)
            with conn.cursor() as cur:
                cur.execute("UPDATE image_assets SET sha256=%s WHERE id=%s", (sha, old_aid))
            return self.send_json({'status': 'success', 'id': int(link_id), 'image_asset_id': old_aid, 'replaced': True}, start_response)

        base = self._sanitize_folder_component(os.path.splitext(filename)[0], 80) or sha[:12]
        safe_name = f"A+-{base}{ext}"
        abs_path = os.path.join(folder_abs, self._safe_fsencode(safe_name))
        if os.path.exists(abs_path):
            safe_name = f"A+-{base}_{int(time.time())}{ext}"
            abs_path = os.path.join(folder_abs, self._safe_fsencode(safe_name))
        with open(abs_path, 'wb') as f:
            f.write(content)
        storage_path = self._storage_path_from_abs(abs_path) if hasattr(self, '_storage_path_from_abs') else ''
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO image_assets (sha256, storage_path, image_type_id) VALUES (%s, %s, %s)",
                (sha, storage_path, int(old_type_id) if old_type_id else None),
            )
            new_aid = int(cur.lastrowid or 0)
            cur.execute("UPDATE aplus_version_assets SET image_asset_id=%s WHERE id=%s", (new_aid, int(link_id)))
        self._aplus_recycle_asset_file_if_orphan(conn, old_aid, exclude_link_id=link_id, reason='替换')
        return self.send_json({'status': 'success', 'id': int(link_id), 'image_asset_id': new_aid, 'replaced': True}, start_response)
