# -*- coding: utf-8 -*-
"""面料管理 Mixin - 包含 5 个 fabric API 处理器"""

import os
import base64
import json
import time
import cgi
import io
import re
import hashlib
import unicodedata
from urllib.parse import parse_qs

class FabricManagementMixin:
    """面料管理 API 处理器"""

    def _fabric_folder_candidates(self):
        # Historical folders used by different implementations
        return [
            self._join_resources('『面料』'),
            self._join_resources('面料库'),
        ]

    def _resolve_fabric_image_abs_path(self, image_name):
        name = os.path.basename(str(image_name or '').strip())
        if not name:
            return None
        for folder in self._fabric_folder_candidates():
            try:
                p = os.path.join(folder, self._safe_fsencode(name))
            except Exception:
                p = os.path.join(folder, name.encode('utf-8', errors='surrogatepass'))
            if os.path.exists(p):
                return p
        return None

    def _is_fabric_assets_ready(self):
        try:
            return bool(self._is_schema_marker_ready('fabric_image_assets_ready'))
        except Exception:
            return False

    def _get_fabric_folder_bytes(self):
        return self._join_resources('『面料』')

    def _next_fabric_image_index(self, existing_names, fabric_code):
        max_idx = 0
        prefix = f"{fabric_code}_"
        for name in existing_names:
            if not name:
                continue
            if name.startswith(prefix):
                match = re.match(rf"^{re.escape(prefix)}(\\d+)", name)
                if match:
                    try:
                        max_idx = max(max_idx, int(match.group(1)))
                    except Exception:
                        continue
            elif name.startswith(f"{fabric_code}."):
                max_idx = max(max_idx, 1)
        return max_idx + 1

    def handle_fabric_images_api(self, environ, start_response):
        """列出面料文件夹内图片"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', '') or '')
            unbound_only = str(query_params.get('unbound', [''])[0]).strip().lower() in ('1', 'true', 'yes')
            current_fabric_id = None
            try:
                raw_fabric_id = str(query_params.get('fabric_id', [''])[0]).strip()
                if raw_fabric_id:
                    current_fabric_id = int(raw_fabric_id)
            except Exception:
                current_fabric_id = None

            bound_name_to_fabric_ids = {}
            bound_b64_to_fabric_ids = {}
            if unbound_only:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if self._has_required_tables(['fabric_image_mappings', 'image_assets']):
                            cur.execute(
                                """
                                SELECT fim.fabric_id AS fabric_id, ia.storage_path AS storage_path
                                FROM fabric_image_mappings fim
                                INNER JOIN image_assets ia ON ia.id = fim.image_asset_id
                                """
                            )
                            db_rows = cur.fetchall() or []
                        else:
                            db_rows = []
                        db_count = 0
                        for row in db_rows:
                            sp = (row.get('storage_path') or '').strip()
                            display = os.path.basename(sp) if sp else ''
                            image_name = str(display or '').strip().replace('\\', '/')
                            if not image_name:
                                continue
                            fid = row.get('fabric_id')
                            db_count += 1
                            self._add_name_and_b64_variants(bound_name_to_fabric_ids, bound_b64_to_fabric_ids, image_name, fid)

            folder = self._get_fabric_folder_bytes()
            if not os.path.exists(folder):
                return self.send_json({'status': 'success', 'items': []}, start_response)

            items = []
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        raw = entry.name
                        if isinstance(raw, (str,)):
                            try:
                                raw_bytes = os.fsencode(raw)
                            except Exception:
                                raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                        else:
                            raw_bytes = raw

                        display = None
                        try:
                            display = os.fsdecode(raw_bytes)
                            display = display.encode('utf-8', errors='surrogatepass').decode('utf-8', errors='replace')
                        except Exception:
                            try:
                                display = raw_bytes.decode('utf-8', errors='replace')
                            except Exception:
                                try:
                                    display = raw_bytes.decode('gb18030', errors='replace')
                                except Exception:
                                    display = raw_bytes.decode('latin-1', errors='replace')

                        if unbound_only:
                            normalized_display = (display or '').replace('\\', '/').split('/')[-1].strip()
                            try:
                                nd_nfc = unicodedata.normalize('NFC', normalized_display)
                            except Exception:
                                nd_nfc = normalized_display
                            try:
                                nd_nfd = unicodedata.normalize('NFD', nd_nfc)
                            except Exception:
                                nd_nfd = nd_nfc

                            check_ids = set()
                            for variant in (nd_nfc, nd_nfc.lower(), nd_nfd, nd_nfd.lower()):
                                if variant:
                                    ids = bound_name_to_fabric_ids.get(variant, set())
                                    if ids:
                                        check_ids |= ids

                            try:
                                b64_display_raw = base64.b64encode(raw_bytes).decode('ascii')
                                ids = bound_b64_to_fabric_ids.get(b64_display_raw, set())
                                if ids:
                                    check_ids |= ids
                            except Exception:
                                pass

                            for variant in (nd_nfc, nd_nfd):
                                try:
                                    vb = os.fsencode(variant)
                                    b64_v = base64.b64encode(vb).decode('ascii')
                                    ids = bound_b64_to_fabric_ids.get(b64_v, set())
                                    if ids:
                                        check_ids |= ids
                                except Exception:
                                    pass

                            if check_ids:
                                if current_fabric_id is None or current_fabric_id not in check_ids:
                                    continue

                        try:
                            folder_bytes = os.fsencode('『面料』')
                        except Exception:
                            folder_bytes = '『面料』'.encode('utf-8', errors='surrogatepass')
                        try:
                            rel_bytes = os.path.join(folder_bytes, raw_bytes)
                        except Exception:
                            rel_bytes = folder_bytes + os.sep.encode('utf-8', errors='surrogatepass') + raw_bytes
                        b64 = base64.b64encode(rel_bytes).decode('ascii')
                        name_raw_b64 = base64.b64encode(raw_bytes).decode('ascii')
                        items.append({'name': display, 'name_raw_b64': name_raw_b64, 'b64': b64})

            try:
                items.sort(key=lambda x: (x.get('name') or '').lower())
            except Exception:
                pass
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_upload_api(self, environ, start_response):
        """上传面料图片"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)

            fabric_code = (form.getfirst('fabric_code', '') or '').strip()
            if not fabric_code:
                return self.send_json({'status': 'error', 'message': 'Missing fabric_code'}, start_response)

            all_parts = getattr(form, 'list', []) or []
            uploads = []
            for p in all_parts:
                if getattr(p, 'filename', None):
                    try:
                        content = p.file.read() or b''
                    except Exception:
                        content = b''
                    uploads.append({'filename': p.filename, 'type': getattr(p, 'type', None), 'content': content})

            if not uploads:
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded'}, start_response)

            folder = self._ensure_fabric_folder()
            existing = set()
            try:
                with os.scandir(folder) as it:
                    for entry in it:
                        if entry.is_file(follow_symlinks=False):
                            name = entry.name
                            if isinstance(name, (bytes, bytearray)):
                                try:
                                    name = os.fsdecode(name)
                                except Exception:
                                    name = name.decode('utf-8', errors='ignore')
                            existing.add(str(name))
            except Exception:
                existing = set()

            saved_names = []
            for item in uploads:
                try:
                    orig_filename = os.path.basename(item.get('filename') or '')
                    content = item.get('content') or b''

                    if len(content) == 0:
                        continue

                    def infer_ext_from_bytes(b):
                        if not b or len(b) < 4:
                            return ''
                        if b.startswith(b"\xff\xd8\xff"):
                            return '.jpg'
                        if b.startswith(b"\x89PNG"):
                            return '.png'
                        if b.startswith(b"GIF8"):
                            return '.gif'
                        return ''

                    ext = ''
                    if orig_filename and self._is_image_name(orig_filename):
                        ext = os.path.splitext(orig_filename)[1]
                    if not ext:
                        ext = infer_ext_from_bytes(content)
                    if not ext:
                        continue

                    index = self._next_fabric_image_index(existing, fabric_code)
                    target_name = f"{fabric_code}_{index:02d}{ext}"
                    dest_path = os.path.join(folder, os.fsencode(target_name))
                    
                    if target_name not in existing and not os.path.exists(dest_path):
                        with open(dest_path, 'wb') as f:
                            f.write(content)
                        saved_names.append(target_name)
                        existing.add(target_name)
                except Exception:
                    pass

            if not saved_names:
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded'}, start_response)

            return self.send_json({'status': 'success', 'image_names': saved_names}, start_response)
        except Exception as e:
            print("Fabric upload error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_image_delete_api(self, environ, method, start_response):
        """删除面料图片"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            data = self._read_json_body(environ)
            image_name = (data.get('image_name') or '').strip()
            raw_b64 = (data.get('image_name_raw_b64') or '').strip()

            if not image_name and not raw_b64:
                return self.send_json({'status': 'error', 'message': 'Missing image_name'}, start_response)

            raw_bytes = None
            if raw_b64:
                try:
                    raw_bytes = base64.b64decode(raw_b64)
                except Exception:
                    raw_bytes = None

            folder = self._get_fabric_folder_bytes()
            if not os.path.exists(folder):
                return self.send_json({'status': 'error', 'message': '面料图片目录不存在'}, start_response)

            file_candidates = []
            if raw_bytes is not None:
                file_candidates.append(os.path.join(folder, raw_bytes))
            if image_name:
                file_candidates.append(os.path.join(folder, self._safe_fsencode(os.path.basename(image_name))))

            file_path = None
            for candidate in file_candidates:
                if os.path.exists(candidate):
                    file_path = candidate
                    break

            if file_path is None:
                return self.send_json({'status': 'error', 'message': '图片文件不存在'}, start_response)

            try:
                os.remove(file_path)
            except Exception as remove_err:
                return self.send_json({'status': 'error', 'message': f'删除文件失败: {remove_err}'}, start_response)

            return self.send_json({'status': 'success'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_attach_api(self, environ, start_response):
        """关联面料图片"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8')) if body else {}
            
            fabric_code = (data.get('fabric_code') or '').strip()
            items = data.get('items') or []
            
            if not fabric_code or not items:
                return self.send_json({'status': 'error', 'message': 'Missing fabric_code or items'}, start_response)

            folder = self._ensure_fabric_folder()
            existing = set()
            try:
                with os.scandir(folder) as it:
                    for entry in it:
                        if entry.is_file(follow_symlinks=False):
                            name = entry.name
                            if isinstance(name, (bytes, bytearray)):
                                try:
                                    name = os.fsdecode(name)
                                except Exception:
                                    name = name.decode('utf-8', errors='ignore')
                            existing.add(str(name))
            except Exception:
                existing = set()

            results = []
            next_idx = 1
            
            for raw_b64 in items:
                try:
                    raw_bytes = base64.b64decode(raw_b64)
                    src = None
                    try:
                        src = os.path.join(folder, raw_bytes)
                    except Exception:
                        try:
                            name_str = os.fsdecode(raw_bytes)
                        except Exception:
                            name_str = None
                        if name_str:
                            src = os.path.join(folder, os.fsencode(name_str))

                    if not src or not os.path.exists(src):
                        continue

                    src_basename = os.path.basename(src)
                    try:
                        src_basename_str = os.fsdecode(src_basename)
                    except Exception:
                        src_basename_str = 'img'

                    ext = os.path.splitext(src_basename_str)[1] or ''
                    idx = next_idx
                    while True:
                        candidate = f"{fabric_code}_{idx:02d}{ext}"
                        if candidate not in existing:
                            break
                        idx += 1

                    dst = os.path.join(folder, os.fsencode(candidate))
                    try:
                        os.rename(src, dst)
                        results.append({'old_b64': raw_b64, 'new_name': candidate})
                        existing.add(candidate)
                        next_idx = idx + 1
                    except Exception:
                        pass
                except Exception:
                    pass

            return self.send_json({'status': 'success', 'items': results}, start_response)
        except Exception as e:
            print('Fabric attach error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_api(self, environ, method, start_response):
        """面料管理 API（CRUD）"""
        try:

            def _normalize_color(value):
                import re
                text = str(value or '').strip().upper()
                if not text:
                    return None
                if re.match(r'^#[0-9A-F]{6}$', text):
                    return text
                return None

            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        where_sql = ""
                        params = []
                        if keyword:
                            where_sql = "WHERE fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s"
                            params = [f"%{keyword}%", f"%{keyword}%"]

                        if keyword:
                            cur.execute(
                                f"""
                                SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.representative_color, fm.material_id,
                                        m.name AS material_name, m.name_en AS material_name_en,
                                        fm.created_at
                                FROM fabric_materials fm
                                LEFT JOIN materials m ON fm.material_id = m.id
                                {where_sql}
                                ORDER BY fm.id DESC
                                """,
                                tuple(params)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.representative_color, fm.material_id,
                                        m.name AS material_name, m.name_en AS material_name_en,
                                        fm.created_at
                                FROM fabric_materials fm
                                LEFT JOIN materials m ON fm.material_id = m.id
                                ORDER BY fm.id DESC
                                """
                            )
                        rows = cur.fetchall() or []

                        fabric_ids = [self._parse_int(row.get('id')) for row in rows if self._parse_int(row.get('id'))]
                        image_map = {}
                        sku_map = {}

                        if fabric_ids:
                            placeholders = ','.join(['%s'] * len(fabric_ids))
                            if self._has_required_tables(['fabric_image_mappings', 'image_assets']):
                                has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
                                has_ia_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')
                                dep_expr = "COALESCE(ia.is_deprecated,0)" if has_ia_dep else "0"
                                join_it = "LEFT JOIN image_types it ON it.id = ia.image_type_id" if has_ia_tid else ""
                                tid_sel = "ia.image_type_id AS image_type_id" if has_ia_tid else "NULL AS image_type_id"
                                tname_sel = "it.name AS type_name" if has_ia_tid else "NULL AS type_name"
                                cur.execute(
                                    f"""
                                    SELECT fim.fabric_id, ia.storage_path AS storage_path,
                                           fim.sort_order, ia.description AS description,
                                           {dep_expr} AS is_deprecated,
                                           {tname_sel}, {tid_sel}
                                    FROM fabric_image_mappings fim
                                    JOIN image_assets ia ON ia.id = fim.image_asset_id
                                    {join_it}
                                    WHERE fim.fabric_id IN ({placeholders})
                                    ORDER BY fim.fabric_id ASC, {dep_expr} ASC, fim.sort_order ASC, fim.id ASC
                                    """,
                                    tuple(fabric_ids)
                                )
                                for img in (cur.fetchall() or []):
                                    fid = self._parse_int(img.get('fabric_id'))
                                    if not fid:
                                        continue
                                    storage_path = (img.get('storage_path') or '').strip()
                                    display_name = os.path.basename(storage_path) if storage_path else ''
                                    tname = (img.get('type_name') or '').strip()
                                    image_map.setdefault(fid, []).append({
                                        'image_name': display_name or '',
                                        'remark': tname,
                                        'description': (img.get('description') or '').strip(),
                                        'sort_order': self._parse_int(img.get('sort_order')) or 0,
                                        'is_deprecated': int(img.get('is_deprecated') or 0),
                                    })

                            cur.execute(
                                f"""
                                SELECT fpf.fabric_id, fpf.sku_family_id, pf.sku_family
                                FROM fabric_product_families fpf
                                LEFT JOIN product_families pf ON pf.id = fpf.sku_family_id
                                WHERE fpf.fabric_id IN ({placeholders})
                                ORDER BY fpf.fabric_id ASC, fpf.sku_family_id ASC
                                """,
                                tuple(fabric_ids)
                            )
                            for rel in (cur.fetchall() or []):
                                fid = self._parse_int(rel.get('fabric_id'))
                                sku_id = self._parse_int(rel.get('sku_family_id'))
                                if not fid or not sku_id:
                                    continue
                                sku_map.setdefault(fid, []).append({
                                    'id': sku_id,
                                    'sku_family': rel.get('sku_family') or ''
                                })

                        for row in rows:
                            fid = self._parse_int(row.get('id'))
                            images = image_map.get(fid, []) if fid else []
                            skus = sku_map.get(fid, []) if fid else []
                            row['images'] = images
                            row['image_names'] = [x.get('image_name') for x in images if x.get('image_name')]
                            row['sku_family_ids'] = [x.get('id') for x in skus if x.get('id')]
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                representative_color = _normalize_color(data.get('representative_color'))
                material_id = self._parse_int(data.get('material_id'))
                images = data.get('images') or []
                sku_family_ids = [self._parse_int(v) for v in (data.get('sku_family_ids') or [])]
                sku_family_ids = [v for v in sku_family_ids if v]
                
                if not fabric_code or not fabric_name_en or not material_id:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO fabric_materials (fabric_code, fabric_name_en, representative_color, material_id)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (fabric_code, fabric_name_en, representative_color, material_id)
                        )
                        new_id = cur.lastrowid
                    self._replace_fabric_image_mappings(conn, new_id, images)
                    self._replace_fabric_sku_families(conn, new_id, sku_family_ids)

                self._template_options_cache.pop('fabric_list_all', None)
                self._template_options_cache.pop('sku_list_all', None)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                representative_color = _normalize_color(data.get('representative_color'))
                material_id = self._parse_int(data.get('material_id'))
                images = data.get('images') or []
                sku_family_ids = [self._parse_int(v) for v in (data.get('sku_family_ids') or [])]
                sku_family_ids = [v for v in sku_family_ids if v]
                
                if not item_id or not fabric_code or not fabric_name_en or not material_id:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE fabric_materials
                            SET fabric_code=%s, fabric_name_en=%s, representative_color=%s, material_id=%s
                            WHERE id=%s
                            """,
                            (fabric_code, fabric_name_en, representative_color, material_id, item_id)
                        )
                    self._replace_fabric_image_mappings(conn, item_id, images)
                    self._replace_fabric_sku_families(conn, item_id, sku_family_ids)

                self._template_options_cache.pop('fabric_list_all', None)
                self._template_options_cache.pop('sku_list_all', None)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM fabric_materials WHERE id=%s", (item_id,))
                
                self._template_options_cache.pop('fabric_list_all', None)
                self._template_options_cache.pop('sku_list_all', None)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            err_text = str(e).lower()
            if 'duplicate entry' in err_text or '1062' in err_text:
                return self.send_json({'status': 'error', 'message': '面料编号已存在'}, start_response)
            print("Fabric API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _replace_fabric_image_mappings(self, conn, fabric_id, images):
        """
        Persist fabric image order + per-asset description/type on image_assets.
        Requires fabric_image_mappings + image_assets (legacy fabric_images removed).
        """
        if not self._has_required_tables(['fabric_image_mappings', 'image_assets']):
            raise RuntimeError('缺少 fabric_image_mappings / image_assets，请先执行 scripts/sql/20260422_04_image_asset_center.sql 并完成面料图迁移')
        fid = int(fabric_id or 0)
        if not fid:
            return

        rows = []
        for idx, item in enumerate(images or []):
            if isinstance(item, dict):
                image_name = str(item.get('image_name') or '').strip()
                type_name = str(item.get('remark') or '').strip()
                description = str(item.get('description') or '').strip()
                sort_order = self._parse_int(item.get('sort_order'))
            else:
                image_name = str(item or '').strip()
                type_name = ''
                description = ''
                sort_order = None
            if not image_name:
                continue
            rows.append((image_name, type_name, description, sort_order if sort_order is not None else idx))

        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_image_mappings WHERE fabric_id=%s", (fid,))

        has_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')

        for image_name, type_name, description, sort_order in rows:
            abs_path = self._resolve_fabric_image_abs_path(image_name)
            if not abs_path or not os.path.exists(abs_path):
                continue
            try:
                with open(abs_path, 'rb') as f:
                    content = f.read() or b''
            except Exception:
                continue
            if not content:
                continue
            sha256 = hashlib.sha256(content).hexdigest()
            try:
                res_root = self._join_resources('')
                rel_bytes = os.path.relpath(abs_path, res_root)
                storage_path = os.fsdecode(rel_bytes).replace('\\', '/')
            except Exception:
                storage_path = str(image_name).replace('\\', '/')
            orig_fn = os.path.basename(str(image_name).strip().replace('\\', '/')) or os.path.basename(storage_path)
            desc_v = (description or '')[:1000]

            tid = None
            if type_name and has_tid:
                try:
                    tid = self._get_image_type_id_by_name(conn, type_name)
                except Exception:
                    tid = None
            if not tid and has_tid:
                try:
                    tid = self._get_image_type_id_by_name(conn, '文字卖点图')
                except Exception:
                    tid = None

            with conn.cursor() as cur:
                cur.execute("SELECT id FROM image_assets WHERE sha256=%s LIMIT 1", (sha256,))
                exist = cur.fetchone() or {}
                aid = self._parse_int(exist.get('id'))
                if aid:
                    sets = ["description=%s"]
                    vals = [desc_v or None]
                    if has_tid and tid:
                        sets.append("image_type_id=%s")
                        vals.append(tid)
                    vals.append(aid)
                    cur.execute(f"UPDATE image_assets SET {', '.join(sets)} WHERE id=%s", tuple(vals))
                else:
                    cols = ["sha256", "storage_path", "description"]
                    vals = [sha256, storage_path, desc_v or None]
                    if has_tid:
                        cols.append("image_type_id")
                        vals.append(tid)
                    if has_dep:
                        cols.append("is_deprecated")
                        vals.append(0)
                    ph = ", ".join(["%s"] * len(cols))
                    cur.execute(
                        f"INSERT INTO image_assets ({', '.join(cols)}) VALUES ({ph})",
                        tuple(vals),
                    )
                    aid = cur.lastrowid

                cur.execute(
                    "INSERT INTO fabric_image_mappings (fabric_id, image_asset_id, sort_order) VALUES (%s,%s,%s)",
                    (fid, int(aid), int(sort_order)),
                )

    def _replace_fabric_sku_families(self, conn, fabric_id, sku_family_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE fabric_id=%s", (fabric_id,))
            for sku_family_id in sku_family_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def handle_fabric_image_migrate_api(self, environ, method, start_response):
        """
        One-time migration helper:
        - Read existing fabric_images rows
        - Locate files in resources (面料库 / 『面料』)
        - Compute sha256 and upsert image_assets
        - Create fabric_image_mappings rows
        - Mark schema switch ready: fabric_image_assets_ready
        """
        try:
            if method == 'GET':
                # Some reverse proxies block/redirect POST for custom endpoints. Provide a safe GET trigger
                # behind login: /api/fabric-image-migrate?run=1&limit=50
                query_params = parse_qs(environ.get('QUERY_STRING', '') or '')
                run = str(query_params.get('run', ['0'])[0] or '0').strip().lower() in ('1', 'true', 'yes', 'on')
                if not run:
                    return self.send_json(
                        {
                            'status': 'info',
                            'message': '该接口用于迁移面料图片到 image_assets。默认仅展示说明；要执行迁移请使用 POST，或在已登录状态下用 GET 带 run=1。',
                            'examples': {
                                'browser_get': '/api/fabric-image-migrate?run=1&limit=50',
                                'powershell_post': "Invoke-RestMethod -Method Post -Uri 'http://<host>/api/fabric-image-migrate' -ContentType 'application/json' -Body '{\"limit\":0}'",
                            },
                        },
                        start_response,
                    )
                # Convert GET run request into the same flow as POST, reading params from query string.
                try:
                    limit = int(str(query_params.get('limit', ['0'])[0] or '0').strip() or '0')
                except Exception:
                    limit = 0
                data = {'limit': limit}
            else:
                data = self._read_json_body(environ)
            if method != 'POST':
                # GET run=1 is handled above
                if method != 'GET':
                    return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)
            if not self._has_required_tables(['image_assets', 'fabric_image_mappings']):
                return self.send_json({'status': 'error', 'message': 'Missing image_assets / fabric_image_mappings'}, start_response)
            if not self._has_required_tables(['fabric_images']):
                return self.send_json(
                    {
                        'status': 'success',
                        'migrated': 0,
                        'skipped': [],
                        'message': 'fabric_images 表不存在，跳过迁移（若已执行 20260422_04 清理脚本则属正常）。',
                    },
                    start_response,
                )

            try:
                limit = int((data or {}).get('limit') or 0) or 0
            except Exception:
                limit = 0

            migrated = 0
            skipped = []
            with self._get_db_connection() as conn:

                def _insert_image_asset_row(cur, sha256_val, storage_path_val, orig_fn, content_len, remark_text):
                    has = lambda col: self._table_has_column(conn, 'image_assets', col)
                    cols = ['sha256', 'storage_path']
                    vals = [sha256_val, storage_path_val]
                    if has('description'):
                        cols.append('description')
                        vals.append('')
                    if has('file_ext'):
                        ext = os.path.splitext(orig_fn)[1].lower() or '.jpg'
                        cols.append('file_ext')
                        vals.append(ext)
                    if has('mime_type'):
                        cols.append('mime_type')
                        vals.append('image/*')
                    if has('file_size'):
                        cols.append('file_size')
                        vals.append(int(content_len or 0))
                    if has('image_type_id'):
                        tid = None
                        if remark_text:
                            try:
                                tid = self._get_image_type_id_by_name(conn, str(remark_text).strip())
                            except Exception:
                                tid = None
                        if not tid:
                            try:
                                tid = self._get_image_type_id_by_name(conn, '文字卖点图')
                            except Exception:
                                tid = None
                        cols.append('image_type_id')
                        vals.append(tid)
                    if has('is_deprecated'):
                        cols.append('is_deprecated')
                        vals.append(0)
                    ph = ', '.join(['%s'] * len(cols))
                    cur.execute(
                        f"INSERT INTO image_assets ({', '.join(cols)}) VALUES ({ph})",
                        tuple(vals),
                    )
                    return cur.lastrowid

                with conn.cursor() as cur:
                    sql = (
                        "SELECT id, fabric_id, image_name, remark, sort_order "
                        "FROM fabric_images ORDER BY fabric_id ASC, sort_order ASC, id ASC"
                    )
                    if limit > 0:
                        sql += " LIMIT %s"
                        cur.execute(sql, (limit,))
                    else:
                        cur.execute(sql)
                    rows = cur.fetchall() or []

                fim_has_remark = self._table_has_column(conn, 'fabric_image_mappings', 'remark')
                fim_has_dep = self._table_has_column(conn, 'fabric_image_mappings', 'is_deprecated')

                for row in rows:
                    image_name = (row.get('image_name') or '').strip()
                    remark = (row.get('remark') or '').strip()
                    if remark == '原图':
                        try:
                            with conn.cursor() as cur:
                                cur.execute("DELETE FROM fabric_images WHERE id=%s", (row.get('id'),))
                        except Exception:
                            pass
                        continue
                    abs_path = self._resolve_fabric_image_abs_path(image_name)
                    if not abs_path or not os.path.exists(abs_path):
                        skipped.append({'image_name': image_name, 'reason': 'file_not_found'})
                        continue
                    try:
                        with open(abs_path, 'rb') as f:
                            content = f.read() or b''
                    except Exception:
                        skipped.append({'image_name': image_name, 'reason': 'read_failed'})
                        continue
                    if not content:
                        skipped.append({'image_name': image_name, 'reason': 'empty_file'})
                        continue

                    sha256 = hashlib.sha256(content).hexdigest()
                    try:
                        res_root = self._join_resources('')
                        rel_bytes = os.path.relpath(abs_path, res_root)
                        storage_path = os.fsdecode(rel_bytes).replace('\\', '/')
                    except Exception:
                        storage_path = str(image_name).replace('\\', '/')
                    orig_fn = os.path.basename(image_name)

                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM image_assets WHERE sha256=%s LIMIT 1", (sha256,))
                        asset = cur.fetchone() or {}
                        asset_id = asset.get('id')
                        if not asset_id:
                            asset_id = _insert_image_asset_row(cur, sha256, storage_path, orig_fn, len(content), remark)
                        elif self._table_has_column(conn, 'image_assets', 'image_type_id') and remark:
                            try:
                                tid = self._get_image_type_id_by_name(conn, remark)
                                if tid:
                                    cur.execute(
                                        "UPDATE image_assets SET image_type_id=COALESCE(image_type_id, %s) WHERE id=%s",
                                        (tid, int(asset_id)),
                                    )
                            except Exception:
                                pass

                        if fim_has_remark or fim_has_dep:
                            cols = ['fabric_id', 'image_asset_id', 'sort_order']
                            vals = [int(row.get('fabric_id') or 0), int(asset_id), int(row.get('sort_order') or 0)]
                            if fim_has_remark:
                                cols.insert(2, 'remark')
                                vals.insert(2, remark or None)
                            if fim_has_dep:
                                cols.append('is_deprecated')
                                vals.append(0)
                            dup_sql = ''
                            if fim_has_remark:
                                dup_sql = ', remark=VALUES(remark)'
                            cur.execute(
                                f"""
                                INSERT INTO fabric_image_mappings ({', '.join(cols)})
                                VALUES ({', '.join(['%s'] * len(vals))})
                                ON DUPLICATE KEY UPDATE sort_order=VALUES(sort_order){dup_sql}
                                """,
                                tuple(vals),
                            )
                        else:
                            cur.execute(
                                """
                                INSERT INTO fabric_image_mappings (fabric_id, image_asset_id, sort_order)
                                VALUES (%s,%s,%s)
                                ON DUPLICATE KEY UPDATE sort_order=VALUES(sort_order)
                                """,
                                (int(row.get('fabric_id') or 0), int(asset_id), int(row.get('sort_order') or 0)),
                            )
                    migrated += 1

            try:
                self._set_schema_marker_ready('fabric_image_assets_ready')
            except Exception:
                pass

            return self.send_json({'status': 'success', 'migrated': migrated, 'skipped': skipped[:50]}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
