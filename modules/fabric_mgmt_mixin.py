# -*- coding: utf-8 -*-
"""面料管理 Mixin - 包含 5 个 fabric API 处理器"""

import os
import base64
import json
import time
import cgi
import io
import unicodedata
from urllib.parse import parse_qs

class FabricManagementMixin:
    """面料管理 API 处理器"""

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
                        cur.execute("SELECT fabric_id, image_name FROM fabric_images")
                        db_count = 0
                        for row in (cur.fetchall() or []):
                            image_name = (row.get('image_name') or '').strip().replace('\\', '/')
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
            self._ensure_fabric_table()
            
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
                        if keyword:
                            cur.execute(
                                """
                                SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.representative_color, fm.material_id,
                                        m.name AS material_name, m.name_en AS material_name_en,
                                        fm.created_at
                                FROM fabric_materials fm
                                LEFT JOIN materials m ON fm.material_id = m.id
                                WHERE fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s
                                ORDER BY fm.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
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
                        for row in rows:
                            row['images'] = []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                representative_color = _normalize_color(data.get('representative_color'))
                material_id = self._parse_int(data.get('material_id'))
                
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

                self._template_options_cache.pop('fabric_list_all', None)
                self._template_options_cache.pop('sku_list_all', None)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                representative_color = _normalize_color(data.get('representative_color'))
                material_id = self._parse_int(data.get('material_id'))
                
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
            import pymysql
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '面料编号已存在'}, start_response)
            print("Fabric API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
