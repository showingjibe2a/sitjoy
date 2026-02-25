#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSGI 应用 - 用于 Synology Web Station
兼容 Apache + mod_wsgi
"""

import sys
import os

# 强制设置所有I/O为UTF-8（这是关键）
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

os.environ['PYTHONIOENCODING'] = 'utf-8'

from urllib.parse import urlparse, parse_qs
import json
import re
from datetime import datetime, timedelta
import calendar
import mimetypes
import base64
import io
from pathlib import Path
import time
import cgi
import tempfile
import zipfile
import hmac
import hashlib
import secrets
try:
    from PIL import Image
    _pillow_import_error = None
except Exception as e:
    Image = None
    _pillow_import_error = str(e)
try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)
try:
    import pymysql
    _pymysql_import_error = None
except Exception as e:
    pymysql = None
    _pymysql_import_error = str(e)

# 外部文件夹路径
# 使用 Base64 的子目录名，避免手动输入特殊字符出错
_RESOURCES_PARENT = '/volume1/公共文件SITJOY'
_RESOURCES_CHILD_B64 = '44CO5LiK5p626LWE5rqQ44CP'
_RESOURCES_PARENT_BYTES = _RESOURCES_PARENT.encode('utf-8', errors='surrogatepass')
_RESOURCES_CHILD_BYTES = base64.b64decode(_RESOURCES_CHILD_B64)
RESOURCES_PATH_BYTES = os.path.join(_RESOURCES_PARENT_BYTES, _RESOURCES_CHILD_BYTES)
RESOURCES_PATH = os.fsdecode(RESOURCES_PATH_BYTES)

class WSGIApp:
    """WSGI 应用处理器"""
    
    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self._db_ready = False
        self._order_product_ready = False
        self._material_types_ready = False
        self._materials_ready = False
        self._platform_types_ready = False
        self._brands_ready = False
        self._shops_ready = False
        self._amazon_ad_ready = False
        self._amazon_ad_subtypes_ready = False
        self._amazon_ad_operation_types_ready = False
        self._sales_product_ready = False
        self._todo_ready = False
        self._user_session = {}

    def _get_session_id(self, environ):
        """从 cookie 获取 session_id"""
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == 'session_id'), None)

    def _get_cookie_value(self, environ, name):
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == name), None)

    def _get_auth_secret(self):
        # Stable secret derived from env or db config, avoids cross-worker mismatch
        env_secret = os.environ.get('SITJOY_AUTH_SECRET')
        if env_secret:
            return env_secret.encode('utf-8', errors='ignore')
        cfg = self._get_db_config() or {}
        seed = f"{cfg.get('host','')}|{cfg.get('user','')}|{cfg.get('password','')}|{cfg.get('database','')}"
        return hashlib.sha256(seed.encode('utf-8', errors='ignore')).digest()

    def _b64url_encode(self, raw):
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    def _b64url_decode(self, text):
        pad = '=' * (-len(text) % 4)
        return base64.urlsafe_b64decode((text + pad).encode('ascii'))

    def _make_stateless_token(self, user_id, ttl_seconds=7 * 24 * 3600):
        exp = int(time.time()) + int(ttl_seconds)
        payload = f"{user_id}|{exp}".encode('utf-8')
        sig = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
        return self._b64url_encode(payload + b'|' + sig)

    def _verify_stateless_token(self, token):
        if not token:
            return None
        try:
            raw = self._b64url_decode(token)
            parts = raw.split(b'|')
            if len(parts) != 3:
                return None
            user_id_b, exp_b, sig_b = parts
            payload = user_id_b + b'|' + exp_b
            expected = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
            if not hmac.compare_digest(sig_b, expected):
                return None
            exp = int(exp_b.decode('utf-8', errors='ignore') or '0')
            if exp < int(time.time()):
                return None
            return int(user_id_b.decode('utf-8', errors='ignore'))
        except Exception:
            return None

    def _get_session_user(self, environ):
        """从cookie读取登录用户ID"""
        session_id = self._get_session_id(environ)
        if not session_id:
            # stateless fallback for environments where DB sessions fail
            token = self._get_cookie_value(environ, 'session_token')
            token_user = self._verify_stateless_token(token)
            if token_user:
                return token_user
        if session_id:
            # 先检查内存缓存
            if session_id in self._user_session:
                return self._user_session[session_id]
            # 回退到数据库查询（支持多进程部署）
            try:
                cfg = self._get_db_config()
                if cfg:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT employee_id FROM sessions WHERE session_id=%s AND (expires_at IS NULL OR expires_at>NOW())",
                                (session_id,)
                            )
                            row = cur.fetchone()
                            if row and row.get('employee_id'):
                                self._user_session[session_id] = row['employee_id']
                                return row['employee_id']
            except Exception as e:
                print(f"Session DB lookup failed: {type(e).__name__}: {e}")
            # session_id 无效时，尝试 stateless token 作为回退
            token = self._get_cookie_value(environ, 'session_token')
            token_user = self._verify_stateless_token(token)
            if token_user:
                return token_user
        return None

    def _set_session_user(self, user_id):
        """创建session并返回session_id"""
        import uuid
        session_id = str(uuid.uuid4())
        # 写入内存缓存
        self._user_session[session_id] = user_id
        # 尝试写入数据库以便在多进程下共享会话
        try:
            cfg = self._get_db_config()
            if cfg:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        # 过期时间设为 7 天
                        cur.execute(
                            "REPLACE INTO sessions (session_id, employee_id, expires_at) VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 7 DAY))",
                            (session_id, user_id)
                        )
        except Exception as e:
            print(f"Session DB write failed: {type(e).__name__}: {e}")
        return session_id

    def _b64_from_fs(self, value):
        """将文件系统路径/名称转为 Base64（保留原始字节）"""
        try:
            raw = self._safe_fsencode(value)
        except Exception:
            raw = str(value).encode('utf-8', errors='surrogatepass')
        return base64.b64encode(raw).decode('ascii')

    def _fs_from_b64(self, value):
        """从 Base64 还原文件系统路径/名称"""
        raw = base64.b64decode(value)
        return os.fsdecode(raw)

    def _join_resources(self, rel_path):
        """拼接资源目录（返回 bytes 路径）"""
        if not rel_path:
            return RESOURCES_PATH_BYTES
        try:
            rel_bytes = self._safe_fsencode(rel_path)
        except Exception:
            rel_bytes = str(rel_path).encode('utf-8', errors='surrogatepass')
        return os.path.join(RESOURCES_PATH_BYTES, rel_bytes)

    def _safe_fsencode(self, value):
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        try:
            return os.fsencode(value)
        except Exception:
            return str(value).encode('utf-8', errors='surrogatepass')

    def _safe_fsdecode(self, value):
        if isinstance(value, str):
            return value
        try:
            return os.fsdecode(value)
        except Exception:
            return bytes(value).decode('utf-8', errors='surrogatepass')

    def _is_image_name(self, name):
        """判断是否为图片文件名（兼容 bytes/str）"""
        if isinstance(name, (bytes, bytearray)):
            try:
                name = os.fsdecode(name)
            except Exception:
                name = name.decode('utf-8', errors='ignore')
        return str(name).lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))

    def _to_int(self, value, default=None):
        try:
            return int(value)
        except Exception:
            return default

    def _normalize_fabric_remark(self, remark):
        value = (remark or '').strip()
        if value in ('原图', '卖点图'):
            return value
        if value in ('平面原图', '褶皱原图'):
            return '原图'
        if '卖点' in value:
            return '卖点图'
        return '原图'

    def _build_fabric_image_plan(self, images, fabric_code):
        """为面料图片生成重命名计划和最终入库数据"""
        folder = self._ensure_fabric_folder()
        remark_counters = {}
        planned_images = []
        rename_pairs = []
        missing = []
        not_ready = []

        for idx, img in enumerate(images):
            old_name = (img.get('image_name') or '').strip()
            if not old_name:
                continue

            src_path = os.path.join(folder, self._safe_fsencode(old_name))
            if not os.path.exists(src_path):
                missing.append(old_name)
                continue
            try:
                if os.path.getsize(src_path) <= 0:
                    not_ready.append(old_name)
                    continue
            except Exception:
                not_ready.append(old_name)
                continue

            remark = self._normalize_fabric_remark(img.get('remark'))
            remark_counters[remark] = remark_counters.get(remark, 0) + 1
            index_in_remark = remark_counters[remark]
            new_name = self._rename_fabric_image_with_remark(old_name, fabric_code, remark, index_in_remark)

            planned_images.append({
                'image_name': new_name,
                'remark': remark,
                'sort_order': self._to_int(img.get('sort_order'), idx) if isinstance(img, dict) else idx,
                'is_primary': bool(img.get('is_primary', idx == 0)) if isinstance(img, dict) else (idx == 0),
            })

            if new_name != old_name:
                rename_pairs.append((old_name, new_name))

        return {
            'planned_images': planned_images,
            'rename_pairs': rename_pairs,
            'missing': missing,
            'not_ready': not_ready,
        }

    def _execute_fabric_rename_pairs(self, rename_pairs):
        """安全执行批量重命名，避免目标名冲突（两阶段：先临时名，再目标名）"""
        if not rename_pairs:
            return {'status': 'success', 'rollback_pairs': []}

        folder = self._ensure_fabric_folder()
        normalized = []
        seen_src = set()
        seen_dst = set()
        for src_name, dst_name in rename_pairs:
            src = (src_name or '').strip()
            dst = (dst_name or '').strip()
            if not src or not dst or src == dst:
                continue
            if src in seen_src:
                return {'status': 'error', 'message': f'重复源文件: {src}'}
            if dst in seen_dst:
                return {'status': 'error', 'message': f'目标文件名冲突: {dst}'}
            seen_src.add(src)
            seen_dst.add(dst)
            normalized.append((src, dst))

        if not normalized:
            return {'status': 'success', 'rollback_pairs': []}

        src_set = {src for src, _ in normalized}
        for src, dst in normalized:
            src_path = os.path.join(folder, self._safe_fsencode(src))
            dst_path = os.path.join(folder, self._safe_fsencode(dst))
            if not os.path.exists(src_path):
                return {'status': 'error', 'message': f'源文件不存在: {src}'}
            if dst not in src_set and os.path.exists(dst_path):
                return {'status': 'error', 'message': f'目标文件已存在: {dst}'}

        temp_pairs = []
        for index, (src, dst) in enumerate(normalized):
            token = secrets.token_hex(6)
            temp_name = f".__sitjoy_tmp__{token}_{index}"
            while os.path.exists(os.path.join(folder, self._safe_fsencode(temp_name))):
                token = secrets.token_hex(6)
                temp_name = f".__sitjoy_tmp__{token}_{index}"
            temp_pairs.append((src, temp_name, dst))

        moved_to_temp = []
        moved_to_final = []
        try:
            for src, temp_name, _ in temp_pairs:
                src_path = os.path.join(folder, self._safe_fsencode(src))
                temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                os.rename(src_path, temp_path)
                moved_to_temp.append((src, temp_name))

            for src, temp_name, dst in temp_pairs:
                temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                dst_path = os.path.join(folder, self._safe_fsencode(dst))
                os.rename(temp_path, dst_path)
                moved_to_final.append((src, dst))

            rollback_pairs = [(dst, src) for src, dst in reversed(moved_to_final)]
            return {'status': 'success', 'rollback_pairs': rollback_pairs}
        except Exception as e:
            try:
                final_map = {dst: src for src, dst in moved_to_final}
                for _, dst in reversed(moved_to_final):
                    dst_path = os.path.join(folder, self._safe_fsencode(dst))
                    src = final_map.get(dst)
                    if src and os.path.exists(dst_path):
                        os.rename(dst_path, os.path.join(folder, self._safe_fsencode(src)))
            except Exception:
                pass

            try:
                for src, temp_name in reversed(moved_to_temp):
                    temp_path = os.path.join(folder, self._safe_fsencode(temp_name))
                    src_path = os.path.join(folder, self._safe_fsencode(src))
                    if os.path.exists(temp_path):
                        os.rename(temp_path, src_path)
            except Exception:
                pass

            return {'status': 'error', 'message': f'文件重命名失败: {str(e)}'}
    
    def __call__(self, environ, start_response):
        """WSGI 应用入口"""
        try:
            path = environ['PATH_INFO']
            method = environ['REQUEST_METHOD']

            # 路由处理
            if path == '/' or path == '/index.html':
                # 检查是否登录，未登录则重定向到登录页
                user_id = self._get_session_user(environ)
                if not user_id:
                    start_response('302 Found', [('Location', '/login')])
                    return [b'']
                return self.serve_file('templates/index.html', 'text/html', start_response)
            elif path == '/login' or path == '/login.html':
                return self.serve_file('templates/login.html', 'text/html', start_response)
            elif path.startswith('/api/auth'):
                return self.handle_auth_api(environ, method, start_response)
            elif path == '/about' or path == '/about.html':
                return self.serve_file('templates/about.html', 'text/html', start_response)
            elif path == '/gallery':
                return self.serve_file('templates/gallery.html', 'text/html', start_response)
            elif path == '/product-management':
                return self.serve_file('templates/product_management.html', 'text/html', start_response)
            elif path == '/category-management':
                return self.serve_file('templates/category_management.html', 'text/html', start_response)
            elif path == '/fabric-management':
                return self.serve_file('templates/fabric_management.html', 'text/html', start_response)
            elif path == '/feature-management':
                return self.serve_file('templates/feature_management.html', 'text/html', start_response)
            elif path == '/material-management':
                return self.serve_file('templates/material_management.html', 'text/html', start_response)
            elif path == '/certification-management':
                return self.serve_file('templates/certification_management.html', 'text/html', start_response)
            elif path == '/order-product-management':
                return self.serve_file('templates/order_product_management.html', 'text/html', start_response)
            elif path == '/shop-brand-management':
                return self.serve_file('templates/shop_brand_management.html', 'text/html', start_response)
            elif path == '/sales-product-management':
                return self.serve_file('templates/sales_product_management.html', 'text/html', start_response)
            elif path == '/amazon-ad-management':
                return self.serve_file('templates/amazon_ad_management.html', 'text/html', start_response)
            elif path == '/amazon-ad-subtype-management':
                return self.serve_file('templates/amazon_ad_subtype_management.html', 'text/html', start_response)
            elif path.startswith('/api/hello'):
                return self.handle_hello_api(environ, path, method, start_response)
            elif path == '/api/employee':
                return self.handle_employee_api(environ, method, start_response)
            elif path == '/api/todo':
                return self.handle_todo_api(environ, method, start_response)
            elif path == '/api/calendar':
                return self.handle_calendar_api(environ, method, start_response)
            elif path == '/status':
                return self.handle_status(start_response)
            elif path == '/api/images':
                return self.handle_images_api(environ, start_response)
            elif path == '/api/browse':
                return self.handle_browse_api(environ, start_response)
            elif path == '/api/debug-paths':
                return self.handle_debug_paths(environ, start_response)
            elif path == '/api/debug-perms':
                return self.handle_debug_perms(environ, start_response)
            elif path == '/api/debug-list':
                return self.handle_debug_list(environ, start_response)
            elif path == '/api/debug-volumes':
                return self.handle_debug_volumes(environ, start_response)
            elif path == '/api/debug-list-abs':
                return self.handle_debug_list_abs(environ, start_response)
            elif path == '/api/image-preview':
                return self.handle_image_preview(environ, start_response)
            elif path == '/api/rename':
                return self.handle_rename_api(environ, start_response)
            elif path == '/api/move':
                return self.handle_move_api(environ, start_response)
            elif path == '/api/sku':
                return self.handle_sku_api(environ, method, start_response)
            elif path == '/api/category':
                return self.handle_category_api(environ, method, start_response)
            elif path == '/api/fabric':
                return self.handle_fabric_api(environ, method, start_response)
            elif path == '/api/feature':
                return self.handle_feature_api(environ, method, start_response)
            elif path == '/api/material':
                return self.handle_material_api(environ, method, start_response)
            elif path == '/api/material-type':
                return self.handle_material_type_api(environ, method, start_response)
            elif path == '/api/platform-type':
                return self.handle_platform_type_api(environ, method, start_response)
            elif path == '/api/brand':
                return self.handle_brand_api(environ, method, start_response)
            elif path == '/api/shop':
                return self.handle_shop_api(environ, method, start_response)
            elif path == '/api/amazon-ad-subtype':
                return self.handle_amazon_ad_subtype_api(environ, method, start_response)
            elif path == '/api/amazon-ad-operation-type':
                return self.handle_amazon_ad_operation_type_api(environ, method, start_response)
            elif path == '/api/amazon-ad':
                return self.handle_amazon_ad_api(environ, method, start_response)
            elif path == '/api/certification':
                return self.handle_certification_api(environ, method, start_response)
            elif path == '/api/certification-images':
                return self.handle_certification_images_api(environ, start_response)
            elif path == '/api/order-product':
                return self.handle_order_product_api(environ, method, start_response)
            elif path == '/api/order-product-template':
                return self.handle_order_product_template_api(environ, method, start_response)
            elif path == '/api/order-product-import':
                return self.handle_order_product_import_api(environ, method, start_response)
            elif path == '/api/sales-product':
                return self.handle_sales_product_api(environ, method, start_response)
            elif path == '/api/sales-product-template':
                return self.handle_sales_product_template_api(environ, method, start_response)
            elif path == '/api/sales-product-import':
                return self.handle_sales_product_import_api(environ, method, start_response)
            elif path == '/api/fabric-images':
                return self.handle_fabric_images_api(environ, start_response)
            elif path == '/api/listing-images':
                return self.handle_listing_images_api(environ, start_response)
            elif path == '/api/fabric-attach':
                return self.handle_fabric_attach_api(environ, start_response)
            elif path == '/api/fabric-upload':
                return self.handle_fabric_upload_api(environ, start_response)
            elif path == '/api/upload':
                return self.handle_upload_api(environ, start_response)
            elif path == '/api/download-zip':
                return self.handle_download_zip(environ, method, start_response)
            elif path.startswith('/static/'):
                return self.serve_static(path, start_response)
            else:
                return self.send_error(404, 'Not Found', start_response)

        except Exception as e:
            print(f"WSGI 错误: {str(e)}")
            import traceback
            traceback.print_exc()
            return self.send_error(500, f'服务器错误: {str(e)}', start_response)

    def handle_hello_api(self, environ, path, method, start_response):
        """处理问候 API"""
        try:
            if method == 'POST':
                content_length = int(environ.get('CONTENT_LENGTH', 0))
                body = environ['wsgi.input'].read(content_length)
                data = json.loads(body.decode('utf-8'))
                name = data.get('name', '访客')
            else:
                query_string = environ.get('QUERY_STRING', '')
                query_params = parse_qs(query_string)
                name = query_params.get('name', ['访客'])[0]

            response = {
                'message': f'你好，{name}！',
                'timestamp': datetime.now().isoformat(),
                'status': 'success'
            }
            return self.send_json(response, start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def handle_auth_api(self, environ, method, start_response):
        """用户认证 API"""
        try:
            self._ensure_todo_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            action = query_params.get('action', [''])[0]

            if method == 'POST' and action == 'login':
                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '用户名密码不能为空'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT u.id, u.password_hash, u.name, u.username
                            FROM users u
                            WHERE u.username=%s
                            """,
                            (username,)
                        )
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': '用户不存在'}, start_response)

                        import hashlib
                        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                        if row['password_hash'] != pwd_hash:
                            return self.send_json({'status': 'error', 'message': '密码错误'}, start_response)

                        session_id = self._set_session_user(row['id'])
                        token = self._make_stateless_token(row['id'])
                        # 设置 Set-Cookie 头
                        headers = [
                            ('Content-Type', 'application/json; charset=utf-8'),
                            ('Set-Cookie', f'session_id={session_id}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax'),
                            ('Set-Cookie', f'session_token={token}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax')
                        ]
                        response_body = json.dumps({
                            'status': 'success',
                            'session_id': session_id,
                            'employee_id': row['id'],
                            'name': row.get('name') or row.get('username')
                        }).encode('utf-8')
                        start_response('200 OK', headers)
                        return [response_body]

            elif method == 'POST' and action == 'logout':
                user = self._get_session_user(environ)
                session_id = self._get_session_id(environ)
                if user:
                    for sid, uid in list(self._user_session.items()):
                        if uid == user:
                            del self._user_session[sid]
                if session_id:
                    try:
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute("DELETE FROM sessions WHERE session_id=%s", (session_id,))
                    except Exception as e:
                        print(f"Session DB delete failed: {type(e).__name__}: {e}")
                headers = [
                    ('Content-Type', 'application/json; charset=utf-8'),
                    ('Set-Cookie', 'session_id=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'),
                    ('Set-Cookie', 'session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
                ]
                start_response('200 OK', headers)
                return [json.dumps({'status': 'success'}).encode('utf-8')]

            elif method == 'GET' and action == 'current':
                user_id = self._get_session_user(environ)
                if not user_id:
                    return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, username, name, phone, birthday, is_admin, can_manage_todos
                            FROM users WHERE id=%s
                            """,
                            (user_id,)
                        )
                        row = cur.fetchone()
                        if row:
                            return self.send_json({
                                'status': 'success',
                                'id': row['id'],
                                'name': row.get('name') or row.get('username'),
                                'phone': row['phone'],
                                'birthday': row['birthday'],
                                'is_admin': row['is_admin'],
                                'can_manage_todos': row['can_manage_todos']
                            }, start_response)
                        return self.send_json({'status': 'error', 'message': '用户信息未找到'}, start_response)

            elif method == 'GET' and action == 'debug':
                session_id = self._get_session_id(environ)
                db_found = False
                employee_id = None
                if session_id:
                    try:
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    "SELECT employee_id FROM sessions WHERE session_id=%s AND (expires_at IS NULL OR expires_at>NOW())",
                                    (session_id,)
                                )
                                row = cur.fetchone()
                                if row and row.get('employee_id'):
                                    db_found = True
                                    employee_id = row['employee_id']
                    except Exception as e:
                        return self.send_json({'status': 'error', 'message': str(e)}, start_response)
                return self.send_json({
                    'status': 'success',
                    'session_id': session_id,
                    'db_session_found': db_found,
                    'employee_id': employee_id
                }, start_response)

            elif method == 'POST' and action == 'register':
                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '缺少必要字段'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        try:
                            import hashlib
                            pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                            cur.execute(
                                """
                                INSERT INTO users (username, password_hash, name, phone, birthday)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (username, pwd_hash, name or None, phone or None, birthday)
                            )
                            emp_id = cur.lastrowid
                            # 创建 session 并通过 Set-Cookie 返回
                            session_id = self._set_session_user(emp_id)
                            token = self._make_stateless_token(emp_id)
                            headers = [
                                ('Content-Type', 'application/json; charset=utf-8'),
                                ('Set-Cookie', f'session_id={session_id}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax'),
                                ('Set-Cookie', f'session_token={token}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax')
                            ]
                            response_body = json.dumps({
                                'status': 'success',
                                'session_id': session_id,
                                'employee_id': emp_id
                            }).encode('utf-8')
                            start_response('200 OK', headers)
                            return [response_body]
                        except Exception as e:
                            if 'Duplicate' in str(e):
                                return self.send_json({'status': 'error', 'message': '用户名已存在'}, start_response)
                            raise

            return self.send_json({'status': 'error', 'message': '不支持的操作'}, start_response)
        except Exception as e:
            print('Auth API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_status(self, start_response):
        """处理系统状态"""
        response = {
            'status': 'running',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat()
        }
        return self.send_json(response, start_response)

    def handle_debug_paths(self, environ, start_response):
        """调试API：列出所有volume和路径"""
        result = {'status': 'success', 'volumes': {}}
        try:
            base = '/volume1'
            if not os.path.exists(base):
                return self.send_json({'status': 'error', 'message': 'Volume root not found'}, start_response)

            for vol in os.listdir(base):
                vol_path = os.path.join(base, vol)
                if not os.path.isdir(vol_path):
                    continue

                try:
                    contents = {'folders': [], 'images': []}
                    for item in os.listdir(vol_path):
                        try:
                            if item.startswith('@') or item.startswith('.'):
                                continue

                            item_path = os.path.join(vol_path, item)
                            # 文件夹
                            if os.path.isdir(item_path):
                                rel = item
                                contents['folders'].append({
                                    'name': base64.b64encode(item.encode('utf-8')).decode('ascii'),
                                    'path': base64.b64encode(rel.encode('utf-8')).decode('ascii'),
                                    'type': 'folder'
                                })
                            # 图片文件
                            elif item.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp')):
                                rel = item
                                contents['images'].append({
                                    'name': base64.b64encode(item.encode('utf-8')).decode('ascii'),
                                    'path': base64.b64encode(rel.encode('utf-8')).decode('ascii'),
                                    'type': 'image'
                                })
                        except Exception:
                            # 忽略单个条目错误
                            continue

                    result['volumes'][vol] = contents
                except Exception as e:
                    result['volumes'][vol] = f'Error: {type(e).__name__}'

            return self.send_json(result, start_response)
        except Exception as e:
            return self.send_json({
                'status': 'error',
                'message': f'Debug error: {type(e).__name__}'
            }, start_response)

    def handle_debug_perms(self, environ, start_response):
        """调试API：返回当前运行用户与目录权限检查"""
        try:
            uid = os.getuid() if hasattr(os, 'getuid') else None
            gid = os.getgid() if hasattr(os, 'getgid') else None
            path_bytes = RESOURCES_PATH_BYTES

            exists = os.path.exists(path_bytes)
            is_dir = os.path.isdir(path_bytes)
            can_read = os.access(path_bytes, os.R_OK)
            can_execute = os.access(path_bytes, os.X_OK)

            info = {
                'status': 'success',
                'resources_path_b64': base64.b64encode(path_bytes).decode('ascii'),
                'exists': bool(exists),
                'is_dir': bool(is_dir),
                'can_read': bool(can_read),
                'can_execute': bool(can_execute),
                'uid': uid,
                'gid': gid
            }
            return self.send_json(info, start_response)
        except Exception as e:
            return self.send_json({
                'status': 'error',
                'message': f'Debug error: {type(e).__name__}'
            }, start_response)

    def handle_debug_list(self, environ, start_response):
        """调试API：列出目标目录前200个条目（不过滤）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('path', [''])[0]

            if path_b64:
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except:
                    return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)
            else:
                rel_path = ''

            if '..' in rel_path:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            current_path = self._join_resources(rel_path)

            abs_path = os.path.abspath(current_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(current_path):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            items = []
            count = 0
            with os.scandir(current_path) as it:
                for entry in it:
                    try:
                        name_b64 = self._b64_from_fs(entry.name)
                        items.append({
                            'name': name_b64,
                            'is_dir': entry.is_dir(follow_symlinks=False),
                            'is_file': entry.is_file(follow_symlinks=False)
                        })
                        count += 1
                        if count >= 200:
                            break
                    except Exception:
                        continue

            return self.send_json({
                'status': 'success',
                'current_path': path_b64,
                'count': len(items),
                'items': items
            }, start_response)
        except Exception as e:
            return self.send_json({
                'status': 'error',
                'message': f'Debug error: {type(e).__name__}'
            }, start_response)

    def handle_debug_volumes(self, environ, start_response):
        """调试API：列出 /volume1 下的顶层目录与权限"""
        try:
            base = '/volume1'
            if not os.path.exists(base):
                return self.send_json({'status': 'error', 'message': 'Volume root not found'}, start_response)

            items = []
            with os.scandir(base) as it:
                for entry in it:
                    try:
                        name_b64 = self._b64_from_fs(entry.name)
                        entry_path = os.path.join(base, entry.name)
                        items.append({
                            'name': name_b64,
                            'is_dir': entry.is_dir(follow_symlinks=False),
                            'can_read': os.access(entry_path, os.R_OK),
                            'can_execute': os.access(entry_path, os.X_OK)
                        })
                    except Exception:
                        continue

            return self.send_json({
                'status': 'success',
                'count': len(items),
                'items': items
            }, start_response)
        except Exception as e:
            return self.send_json({
                'status': 'error',
                'message': f'Debug error: {type(e).__name__}'
            }, start_response)

    def handle_debug_list_abs(self, environ, start_response):
        """调试API：列出指定绝对路径的前200个条目（限 /volume1）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('path', [''])[0]

            if not path_b64:
                return self.send_json({'status': 'error', 'message': 'Missing path'}, start_response)

            try:
                abs_path = self._fs_from_b64(path_b64)
            except:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            abs_path = os.path.abspath(abs_path)
            if not abs_path.startswith('/volume1'):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(abs_path):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            items = []
            count = 0
            with os.scandir(abs_path) as it:
                for entry in it:
                    try:
                        name_b64 = self._b64_from_fs(entry.name)
                        items.append({
                            'name': name_b64,
                            'is_dir': entry.is_dir(follow_symlinks=False),
                            'is_file': entry.is_file(follow_symlinks=False)
                        })
                        count += 1
                        if count >= 200:
                            break
                    except Exception:
                        continue

            return self.send_json({
                'status': 'success',
                'path': path_b64,
                'count': len(items),
                'items': items
            }, start_response)
        except Exception as e:
            return self.send_json({
                'status': 'error',
                'message': f'Debug error: {type(e).__name__}'
            }, start_response)
    
    def handle_images_api(self, environ, start_response):
        """获取图片列表（用Base64编码路径避免编码问题）"""
        images = []
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            page = int(query_params.get('page', ['1'])[0])
            per_page = min(int(query_params.get('per_page', ['100'])[0]), 200)
            
            # 检查RESOURCES_PATH是否存在
            if not os.path.exists(RESOURCES_PATH_BYTES):
                # 列出/volume1/下的文件夹帮助调试
                try:
                    volume_contents = os.listdir('/volume1') if os.path.exists('/volume1') else []
                    folders_list = [f for f in volume_contents if os.path.isdir(f'/volume1/{f}')]
                    # 用Base64编码文件夹列表以避免编码问题
                    folders_b64 = base64.b64encode(str(folders_list).encode('utf-8')).decode('ascii')
                    return self.send_json({
                        'status': 'error', 
                        'message': 'Path not found',
                        'available_folders_b64': folders_b64
                    }, start_response)
                except:
                    return self.send_json({
                        'status': 'error', 
                        'message': f'Path not found and cannot list volume'
                    }, start_response)
            
            # 扫描文件
            count = 0
            for root, dirs, files in os.walk(RESOURCES_PATH_BYTES):
                for file in files:
                    if self._is_image_name(file):
                        try:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, RESOURCES_PATH_BYTES)
                            
                            # 用Base64编码所有内容（保留文件系统原始字节）
                            path_b64 = self._b64_from_fs(rel_path)
                            filename_b64 = self._b64_from_fs(file)
                            
                            # folder也编码，完全避免中文
                            folder = os.path.dirname(rel_path) or b'root'
                            folder_b64 = self._b64_from_fs(folder)
                            
                            images.append({
                                'id': path_b64,
                                'filename': filename_b64,
                                'folder': folder_b64
                            })
                            count += 1
                        except Exception as e:
                            print(f"File error: {type(e).__name__}")
                            pass
            
            # 分页
            total = len(images)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated = images[start_idx:end_idx]
            
            # 计算总页数
            import math
            total_pages = math.ceil(total / per_page) if total > 0 else 1
            
            # 完全ASCII的响应
            resp = {
                'status': 'success',
                'total': total,
                'page': page,
                'pages': total_pages,
                'count': len(paginated),
                'images': paginated
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print(f"Exception in handle_images_api: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            # 返回错误时，消息也要清理，不含中文
            return self.send_json({
                'status': 'error', 
                'message': f'Error: {type(e).__name__}'
            }, start_response)
    
    def handle_browse_api(self, environ, start_response):
        """浏览目录API：返回指定目录下的文件夹和图片"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('path', [''])[0]
            debug = query_params.get('debug', ['0'])[0] == '1'

            # 解码路径（如果为空则为根目录）
            if path_b64:
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except:
                    return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)
            else:
                rel_path = ''

            # 防止路径遍历
            if '..' in rel_path:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            # 构建完整路径（bytes）
            current_path = self._join_resources(rel_path)

            # 验证路径安全性
            abs_path = os.path.abspath(current_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(current_path):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            folders = []
            images = []

            try:
                debug_items = []
                rel_path_bytes = os.fsencode(rel_path) if rel_path else b''
                with os.scandir(current_path) as it:
                    for entry in it:
                        try:
                            item = entry.name
                            item_bytes = item if isinstance(item, (bytes, bytearray)) else os.fsencode(item)

                            # 跳过系统文件夹
                            if item_bytes.startswith(b'@') or item_bytes.startswith(b'.'):
                                if debug:
                                    debug_items.append({
                                        'name': self._b64_from_fs(item),
                                        'skipped': 'system',
                                        'is_dir': entry.is_dir(follow_symlinks=False),
                                        'is_file': entry.is_file(follow_symlinks=False)
                                    })
                                continue

                            if entry.is_dir(follow_symlinks=False):
                                folder_rel_path = os.path.join(rel_path_bytes, item_bytes) if rel_path_bytes else item_bytes
                                folders.append({
                                    'name': self._b64_from_fs(item_bytes),
                                    'path': self._b64_from_fs(folder_rel_path),
                                    'type': 'folder'
                                })
                            elif entry.is_file(follow_symlinks=False):
                                if self._is_image_name(item_bytes):
                                    image_rel_path = os.path.join(rel_path_bytes, item_bytes) if rel_path_bytes else item_bytes
                                    images.append({
                                        'name': self._b64_from_fs(item_bytes),
                                        'path': self._b64_from_fs(image_rel_path),
                                        'type': 'image'
                                    })
                                elif debug:
                                    debug_items.append({
                                        'name': self._b64_from_fs(item_bytes),
                                        'skipped': 'not_image',
                                        'is_dir': False,
                                        'is_file': True
                                    })
                            elif debug:
                                debug_items.append({
                                    'name': self._b64_from_fs(item_bytes),
                                    'skipped': 'unknown_type',
                                    'is_dir': entry.is_dir(follow_symlinks=False),
                                    'is_file': entry.is_file(follow_symlinks=False)
                                })
                        except Exception as e:
                            print(f"Item error: {type(e).__name__}")
                            if debug:
                                debug_items.append({
                                    'name': 'unknown',
                                    'skipped': f'error:{type(e).__name__}'
                                })
                            pass
            except Exception as e:
                return self.send_json({'status': 'error', 'message': f'Cannot read directory: {type(e).__name__}'}, start_response)

            folders.sort(key=lambda x: x['name'])
            images.sort(key=lambda x: x['name'])

            breadcrumbs = []
            if rel_path:
                rel_path_bytes = os.fsencode(rel_path)
                parts = rel_path_bytes.split(b'/')
                current = b''
                for part in parts:
                    current = os.path.join(current, part) if current else part
                    breadcrumbs.append({
                        'name': self._b64_from_fs(part),
                        'path': self._b64_from_fs(current)
                    })

            resp = {
                'status': 'success',
                'current_path': path_b64,
                'breadcrumbs': breadcrumbs,
                'folders': folders,
                'images': images,
                'total_folders': len(folders),
                'total_images': len(images)
            }

            if debug:
                resp['debug_items'] = debug_items

            return self.send_json(resp, start_response)

        except Exception as e:
            print(f"Browse error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return self.send_json({'status': 'error', 'message': f'Error: {type(e).__name__}'}, start_response)
    
    def handle_image_preview(self, environ, start_response):
        """获取图片预览（接受Base64编码的路径）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            path_b64 = query_params.get('id', [''])[0]
            mode = (query_params.get('mode', [''])[0] or '').strip().lower()
            max_w = self._to_int(query_params.get('w', [''])[0], 0) or 0
            max_h = self._to_int(query_params.get('h', [''])[0], 0) or 0
            quality = self._to_int(query_params.get('q', [''])[0], 0) or 0
            use_compressed = mode in ('thumb', 'compressed') or max_w > 0 or max_h > 0 or quality > 0
            
            if not path_b64:
                return self.send_error(400, 'Missing id parameter', start_response)
            
            # 解码Base64路径。前端可能对文件名做了 UTF-8 编码再 base64，
            # 也可能对文件系统原始 bytes 做 base64。优先尝试使用原始 bytes 直接拼接路径。
            try:
                raw = base64.b64decode(path_b64)
            except Exception:
                return self.send_error(400, 'Invalid id', start_response)

            full_path = None
            # 1) 尝试将 raw 作为相对 bytes 路径直接拼接并检查
            try:
                candidate = os.path.join(RESOURCES_PATH_BYTES, raw)
                abs_candidate = os.path.abspath(candidate)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if abs_candidate.startswith(abs_resources) and os.path.exists(candidate):
                    full_path = candidate
            except Exception:
                full_path = None

            # 2) 回退：把 raw 解为字符串（filesystem decode）再拼接
            if full_path is None:
                try:
                    rel_path = os.fsdecode(raw)
                except Exception:
                    try:
                        rel_path = raw.decode('utf-8', errors='surrogatepass')
                    except Exception:
                        return self.send_error(400, 'Invalid id', start_response)

                # 防止路径遍历
                if '..' in rel_path or rel_path.startswith('/'):
                    return self.send_error(403, 'Invalid path', start_response)

                full_path = self._join_resources(rel_path)
            
            # 验证路径安全性并存在性
            try:
                abs_path = os.path.abspath(full_path)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if not abs_path.startswith(abs_resources):
                    return self.send_error(403, 'Access denied', start_response)
            except Exception:
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_path):
                return self.send_error(404, 'File not found', start_response)
            
            # 读取图片
            mime_path = os.fsdecode(full_path) if isinstance(full_path, (bytes, bytearray)) else full_path
            mime_type, _ = mimetypes.guess_type(mime_path)
            if not mime_type:
                mime_type = 'image/jpeg'

            if use_compressed and Image:
                try:
                    img = Image.open(full_path)
                    if max_w <= 0 and max_h <= 0:
                        max_w, max_h = 360, 360
                    max_w = max(1, max_w) if max_w > 0 else 360
                    max_h = max(1, max_h) if max_h > 0 else 360
                    img.thumbnail((max_w, max_h), Image.Resampling.LANCZOS)

                    if quality <= 0:
                        quality = 72
                    quality = max(35, min(90, quality))

                    output = io.BytesIO()
                    if img.mode not in ('RGB', 'L'):
                        img = img.convert('RGB')
                    img.save(output, format='JPEG', quality=quality, optimize=True)
                    image_data = output.getvalue()
                    mime_type = 'image/jpeg'
                except Exception:
                    with open(full_path, 'rb') as f:
                        image_data = f.read()
            else:
                with open(full_path, 'rb') as f:
                    image_data = f.read()
            
            start_response('200 OK', [
                ('Content-Type', mime_type),
                ('Content-Length', str(len(image_data))),
                ('Cache-Control', 'public, max-age=300')
            ])
            
            return [image_data]
                    
        except Exception as e:
            print("Preview error: " + str(e))
            return self.send_error(500, str(e), start_response)
    
    def handle_rename_api(self, environ, start_response):
        """处理文件重命名（接受Base64编码路径）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8'))

            path_b64 = data.get('id', '')
            new_name_b64 = data.get('new_name_b64', '')

            if not path_b64:
                return self.send_error(400, 'Missing parameters', start_response)

            # 解码路径和新名称
            try:
                old_path = self._fs_from_b64(path_b64)
                new_name = self._fs_from_b64(new_name_b64) if new_name_b64 else ''
            except:
                return self.send_error(400, 'Invalid parameters', start_response)

            if '..' in old_path or ('..' in new_name if new_name else False):
                return self.send_error(403, 'Invalid path', start_response)

            full_old_path = self._join_resources(old_path)

            # 验证安全性
            abs_path = os.path.abspath(full_old_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_old_path):
                return self.send_error(404, 'File not found', start_response)

            # 获取扩展名
            folder = os.path.dirname(full_old_path)
            ext = os.path.splitext(os.path.basename(full_old_path))[1]
            new_name_bytes = os.fsencode(new_name)
            new_filename = new_name_bytes + ext if not new_name_bytes.endswith(ext) else new_name_bytes
            full_new_path = os.path.join(folder, new_filename)

            # 检查新名称是否已存在
            if os.path.exists(full_new_path):
                return self.send_error(409, 'File already exists', start_response)

            # 重命名
            os.rename(full_old_path, full_new_path)

            resp = {
                'status': 'success',
                'message': 'Renamed',
                'new_name': os.fsdecode(new_filename)
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print("Rename error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_move_api(self, environ, start_response):
        """处理文件移动+重命名（目标仅允许根目录下）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0))
            body = environ['wsgi.input'].read(content_length)
            data = json.loads(body.decode('utf-8'))

            path_b64 = data.get('id', '')
            new_name_b64 = data.get('new_name_b64', '')
            target_folder_b64 = data.get('target_folder_b64', '')

            if not path_b64 or not new_name_b64:
                return self.send_error(400, 'Missing parameters', start_response)

            try:
                old_path = self._fs_from_b64(path_b64)
                new_name = self._fs_from_b64(new_name_b64)
            except:
                return self.send_error(400, 'Invalid parameters', start_response)

            if '..' in old_path or '..' in new_name:
                return self.send_error(403, 'Invalid path', start_response)

            if target_folder_b64:
                try:
                    target_folder_bytes = base64.b64decode(target_folder_b64)
                except:
                    return self.send_error(400, 'Invalid target folder', start_response)
            else:
                target_folder_bytes = b''

            # 仅允许资源根目录内路径
            if target_folder_bytes.startswith((b'/', b'\\')):
                return self.send_error(403, 'Target folder not allowed', start_response)
            if b'..' in target_folder_bytes.split(b'/') or b'..' in target_folder_bytes.split(b'\\'):
                return self.send_error(403, 'Target folder not allowed', start_response)

            full_old_path = self._join_resources(old_path)

            abs_old = os.path.abspath(full_old_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_old.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)

            if not os.path.exists(full_old_path):
                return self.send_error(404, 'File not found', start_response)

            dest_dir = os.path.join(RESOURCES_PATH_BYTES, target_folder_bytes) if target_folder_bytes else os.path.dirname(full_old_path)
            if not os.path.exists(dest_dir) or not os.path.isdir(dest_dir):
                return self.send_error(404, 'Target folder not found', start_response)

            old_basename = os.path.basename(full_old_path)
            ext = os.path.splitext(old_basename)[1]
            if new_name:
                new_name_bytes = os.fsencode(new_name)
                new_filename = new_name_bytes + ext if not new_name_bytes.endswith(ext) else new_name_bytes
            else:
                new_filename = old_basename
            full_new_path = os.path.join(dest_dir, new_filename)

            if os.path.abspath(full_new_path) == os.path.abspath(full_old_path):
                return self.send_error(400, 'No changes', start_response)

            if os.path.exists(full_new_path):
                return self.send_error(409, 'File already exists', start_response)

            os.rename(full_old_path, full_new_path)

            resp = {
                'status': 'success',
                'message': 'Moved',
                'new_name': os.fsdecode(new_filename)
            }
            return self.send_json(resp, start_response)
        except Exception as e:
            print("Move error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_upload_api(self, environ, start_response):
        """处理图片上传（multipart/form-data）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=True)
            path_b64 = form.getfirst('path', '')

            if path_b64:
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except Exception:
                    return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)
            else:
                rel_path = ''

            if '..' in rel_path:
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            target_dir = self._join_resources(rel_path)

            abs_target = os.path.abspath(target_dir)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_target.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)

            if not os.path.exists(target_dir):
                return self.send_json({'status': 'error', 'message': 'Path not found'}, start_response)

            if 'file' not in form:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)

            files_field = form['file']
            if isinstance(files_field, list):
                files_list = files_field
            else:
                files_list = [files_field]

            saved = []
            skipped = []
            for item in files_list:
                try:
                    if not item.filename:
                        continue

                    filename = os.path.basename(item.filename)
                    if not self._is_image_name(filename):
                        skipped.append({'name': str(filename), 'reason': 'not_image'})
                        continue

                    try:
                        filename_bytes = os.fsencode(filename)
                    except Exception:
                        filename_bytes = str(filename).encode('utf-8', errors='surrogatepass')

                    dest_path = os.path.join(target_dir, filename_bytes)
                    if os.path.exists(dest_path):
                        skipped.append({'name': str(filename), 'reason': 'exists'})
                        continue

                    with open(dest_path, 'wb') as f:
                        while True:
                            chunk = item.file.read(1024 * 1024)
                            if not chunk:
                                break
                            f.write(chunk)

                    saved.append(str(filename))
                except Exception as e:
                    skipped.append({'name': str(getattr(item, 'filename', 'unknown')), 'reason': str(e)})

            return self.send_json({'status': 'success', 'count': len(saved), 'files': saved, 'skipped': skipped}, start_response)
        except Exception as e:
            print("Upload error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_download_zip(self, environ, method, start_response):
        """将选中图片/文件夹打包为 zip 下载"""
        try:
            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ)
            items = data.get('items', []) if isinstance(data, dict) else []
            if not items:
                return self.send_json({'status': 'error', 'message': 'No items selected'}, start_response)

            resources_bytes = RESOURCES_PATH_BYTES
            files = set()

            for item in items:
                path_b64 = item.get('path', '') if isinstance(item, dict) else ''
                if not path_b64:
                    continue
                try:
                    rel_path = self._fs_from_b64(path_b64)
                except Exception:
                    continue
                if '..' in rel_path or rel_path.startswith('/'):
                    continue

                full_path = self._join_resources(rel_path)
                abs_path = os.path.abspath(full_path)
                abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
                if not abs_path.startswith(abs_resources):
                    continue

                if os.path.isdir(full_path):
                    for root, _, filenames in os.walk(full_path):
                        for name in filenames:
                            if not self._is_image_name(name):
                                continue
                            files.add(os.path.join(root, name))
                elif os.path.isfile(full_path):
                    if self._is_image_name(full_path):
                        files.add(full_path)

            if not files:
                return self.send_json({'status': 'error', 'message': 'No images found'}, start_response)

            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            tmp_path = tmp.name
            tmp.close()

            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in files:
                    file_bytes = file_path if isinstance(file_path, (bytes, bytearray)) else os.fsencode(file_path)
                    try:
                        rel_bytes = os.path.relpath(file_bytes, resources_bytes)
                    except Exception:
                        rel_bytes = os.path.basename(file_bytes)
                    if rel_bytes.startswith(b'..'):
                        continue
                    arcname = rel_bytes.decode('utf-8', errors='replace').replace('\\', '/')
                    zf.write(os.fsdecode(file_bytes), arcname)

            with open(tmp_path, 'rb') as f:
                data_bytes = f.read()

            try:
                os.remove(tmp_path)
            except Exception:
                pass

            filename = f"sitjoy_download_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
            start_response('200 OK', [
                ('Content-Type', 'application/zip'),
                ('Content-Disposition', f'attachment; filename="{filename}"'),
                ('Content-Length', str(len(data_bytes)))
            ])
            return [data_bytes]
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _read_json_body(self, environ):
        """读取请求 JSON body"""
        content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
        if content_length <= 0:
            return {}
        body = environ['wsgi.input'].read(content_length)
        if not body:
            return {}
        return json.loads(body.decode('utf-8'))

    def _send_excel_workbook(self, workbook, filename, start_response):
        output = io.BytesIO()
        workbook.save(output)
        data = output.getvalue()
        start_response('200 OK', [
            ('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'),
            ('Content-Disposition', f'attachment; filename="{filename}"'),
            ('Content-Length', str(len(data)))
        ])
        return [data]

    def _get_db_config(self):
        """从环境变量读取数据库配置"""
        config = {
            'host': os.environ.get('SITJOY_DB_HOST', '127.0.0.1'),
            'user': os.environ.get('SITJOY_DB_USER', 'root'),
            'password': os.environ.get('SITJOY_DB_PASSWORD', ''),
            'database': os.environ.get('SITJOY_DB_NAME', 'sitjoy'),
            'port': int(os.environ.get('SITJOY_DB_PORT', '3306')),
            'charset': 'utf8mb4'
        }
        # 读取本地配置文件（若存在则覆盖）
        file_cfg = self._load_local_db_config()
        if file_cfg:
            for key in ['host', 'user', 'password', 'database', 'port', 'charset']:
                if key in file_cfg and file_cfg[key] not in (None, ''):
                    if key == 'port':
                        try:
                            config[key] = int(file_cfg[key])
                        except Exception:
                            continue
                    else:
                        config[key] = file_cfg[key]
        return config

    def _load_local_db_config(self):
        """读取项目内 db_config.json（可选）"""
        try:
            cfg_path = os.path.join(self.base_path, 'db_config.json')
            if not os.path.exists(cfg_path):
                return None
            with open(cfg_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def _get_db_connection(self):
        if not pymysql:
            raise RuntimeError(f"PyMySQL not available: {_pymysql_import_error}")
        cfg = self._get_db_config()
        return pymysql.connect(
            host=cfg['host'],
            user=cfg['user'],
            password=cfg['password'],
            database=cfg['database'],
            port=cfg['port'],
            charset=cfg['charset'],
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True
        )

    def _ensure_product_table(self):
        if self._db_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS product_families (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku_family VARCHAR(64) NOT NULL UNIQUE,
            category VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(create_sql)
            self._db_ready = True
        except Exception as e:
            self._db_ready = False
            raise e

    def _ensure_category_table(self):
        create_sql = """
        CREATE TABLE IF NOT EXISTS product_categories (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            category_cn VARCHAR(64) NOT NULL,
            category_en VARCHAR(64) NOT NULL,
            category_en_name VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_category_cn (category_cn),
            UNIQUE KEY uniq_category_en (category_en)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'product_categories'
                      AND COLUMN_NAME = 'category_en_name'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE product_categories ADD COLUMN category_en_name VARCHAR(128) NOT NULL DEFAULT ''")

    def _ensure_fabric_table(self):
        self._ensure_materials_table()
        self._ensure_product_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS fabric_materials (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            fabric_code VARCHAR(64) NOT NULL UNIQUE,
            fabric_name_en VARCHAR(128) NOT NULL,
            material_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_material (material_id),
            CONSTRAINT fk_fabric_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_images_sql = """
        CREATE TABLE IF NOT EXISTS fabric_images (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            fabric_id INT UNSIGNED NOT NULL,
            image_name VARCHAR(255) NOT NULL,
            sort_order INT UNSIGNED NOT NULL DEFAULT 0,
            is_primary TINYINT(1) NOT NULL DEFAULT 0,
            remark VARCHAR(50) NULL DEFAULT NULL COMMENT '备注类型：平面原图/褶皱原图/卖点图',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_images_fabric (fabric_id),
            INDEX idx_fabric_images_primary (fabric_id, is_primary),
            CONSTRAINT fk_fabric_images_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_fabric_sku_relation = """
        CREATE TABLE IF NOT EXISTS fabric_product_families (
            fabric_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (fabric_id, sku_family_id),
            CONSTRAINT fk_fpf_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE CASCADE,
            CONSTRAINT fk_fpf_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(create_images_sql)
                cur.execute(create_fabric_sku_relation)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_materials'
                      AND COLUMN_NAME = 'material_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE fabric_materials ADD COLUMN material_id INT UNSIGNED NULL")
                    try:
                        cur.execute("ALTER TABLE fabric_materials ADD INDEX idx_fabric_material (material_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE fabric_materials
                            ADD CONSTRAINT fk_fabric_material
                            FOREIGN KEY (material_id) REFERENCES materials(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_materials'
                      AND COLUMN_NAME = 'image_name'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    cur.execute(
                        """
                        INSERT INTO fabric_images (fabric_id, image_name, sort_order, is_primary)
                        SELECT fm.id, fm.image_name, 0, 1
                        FROM fabric_materials fm
                        LEFT JOIN fabric_images fi
                            ON fi.fabric_id = fm.id AND fi.image_name = fm.image_name
                        WHERE fm.image_name IS NOT NULL AND fm.image_name <> ''
                          AND fi.id IS NULL
                        """
                    )
                    try:
                        cur.execute("ALTER TABLE fabric_materials DROP COLUMN image_name")
                    except Exception:
                        pass
                
                # 添加 remark 字段用于图片类型标注
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'fabric_images'
                      AND COLUMN_NAME = 'remark'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute(
                        """
                        ALTER TABLE fabric_images
                        ADD COLUMN remark VARCHAR(50) NULL DEFAULT NULL COMMENT '备注类型：平面原图/褶皱原图/卖点图'
                        AFTER is_primary
                        """
                    )

    def _ensure_material_types_table(self):
        if self._material_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS material_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._material_types_ready = True

    def _ensure_materials_table(self):
        if self._materials_ready:
            return
        self._ensure_material_types_table()
        type_map = {
            'fabric': '面料',
            'filling': '填充',
            'frame': '框架',
            'electronics': '电子元器件'
        }
        create_materials = """
        CREATE TABLE IF NOT EXISTS materials (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            material_type_id INT UNSIGNED NOT NULL,
            parent_id INT UNSIGNED NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_material (material_type_id, name),
            INDEX idx_material_type_id (material_type_id),
            INDEX idx_material_parent (parent_id),
            CONSTRAINT fk_material_type FOREIGN KEY (material_type_id)
                REFERENCES material_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_material_parent FOREIGN KEY (parent_id)
                REFERENCES materials(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_materials)
                cur.execute("SELECT COUNT(*) AS cnt FROM material_types")
                type_count = cur.fetchone()
                if type_count and type_count.get('cnt', 0) == 0:
                    for name in type_map.values():
                        cur.execute("INSERT IGNORE INTO material_types (name) VALUES (%s)", (name,))
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'material_type_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN material_type_id INT UNSIGNED NULL")
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'parent_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE materials ADD COLUMN parent_id INT UNSIGNED NULL")
                    try:
                        cur.execute("ALTER TABLE materials ADD INDEX idx_material_parent (parent_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE materials
                            ADD CONSTRAINT fk_material_parent
                            FOREIGN KEY (parent_id) REFERENCES materials(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'materials'
                      AND COLUMN_NAME = 'material_type'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        for code, name in type_map.items():
                            cur.execute(
                                """
                                UPDATE materials m
                                JOIN material_types mt ON mt.name = %s
                                SET m.material_type_id = mt.id
                                WHERE m.material_type_id IS NULL AND m.material_type = %s
                                """,
                                (name, code)
                            )
                    except Exception:
                        pass
                    cur.execute("SELECT COUNT(*) AS cnt FROM materials WHERE material_type_id IS NULL")
                    missing = cur.fetchone()
                    if missing and missing.get('cnt', 0) == 0:
                        try:
                            cur.execute("ALTER TABLE materials MODIFY material_type_id INT UNSIGNED NOT NULL")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE materials ADD UNIQUE KEY uniq_material (material_type_id, name)")
                        except Exception:
                            pass
                        try:
                            cur.execute("ALTER TABLE materials ADD INDEX idx_material_type_id (material_type_id)")
                        except Exception:
                            pass
                        try:
                            cur.execute(
                                """
                                ALTER TABLE materials
                                ADD CONSTRAINT fk_material_type
                                FOREIGN KEY (material_type_id) REFERENCES material_types(id)
                                ON DELETE RESTRICT
                                """
                            )
                        except Exception:
                            pass
        self._materials_ready = True

    def _ensure_platform_types_table(self):
        if self._platform_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS platform_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(64) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._platform_types_ready = True

    def _ensure_brands_table(self):
        if self._brands_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS brands (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._brands_ready = True

    def _ensure_shops_table(self):
        if self._shops_ready:
            return
        self._ensure_platform_types_table()
        self._ensure_brands_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS shops (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_name VARCHAR(128) NOT NULL,
            platform_type_id INT UNSIGNED NOT NULL,
            brand_id INT UNSIGNED NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_shop (shop_name, platform_type_id, brand_id),
            INDEX idx_shop_platform (platform_type_id),
            INDEX idx_shop_brand (brand_id),
            CONSTRAINT fk_shop_platform_type FOREIGN KEY (platform_type_id)
                REFERENCES platform_types(id) ON DELETE RESTRICT,
            CONSTRAINT fk_shop_brand FOREIGN KEY (brand_id)
                REFERENCES brands(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._shops_ready = True

    def _ensure_amazon_ad_subtypes_table(self):
        if self._amazon_ad_subtypes_ready:
            return
        self._ensure_amazon_ad_operation_types_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtypes (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            description VARCHAR(255) NOT NULL,
            ad_class VARCHAR(8) NOT NULL DEFAULT 'SP',
            subtype_code VARCHAR(64) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uniq_ad_subtype (ad_class, subtype_code)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        relation_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_subtype_operation_types (
            subtype_id INT UNSIGNED NOT NULL,
            operation_type_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (subtype_id, operation_type_id),
            CONSTRAINT fk_ad_subtype_op_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype_op_type FOREIGN KEY (operation_type_id)
                REFERENCES amazon_ad_operation_types(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(relation_sql)
        self._amazon_ad_subtypes_ready = True

    def _ensure_amazon_ad_operation_types_table(self):
        if self._amazon_ad_operation_types_ready:
            return
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_operation_types (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            apply_campaign TINYINT(1) NOT NULL DEFAULT 1,
            apply_group TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_campaign'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_campaign TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'amazon_ad_operation_types'
                      AND COLUMN_NAME = 'apply_group'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE amazon_ad_operation_types ADD COLUMN apply_group TINYINT(1) NOT NULL DEFAULT 1")
                    except Exception as e:
                        if pymysql and isinstance(e, pymysql.err.OperationalError) and getattr(e, 'args', [None])[0] == 1060:
                            pass
                        else:
                            raise
        self._amazon_ad_operation_types_ready = True

    def _ensure_amazon_ad_tables(self):
        if self._amazon_ad_ready:
            return
        self._ensure_product_table()
        self._ensure_category_table()
        self._ensure_amazon_ad_subtypes_table()
        create_sql = """
        CREATE TABLE IF NOT EXISTS amazon_ad_items (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ad_level VARCHAR(16) NOT NULL,
            sku_family_id INT UNSIGNED NULL,
            portfolio_id INT UNSIGNED NULL,
            campaign_id INT UNSIGNED NULL,
            strategy_code VARCHAR(8) NULL,
            subtype_id INT UNSIGNED NULL,
            name VARCHAR(255) NOT NULL,
            is_shared_budget TINYINT(1) NULL,
            status VARCHAR(16) NULL,
            budget DECIMAL(12,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_ad_level (ad_level),
            INDEX idx_ad_sku (sku_family_id),
            INDEX idx_ad_portfolio (portfolio_id),
            INDEX idx_ad_campaign (campaign_id),
            INDEX idx_ad_subtype (subtype_id),
            CONSTRAINT fk_ad_sku FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_ad_portfolio FOREIGN KEY (portfolio_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_campaign FOREIGN KEY (campaign_id)
                REFERENCES amazon_ad_items(id) ON DELETE CASCADE,
            CONSTRAINT fk_ad_subtype FOREIGN KEY (subtype_id)
                REFERENCES amazon_ad_subtypes(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)
        self._amazon_ad_ready = True

    def _ensure_certification_table(self):
        create_sql = """
        CREATE TABLE IF NOT EXISTS certifications (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            icon_name VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sql)

    def _ensure_features_table(self):
        self._ensure_category_table()
        create_features = """
        CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        create_feature_categories = """
        CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_features)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'features'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE features ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(create_feature_categories)

    def _ensure_order_product_tables(self):
        if self._order_product_ready:
            return
        self._ensure_product_table()
        self._ensure_fabric_table()
        self._ensure_category_table()
        self._ensure_certification_table()
        self._ensure_materials_table()

        create_order_products = """
        CREATE TABLE IF NOT EXISTS order_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            sku VARCHAR(64) NOT NULL UNIQUE,
            sku_family_id INT UNSIGNED NULL,
            version_no VARCHAR(64) NOT NULL,
            fabric_id INT UNSIGNED NULL,
            spec_qty_short VARCHAR(128) NOT NULL,
            listing_image_b64 VARCHAR(512) NULL,
            is_iteration TINYINT(1) NOT NULL DEFAULT 0,
            source_order_product_id INT UNSIGNED NULL,
            finished_length_in DECIMAL(10,2) NULL,
            finished_width_in DECIMAL(10,2) NULL,
            finished_height_in DECIMAL(10,2) NULL,
            net_weight_lbs DECIMAL(10,2) NULL,
            package_length_in DECIMAL(10,2) NULL,
            package_width_in DECIMAL(10,2) NULL,
            package_height_in DECIMAL(10,2) NULL,
            gross_weight_lbs DECIMAL(10,2) NULL,
            cost_usd DECIMAL(10,2) NULL,
            carton_qty INT UNSIGNED NULL,
            package_size_class VARCHAR(64) NULL,
            last_mile_avg_freight_usd DECIMAL(10,2) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_sku_family (sku_family_id),
            INDEX idx_fabric (fabric_id),
            INDEX idx_source_order_product (source_order_product_id),
            CONSTRAINT fk_order_products_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_source FOREIGN KEY (source_order_product_id)
                REFERENCES order_products(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_materials = """
        CREATE TABLE IF NOT EXISTS order_product_materials (
            order_product_id INT UNSIGNED NOT NULL,
            material_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, material_id),
            CONSTRAINT fk_opm_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opm_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_features = """
        CREATE TABLE IF NOT EXISTS features (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            name_en VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_feature_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_feature_categories = """
        CREATE TABLE IF NOT EXISTS feature_categories (
            feature_id INT UNSIGNED NOT NULL,
            category_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (feature_id, category_id),
            CONSTRAINT fk_feature_category_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE,
            CONSTRAINT fk_feature_category_category FOREIGN KEY (category_id)
                REFERENCES product_categories(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_features = """
        CREATE TABLE IF NOT EXISTS order_product_features (
            order_product_id INT UNSIGNED NOT NULL,
            feature_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, feature_id),
            CONSTRAINT fk_opf_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opf_feature FOREIGN KEY (feature_id)
                REFERENCES features(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_order_product_certifications = """
        CREATE TABLE IF NOT EXISTS order_product_certifications (
            order_product_id INT UNSIGNED NOT NULL,
            certification_id INT UNSIGNED NOT NULL,
            PRIMARY KEY (order_product_id, certification_id),
            CONSTRAINT fk_opc_order_product FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_opc_certification FOREIGN KEY (certification_id)
                REFERENCES certifications(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_order_products)
                cur.execute(create_order_product_materials)
                cur.execute(create_features)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'features'
                      AND COLUMN_NAME = 'name_en'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    cur.execute("ALTER TABLE features ADD COLUMN name_en VARCHAR(128) NOT NULL DEFAULT ''")
                cur.execute(create_feature_categories)
                cur.execute(create_order_product_features)
                cur.execute(create_order_product_certifications)
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'dachene_yuncang_no'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN dachene_yuncang_no")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'spec_qty'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) > 0:
                    try:
                        cur.execute("ALTER TABLE order_products DROP COLUMN spec_qty")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'listing_image_b64'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN listing_image_b64 VARCHAR(512) NULL")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'is_iteration'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN is_iteration TINYINT(1) NOT NULL DEFAULT 0")
                    except Exception:
                        pass

                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'order_products'
                      AND COLUMN_NAME = 'source_order_product_id'
                    """
                )
                row = cur.fetchone()
                if row and row.get('cnt', 0) == 0:
                    try:
                        cur.execute("ALTER TABLE order_products ADD COLUMN source_order_product_id INT UNSIGNED NULL")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE order_products ADD INDEX idx_source_order_product (source_order_product_id)")
                    except Exception:
                        pass
                    try:
                        cur.execute(
                            """
                            ALTER TABLE order_products
                            ADD CONSTRAINT fk_order_products_source
                            FOREIGN KEY (source_order_product_id) REFERENCES order_products(id)
                            ON DELETE SET NULL
                            """
                        )
                    except Exception:
                        pass

        self._order_product_ready = True

    def _ensure_sales_product_tables(self):
        if self._sales_product_ready:
            return
        self._ensure_shops_table()
        self._ensure_product_table()
        self._ensure_amazon_ad_tables()
        self._ensure_order_product_tables()

        create_sales_products = """
        CREATE TABLE IF NOT EXISTS sales_products (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            shop_id INT UNSIGNED NOT NULL,
            sku_family_id INT UNSIGNED NOT NULL,
            portfolio_id INT UNSIGNED NOT NULL,
            platform_sku VARCHAR(128) NOT NULL UNIQUE,
            parent_asin VARCHAR(32) NULL,
            child_asin VARCHAR(32) NULL,
            fabric VARCHAR(255) NULL,
            spec_name VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sp_shop (shop_id),
            INDEX idx_sp_sku_family (sku_family_id),
            INDEX idx_sp_portfolio (portfolio_id),
            CONSTRAINT fk_sp_shop FOREIGN KEY (shop_id) REFERENCES shops(id) ON DELETE RESTRICT,
            CONSTRAINT fk_sp_sku_family FOREIGN KEY (sku_family_id) REFERENCES product_families(id) ON DELETE RESTRICT,
            CONSTRAINT fk_sp_portfolio FOREIGN KEY (portfolio_id) REFERENCES amazon_ad_items(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_sales_order_links = """
        CREATE TABLE IF NOT EXISTS sales_product_order_links (
            sales_product_id INT UNSIGNED NOT NULL,
            order_product_id INT UNSIGNED NOT NULL,
            quantity INT UNSIGNED NOT NULL DEFAULT 1,
            PRIMARY KEY (sales_product_id, order_product_id),
            CONSTRAINT fk_spol_sales FOREIGN KEY (sales_product_id)
                REFERENCES sales_products(id) ON DELETE CASCADE,
            CONSTRAINT fk_spol_order FOREIGN KEY (order_product_id)
                REFERENCES order_products(id) ON DELETE RESTRICT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_sales_products)
                cur.execute(create_sales_order_links)
                
                # 删除 portfolio_id 字段的迁移
                try:
                    cur.execute("""
                        SELECT COLUMN_NAME FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA=DATABASE()
                        AND TABLE_NAME='sales_products'
                        AND COLUMN_NAME='portfolio_id'
                    """)
                    if cur.fetchone():
                        # 先删除外键约束
                        cur.execute("""
                            SELECT CONSTRAINT_NAME FROM information_schema.KEY_COLUMN_USAGE
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND CONSTRAINT_NAME != 'PRIMARY'
                        """)
                        fk_row = cur.fetchone()
                        if fk_row:
                            fk_name = fk_row['CONSTRAINT_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP FOREIGN KEY {fk_name}")
                        # 删除索引（如果存在）
                        cur.execute("""
                            SELECT INDEX_NAME FROM information_schema.STATISTICS
                            WHERE TABLE_SCHEMA=DATABASE()
                            AND TABLE_NAME='sales_products'
                            AND COLUMN_NAME='portfolio_id'
                            AND INDEX_NAME != 'PRIMARY'
                        """)
                        idx_row = cur.fetchone()
                        if idx_row:
                            idx_name = idx_row['INDEX_NAME']
                            cur.execute(f"ALTER TABLE sales_products DROP INDEX {idx_name}")
                        # 最后删除列
                        cur.execute("ALTER TABLE sales_products DROP COLUMN portfolio_id")
                except Exception:
                    pass
        self._sales_product_ready = True

    def _ensure_todo_tables(self):
        if self._todo_ready:
            return

        create_users = """
        CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(128) NULL,
            phone VARCHAR(64) NULL,
            birthday DATE NULL,
            is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0,
            can_manage_todos TINYINT UNSIGNED NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username (username),
            INDEX idx_birthday (birthday),
            INDEX idx_name (name)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_todos = """
        CREATE TABLE IF NOT EXISTS todos (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            detail TEXT NULL,
            start_date DATE NOT NULL,
            due_date DATE NOT NULL,
            reminder_interval_days INT UNSIGNED NOT NULL DEFAULT 1,
            last_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            next_check_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            is_recurring TINYINT UNSIGNED NOT NULL DEFAULT 0,
            status VARCHAR(16) NOT NULL DEFAULT 'open',
            priority TINYINT UNSIGNED NOT NULL DEFAULT 2,
            created_by INT UNSIGNED NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_due_date (due_date),
            INDEX idx_status (status),
            INDEX idx_created_by (created_by),
            CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by)
                REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_todo_assignments = """
        CREATE TABLE IF NOT EXISTS todo_assignments (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            todo_id INT UNSIGNED NOT NULL,
            assignee_id INT UNSIGNED NOT NULL,
            assignment_status VARCHAR(16) NOT NULL DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uk_todo_assignee (todo_id, assignee_id),
            CONSTRAINT fk_ta_todo FOREIGN KEY (todo_id)
                REFERENCES todos(id) ON DELETE CASCADE,
            CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id)
                REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        create_sessions = """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id VARCHAR(128) PRIMARY KEY,
            employee_id INT UNSIGNED NOT NULL,
            expires_at DATETIME NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_emp (employee_id),
            CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """

        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(create_users)
                cur.execute(create_todos)
                cur.execute(create_todo_assignments)
                cur.execute(create_sessions)

                # Ensure users schema has required columns
                for col, ddl in (
                    ('name', "ALTER TABLE users ADD COLUMN name VARCHAR(128) NULL"),
                    ('phone', "ALTER TABLE users ADD COLUMN phone VARCHAR(64) NULL"),
                    ('birthday', "ALTER TABLE users ADD COLUMN birthday DATE NULL"),
                    ('is_admin', "ALTER TABLE users ADD COLUMN is_admin TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                    ('can_manage_todos', "ALTER TABLE users ADD COLUMN can_manage_todos TINYINT UNSIGNED NOT NULL DEFAULT 0"),
                ):
                    cur.execute(
                        """
                        SELECT COUNT(*) AS cnt
                        FROM information_schema.COLUMNS
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = %s
                        """,
                        (col,)
                    )
                    row = cur.fetchone()
                    if row and row.get('cnt', 0) == 0:
                        cur.execute(ddl)

                # Drop legacy employee_id column on users if present
                cur.execute(
                    """
                    SELECT COUNT(*) AS cnt
                    FROM information_schema.COLUMNS
                    WHERE TABLE_SCHEMA = DATABASE()
                      AND TABLE_NAME = 'users'
                      AND COLUMN_NAME = 'employee_id'
                    """
                )
                emp_col = cur.fetchone()
                if emp_col and emp_col.get('cnt', 0) > 0:
                    cur.execute(
                        """
                        SELECT CONSTRAINT_NAME
                        FROM information_schema.KEY_COLUMN_USAGE
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = 'users'
                          AND COLUMN_NAME = 'employee_id'
                          AND REFERENCED_TABLE_NAME IS NOT NULL
                        """
                    )
                    for fk in cur.fetchall() or []:
                        try:
                            cur.execute(f"ALTER TABLE users DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                        except Exception:
                            pass
                    try:
                        cur.execute("ALTER TABLE users MODIFY COLUMN employee_id INT UNSIGNED NULL")
                    except Exception:
                        pass
                    try:
                        cur.execute("ALTER TABLE users DROP COLUMN employee_id")
                    except Exception:
                        pass

                # Drop legacy foreign keys that reference employees
                for table_name in ('users', 'todos', 'todo_assignments', 'sessions'):
                    cur.execute(
                        """
                        SELECT CONSTRAINT_NAME
                        FROM information_schema.KEY_COLUMN_USAGE
                        WHERE TABLE_SCHEMA = DATABASE()
                          AND TABLE_NAME = %s
                          AND REFERENCED_TABLE_NAME = 'employees'
                        """,
                        (table_name,)
                    )
                    for fk in cur.fetchall() or []:
                        try:
                            cur.execute(f"ALTER TABLE {table_name} DROP FOREIGN KEY {fk['CONSTRAINT_NAME']}")
                        except Exception:
                            pass

                # Drop legacy employees table if it still exists
                try:
                    cur.execute("DROP TABLE IF EXISTS employees")
                except Exception:
                    pass

                # Ensure at least one admin exists
                cur.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_admin=1")
                admin_row = cur.fetchone()
                if admin_row and admin_row.get('cnt', 0) == 0:
                    cur.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1")
                    first_user = cur.fetchone()
                    if first_user and first_user.get('id'):
                        cur.execute(
                            "UPDATE users SET is_admin=1, can_manage_todos=1 WHERE id=%s",
                            (first_user['id'],)
                        )

                # Ensure foreign keys point to users
                try:
                    cur.execute(
                        "ALTER TABLE todos ADD CONSTRAINT fk_todos_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE"
                    )
                except Exception:
                    pass
                try:
                    cur.execute(
                        "ALTER TABLE todo_assignments ADD CONSTRAINT fk_ta_assignee FOREIGN KEY (assignee_id) REFERENCES users(id) ON DELETE CASCADE"
                    )
                except Exception:
                    pass
                try:
                    cur.execute(
                        "ALTER TABLE sessions ADD CONSTRAINT fk_sessions_user FOREIGN KEY (employee_id) REFERENCES users(id) ON DELETE CASCADE"
                    )
                except Exception:
                    pass

        self._todo_ready = True

    def _split_multi_values(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            raw_items = value
        else:
            raw_items = re.split(r'[\n,，;；/]+', str(value))

        seen = set()
        result = []
        for item in raw_items:
            text = str(item).strip()
            if not text:
                continue
            if text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    def _parse_float(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return float(text)
        except Exception:
            return None

    def _parse_int(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return int(float(text))
        except Exception:
            return None

    def _parse_date_str(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            dt = datetime.strptime(text, '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d')
        except Exception:
            return None

    def _normalize_yes_no(self, value):
        text = ('' if value is None else str(value)).strip().lower()
        if text in ('是', 'yes', 'y', 'true', '1'):
            return 1
        if text in ('否', 'no', 'n', 'false', '0'):
            return 0
        return None

    def _normalize_ad_status(self, value):
        text = ('' if value is None else str(value)).strip()
        if text in ('启动', '暂停', '存档'):
            return text
        return None

    def _get_sku_family_with_category_short(self, conn, sku_family_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT pf.id, pf.sku_family, pf.category,
                       pc.category_en AS category_short
                FROM product_families pf
                LEFT JOIN product_categories pc ON pc.category_cn = pf.category
                WHERE pf.id=%s
                """,
                (sku_family_id,)
            )
            return cur.fetchone()

    def _get_ad_item_by_id(self, conn, item_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, ad_level, name, portfolio_id, campaign_id
                FROM amazon_ad_items
                WHERE id=%s
                """,
                (item_id,)
            )
            return cur.fetchone()

    def _build_portfolio_name(self, conn, sku_family_id):
        sku_row = self._get_sku_family_with_category_short(conn, sku_family_id)
        if not sku_row:
            return None
        short = (sku_row.get('category_short') or sku_row.get('category') or '').strip()
        sku_family = (sku_row.get('sku_family') or '').strip()
        if not short or not sku_family:
            return None
        return f"{short}-{sku_family}"

    def _build_campaign_name(self, conn, strategy_code, portfolio_id, subtype_id):
        with conn.cursor() as cur:
            cur.execute("SELECT id, name FROM amazon_ad_items WHERE id=%s AND ad_level='portfolio'", (portfolio_id,))
            portfolio = cur.fetchone()
            if not portfolio:
                return None
            cur.execute("SELECT id, ad_class, subtype_code FROM amazon_ad_subtypes WHERE id=%s", (subtype_id,))
            subtype = cur.fetchone()
            if not subtype:
                return None
        strategy = (strategy_code or '').strip().upper()
        if strategy not in ('BE', 'BD', 'PC'):
            return None
        return f"{strategy}-{portfolio.get('name') or ''}-{subtype.get('ad_class') or ''}-{subtype.get('subtype_code') or ''}"

    def _get_material_type_id(self, conn, name_or_code):
        if not name_or_code:
            return None
        type_map = {
            'fabric': '面料',
            'filling': '填充',
            'frame': '框架',
            'electronics': '电子元器件'
        }
        name = type_map.get(name_or_code, name_or_code)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM material_types WHERE name=%s", (name,))
            row = cur.fetchone()
            return row['id'] if row else None

    def _materials_has_type_id(self, conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'materials'
                  AND COLUMN_NAME = 'material_type_id'
                """
            )
            row = cur.fetchone()
            return bool(row and row.get('cnt', 0) > 0)

    def _materials_has_parent_id(self, conn):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'materials'
                  AND COLUMN_NAME = 'parent_id'
                """
            )
            row = cur.fetchone()
            return bool(row and row.get('cnt', 0) > 0)

    def _upsert_material_ids(self, conn, names, material_type_code):
        ids = []
        if not names:
            return ids
        with conn.cursor() as cur:
            material_type_id = self._get_material_type_id(conn, material_type_code)
            if not material_type_id:
                return ids
            for name in names:
                cur.execute(
                    "SELECT id FROM materials WHERE material_type_id=%s AND name=%s",
                    (material_type_id, name)
                )
                row = cur.fetchone()
                if row:
                    ids.append(row['id'])
                    continue
                cur.execute(
                    "INSERT INTO materials (name, material_type_id) VALUES (%s, %s)",
                    (name, material_type_id)
                )
                ids.append(cur.lastrowid)
        return ids

    def _upsert_feature_ids(self, conn, names):
        ids = []
        if not names:
            return ids
        with conn.cursor() as cur:
            for name in names:
                cur.execute("SELECT id FROM features WHERE name=%s", (name,))
                row = cur.fetchone()
                if row:
                    ids.append(row['id'])
                    continue
                cur.execute("INSERT INTO features (name) VALUES (%s)", (name,))
                ids.append(cur.lastrowid)
        return ids

    def _replace_order_product_materials(self, conn, order_product_id, filling_names, frame_names):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_materials WHERE order_product_id=%s", (order_product_id,))

        for material_type, names in (
            ('filling', filling_names),
            ('frame', frame_names)
        ):
            ids = self._upsert_material_ids(conn, names, material_type)
            if not ids:
                continue
            with conn.cursor() as cur:
                for material_id in ids:
                    cur.execute(
                        "INSERT IGNORE INTO order_product_materials (order_product_id, material_id) VALUES (%s, %s)",
                        (order_product_id, material_id)
                    )

    def _replace_order_product_features(self, conn, order_product_id, feature_names):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_features WHERE order_product_id=%s", (order_product_id,))

        feature_ids = self._upsert_feature_ids(conn, feature_names)
        if not feature_ids:
            return
        with conn.cursor() as cur:
            for feature_id in feature_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_features (order_product_id, feature_id) VALUES (%s, %s)",
                    (order_product_id, feature_id)
                )

    def _replace_order_product_material_ids(self, conn, order_product_id, filling_ids, frame_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_materials WHERE order_product_id=%s", (order_product_id,))

        material_ids = []
        if filling_ids:
            material_ids.extend(filling_ids)
        if frame_ids:
            material_ids.extend(frame_ids)
        if not material_ids:
            return
        with conn.cursor() as cur:
            for material_id in material_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_materials (order_product_id, material_id) VALUES (%s, %s)",
                    (order_product_id, material_id)
                )

    def _replace_order_product_feature_ids(self, conn, order_product_id, feature_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_features WHERE order_product_id=%s", (order_product_id,))

        if not feature_ids:
            return
        with conn.cursor() as cur:
            for feature_id in feature_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_features (order_product_id, feature_id) VALUES (%s, %s)",
                    (order_product_id, feature_id)
                )

    def _replace_order_product_certification_ids(self, conn, order_product_id, certification_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_certifications WHERE order_product_id=%s", (order_product_id,))

        if not certification_ids:
            return
        with conn.cursor() as cur:
            for certification_id in certification_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_certifications (order_product_id, certification_id) VALUES (%s, %s)",
                    (order_product_id, certification_id)
                )

    def _replace_feature_categories(self, conn, feature_id, category_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM feature_categories WHERE feature_id=%s", (feature_id,))

        if not category_ids:
            return
        with conn.cursor() as cur:
            for category_id in category_ids:
                cur.execute(
                    "INSERT IGNORE INTO feature_categories (feature_id, category_id) VALUES (%s, %s)",
                    (feature_id, category_id)
                )

    def _replace_fabric_sku_family_ids(self, conn, fabric_id, sku_family_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE fabric_id=%s", (fabric_id,))

        if not sku_family_ids:
            return
        with conn.cursor() as cur:
            for sku_family_id in sku_family_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def _replace_sku_family_fabric_ids(self, conn, sku_family_id, fabric_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE sku_family_id=%s", (sku_family_id,))

        if not fabric_ids:
            return
        with conn.cursor() as cur:
            for fabric_id in fabric_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def _replace_ad_subtype_operation_type_ids(self, conn, subtype_id, operation_type_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM amazon_ad_subtype_operation_types WHERE subtype_id=%s", (subtype_id,))

        if not operation_type_ids:
            return
        with conn.cursor() as cur:
            for operation_type_id in operation_type_ids:
                cur.execute(
                    "INSERT IGNORE INTO amazon_ad_subtype_operation_types (subtype_id, operation_type_id) VALUES (%s, %s)",
                    (subtype_id, operation_type_id)
                )

    def _normalize_sales_order_links(self, links):
        items = []
        if not isinstance(links, list):
            return items
        for entry in links:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not order_product_id:
                continue
            items.append({'order_product_id': order_product_id, 'quantity': max(1, quantity)})
        return items

    def _replace_sales_order_links(self, conn, sales_product_id, links):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sales_product_order_links WHERE sales_product_id=%s", (sales_product_id,))
        if not links:
            return
        with conn.cursor() as cur:
            for entry in links:
                cur.execute(
                    """
                    INSERT INTO sales_product_order_links (sales_product_id, order_product_id, quantity)
                    VALUES (%s, %s, %s)
                    """,
                    (sales_product_id, entry['order_product_id'], entry['quantity'])
                )

    def _derive_sales_fields(self, conn, sku_family_id, links):
        """自动推导销售产品的面料、规格名称和平台SKU"""
        if not links or not sku_family_id:
            return '', '', ''
        
        # 获取货号系列代码
        sku_family_code = ''
        with conn.cursor() as cur:
            cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
            row = cur.fetchone()
            if row:
                sku_family_code = (row.get('sku_family') or '').strip()
        
        # 获取下单产品信息
        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT op.id, op.sku, op.spec_qty_short, fm.fabric_name_en
                FROM order_products op
                LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                WHERE op.id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []
        
        row_map = {row['id']: row for row in rows}
        fabrics = []
        spec_parts = []
        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            fabric_name = (row.get('fabric_name_en') or '').strip()
            if fabric_name and fabric_name not in fabrics:
                fabrics.append(fabric_name)
            spec_short = (row.get('spec_qty_short') or '').strip()
            if spec_short:
                spec_parts.append(f"{entry['quantity']}{spec_short}")
        
        fabric = ' / '.join(fabrics)
        spec_name = ''.join(spec_parts)
        
        # 自动生成平台SKU: 货号-面料-规格
        platform_sku = ''
        if sku_family_code and fabric and spec_name:
            # 使用第一个面料（如果有多个面料，用第一个）
            first_fabric = fabrics[0] if fabrics else ''
            platform_sku = f"{sku_family_code}-{first_fabric}-{spec_name}"
        
        return fabric, spec_name, platform_sku

    def _get_fabric_folder_bytes(self):
        return self._join_resources('『面料』')

    def _ensure_fabric_folder(self):
        folder = self._get_fabric_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _get_listing_folder_bytes(self):
        return self._join_resources('上架资源')

    def _ensure_listing_folder(self):
        folder = self._get_listing_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _ensure_listing_sku_folder(self, sku_family):
        if not sku_family:
            return
        base_folder = self._ensure_listing_folder()
        try:
            sku_bytes = os.fsencode(sku_family)
        except Exception:
            sku_bytes = str(sku_family).encode('utf-8', errors='surrogatepass')
        target = os.path.join(base_folder, sku_bytes)
        if not os.path.exists(target):
            os.makedirs(target, exist_ok=True)

    def _get_certification_folder_bytes(self):
        return self._join_resources('『认证』')

    def _ensure_certification_folder(self):
        folder = self._get_certification_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _normalize_fabric_image_names(self, image_names):
        if not image_names:
            return []
        if isinstance(image_names, (str, bytes, bytearray)):
            raw = [image_names]
        else:
            raw = list(image_names)
        seen = set()
        result = []
        for name in raw:
            if isinstance(name, (bytes, bytearray)):
                try:
                    name = os.fsdecode(name)
                except Exception:
                    name = name.decode('utf-8', errors='ignore')
            name = (str(name).strip() if name is not None else '')
            if not name or name in seen:
                continue
            seen.add(name)
            result.append(name)
        return result

    def _parse_fabric_images_payload(self, images_data):
        """解析图片数组数据，支持新旧格式
        新格式: [{'image_name': 'xxx', 'remark': '原图/卖点图', 'sort_order': 0}, ...]
        旧格式: ['image_name1', 'image_name2', ...]
        返回: [{'image_name': str, 'remark': str|None, 'sort_order': int, 'is_primary': bool}, ...]
        """
        if not images_data:
            return []
        
        result = []
        if isinstance(images_data, list):
            for idx, item in enumerate(images_data):
                if isinstance(item, dict):
                    # 新格式
                    result.append({
                        'image_name': (item.get('image_name') or '').strip(),
                        'remark': self._normalize_fabric_remark(item.get('remark')),
                        'sort_order': self._parse_int(item.get('sort_order')) or idx,
                        'is_primary': bool(item.get('is_primary', idx == 0))
                    })
                else:
                    # 旧格式字符串
                    result.append({
                        'image_name': str(item).strip(),
                        'remark': '原图',
                        'sort_order': idx,
                        'is_primary': (idx == 0)
                    })
        return [r for r in result if r['image_name']]
    
    def _rename_fabric_image_with_remark(self, old_name, fabric_code, remark, index):
        """根据新命名规则重命名图片: 面料编号-备注-序号
        Args:
            old_name: 原文件名
            fabric_code: 面料编号
            remark: 备注类型（原图/卖点图）
            index: 在该备注类型下的序号（从1开始）
        Returns:
            新文件名，如果文件名已符合规则且序号正确则返回原文件名
        """
        if not old_name:
            return None
        
        ext = os.path.splitext(old_name)[1] or '.jpg'
        remark_str = remark or '未分类'
        new_name = f"{fabric_code}-{remark_str}-{index:02d}{ext}"
        
        # 如果原文件名已经符合新规则，保持不变
        if old_name == new_name:
            return old_name
        
        return new_name

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

    def _build_fabric_upload_name(self, fabric_code, filename, existing_names):
        ext = os.path.splitext(filename)[1]
        index = self._next_fabric_image_index(existing_names, fabric_code)
        return f"{fabric_code}_{index:02d}{ext}"

    def handle_sku_api(self, environ, method, start_response):
        """货号管理 API（CRUD）"""
        try:
            self._ensure_fabric_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT pf.id, pf.sku_family, pf.category, pf.created_at,
                                    GROUP_CONCAT(DISTINCT fm.id ORDER BY fm.id SEPARATOR ',') AS fabric_ids,
                                    GROUP_CONCAT(DISTINCT fm.fabric_code ORDER BY fm.fabric_code SEPARATOR ' / ') AS fabric_codes
                                FROM product_families pf
                                LEFT JOIN fabric_product_families fpf ON fpf.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                                WHERE pf.sku_family LIKE %s OR pf.category LIKE %s
                                GROUP BY pf.id, pf.sku_family, pf.category, pf.created_at
                                ORDER BY pf.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT pf.id, pf.sku_family, pf.category, pf.created_at,
                                    GROUP_CONCAT(DISTINCT fm.id ORDER BY fm.id SEPARATOR ',') AS fabric_ids,
                                    GROUP_CONCAT(DISTINCT fm.fabric_code ORDER BY fm.fabric_code SEPARATOR ' / ') AS fabric_codes
                                FROM product_families pf
                                LEFT JOIN fabric_product_families fpf ON fpf.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                                GROUP BY pf.id, pf.sku_family, pf.category, pf.created_at
                                ORDER BY pf.id DESC
                                """
                            )
                        rows = cur.fetchall()
                for row in rows:
                    fabric_ids = row.get('fabric_ids')
                    if fabric_ids:
                        row['fabric_ids'] = [v for v in fabric_ids.split(',') if v]
                    else:
                        row['fabric_ids'] = []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                fabric_ids = [self._parse_int(v) for v in (data.get('fabric_ids') or [])]
                fabric_ids = [v for v in fabric_ids if v]
                if not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing sku_family or category'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_families (sku_family, category) VALUES (%s, %s)",
                            (sku_family, category)
                        )
                        new_id = cur.lastrowid
                    self._replace_sku_family_fabric_ids(conn, new_id, fabric_ids)
                self._ensure_listing_sku_folder(sku_family)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                fabric_ids = [self._parse_int(v) for v in (data.get('fabric_ids') or [])]
                fabric_ids = [v for v in fabric_ids if v]
                if not item_id or not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE product_families
                            SET sku_family=%s, category=%s
                            WHERE id=%s
                            """,
                            (sku_family, category, item_id)
                        )
                    self._replace_sku_family_fabric_ids(conn, item_id, fabric_ids)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM product_families WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': 'SKU 已存在'}, start_response)
            print("SKU API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_category_api(self, environ, method, start_response):
        """品类管理 API（CRUD）"""
        try:
            self._ensure_category_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, category_cn, category_en, category_en_name, created_at
                                FROM product_categories
                                WHERE category_cn LIKE %s OR category_en LIKE %s OR category_en_name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, category_cn, category_en, category_en_name, created_at
                                FROM product_categories
                                ORDER BY id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                category_cn = (data.get('category_cn') or '').strip()
                category_en = (data.get('category_en') or '').strip()
                category_en_name = (data.get('category_en_name') or '').strip()
                if not category_cn or not category_en or not category_en_name:
                    return self.send_json({'status': 'error', 'message': 'Missing category_cn or category_en or category_en_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_categories (category_cn, category_en, category_en_name) VALUES (%s, %s, %s)",
                            (category_cn, category_en, category_en_name)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                category_cn = (data.get('category_cn') or '').strip()
                category_en = (data.get('category_en') or '').strip()
                category_en_name = (data.get('category_en_name') or '').strip()
                if not item_id or not category_cn or not category_en or not category_en_name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE product_categories
                            SET category_cn=%s, category_en=%s, category_en_name=%s
                            WHERE id=%s
                            """,
                            (category_cn, category_en, category_en_name, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM product_categories WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '品类已存在'}, start_response)
            print("Category API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_fabric_images_api(self, environ, start_response):
        """列出面料文件夹内图片"""
        try:
            folder = self._get_fabric_folder_bytes()
            if not os.path.exists(folder):
                return self.send_json({'status': 'success', 'items': []}, start_response)

            items = []
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        raw = entry.name
                        # raw may be bytes when scanning a bytes path; ensure we capture original bytes
                        if isinstance(raw, (str,)):
                            try:
                                raw_bytes = os.fsencode(raw)
                            except Exception:
                                raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                        else:
                            raw_bytes = raw

                        # Try best-effort decode for display name (utf-8, then gb18030, then fs decode)
                        display = None
                        try:
                            display = os.fsdecode(raw_bytes)
                        except Exception:
                            try:
                                display = raw_bytes.decode('utf-8')
                            except Exception:
                                try:
                                    display = raw_bytes.decode('gb18030')
                                except Exception:
                                    display = raw_bytes.decode('latin-1', errors='replace')

                        # 返回相对于 resources 的字节路径 base64（包含『面料』子目录），
                        # 以便前端直接传回 /api/image-preview 使用
                        try:
                            folder_bytes = os.fsencode('『面料』')
                        except Exception:
                            folder_bytes = '『面料』'.encode('utf-8', errors='surrogatepass')
                        try:
                            rel_bytes = os.path.join(folder_bytes, raw_bytes)
                        except Exception:
                            # fallback: simple concat with os.sep
                            rel_bytes = folder_bytes + os.sep.encode() + raw_bytes
                        b64 = base64.b64encode(rel_bytes).decode('ascii')
                        name_raw_b64 = base64.b64encode(raw_bytes).decode('ascii')
                        items.append({'name': display, 'name_raw_b64': name_raw_b64, 'b64': b64})

            # 按显示名排序
            try:
                items.sort(key=lambda x: (x.get('name') or '').lower())
            except Exception:
                pass
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_listing_images_api(self, environ, start_response):
        """列出上架资源文件夹内图片（递归）"""
        try:
            folder = self._ensure_listing_folder()
            items = []
            for root, _, files in os.walk(folder):
                for fname in files:
                    if not self._is_image_name(fname):
                        continue
                    raw = fname
                    if isinstance(raw, (str,)):
                        try:
                            raw_bytes = os.fsencode(raw)
                        except Exception:
                            raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                    else:
                        raw_bytes = raw

                    rel_dir = os.path.relpath(root, folder)
                    if rel_dir == '.':
                        rel_bytes = raw_bytes
                        display_name = os.fsdecode(raw_bytes)
                    else:
                        try:
                            rel_dir_bytes = os.fsencode(rel_dir)
                        except Exception:
                            rel_dir_bytes = rel_dir.encode('utf-8', errors='surrogatepass')
                        rel_bytes = os.path.join(rel_dir_bytes, raw_bytes)
                        display_name = os.fsdecode(rel_bytes)

                    try:
                        folder_bytes = os.fsencode('上架资源')
                    except Exception:
                        folder_bytes = '上架资源'.encode('utf-8', errors='surrogatepass')
                    try:
                        rel_path_bytes = os.path.join(folder_bytes, rel_bytes)
                    except Exception:
                        rel_path_bytes = folder_bytes + os.sep.encode() + rel_bytes

                    b64 = base64.b64encode(rel_path_bytes).decode('ascii')
                    items.append({'name': display_name, 'b64': b64})

            items.sort(key=lambda x: (x.get('name') or '').lower())
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_certification_images_api(self, environ, start_response):
        """列出认证文件夹内图片"""
        try:
            folder = self._ensure_certification_folder()

            items = []
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        name = entry.name
                        if isinstance(name, (bytes, bytearray)):
                            try:
                                name = os.fsdecode(name)
                            except Exception:
                                name = name.decode('utf-8', errors='ignore')
                        items.append(name)

            items.sort()
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_upload_api(self, environ, start_response):
        """上传面料图片（支持多张）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            # Read raw body once and parse via FieldStorage on a BytesIO buffer
            t_start = time.time()
            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            t_before_read = time.time()
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            t_after_read = time.time()
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            t_before_parse = time.time()
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            t_after_parse = time.time()

            fabric_code = (form.getfirst('fabric_code', '') or '').strip()
            # debug: log incoming FieldStorage info
            try:
                fs_list = getattr(form, 'list', None)
                print('=== Fabric upload debug: FieldStorage list ===')
                if fs_list:
                    for fi in fs_list:
                        try:
                            print('Field name=', getattr(fi, 'name', None), 'filename=', getattr(fi, 'filename', None), 'type=', getattr(fi, 'type', None))
                        except Exception:
                            print('Field entry repr:', repr(fi))
                else:
                    print('FieldStorage.list is empty or missing')
            except Exception as _e:
                print('Failed to inspect FieldStorage:', str(_e))
            if not fabric_code:
                return self.send_json({'status': 'error', 'message': 'Missing fabric_code'}, start_response)

            # Accept files from any multipart field: FieldStorage.list contains all parts
            all_parts = getattr(form, 'list', []) or []

            # collect diagnostics about raw form items (helpful when filename is missing)
            raw_items_info = []
            for idx, it in enumerate(all_parts):
                try:
                    raw_items_info.append({
                        'index': idx,
                        'field_name': getattr(it, 'name', None),
                        'filename': getattr(it, 'filename', None),
                        'type': getattr(it, 'type', None)
                    })
                except Exception:
                    raw_items_info.append({'index': idx, 'error': 'inspect_failed'})

            uploads = []
            for p in all_parts:
                if getattr(p, 'filename', None):
                    try:
                        content = p.file.read() or b''
                    except Exception:
                        content = b''
                    uploads.append({
                        'filename': p.filename,
                        'type': getattr(p, 'type', None),
                        'content': content
                    })

            debug_info = {
                'raw_body_len': len(raw_body),
                'content_type': env_copy.get('CONTENT_TYPE', ''),
                'parts': raw_items_info,
                'uploads_count': len(uploads),
                'timing': {
                    'total_since_start': round(time.time() - t_start, 3),
                    'read_seconds': round(t_after_read - t_before_read, 3),
                    'parse_seconds': round(t_after_parse - t_before_parse, 3)
                }
            }

            # Fallback: parse multipart via email parser if FieldStorage failed to extract files
            if not uploads and raw_body:
                try:
                    from email.parser import BytesParser
                    from email.policy import default
                    ct = env_copy.get('CONTENT_TYPE', '')
                    t_email_before = time.time()
                    if ct.startswith('multipart/form-data'):
                        mime_bytes = (
                            b'Content-Type: ' + ct.encode('utf-8', errors='ignore') +
                            b'\r\nMIME-Version: 1.0\r\n\r\n' + raw_body
                        )
                        msg = BytesParser(policy=default).parsebytes(mime_bytes)
                        if msg.is_multipart():
                            for part in msg.iter_parts():
                                disp = part.get('Content-Disposition', '') or ''
                                filename = part.get_filename()
                                name = part.get_param('name', header='content-disposition')
                                if 'form-data' in disp and (filename or name == 'file'):
                                    payload = part.get_payload(decode=True) or b''
                                    uploads.append({
                                        'filename': filename or '',
                                        'type': part.get_content_type(),
                                        'content': payload
                                    })
                    t_email_after = time.time()
                    debug_info['timing']['email_parse_seconds'] = round(t_email_after - t_email_before, 3)
                except Exception as e:
                    print('Fabric upload fallback parser error:', str(e))

            if not uploads:
                print('Fabric upload: no valid items found, debug:', debug_info)
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded', 'details': debug_info}, start_response)

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
            file_reports = []
            t_before_write = time.time()
            for item in uploads:
                report = {
                    'orig_filename': '',
                    'content_len': 0,
                    'ext_from_name': '',
                    'ext_from_type': '',
                    'ext_from_magic': '',
                    'saved': False,
                    'reason': ''
                }
                try:
                    # Determine filename and extension; accept images even if filename lacks proper ext
                    orig_filename = os.path.basename(item.get('filename') or '')
                    content = item.get('content') or b''
                    report['orig_filename'] = orig_filename
                    report['content_len'] = len(content) if isinstance(content, (bytes, bytearray)) else 0
                    report['ext_from_name'] = os.path.splitext(orig_filename)[1] if orig_filename else ''

                    if report['content_len'] == 0:
                        report['reason'] = 'empty_content'
                        file_reports.append(report)
                        continue

                    # helper to infer extension from magic bytes
                    def infer_ext_from_bytes(b):
                        if not b or len(b) < 4:
                            return ''
                        if b.startswith(b"\xff\xd8\xff"):
                            return '.jpg'
                        if b.startswith(b"\x89PNG"):
                            return '.png'
                        if b.startswith(b"GIF8"):
                            return '.gif'
                        if b.startswith(b"BM"):
                            return '.bmp'
                        if b[0:4] == b'RIFF' and b[8:12] == b'WEBP':
                            return '.webp'
                        return ''

                    ext = ''
                    # try from original filename
                    if orig_filename and self._is_image_name(orig_filename):
                        try:
                            ext = os.path.splitext(orig_filename)[1]
                        except Exception:
                            ext = ''

                    # try from content-type provided by field
                    if not ext and item.get('type'):
                        t = (item.get('type') or '').lower()
                        if 'jpeg' in t or 'jpg' in t:
                            ext = '.jpg'
                        elif 'png' in t:
                            ext = '.png'
                        elif 'gif' in t:
                            ext = '.gif'
                        elif 'bmp' in t:
                            ext = '.bmp'
                        elif 'webp' in t:
                            ext = '.webp'
                        report['ext_from_type'] = ext

                    # try magic bytes
                    if not ext:
                        ext = infer_ext_from_bytes(content)
                        report['ext_from_magic'] = ext

                    if not ext:
                        report['reason'] = '无法推断图片类型'
                        file_reports.append(report)
                        continue

                    # build a base filename (use original name without ext if available, else fabric_code)
                    base_name = (os.path.splitext(orig_filename)[0] or fabric_code)
                    # ensure target name is unique according to naming scheme, even if existing set is stale
                    max_attempts = 500
                    index = self._next_fabric_image_index(existing, fabric_code)
                    target_name = None
                    dest_path = None
                    for _ in range(max_attempts):
                        target_name = f"{fabric_code}_{index:02d}{ext}"
                        dest_path = os.path.join(folder, os.fsencode(target_name))
                        if target_name not in existing and not os.path.exists(dest_path):
                            break
                        existing.add(target_name)
                        index += 1
                    if not target_name or not dest_path or os.path.exists(dest_path):
                        report['reason'] = 'target_exists'
                        file_reports.append(report)
                        continue
                    existing.add(target_name)

                    with open(dest_path, 'wb') as f:
                        f.write(content)
                    saved_names.append(target_name)
                    report['saved'] = True
                    report['reason'] = 'saved'
                    file_reports.append(report)
                except Exception as e:
                    report['reason'] = f'exception: {str(e)}'
                    file_reports.append(report)
            t_after_write = time.time()
            debug_info['timing']['write_seconds'] = round(t_after_write - t_before_write, 3)
            debug_info['timing']['total_seconds'] = round(time.time() - t_start, 3)

            if not saved_names:
                # return detailed diagnostics to help debugging
                details = file_reports if file_reports else debug_info
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded', 'details': details}, start_response)

            return self.send_json({'status': 'success', 'image_names': saved_names}, start_response)
        except Exception as e:
            print("Fabric upload error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_fabric_attach_api(self, environ, start_response):
        """将已存在的面料图片关联并重命名为面料编号下划线序号形式，返回新文件名列表
        接受 JSON: { fabric_code: 'FAB001', items: [ <base64 of raw filename bytes>, ... ] }
        返回: { status: 'success', items: [ {old_b64:..., new_name:...}, ... ] }
        """
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
            # build existing names set (decoded strings)
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
            # collect valid source paths
            to_process = []
            for raw_b64 in items:
                try:
                    raw_bytes = base64.b64decode(raw_b64)
                except Exception:
                    continue

                # attempt to build source path bytes
                src = None
                try:
                    src = os.path.join(folder, raw_bytes)
                except Exception:
                    try:
                        name_str = os.fsdecode(raw_bytes)
                    except Exception:
                        try:
                            name_str = raw_bytes.decode('utf-8', errors='surrogatepass')
                        except Exception:
                            name_str = None
                    if name_str:
                        src = os.path.join(folder, os.fsencode(name_str))

                if not src or not os.path.exists(src):
                    # try alternative decode
                    try:
                        name_str = None
                        try:
                            name_str = os.fsdecode(raw_bytes)
                        except Exception:
                            name_str = raw_bytes.decode('utf-8', errors='ignore')
                        alt = os.path.join(folder, os.fsencode(name_str))
                        if os.path.exists(alt):
                            src = alt
                    except Exception:
                        src = None

                if not src or not os.path.exists(src):
                    continue

                to_process.append({'raw_b64': raw_b64, 'raw_bytes': raw_bytes, 'src': src})

            if not to_process:
                return self.send_json({'status': 'success', 'items': []}, start_response)

            # compute starting index: always start from 1 as requested
            next_idx = 1

            # plan final names ensuring uniqueness
            planned = []
            used = set(existing)

            # First, detect files that already follow the naming convention for this fabric
            import re
            already_assigned = []
            remaining = []
            pattern = re.compile(rf"^{re.escape(fabric_code)}_(\d+)\.(.+)$")
            for item in to_process:
                src = item['src']
                src_basename = os.path.basename(src)
                try:
                    src_basename_str = os.fsdecode(src_basename)
                except Exception:
                    try:
                        src_basename_str = src_basename.decode('utf-8', errors='ignore')
                    except Exception:
                        src_basename_str = ''

                m = pattern.match(src_basename_str or '')
                if m:
                    # file already matches FABCODE_##.ext — treat as already assigned
                    assigned_name = src_basename_str
                    already_assigned.append({'raw_b64': item['raw_b64'], 'new_name': assigned_name})
                    used.add(assigned_name)
                else:
                    remaining.append(item)

            # For remaining files, assign sequential names starting from 1, skipping used
            for item in remaining:
                src = item['src']
                src_basename = os.path.basename(src)
                try:
                    src_basename_str = os.fsdecode(src_basename)
                except Exception:
                    try:
                        src_basename_str = src_basename.decode('utf-8', errors='ignore')
                    except Exception:
                        src_basename_str = 'img'
                ext = os.path.splitext(src_basename_str)[1] or ''

                idx = next_idx
                # avoid building list comprehension inside loop repeatedly
                planned_names = set(p['new_name'] for p in planned)
                while True:
                    candidate = f"{fabric_code}_{idx:02d}{ext}"
                    if candidate not in used and candidate not in planned_names:
                        break
                    idx += 1
                planned.append({'raw_b64': item['raw_b64'], 'src': src, 'new_name': candidate})
                used.add(candidate)
                next_idx = idx + 1

            # two-phase rename: first -> temp names, then temp -> final
            import time
            temp_paths = []
            ts = int(time.time() * 1000)
            for j, p in enumerate(planned):
                src = p['src']
                tmp_name = f".tmp_attach_{ts}_{j}"
                tmp_bytes = os.fsencode(tmp_name)
                tmp_path = os.path.join(folder, tmp_bytes)
                try:
                    # ensure tmp_path does not exist
                    if os.path.exists(tmp_path):
                        os.unlink(tmp_path)
                    os.rename(src, tmp_path)
                    temp_paths.append({'tmp': tmp_path, 'new_name': p['new_name'], 'raw_b64': p['raw_b64']})
                except Exception:
                    # failed to move -> skip this item
                    continue

            # now rename temps to final names, backing up any existing dst first
            for idx_tp, tp in enumerate(temp_paths):
                try:
                    dst = os.path.join(folder, os.fsencode(tp['new_name']))
                    backup = None
                    if os.path.exists(dst):
                        # move existing dst to backup tmp to avoid overwrite
                        bak_name = f".bak_attach_{ts}_{idx_tp}"
                        bak_bytes = os.fsencode(bak_name)
                        backup = os.path.join(folder, bak_bytes)
                        try:
                            if os.path.exists(backup):
                                try:
                                    os.unlink(backup)
                                except Exception:
                                    pass
                            os.rename(dst, backup)
                        except Exception:
                            backup = None
                    os.rename(tp['tmp'], dst)
                    # remove backup if present
                    if backup and os.path.exists(backup):
                        try:
                            os.unlink(backup)
                        except Exception:
                            pass
                    results.append({'old_b64': tp['raw_b64'], 'new_name': tp['new_name']})
                except Exception:
                    # try to move back from tmp to original name (best effort)
                    try:
                        orig_bytes = base64.b64decode(tp['raw_b64'])
                        try:
                            orig_path = os.path.join(folder, orig_bytes)
                        except Exception:
                            try:
                                orig_path = os.path.join(folder, os.fsencode(os.fsdecode(orig_bytes)))
                            except Exception:
                                orig_path = None
                        if orig_path and os.path.exists(tp['tmp']):
                            os.rename(tp['tmp'], orig_path)
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
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                    SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.material_id,
                                            m.name AS material_name, m.name_en AS material_name_en,
                                            GROUP_CONCAT(fi.image_name ORDER BY fi.is_primary DESC, fi.sort_order ASC, fi.id ASC SEPARATOR '||') AS image_names,
                                            SUBSTRING_INDEX(
                                                GROUP_CONCAT(fi.image_name ORDER BY fi.is_primary DESC, fi.sort_order ASC, fi.id ASC SEPARATOR '||'),
                                                '||',
                                                1
                                            ) AS image_name,
                                            GROUP_CONCAT(DISTINCT pf.id ORDER BY pf.id SEPARATOR ',') AS sku_family_ids,
                                            GROUP_CONCAT(DISTINCT pf.sku_family ORDER BY pf.sku_family SEPARATOR ' / ') AS sku_family_names,
                                            fm.created_at
                                    FROM fabric_materials fm
                                    LEFT JOIN materials m ON fm.material_id = m.id
                                    LEFT JOIN fabric_images fi ON fi.fabric_id = fm.id
                                    LEFT JOIN fabric_product_families fpf ON fpf.fabric_id = fm.id
                                    LEFT JOIN product_families pf ON pf.id = fpf.sku_family_id
                                    WHERE fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s OR m.name LIKE %s OR m.name_en LIKE %s
                                    GROUP BY fm.id, fm.fabric_code, fm.fabric_name_en, fm.material_id, m.name, m.name_en, fm.created_at
                                    ORDER BY fm.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                    SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.material_id,
                                            m.name AS material_name, m.name_en AS material_name_en,
                                            GROUP_CONCAT(fi.image_name ORDER BY fi.is_primary DESC, fi.sort_order ASC, fi.id ASC SEPARATOR '||') AS image_names,
                                            SUBSTRING_INDEX(
                                                GROUP_CONCAT(fi.image_name ORDER BY fi.is_primary DESC, fi.sort_order ASC, fi.id ASC SEPARATOR '||'),
                                                '||',
                                                1
                                            ) AS image_name,
                                            GROUP_CONCAT(DISTINCT pf.id ORDER BY pf.id SEPARATOR ',') AS sku_family_ids,
                                            GROUP_CONCAT(DISTINCT pf.sku_family ORDER BY pf.sku_family SEPARATOR ' / ') AS sku_family_names,
                                            fm.created_at
                                    FROM fabric_materials fm
                                    LEFT JOIN materials m ON fm.material_id = m.id
                                    LEFT JOIN fabric_images fi ON fi.fabric_id = fm.id
                                    LEFT JOIN fabric_product_families fpf ON fpf.fabric_id = fm.id
                                    LEFT JOIN product_families pf ON pf.id = fpf.sku_family_id
                                    GROUP BY fm.id, fm.fabric_code, fm.fabric_name_en, fm.material_id, m.name, m.name_en, fm.created_at
                                    ORDER BY fm.id DESC
                                """
                            )
                        rows = cur.fetchall()
                        
                        # 获取每个面料的图片详细信息（包含 remark）
                        fabric_ids = [row['id'] for row in rows]
                        images_map = {}
                        cleaned_missing = 0
                        if fabric_ids:
                            placeholders = ','.join(['%s'] * len(fabric_ids))
                            cur.execute(
                                f"""
                                SELECT id, fabric_id, image_name, sort_order, is_primary, remark
                                FROM fabric_images
                                WHERE fabric_id IN ({placeholders})
                                ORDER BY fabric_id, is_primary DESC, sort_order ASC, id ASC
                                """,
                                fabric_ids
                            )
                            image_rows = cur.fetchall()
                            fabric_folder = self._ensure_fabric_folder()
                            missing_image_ids = []
                            for img in image_rows:
                                image_name = (img.get('image_name') or '').strip()
                                image_path = os.path.join(fabric_folder, self._safe_fsencode(image_name))
                                if not image_name or not os.path.exists(image_path):
                                    missing_image_ids.append(img['id'])
                                    continue

                                fid = img['fabric_id']
                                if fid not in images_map:
                                    images_map[fid] = []
                                images_map[fid].append({
                                    'id': img['id'],
                                    'image_name': image_name,
                                    'sort_order': img['sort_order'],
                                    'is_primary': img['is_primary'],
                                    'remark': self._normalize_fabric_remark(img.get('remark'))
                                })

                            if missing_image_ids:
                                del_placeholders = ','.join(['%s'] * len(missing_image_ids))
                                cur.execute(
                                    f"DELETE FROM fabric_images WHERE id IN ({del_placeholders})",
                                    missing_image_ids
                                )
                                cleaned_missing = len(missing_image_ids)
                        
                for row in rows:
                    # 用详细图片信息替换简单的 image_names 列表
                    row['images'] = images_map.get(row['id'], [])
                    # 保留向后兼容的 image_names
                    names = row.get('image_names')
                    if names:
                        row['image_names'] = [name for name in names.split('||') if name]
                    else:
                        row['image_names'] = []
                    sku_ids = row.get('sku_family_ids')
                    if sku_ids:
                        row['sku_family_ids'] = [v for v in sku_ids.split(',') if v]
                    else:
                        row['sku_family_ids'] = []
                response = {'status': 'success', 'items': rows}
                if cleaned_missing:
                    response['warning'] = f'已清理 {cleaned_missing} 条文件缺失的图片记录'
                    response['cleaned_missing_images'] = cleaned_missing
                return self.send_json(response, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                material_id = self._parse_int(data.get('material_id'))
                
                # 支持新旧格式
                images_payload = data.get('images') or data.get('image_names') or data.get('image_name')
                images = self._parse_fabric_images_payload(images_payload)
                
                sku_family_ids = [self._parse_int(v) for v in (data.get('sku_family_ids') or [])]
                sku_family_ids = [v for v in sku_family_ids if v]
                
                if not fabric_code or not fabric_name_en or not material_id or not images:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                plan = self._build_fabric_image_plan(images, fabric_code)
                if plan['not_ready']:
                    not_ready_preview = '、'.join(plan['not_ready'][:3])
                    suffix = '...' if len(plan['not_ready']) > 3 else ''
                    return self.send_json({
                        'status': 'error',
                        'message': f"检测到图片仍在上传或文件不完整，请稍后重试：{not_ready_preview}{suffix}"
                    }, start_response)
                if plan['missing']:
                    missing_preview = '、'.join(plan['missing'][:3])
                    suffix = '...' if len(plan['missing']) > 3 else ''
                    return self.send_json({
                        'status': 'error',
                        'message': f"图片文件不存在，已取消保存：{missing_preview}{suffix}"
                    }, start_response)

                rename_result = self._execute_fabric_rename_pairs(plan['rename_pairs'])
                if rename_result.get('status') != 'success':
                    return self.send_json(rename_result, start_response)

                rollback_pairs = rename_result.get('rollback_pairs') or []

                try:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO fabric_materials (fabric_code, fabric_name_en, material_id)
                                VALUES (%s, %s, %s)
                                """,
                                (fabric_code, fabric_name_en, material_id)
                            )
                            new_id = cur.lastrowid

                            for img in plan['planned_images']:
                                cur.execute(
                                    """
                                    INSERT INTO fabric_images (fabric_id, image_name, sort_order, is_primary, remark)
                                    VALUES (%s, %s, %s, %s, %s)
                                    """,
                                    (new_id, img['image_name'], img['sort_order'], int(img['is_primary']), img['remark'])
                                )
                        self._replace_fabric_sku_family_ids(conn, new_id, sku_family_ids)
                except Exception:
                    rollback_result = self._execute_fabric_rename_pairs(rollback_pairs)
                    if rollback_result.get('status') != 'success':
                        print('Fabric POST rollback failed:', rollback_result.get('message'))
                    raise

                image_names = [img['image_name'] for img in plan['planned_images']]
                return self.send_json({'status': 'success', 'id': new_id, 'image_names': image_names}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                material_id = self._parse_int(data.get('material_id'))
                
                # 支持新旧格式
                images_payload = data.get('images') or data.get('image_names') or data.get('image_name')
                images = self._parse_fabric_images_payload(images_payload)
                
                sku_family_ids = [self._parse_int(v) for v in (data.get('sku_family_ids') or [])]
                sku_family_ids = [v for v in sku_family_ids if v]
                
                if not item_id or not fabric_code or not fabric_name_en or not material_id or not images:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                plan = self._build_fabric_image_plan(images, fabric_code)
                if plan['not_ready']:
                    not_ready_preview = '、'.join(plan['not_ready'][:3])
                    suffix = '...' if len(plan['not_ready']) > 3 else ''
                    return self.send_json({
                        'status': 'error',
                        'message': f"检测到图片仍在上传或文件不完整，请稍后重试：{not_ready_preview}{suffix}"
                    }, start_response)
                if plan['missing']:
                    missing_preview = '、'.join(plan['missing'][:3])
                    suffix = '...' if len(plan['missing']) > 3 else ''
                    return self.send_json({
                        'status': 'error',
                        'message': f"图片文件不存在，已取消保存：{missing_preview}{suffix}"
                    }, start_response)

                rename_result = self._execute_fabric_rename_pairs(plan['rename_pairs'])
                if rename_result.get('status') != 'success':
                    return self.send_json(rename_result, start_response)

                rollback_pairs = rename_result.get('rollback_pairs') or []

                try:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE fabric_materials
                                SET fabric_code=%s, fabric_name_en=%s, material_id=%s
                                WHERE id=%s
                                """,
                                (fabric_code, fabric_name_en, material_id, item_id)
                            )
                            cur.execute("DELETE FROM fabric_images WHERE fabric_id=%s", (item_id,))

                            for img in plan['planned_images']:
                                cur.execute(
                                    """
                                    INSERT INTO fabric_images (fabric_id, image_name, sort_order, is_primary, remark)
                                    VALUES (%s, %s, %s, %s, %s)
                                    """,
                                    (item_id, img['image_name'], img['sort_order'], int(img['is_primary']), img['remark'])
                                )
                        self._replace_fabric_sku_family_ids(conn, item_id, sku_family_ids)
                except Exception:
                    rollback_result = self._execute_fabric_rename_pairs(rollback_pairs)
                    if rollback_result.get('status') != 'success':
                        print('Fabric PUT rollback failed:', rollback_result.get('message'))
                    raise

                image_names = [img['image_name'] for img in plan['planned_images']]
                return self.send_json({'status': 'success', 'image_names': image_names}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM fabric_materials WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '面料编号已存在'}, start_response)
            print("Fabric API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_employee_api(self, environ, method, start_response):
        """员工信息 API（CRUD，仅管理权限可修改他人）"""
        try:
            self._ensure_todo_tables()
            user_id = self._get_session_user(environ)
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            # 检查当前用户是否为管理员
            user_is_admin = False
            if user_id:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT is_admin FROM users WHERE id=%s", (user_id,))
                        row = cur.fetchone()
                        user_is_admin = row and row.get('is_admin', 0) == 1

            if method == 'GET':
                # 任何人都能获取员工列表（用于待办分配）
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, username, name, phone, birthday, is_admin, can_manage_todos, created_at
                                FROM users
                                WHERE name LIKE %s OR username LIKE %s OR phone LIKE %s
                                ORDER BY id ASC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, username, name, phone, birthday, is_admin, can_manage_todos, created_at
                                FROM users
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                # 仅管理员可新增账号
                if not user_is_admin:
                    return self.send_json({'status': 'error', 'message': '仅管理员可新增账号'}, start_response)

                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                can_manage = self._parse_int(data.get('can_manage_todos')) or 0
                is_admin = self._parse_int(data.get('is_admin')) or 0
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '缺少必要字段'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
                        cur.execute(
                            """
                            INSERT INTO users (username, password_hash, name, phone, birthday, is_admin, can_manage_todos)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (username, pwd_hash, name or None, phone or None, birthday, is_admin, can_manage)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                # 管理员可修改任何人；其他人仅可修改自己
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少员工ID'}, start_response)

                if not user_is_admin and item_id != user_id:
                    return self.send_json({'status': 'error', 'message': '无权修改其他员工信息'}, start_response)

                # 只有管理员可编辑姓名与生日
                if not user_is_admin and ('name' in data or 'birthday' in data):
                    return self.send_json({'status': 'error', 'message': '仅管理员可修改姓名或生日'}, start_response)

                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                can_manage = self._parse_int(data.get('can_manage_todos'))
                is_admin = self._parse_int(data.get('is_admin'))

                updates = []
                params = []

                if 'name' in data:
                    updates.append('name=%s')
                    params.append(name or None)
                if 'phone' in data:
                    updates.append('phone=%s')
                    params.append(phone or None)
                if 'birthday' in data:
                    updates.append('birthday=%s')
                    params.append(birthday)
                
                # 仅管理员可修改权限字段
                if user_is_admin and can_manage is not None:
                    updates.append('can_manage_todos=%s')
                    params.append(can_manage)
                if user_is_admin and is_admin is not None:
                    updates.append('is_admin=%s')
                    params.append(is_admin)

                if not updates:
                    return self.send_json({'status': 'error', 'message': '无可更新字段'}, start_response)

                params.append(item_id)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"UPDATE users SET {', '.join(updates)} WHERE id=%s",
                            tuple(params)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                # 仅管理员可删除员工
                if not user_is_admin:
                    return self.send_json({'status': 'error', 'message': '仅管理员可删除员工'}, start_response)

                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少员工ID'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM users WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print('Employee API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            print('Employee API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_todo_api(self, environ, method, start_response):
        """待办事项 API（CRUD，每人独立待办）"""
        try:
            self._ensure_todo_tables()
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                # 获取当前用户的所有待办（包括分配给他的）
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT DISTINCT t.id, t.title, t.detail, t.start_date, t.due_date, 
                                t.reminder_interval_days, t.last_check_time, t.next_check_time,
                                t.is_recurring, t.status, t.priority, t.created_by, 
                                COALESCE(NULLIF(u.name, ''), u.username) AS created_by_name, t.created_at
                            FROM todos t
                            LEFT JOIN todo_assignments ta ON t.id = ta.todo_id
                            JOIN users u ON t.created_by = u.id
                            WHERE t.created_by = %s OR ta.assignee_id = %s
                            ORDER BY t.due_date ASC, t.priority DESC, t.id ASC
                            LIMIT 500
                            """,
                            (user_id, user_id)
                        )
                        rows = cur.fetchall()
                        todos = []
                        for row in rows:
                            todo_dict = dict(row)
                            # 获取分配给这个待办的所有人
                            cur.execute(
                                """
                                    SELECT ta.assignee_id, ta.assignment_status,
                                        COALESCE(NULLIF(u.name, ''), u.username) AS name
                                    FROM todo_assignments ta
                                    JOIN users u ON ta.assignee_id = u.id
                                    WHERE ta.todo_id = %s
                                """,
                                (row['id'],)
                            )
                            assignees = cur.fetchall()
                            todo_dict['assignees'] = assignees
                            todos.append(todo_dict)
                return self.send_json({'status': 'success', 'items': todos}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                title = (data.get('title') or '').strip()
                detail = (data.get('detail') or '').strip()
                start_date = self._parse_date_str(data.get('start_date'))
                due_date = self._parse_date_str(data.get('due_date'))
                reminder_interval = self._parse_int(data.get('reminder_interval_days')) or 1
                is_recurring = self._parse_int(data.get('is_recurring')) or 0
                priority = self._parse_int(data.get('priority')) or 2
                status = (data.get('status') or 'open').strip().lower()
                assignee_ids = data.get('assignee_ids') or []
                
                if status not in ('open', 'done', 'hold'):
                    status = 'open'
                if priority not in (1, 2, 3):
                    priority = 2
                if not title or not start_date or not due_date:
                    return self.send_json({'status': 'error', 'message': '缺少必要字段'}, start_response)

                now = datetime.now()
                next_check = datetime.strptime(start_date, '%Y-%m-%d') + timedelta(days=reminder_interval)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO todos 
                            (title, detail, start_date, due_date, reminder_interval_days, 
                             last_check_time, next_check_time, is_recurring, status, priority, created_by)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (title, detail, start_date, due_date, reminder_interval, 
                             now, next_check, is_recurring, status, priority, user_id)
                        )
                        todo_id = cur.lastrowid

                        # 添加分配记录（如果有指定待办人）
                        if assignee_ids:
                            for eid in assignee_ids:
                                eid = self._parse_int(eid)
                                if eid:
                                    try:
                                        cur.execute(
                                            """
                                            INSERT INTO todo_assignments 
                                            (todo_id, assignee_id, assignment_status)
                                            VALUES (%s, %s, %s)
                                            """,
                                            (todo_id, eid, 'pending')
                                        )
                                    except Exception:
                                        pass

                return self.send_json({'status': 'success', 'id': todo_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少待办ID'}, start_response)

                # 检查权限：只有创建人或分配对象可编辑
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT created_by FROM todos WHERE id=%s
                            """,
                            (item_id,)
                        )
                        row = cur.fetchone()
                        if not row or (row['created_by'] != user_id):
                            # 检查是否是分配对象且权限允许编辑
                            cur.execute(
                                """
                                SELECT assignment_status FROM todo_assignments 
                                WHERE todo_id=%s AND assignee_id=%s
                                """,
                                (item_id, user_id)
                            )
                            if not cur.fetchone():
                                return self.send_json({'status': 'error', 'message': '权限不足'}, start_response)

                updates = []
                params = []
                if 'title' in data:
                    updates.append('title=%s')
                    params.append((data.get('title') or '').strip())
                if 'detail' in data:
                    updates.append('detail=%s')
                    params.append((data.get('detail') or '').strip())
                if 'status' in data:
                    status = (data.get('status') or '').strip().lower()
                    if status in ('open', 'done', 'hold'):
                        updates.append('status=%s')
                        params.append(status)
                if 'priority' in data:
                    priority = self._parse_int(data.get('priority'))
                    if priority in (1, 2, 3):
                        updates.append('priority=%s')
                        params.append(priority)

                if not updates:
                    return self.send_json({'status': 'error', 'message': '无可更新字段'}, start_response)

                params.append(item_id)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"UPDATE todos SET {', '.join(updates)} WHERE id=%s",
                            tuple(params)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少待办ID'}, start_response)

                # 只有创建人可删除
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT created_by FROM todos WHERE id=%s",
                            (item_id,)
                        )
                        row = cur.fetchone()
                        if not row or row['created_by'] != user_id:
                            return self.send_json({'status': 'error', 'message': '只有创建人可删除'}, start_response)

                        cur.execute("DELETE FROM todos WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print('Todo API error: ' + str(e))
            import traceback
            traceback.print_exc()
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_calendar_api(self, environ, method, start_response):
        """日历数据 API（按月汇总待办与生日）"""
        try:
            if method != 'GET':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            self._ensure_todo_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            now = datetime.now()
            year = self._parse_int(query_params.get('year', [now.year])[0]) or now.year
            month = self._parse_int(query_params.get('month', [now.month])[0]) or now.month
            if month < 1 or month > 12:
                return self.send_json({'status': 'error', 'message': 'Invalid month'}, start_response)

            days_in_month = calendar.monthrange(year, month)[1]
            start_date = f"{year:04d}-{month:02d}-01"
            end_date = f"{year:04d}-{month:02d}-{days_in_month:02d}"

            days = {}

            def ensure_day(key):
                if key not in days:
                    days[key] = {'todos': [], 'birthdays': []}

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, title, detail, due_date, status, priority
                        FROM todos
                        WHERE due_date BETWEEN %s AND %s
                        ORDER BY due_date ASC, priority DESC, id ASC
                        """,
                        (start_date, end_date)
                    )
                    todo_rows = cur.fetchall()

                    cur.execute(
                        """
                        SELECT id, COALESCE(NULLIF(name, ''), username) AS name, phone, birthday
                        FROM users
                        WHERE birthday IS NOT NULL AND MONTH(birthday)=%s
                        ORDER BY DAY(birthday) ASC, id ASC
                        """,
                        (month,)
                    )
                    employee_rows = cur.fetchall()

            for row in todo_rows:
                due = row.get('due_date')
                if hasattr(due, 'strftime'):
                    key = due.strftime('%Y-%m-%d')
                else:
                    key = str(due)
                ensure_day(key)
                days[key]['todos'].append(row)

            for row in employee_rows:
                bday = row.get('birthday')
                if hasattr(bday, 'strftime'):
                    day_num = int(bday.strftime('%d'))
                    month_num = int(bday.strftime('%m'))
                else:
                    try:
                        parts = str(bday).split('-')
                        month_num = int(parts[1])
                        day_num = int(parts[2])
                    except Exception:
                        continue
                if month_num != month:
                    continue
                key = f"{year:04d}-{month:02d}-{day_num:02d}"
                ensure_day(key)
                days[key]['birthdays'].append(row)

            return self.send_json({
                'status': 'success',
                'year': year,
                'month': month,
                'days': days
            }, start_response)
        except Exception as e:
            print('Calendar API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_feature_api(self, environ, method, start_response):
        """卖点管理 API（CRUD）"""
        try:
            self._ensure_features_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                    SELECT f.id, f.name, f.name_en, f.created_at,
                                        GROUP_CONCAT(DISTINCT c.category_cn ORDER BY c.category_cn SEPARATOR ' / ') AS category_cn,
                                        GROUP_CONCAT(DISTINCT c.category_en ORDER BY c.category_en SEPARATOR ' / ') AS category_en,
                                        GROUP_CONCAT(DISTINCT c.id ORDER BY c.id SEPARATOR ',') AS category_ids
                                FROM features f
                                    LEFT JOIN feature_categories fc ON fc.feature_id = f.id
                                    LEFT JOIN product_categories c ON fc.category_id = c.id
                                    WHERE f.name LIKE %s OR f.name_en LIKE %s OR c.category_cn LIKE %s OR c.category_en LIKE %s
                                    GROUP BY f.id
                                    ORDER BY f.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                    SELECT f.id, f.name, f.name_en, f.created_at,
                                        GROUP_CONCAT(DISTINCT c.category_cn ORDER BY c.category_cn SEPARATOR ' / ') AS category_cn,
                                        GROUP_CONCAT(DISTINCT c.category_en ORDER BY c.category_en SEPARATOR ' / ') AS category_en,
                                        GROUP_CONCAT(DISTINCT c.id ORDER BY c.id SEPARATOR ',') AS category_ids
                                FROM features f
                                    LEFT JOIN feature_categories fc ON fc.feature_id = f.id
                                    LEFT JOIN product_categories c ON fc.category_id = c.id
                                    GROUP BY f.id
                                    ORDER BY f.id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                raw_category_ids = data.get('category_ids')
                category_ids = [self._parse_int(cid) for cid in (raw_category_ids or [])]
                category_ids = [cid for cid in category_ids if cid]
                if not name or not name_en or not category_ids:
                    return self.send_json({'status': 'error', 'message': 'Missing name, name_en or category_ids'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO features (name, name_en) VALUES (%s, %s)",
                            (name, name_en)
                        )
                        new_id = cur.lastrowid
                    self._replace_feature_categories(conn, new_id, category_ids)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                raw_category_ids = data.get('category_ids')
                category_ids = [self._parse_int(cid) for cid in (raw_category_ids or [])]
                category_ids = [cid for cid in category_ids if cid]
                if not item_id or not name or not name_en or not category_ids:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE features
                            SET name=%s, name_en=%s
                            WHERE id=%s
                            """,
                            (name, name_en, item_id)
                        )
                    self._replace_feature_categories(conn, item_id, category_ids)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM features WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '卖点已存在'}, start_response)
            print("Feature API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_material_type_api(self, environ, method, start_response):
        """材料类型管理 API（CRUD）"""
        try:
            self._ensure_material_types_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM material_types
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM material_types
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO material_types (name) VALUES (%s)",
                            (name,)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM material_types WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute(
                            """
                            UPDATE material_types
                            SET name=%s
                            WHERE id=%s
                            """,
                            (name, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM material_types WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("DELETE FROM material_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '材料类型已存在或被使用'}, start_response)
            print("MaterialType API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_platform_type_api(self, environ, method, start_response):
        """平台类型管理 API（CRUD）"""
        try:
            self._ensure_platform_types_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM platform_types
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM platform_types
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO platform_types (name) VALUES (%s)",
                            (name,)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM platform_types WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute(
                            """
                            UPDATE platform_types
                            SET name=%s
                            WHERE id=%s
                            """,
                            (name, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM platform_types WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("DELETE FROM platform_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '平台类型已存在或被使用'}, start_response)
            print("PlatformType API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_brand_api(self, environ, method, start_response):
        """品牌管理 API（CRUD）"""
        try:
            self._ensure_brands_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM brands
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM brands
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO brands (name) VALUES (%s)",
                            (name,)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM brands WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute(
                            """
                            UPDATE brands
                            SET name=%s
                            WHERE id=%s
                            """,
                            (name, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM brands WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("DELETE FROM brands WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '品牌已存在或被使用'}, start_response)
            print("Brand API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_shop_api(self, environ, method, start_response):
        """店铺管理 API（CRUD）"""
        try:
            self._ensure_shops_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                platform_type_id = self._parse_int(query_params.get('platform_type_id', [''])[0].strip())
                brand_id = self._parse_int(query_params.get('brand_id', [''])[0].strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        base_sql = """
                            SELECT s.id, s.shop_name, s.platform_type_id, s.brand_id,
                                   pt.name AS platform_type_name,
                                   b.name AS brand_name,
                                   s.created_at
                            FROM shops s
                            LEFT JOIN platform_types pt ON s.platform_type_id = pt.id
                            LEFT JOIN brands b ON s.brand_id = b.id
                        """
                        filters = []
                        params = []
                        if platform_type_id:
                            filters.append("s.platform_type_id=%s")
                            params.append(platform_type_id)
                        if brand_id:
                            filters.append("s.brand_id=%s")
                            params.append(brand_id)
                        if keyword:
                            filters.append("(s.shop_name LIKE %s OR pt.name LIKE %s OR b.name LIKE %s)")
                            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                        cur.execute(base_sql + where_sql + " ORDER BY s.id DESC", params)
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                shop_name = (data.get('shop_name') or '').strip()
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                brand_id = self._parse_int(data.get('brand_id'))
                if not shop_name or not platform_type_id or not brand_id:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO shops (shop_name, platform_type_id, brand_id)
                            VALUES (%s, %s, %s)
                            """,
                            (shop_name, platform_type_id, brand_id)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                shop_name = (data.get('shop_name') or '').strip()
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                brand_id = self._parse_int(data.get('brand_id'))
                if not item_id or not shop_name or not platform_type_id or not brand_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE shops
                            SET shop_name=%s, platform_type_id=%s, brand_id=%s
                            WHERE id=%s
                            """,
                            (shop_name, platform_type_id, brand_id, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM shops WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '店铺已存在'}, start_response)
            print("Shop API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_subtype_api(self, environ, method, start_response):
        """Amazon 广告细分类管理 API（CRUD）"""
        try:
            self._ensure_amazon_ad_subtypes_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT s.id, s.description, s.ad_class, s.subtype_code, s.created_at, s.updated_at,
                                       GROUP_CONCAT(t.id ORDER BY t.id) AS operation_type_ids,
                                       GROUP_CONCAT(t.name ORDER BY t.id SEPARATOR ' / ') AS operation_type_names
                                    FROM amazon_ad_subtypes s
                                LEFT JOIN amazon_ad_subtype_operation_types so ON so.subtype_id = s.id
                                LEFT JOIN amazon_ad_operation_types t ON t.id = so.operation_type_id
                                WHERE s.description LIKE %s OR s.ad_class LIKE %s OR s.subtype_code LIKE %s
                                GROUP BY s.id, s.description, s.ad_class, s.subtype_code, s.created_at, s.updated_at
                                ORDER BY s.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT s.id, s.description, s.ad_class, s.subtype_code, s.created_at, s.updated_at,
                                       GROUP_CONCAT(t.id ORDER BY t.id) AS operation_type_ids,
                                       GROUP_CONCAT(t.name ORDER BY t.id SEPARATOR ' / ') AS operation_type_names
                                FROM amazon_ad_subtypes s
                                LEFT JOIN amazon_ad_subtype_operation_types so ON so.subtype_id = s.id
                                LEFT JOIN amazon_ad_operation_types t ON t.id = so.operation_type_id
                                GROUP BY s.id, s.description, s.ad_class, s.subtype_code, s.created_at, s.updated_at
                                ORDER BY s.id DESC
                                """
                            )
                        rows = cur.fetchall()
                for row in rows:
                    raw_ids = row.get('operation_type_ids') or ''
                    row['operation_type_ids'] = [int(v) for v in raw_ids.split(',') if str(v).strip()] if raw_ids else []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                description = (data.get('description') or '').strip()
                ad_class = (data.get('ad_class') or 'SP').strip().upper()
                subtype_code = (data.get('subtype_code') or '').strip()
                operation_type_ids = [self._parse_int(v) for v in (data.get('operation_type_ids') or [])]
                operation_type_ids = [v for v in operation_type_ids if v]
                if ad_class not in ('SP', 'SB', 'SD'):
                    ad_class = 'SP'
                if not description or not subtype_code:
                    return self.send_json({'status': 'error', 'message': 'Missing description or subtype_code'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_subtypes (description, ad_class, subtype_code)
                            VALUES (%s, %s, %s)
                            """,
                            (description, ad_class, subtype_code)
                        )
                        new_id = cur.lastrowid
                    self._replace_ad_subtype_operation_type_ids(conn, new_id, operation_type_ids)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                description = (data.get('description') or '').strip()
                ad_class = (data.get('ad_class') or 'SP').strip().upper()
                subtype_code = (data.get('subtype_code') or '').strip()
                operation_type_ids = [self._parse_int(v) for v in (data.get('operation_type_ids') or [])]
                operation_type_ids = [v for v in operation_type_ids if v]
                if ad_class not in ('SP', 'SB', 'SD'):
                    ad_class = 'SP'
                if not item_id or not description or not subtype_code:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE amazon_ad_subtypes
                            SET description=%s, ad_class=%s, subtype_code=%s
                            WHERE id=%s
                            """,
                            (description, ad_class, subtype_code, item_id)
                        )
                    self._replace_ad_subtype_operation_type_ids(conn, item_id, operation_type_ids)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_subtypes WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '细分类已存在或被引用'}, start_response)
            print("Amazon ad subtype API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_operation_type_api(self, environ, method, start_response):
        """Amazon 广告操作类型 API（CRUD）"""
        try:
            self._ensure_amazon_ad_operation_types_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, apply_campaign, apply_group, created_at, updated_at
                                FROM amazon_ad_operation_types
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, apply_campaign, apply_group, created_at, updated_at
                                FROM amazon_ad_operation_types
                                ORDER BY id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                apply_campaign = 1 if self._parse_int(data.get('apply_campaign')) else 0
                apply_group = 1 if self._parse_int(data.get('apply_group')) else 0
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO amazon_ad_operation_types (name, apply_campaign, apply_group) VALUES (%s, %s, %s)",
                            (name, apply_campaign, apply_group)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                apply_campaign = 1 if self._parse_int(data.get('apply_campaign')) else 0
                apply_group = 1 if self._parse_int(data.get('apply_group')) else 0
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE amazon_ad_operation_types SET name=%s, apply_campaign=%s, apply_group=%s WHERE id=%s",
                            (name, apply_campaign, apply_group, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_operation_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '操作类型已存在或被引用'}, start_response)
            print("Amazon ad operation type API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_api(self, environ, method, start_response):
        """Amazon 广告信息 API（组合/活动/组）"""
        try:
            self._ensure_amazon_ad_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                level = (query_params.get('level', [''])[0] or '').strip().lower()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = """
                            SELECT
                                ai.id, ai.ad_level, ai.sku_family_id, ai.portfolio_id, ai.campaign_id,
                                ai.strategy_code, ai.subtype_id, ai.name, ai.is_shared_budget,
                                ai.status, ai.budget, ai.created_at, ai.updated_at,
                                pf.sku_family,
                                p.name AS portfolio_name,
                                c.name AS campaign_name,
                                st.description AS subtype_description,
                                st.ad_class,
                                st.subtype_code
                            FROM amazon_ad_items ai
                            LEFT JOIN product_families pf ON ai.sku_family_id = pf.id
                            LEFT JOIN amazon_ad_items p ON ai.portfolio_id = p.id
                            LEFT JOIN amazon_ad_items c ON ai.campaign_id = c.id
                            LEFT JOIN amazon_ad_subtypes st ON ai.subtype_id = st.id
                        """
                        filters = []
                        params = []
                        if level in ('portfolio', 'campaign', 'group'):
                            filters.append("ai.ad_level=%s")
                            params.append(level)
                        if keyword:
                            filters.append("(ai.name LIKE %s OR pf.sku_family LIKE %s OR st.description LIKE %s)")
                            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                        cur.execute(sql + where_sql + " ORDER BY ai.id DESC", params)
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                ad_level = (data.get('ad_level') or '').strip().lower()
                if ad_level not in ('portfolio', 'campaign', 'group'):
                    return self.send_json({'status': 'error', 'message': 'Invalid ad_level'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if ad_level == 'portfolio':
                            sku_family_id = self._parse_int(data.get('sku_family_id'))
                            is_shared_budget = self._normalize_yes_no(data.get('is_shared_budget'))
                            status = self._normalize_ad_status(data.get('status'))
                            if not sku_family_id or is_shared_budget is None or not status:
                                return self.send_json({'status': 'error', 'message': 'Missing sku_family_id/is_shared_budget/status'}, start_response)
                            portfolio_name = self._build_portfolio_name(conn, sku_family_id)
                            if not portfolio_name:
                                return self.send_json({'status': 'error', 'message': 'Unable to build portfolio name from sku'}, start_response)
                            cur.execute(
                                """
                                INSERT INTO amazon_ad_items
                                (ad_level, sku_family_id, name, is_shared_budget, status)
                                VALUES ('portfolio', %s, %s, %s, %s)
                                """,
                                (sku_family_id, portfolio_name, is_shared_budget, status)
                            )
                            return self.send_json({'status': 'success', 'id': cur.lastrowid}, start_response)

                        if ad_level == 'campaign':
                            portfolio_id = self._parse_int(data.get('portfolio_id'))
                            strategy_code = (data.get('strategy_code') or '').strip().upper()
                            subtype_id = self._parse_int(data.get('subtype_id'))
                            budget = self._parse_float(data.get('budget'))
                            custom_name = (data.get('name') or '').strip()
                            if not portfolio_id or strategy_code not in ('BE', 'BD', 'PC') or not subtype_id:
                                return self.send_json({'status': 'error', 'message': 'Missing portfolio_id/strategy_code/subtype_id'}, start_response)
                            row = self._get_ad_item_by_id(conn, portfolio_id)
                            if not row or row.get('ad_level') != 'portfolio':
                                return self.send_json({'status': 'error', 'message': 'Invalid portfolio_id'}, start_response)
                            auto_name = self._build_campaign_name(conn, strategy_code, portfolio_id, subtype_id)
                            campaign_name = custom_name or auto_name
                            if not campaign_name:
                                return self.send_json({'status': 'error', 'message': 'Unable to build campaign name'}, start_response)
                            cur.execute(
                                """
                                INSERT INTO amazon_ad_items
                                (ad_level, portfolio_id, strategy_code, subtype_id, name, budget)
                                VALUES ('campaign', %s, %s, %s, %s, %s)
                                """,
                                (portfolio_id, strategy_code, subtype_id, campaign_name, budget)
                            )
                            return self.send_json({'status': 'success', 'id': cur.lastrowid}, start_response)

                        campaign_id = self._parse_int(data.get('campaign_id'))
                        status = self._normalize_ad_status(data.get('status'))
                        group_name = (data.get('name') or '').strip()
                        if not campaign_id or not group_name:
                            return self.send_json({'status': 'error', 'message': 'Missing campaign_id or name'}, start_response)
                        row = self._get_ad_item_by_id(conn, campaign_id)
                        if not row or row.get('ad_level') != 'campaign':
                            return self.send_json({'status': 'error', 'message': 'Invalid campaign_id'}, start_response)
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_items
                            (ad_level, campaign_id, portfolio_id, name, status)
                            VALUES ('group', %s, %s, %s, %s)
                            """,
                            (campaign_id, row.get('portfolio_id'), group_name, status)
                        )
                        return self.send_json({'status': 'success', 'id': cur.lastrowid}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    current = self._get_ad_item_by_id(conn, item_id)
                    if not current:
                        return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                    ad_level = current.get('ad_level')
                    with conn.cursor() as cur:
                        if ad_level == 'portfolio':
                            sku_family_id = self._parse_int(data.get('sku_family_id'))
                            is_shared_budget = self._normalize_yes_no(data.get('is_shared_budget'))
                            status = self._normalize_ad_status(data.get('status'))
                            if not sku_family_id or is_shared_budget is None or not status:
                                return self.send_json({'status': 'error', 'message': 'Missing sku_family_id/is_shared_budget/status'}, start_response)
                            portfolio_name = self._build_portfolio_name(conn, sku_family_id)
                            if not portfolio_name:
                                return self.send_json({'status': 'error', 'message': 'Unable to build portfolio name from sku'}, start_response)
                            cur.execute(
                                """
                                UPDATE amazon_ad_items
                                SET sku_family_id=%s, name=%s, is_shared_budget=%s, status=%s
                                WHERE id=%s
                                """,
                                (sku_family_id, portfolio_name, is_shared_budget, status, item_id)
                            )
                            return self.send_json({'status': 'success'}, start_response)

                        if ad_level == 'campaign':
                            portfolio_id = self._parse_int(data.get('portfolio_id'))
                            strategy_code = (data.get('strategy_code') or '').strip().upper()
                            subtype_id = self._parse_int(data.get('subtype_id'))
                            budget = self._parse_float(data.get('budget'))
                            custom_name = (data.get('name') or '').strip()
                            if not portfolio_id or strategy_code not in ('BE', 'BD', 'PC') or not subtype_id:
                                return self.send_json({'status': 'error', 'message': 'Missing portfolio_id/strategy_code/subtype_id'}, start_response)
                            row = self._get_ad_item_by_id(conn, portfolio_id)
                            if not row or row.get('ad_level') != 'portfolio':
                                return self.send_json({'status': 'error', 'message': 'Invalid portfolio_id'}, start_response)
                            auto_name = self._build_campaign_name(conn, strategy_code, portfolio_id, subtype_id)
                            campaign_name = custom_name or auto_name
                            if not campaign_name:
                                return self.send_json({'status': 'error', 'message': 'Unable to build campaign name'}, start_response)
                            cur.execute(
                                """
                                UPDATE amazon_ad_items
                                SET portfolio_id=%s, strategy_code=%s, subtype_id=%s, name=%s, budget=%s
                                WHERE id=%s
                                """,
                                (portfolio_id, strategy_code, subtype_id, campaign_name, budget, item_id)
                            )
                            return self.send_json({'status': 'success'}, start_response)

                        campaign_id = self._parse_int(data.get('campaign_id'))
                        group_name = (data.get('name') or '').strip()
                        status = self._normalize_ad_status(data.get('status'))
                        if not campaign_id or not group_name:
                            return self.send_json({'status': 'error', 'message': 'Missing campaign_id or name'}, start_response)
                        row = self._get_ad_item_by_id(conn, campaign_id)
                        if not row or row.get('ad_level') != 'campaign':
                            return self.send_json({'status': 'error', 'message': 'Invalid campaign_id'}, start_response)
                        cur.execute(
                            """
                            UPDATE amazon_ad_items
                            SET campaign_id=%s, portfolio_id=%s, name=%s, status=%s
                            WHERE id=%s
                            """,
                            (campaign_id, row.get('portfolio_id'), group_name, status, item_id)
                        )
                        return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_items WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '广告记录已存在或被引用'}, start_response)
            print("Amazon ad API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_material_api(self, environ, method, start_response):
        """材料管理 API（CRUD）"""
        try:
            self._ensure_materials_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                type_code = query_params.get('type', [''])[0].strip()
                type_name = query_params.get('type_name', [''])[0].strip()
                type_id = self._parse_int(query_params.get('type_id', [''])[0].strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        type_map = {
                            'fabric': '面料',
                            'filling': '填充',
                            'frame': '框架',
                            'electronics': '电子元器件'
                        }
                        has_type_id = self._materials_has_type_id(conn)
                        if has_type_id:
                            base_sql = """
                                SELECT
                                    m.id, m.name, m.name_en, m.material_type_id,
                                    m.parent_id, pm.name AS parent_name,
                                    mt.name AS material_type_name,
                                    m.created_at
                                FROM materials m
                                LEFT JOIN materials pm ON m.parent_id = pm.id
                                LEFT JOIN material_types mt ON m.material_type_id = mt.id
                            """
                            filters = []
                            params = []
                            if type_id:
                                filters.append("m.material_type_id=%s")
                                params.append(type_id)
                            elif type_name or type_code:
                                resolved_name = type_name or type_map.get(type_code, type_code)
                                if resolved_name:
                                    filters.append("mt.name=%s")
                                    params.append(resolved_name)
                            if keyword:
                                filters.append("(m.name LIKE %s OR m.name_en LIKE %s OR mt.name LIKE %s)")
                                params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                            where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                            cur.execute(base_sql + where_sql + " ORDER BY m.id DESC", params)
                            rows = cur.fetchall()
                        else:
                            resolved_name = type_name or type_map.get(type_code, type_code)
                            name_to_code = {v: k for k, v in type_map.items()}
                            legacy_code = name_to_code.get(resolved_name) if resolved_name else None
                            base_sql = """
                                SELECT m.id, m.name, m.name_en, m.material_type, m.parent_id, pm.name AS parent_name, m.created_at
                                FROM materials m
                                LEFT JOIN materials pm ON m.parent_id = pm.id
                            """
                            filters = []
                            params = []
                            if legacy_code:
                                filters.append("material_type=%s")
                                params.append(legacy_code)
                            if keyword:
                                filters.append("(name LIKE %s OR name_en LIKE %s OR material_type LIKE %s)")
                                params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                            where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                            cur.execute(base_sql + where_sql + " ORDER BY id DESC", params)
                            rows = cur.fetchall()
                            cur.execute("SELECT id, name FROM material_types")
                            type_rows = cur.fetchall() or []
                            type_lookup = {row['name']: row for row in type_rows}
                            for row in rows:
                                code = row.get('material_type')
                                name = type_map.get(code, '')
                                mapped = type_lookup.get(name) or {}
                                row['material_type_id'] = mapped.get('id')
                                row['material_type_name'] = name
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                material_type_id = self._parse_int(data.get('material_type_id'))
                material_type_code = (data.get('material_type') or '').strip()
                parent_id = self._parse_int(data.get('parent_id'))
                if not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing name or name_en'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        has_type_id = self._materials_has_type_id(conn)
                        has_parent_id = self._materials_has_parent_id(conn)
                        has_type_id = self._materials_has_type_id(conn)
                        if not material_type_id and material_type_code:
                            material_type_id = self._get_material_type_id(conn, material_type_code)
                        parent_row = None
                        if parent_id:
                            if has_type_id:
                                cur.execute("SELECT id, material_type_id FROM materials WHERE id=%s", (parent_id,))
                            else:
                                cur.execute("SELECT id, material_type FROM materials WHERE id=%s", (parent_id,))
                            parent_row = cur.fetchone()
                            if not parent_row:
                                return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                        if has_type_id:
                            if not material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type_id'}, start_response)
                            if parent_row and parent_row.get('material_type_id') != material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type_id, parent_id) VALUES (%s, %s, %s, %s)",
                                    (name, name_en, material_type_id, parent_id)
                                )
                            else:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type_id) VALUES (%s, %s, %s)",
                                    (name, name_en, material_type_id)
                                )
                        else:
                            if not material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type'}, start_response)
                            if parent_row and parent_row.get('material_type') != material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type, parent_id) VALUES (%s, %s, %s, %s)",
                                    (name, name_en, material_type_code, parent_id)
                                )
                            else:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type) VALUES (%s, %s, %s)",
                                    (name, name_en, material_type_code)
                                )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                material_type_id = self._parse_int(data.get('material_type_id'))
                material_type_code = (data.get('material_type') or '').strip()
                parent_id = self._parse_int(data.get('parent_id'))
                if not item_id or not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                if parent_id and int(parent_id) == int(item_id):
                    return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        has_type_id = self._materials_has_type_id(conn)
                        has_parent_id = self._materials_has_parent_id(conn)
                        has_type_id = self._materials_has_type_id(conn)
                        if not material_type_id and material_type_code:
                            material_type_id = self._get_material_type_id(conn, material_type_code)
                        parent_row = None
                        if parent_id:
                            if has_type_id:
                                cur.execute("SELECT id, material_type_id FROM materials WHERE id=%s", (parent_id,))
                            else:
                                cur.execute("SELECT id, material_type FROM materials WHERE id=%s", (parent_id,))
                            parent_row = cur.fetchone()
                            if not parent_row:
                                return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                        if has_type_id:
                            if not material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type_id'}, start_response)
                            if parent_row and parent_row.get('material_type_id') != material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type_id=%s, parent_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_id, parent_id, item_id)
                                )
                            else:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_id, item_id)
                                )
                        else:
                            if not material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type'}, start_response)
                            if parent_row and parent_row.get('material_type') != material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type=%s, parent_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_code, parent_id, item_id)
                                )
                            else:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_code, item_id)
                                )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM materials WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '材料已存在'}, start_response)
            print("Material API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_certification_api(self, environ, method, start_response):
        """认证管理 API（CRUD）"""
        try:
            self._ensure_certification_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, icon_name, created_at
                                FROM certifications
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, icon_name, created_at
                                FROM certifications
                                ORDER BY id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                icon_name = (data.get('icon_name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO certifications (name, icon_name)
                            VALUES (%s, %s)
                            """,
                            (name, icon_name or None)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                icon_name = (data.get('icon_name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE certifications
                            SET name=%s, icon_name=%s
                            WHERE id=%s
                            """,
                            (name, icon_name or None, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM certifications WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '认证名称已存在'}, start_response)
            print("Certification API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_order_product_api(self, environ, method, start_response):
        """下单产品管理 API（CRUD）"""
        try:
            self._ensure_order_product_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT
                                    op.id, op.sku, op.sku_family_id, op.version_no, op.fabric_id,
                                    op.spec_qty_short, op.listing_image_b64, op.is_iteration, op.source_order_product_id,
                                    op.finished_length_in, op.finished_width_in, op.finished_height_in,
                                    op.net_weight_lbs, op.package_length_in, op.package_width_in,
                                    op.package_height_in, op.gross_weight_lbs, op.cost_usd,
                                    op.carton_qty, op.package_size_class, op.last_mile_avg_freight_usd,
                                    op.created_at,
                                    pf.sku_family, pf.category,
                                    fm.fabric_code, fm.fabric_name_en,
                                    src.sku AS source_sku,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='填充', m.name, NULL) ORDER BY m.name SEPARATOR ' / ') AS filling_materials,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='框架', m.name, NULL) ORDER BY m.name SEPARATOR ' / ') AS frame_materials,
                                    GROUP_CONCAT(DISTINCT f.name ORDER BY f.name SEPARATOR ' / ') AS features,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='填充', m.id, NULL) ORDER BY m.id SEPARATOR ',') AS filling_material_ids,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='框架', m.id, NULL) ORDER BY m.id SEPARATOR ',') AS frame_material_ids,
                                    GROUP_CONCAT(DISTINCT f.id ORDER BY f.id SEPARATOR ',') AS feature_ids,
                                    GROUP_CONCAT(DISTINCT cft.name ORDER BY cft.name SEPARATOR ' / ') AS certifications,
                                    GROUP_CONCAT(DISTINCT cft.id ORDER BY cft.id SEPARATOR ',') AS certification_ids
                                FROM order_products op
                                LEFT JOIN product_families pf ON op.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON op.fabric_id = fm.id
                                LEFT JOIN order_product_materials opm ON opm.order_product_id = op.id
                                LEFT JOIN materials m ON opm.material_id = m.id
                                LEFT JOIN material_types mt ON m.material_type_id = mt.id
                                LEFT JOIN order_product_features opf ON opf.order_product_id = op.id
                                LEFT JOIN features f ON opf.feature_id = f.id
                                LEFT JOIN order_product_certifications opc ON opc.order_product_id = op.id
                                LEFT JOIN certifications cft ON cft.id = opc.certification_id
                                LEFT JOIN order_products src ON src.id = op.source_order_product_id
                                WHERE op.sku LIKE %s
                                   OR op.version_no LIKE %s
                                   OR pf.sku_family LIKE %s
                                   OR fm.fabric_code LIKE %s
                                GROUP BY op.id
                                ORDER BY op.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT
                                    op.id, op.sku, op.sku_family_id, op.version_no, op.fabric_id,
                                    op.spec_qty_short, op.listing_image_b64, op.is_iteration, op.source_order_product_id,
                                    op.finished_length_in, op.finished_width_in, op.finished_height_in,
                                    op.net_weight_lbs, op.package_length_in, op.package_width_in,
                                    op.package_height_in, op.gross_weight_lbs, op.cost_usd,
                                    op.carton_qty, op.package_size_class, op.last_mile_avg_freight_usd,
                                    op.created_at,
                                    pf.sku_family, pf.category,
                                    fm.fabric_code, fm.fabric_name_en,
                                    src.sku AS source_sku,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='填充', m.name, NULL) ORDER BY m.name SEPARATOR ' / ') AS filling_materials,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='框架', m.name, NULL) ORDER BY m.name SEPARATOR ' / ') AS frame_materials,
                                    GROUP_CONCAT(DISTINCT f.name ORDER BY f.name SEPARATOR ' / ') AS features,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='填充', m.id, NULL) ORDER BY m.id SEPARATOR ',') AS filling_material_ids,
                                    GROUP_CONCAT(DISTINCT IF(mt.name='框架', m.id, NULL) ORDER BY m.id SEPARATOR ',') AS frame_material_ids,
                                    GROUP_CONCAT(DISTINCT f.id ORDER BY f.id SEPARATOR ',') AS feature_ids,
                                    GROUP_CONCAT(DISTINCT cft.name ORDER BY cft.name SEPARATOR ' / ') AS certifications,
                                    GROUP_CONCAT(DISTINCT cft.id ORDER BY cft.id SEPARATOR ',') AS certification_ids
                                FROM order_products op
                                LEFT JOIN product_families pf ON op.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON op.fabric_id = fm.id
                                LEFT JOIN order_product_materials opm ON opm.order_product_id = op.id
                                LEFT JOIN materials m ON opm.material_id = m.id
                                LEFT JOIN material_types mt ON m.material_type_id = mt.id
                                LEFT JOIN order_product_features opf ON opf.order_product_id = op.id
                                LEFT JOIN features f ON opf.feature_id = f.id
                                LEFT JOIN order_product_certifications opc ON opc.order_product_id = op.id
                                LEFT JOIN certifications cft ON cft.id = opc.certification_id
                                LEFT JOIN order_products src ON src.id = op.source_order_product_id
                                GROUP BY op.id
                                ORDER BY op.id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku = (data.get('sku') or '').strip()
                sku_family_id = data.get('sku_family_id')
                version_no = (data.get('version_no') or '').strip()
                fabric_id = data.get('fabric_id')
                spec_qty_short = (data.get('spec_qty_short') or '').strip()
                listing_image_b64 = (data.get('listing_image_b64') or '').strip() or None
                is_iteration = 1 if str(data.get('is_iteration') or '').lower() in ('1', 'true', 'yes', 'on') else 0
                source_order_product_id = self._parse_int(data.get('source_order_product_id'))

                if not sku or not sku_family_id or not version_no or not fabric_id or not spec_qty_short:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)
                if is_iteration and not source_order_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing source SKU'}, start_response)

                payload = {
                    'sku': sku,
                    'sku_family_id': self._parse_int(sku_family_id),
                    'version_no': version_no,
                    'fabric_id': self._parse_int(fabric_id),
                    'spec_qty_short': spec_qty_short,
                    'listing_image_b64': listing_image_b64,
                    'is_iteration': is_iteration,
                    'source_order_product_id': source_order_product_id,
                    'finished_length_in': self._parse_float(data.get('finished_length_in')),
                    'finished_width_in': self._parse_float(data.get('finished_width_in')),
                    'finished_height_in': self._parse_float(data.get('finished_height_in')),
                    'net_weight_lbs': self._parse_float(data.get('net_weight_lbs')),
                    'package_length_in': self._parse_float(data.get('package_length_in')),
                    'package_width_in': self._parse_float(data.get('package_width_in')),
                    'package_height_in': self._parse_float(data.get('package_height_in')),
                    'gross_weight_lbs': self._parse_float(data.get('gross_weight_lbs')),
                    'cost_usd': self._parse_float(data.get('cost_usd')),
                    'carton_qty': self._parse_int(data.get('carton_qty')),
                    'package_size_class': (data.get('package_size_class') or '').strip() or None,
                    'last_mile_avg_freight_usd': self._parse_float(data.get('last_mile_avg_freight_usd'))
                }

                filling_material_ids = [self._parse_int(v) for v in (data.get('filling_material_ids') or [])]
                frame_material_ids = [self._parse_int(v) for v in (data.get('frame_material_ids') or [])]
                feature_ids = [self._parse_int(v) for v in (data.get('feature_ids') or [])]
                certification_ids = [self._parse_int(v) for v in (data.get('certification_ids') or [])]
                filling_material_ids = [v for v in filling_material_ids if v]
                frame_material_ids = [v for v in frame_material_ids if v]
                feature_ids = [v for v in feature_ids if v]
                certification_ids = [v for v in certification_ids if v]

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO order_products (
                                sku, sku_family_id, version_no, fabric_id, spec_qty_short,
                                listing_image_b64, is_iteration, source_order_product_id,
                                finished_length_in, finished_width_in, finished_height_in,
                                net_weight_lbs, package_length_in, package_width_in, package_height_in,
                                gross_weight_lbs, cost_usd, carton_qty, package_size_class, last_mile_avg_freight_usd
                            ) VALUES (
                                %(sku)s, %(sku_family_id)s, %(version_no)s, %(fabric_id)s, %(spec_qty_short)s,
                                %(listing_image_b64)s, %(is_iteration)s, %(source_order_product_id)s,
                                %(finished_length_in)s, %(finished_width_in)s, %(finished_height_in)s,
                                %(net_weight_lbs)s, %(package_length_in)s, %(package_width_in)s, %(package_height_in)s,
                                %(gross_weight_lbs)s, %(cost_usd)s, %(carton_qty)s, %(package_size_class)s, %(last_mile_avg_freight_usd)s
                            )
                            """,
                            payload
                        )
                        new_id = cur.lastrowid

                    self._replace_order_product_material_ids(conn, new_id, filling_material_ids, frame_material_ids)
                    self._replace_order_product_feature_ids(conn, new_id, feature_ids)
                    self._replace_order_product_certification_ids(conn, new_id, certification_ids)

                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                sku = (data.get('sku') or '').strip()
                sku_family_id = data.get('sku_family_id')
                version_no = (data.get('version_no') or '').strip()
                fabric_id = data.get('fabric_id')
                spec_qty_short = (data.get('spec_qty_short') or '').strip()
                listing_image_b64 = (data.get('listing_image_b64') or '').strip() or None
                is_iteration = 1 if str(data.get('is_iteration') or '').lower() in ('1', 'true', 'yes', 'on') else 0
                source_order_product_id = self._parse_int(data.get('source_order_product_id'))

                if not item_id or not sku or not sku_family_id or not version_no or not fabric_id or not spec_qty_short:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                if is_iteration and not source_order_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing source SKU'}, start_response)
                if source_order_product_id and int(source_order_product_id) == int(item_id):
                    return self.send_json({'status': 'error', 'message': 'Source SKU cannot be itself'}, start_response)

                payload = {
                    'id': item_id,
                    'sku': sku,
                    'sku_family_id': self._parse_int(sku_family_id),
                    'version_no': version_no,
                    'fabric_id': self._parse_int(fabric_id),
                    'spec_qty_short': spec_qty_short,
                    'listing_image_b64': listing_image_b64,
                    'is_iteration': is_iteration,
                    'source_order_product_id': source_order_product_id,
                    'finished_length_in': self._parse_float(data.get('finished_length_in')),
                    'finished_width_in': self._parse_float(data.get('finished_width_in')),
                    'finished_height_in': self._parse_float(data.get('finished_height_in')),
                    'net_weight_lbs': self._parse_float(data.get('net_weight_lbs')),
                    'package_length_in': self._parse_float(data.get('package_length_in')),
                    'package_width_in': self._parse_float(data.get('package_width_in')),
                    'package_height_in': self._parse_float(data.get('package_height_in')),
                    'gross_weight_lbs': self._parse_float(data.get('gross_weight_lbs')),
                    'cost_usd': self._parse_float(data.get('cost_usd')),
                    'carton_qty': self._parse_int(data.get('carton_qty')),
                    'package_size_class': (data.get('package_size_class') or '').strip() or None,
                    'last_mile_avg_freight_usd': self._parse_float(data.get('last_mile_avg_freight_usd'))
                }

                filling_material_ids = [self._parse_int(v) for v in (data.get('filling_material_ids') or [])]
                frame_material_ids = [self._parse_int(v) for v in (data.get('frame_material_ids') or [])]
                feature_ids = [self._parse_int(v) for v in (data.get('feature_ids') or [])]
                certification_ids = [self._parse_int(v) for v in (data.get('certification_ids') or [])]
                filling_material_ids = [v for v in filling_material_ids if v]
                frame_material_ids = [v for v in frame_material_ids if v]
                feature_ids = [v for v in feature_ids if v]
                certification_ids = [v for v in certification_ids if v]

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE order_products
                            SET sku=%(sku)s,
                                sku_family_id=%(sku_family_id)s,
                                version_no=%(version_no)s,
                                fabric_id=%(fabric_id)s,
                                spec_qty_short=%(spec_qty_short)s,
                                listing_image_b64=%(listing_image_b64)s,
                                is_iteration=%(is_iteration)s,
                                source_order_product_id=%(source_order_product_id)s,
                                finished_length_in=%(finished_length_in)s,
                                finished_width_in=%(finished_width_in)s,
                                finished_height_in=%(finished_height_in)s,
                                net_weight_lbs=%(net_weight_lbs)s,
                                package_length_in=%(package_length_in)s,
                                package_width_in=%(package_width_in)s,
                                package_height_in=%(package_height_in)s,
                                gross_weight_lbs=%(gross_weight_lbs)s,
                                cost_usd=%(cost_usd)s,
                                carton_qty=%(carton_qty)s,
                                package_size_class=%(package_size_class)s,
                                last_mile_avg_freight_usd=%(last_mile_avg_freight_usd)s
                            WHERE id=%(id)s
                            """,
                            payload
                        )

                    self._replace_order_product_material_ids(conn, item_id, filling_material_ids, frame_material_ids)
                    self._replace_order_product_feature_ids(conn, item_id, feature_ids)
                    self._replace_order_product_certification_ids(conn, item_id, certification_ids)

                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM order_products WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': 'SKU 已存在'}, start_response)
            print("Order product API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_order_product_template_api(self, environ, method, start_response):
        """下单产品模板下载"""
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
            wb = Workbook()
            ws = wb.active
            ws.title = 'order_products'
            headers = [
                'sku', 'sku_family', 'version_no', 'fabric_code', 'spec_qty_short',
                'listing_image_path', 'is_iteration', 'source_sku',
                'finished_length_in', 'finished_width_in', 'finished_height_in', 'net_weight_lbs',
                'package_length_in', 'package_width_in', 'package_height_in', 'gross_weight_lbs',
                'cost_usd', 'carton_qty', 'package_size_class', 'last_mile_avg_freight_usd',
                'filling_materials', 'frame_materials', 'features', 'certifications'
            ]
            ws.append(headers)
            ws.append([
                'MS01A-Brown', 'MS01', '1', 'Brown', 'A',
                '上架资源/MS01/cover.jpg', 0, '',
                0, 0, 0, 0,
                0, 0, 0, 0,
                0, 0, '', 0,
                '海绵 / 羽绒', '金属', '可拆洗 / 防水', 'CE'
            ])
            return self._send_excel_workbook(wb, 'order_product_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_order_product_import_api(self, environ, method, start_response):
        """下单产品批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if not file_item or not getattr(file_item, 'file', None):
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active

            headers = [cell.value for cell in ws[1]]
            header_map = {str(h).strip(): idx for idx, h in enumerate(headers) if h}

            def get_cell(row, key):
                idx = header_map.get(key)
                if idx is None:
                    return None
                return row[idx].value

            def parse_list(raw):
                if raw is None:
                    return []
                text = str(raw).strip()
                if not text:
                    return []
                return [t.strip() for t in re.split(r'[;/,，、]+', text) if t.strip()]

            def parse_bool(raw):
                if raw is None:
                    return 0
                text = str(raw).strip().lower()
                if text in ('1', 'true', 'yes', 'y', '是', '对', 'on'):
                    return 1
                return 0

            self._ensure_order_product_tables()
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, sku_family FROM product_families")
                    sku_map = {row['sku_family']: row['id'] for row in cur.fetchall()}
                    cur.execute("SELECT id, fabric_code FROM fabric_materials")
                    fabric_map = {row['fabric_code']: row['id'] for row in cur.fetchall()}
                    cur.execute(
                        """
                        SELECT m.id, m.name, mt.name AS type_name
                        FROM materials m
                        JOIN material_types mt ON m.material_type_id = mt.id
                        """
                    )
                    material_rows = cur.fetchall()
                    filling_map = {row['name']: row['id'] for row in material_rows if row['type_name'] == '填充'}
                    frame_map = {row['name']: row['id'] for row in material_rows if row['type_name'] == '框架'}
                    cur.execute("SELECT id, name FROM features")
                    feature_map = {row['name']: row['id'] for row in cur.fetchall()}
                    cur.execute("SELECT id, name FROM certifications")
                    cert_map = {row['name']: row['id'] for row in cur.fetchall()}
                    cur.execute("SELECT id, sku FROM order_products")
                    order_map = {row['sku']: row['id'] for row in cur.fetchall()}

                created = 0
                errors = []
                for row_idx in range(2, ws.max_row + 1):
                    row = ws[row_idx]
                    row_values = [cell.value for cell in row]
                    if not any(v is not None and str(v).strip() for v in row_values):
                        continue

                    sku = (get_cell(row, 'sku') or '').strip()
                    sku_family = (get_cell(row, 'sku_family') or '').strip()
                    version_no = (get_cell(row, 'version_no') or '').strip()
                    fabric_code = (get_cell(row, 'fabric_code') or '').strip()
                    spec_qty_short = (get_cell(row, 'spec_qty_short') or '').strip()
                    listing_image_path = (get_cell(row, 'listing_image_path') or '').strip()
                    is_iteration = parse_bool(get_cell(row, 'is_iteration'))
                    source_sku = (get_cell(row, 'source_sku') or '').strip()

                    if not sku or not sku_family or not version_no or not fabric_code or not spec_qty_short:
                        errors.append({'row': row_idx, 'error': 'Missing required fields'})
                        continue

                    sku_family_id = sku_map.get(sku_family)
                    fabric_id = fabric_map.get(fabric_code)
                    if not sku_family_id or not fabric_id:
                        errors.append({'row': row_idx, 'error': 'Invalid sku_family or fabric_code'})
                        continue

                    source_order_product_id = None
                    if is_iteration:
                        if not source_sku or source_sku not in order_map:
                            errors.append({'row': row_idx, 'error': 'Invalid source SKU'})
                            continue
                        source_order_product_id = order_map.get(source_sku)

                    listing_image_b64 = None
                    if listing_image_path:
                        rel_path = listing_image_path
                        if not rel_path.startswith('上架资源'):
                            rel_path = f"上架资源/{rel_path}"
                        try:
                            rel_bytes = os.fsencode(rel_path)
                        except Exception:
                            rel_bytes = rel_path.encode('utf-8', errors='surrogatepass')
                        listing_image_b64 = base64.b64encode(rel_bytes).decode('ascii')

                    payload = {
                        'sku': sku,
                        'sku_family_id': sku_family_id,
                        'version_no': version_no,
                        'fabric_id': fabric_id,
                        'spec_qty_short': spec_qty_short,
                        'listing_image_b64': listing_image_b64,
                        'is_iteration': is_iteration,
                        'source_order_product_id': source_order_product_id,
                        'finished_length_in': self._parse_float(get_cell(row, 'finished_length_in')),
                        'finished_width_in': self._parse_float(get_cell(row, 'finished_width_in')),
                        'finished_height_in': self._parse_float(get_cell(row, 'finished_height_in')),
                        'net_weight_lbs': self._parse_float(get_cell(row, 'net_weight_lbs')),
                        'package_length_in': self._parse_float(get_cell(row, 'package_length_in')),
                        'package_width_in': self._parse_float(get_cell(row, 'package_width_in')),
                        'package_height_in': self._parse_float(get_cell(row, 'package_height_in')),
                        'gross_weight_lbs': self._parse_float(get_cell(row, 'gross_weight_lbs')),
                        'cost_usd': self._parse_float(get_cell(row, 'cost_usd')),
                        'carton_qty': self._parse_int(get_cell(row, 'carton_qty')),
                        'package_size_class': (get_cell(row, 'package_size_class') or '').strip() or None,
                        'last_mile_avg_freight_usd': self._parse_float(get_cell(row, 'last_mile_avg_freight_usd'))
                    }

                    filling_ids = [filling_map.get(name) for name in parse_list(get_cell(row, 'filling_materials'))]
                    frame_ids = [frame_map.get(name) for name in parse_list(get_cell(row, 'frame_materials'))]
                    feature_ids = [feature_map.get(name) for name in parse_list(get_cell(row, 'features'))]
                    cert_ids = [cert_map.get(name) for name in parse_list(get_cell(row, 'certifications'))]
                    filling_ids = [v for v in filling_ids if v]
                    frame_ids = [v for v in frame_ids if v]
                    feature_ids = [v for v in feature_ids if v]
                    cert_ids = [v for v in cert_ids if v]

                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO order_products (
                                    sku, sku_family_id, version_no, fabric_id, spec_qty_short,
                                    listing_image_b64, is_iteration, source_order_product_id,
                                    finished_length_in, finished_width_in, finished_height_in,
                                    net_weight_lbs, package_length_in, package_width_in, package_height_in,
                                    gross_weight_lbs, cost_usd, carton_qty, package_size_class, last_mile_avg_freight_usd
                                ) VALUES (
                                    %(sku)s, %(sku_family_id)s, %(version_no)s, %(fabric_id)s, %(spec_qty_short)s,
                                    %(listing_image_b64)s, %(is_iteration)s, %(source_order_product_id)s,
                                    %(finished_length_in)s, %(finished_width_in)s, %(finished_height_in)s,
                                    %(net_weight_lbs)s, %(package_length_in)s, %(package_width_in)s, %(package_height_in)s,
                                    %(gross_weight_lbs)s, %(cost_usd)s, %(carton_qty)s, %(package_size_class)s, %(last_mile_avg_freight_usd)s
                                )
                                """,
                                payload
                            )
                            new_id = cur.lastrowid
                        self._replace_order_product_material_ids(conn, new_id, filling_ids, frame_ids)
                        self._replace_order_product_feature_ids(conn, new_id, feature_ids)
                        self._replace_order_product_certification_ids(conn, new_id, cert_ids)
                        created += 1
                    except Exception as e:
                        errors.append({'row': row_idx, 'error': str(e)})

            return self.send_json({'status': 'success', 'created': created, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_template_api(self, environ, method, start_response):
        """销售产品模板下载"""
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
            wb = Workbook()
            ws = wb.active
            ws.title = 'sales_products'
            headers = [
                'shop_name', 'brand_name', 'platform_type', 'sku_family',
                'platform_sku', 'parent_asin', 'child_asin',
                'fabric', 'spec_name', 'order_sku_links'
            ]
            ws.append(headers)
            ws.append([
                '店铺A', '品牌A', 'Amazon', 'MS01',
                '', 'B01XXXX', 'B01YYYY',
                '', '', 'MS01A-Brown*2;MS01B-Gray*1'
            ])
            return self._send_excel_workbook(wb, 'sales_product_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_import_api(self, environ, method, start_response):
        """销售产品批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if not file_item or not getattr(file_item, 'file', None):
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active

            headers = [cell.value for cell in ws[1]]
            header_map = {str(h).strip(): idx for idx, h in enumerate(headers) if h}

            def get_cell(row, key):
                idx = header_map.get(key)
                if idx is None:
                    return None
                return row[idx].value

            def parse_links(raw):
                if raw is None:
                    return []
                text = str(raw).strip()
                if not text:
                    return []
                parts = [t.strip() for t in re.split(r'[;；|]+', text) if t.strip()]
                result = []
                for part in parts:
                    if '*' in part:
                        sku, qty = part.split('*', 1)
                    else:
                        sku, qty = part, '1'
                    sku = sku.strip()
                    qty = qty.strip()
                    if not sku:
                        continue
                    try:
                        qty_val = int(qty) if qty else 1
                    except Exception:
                        qty_val = 1
                    result.append((sku, max(1, qty_val)))
                return result

            self._ensure_sales_product_tables()
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT s.id, s.shop_name, pt.name AS platform_type_name, b.name AS brand_name
                        FROM shops s
                        JOIN platform_types pt ON pt.id = s.platform_type_id
                        JOIN brands b ON b.id = s.brand_id
                        """
                    )
                    shop_map = {}
                    for row in cur.fetchall():
                        key = (row['shop_name'], row['brand_name'], row['platform_type_name'])
                        shop_map[key] = row['id']

                    cur.execute("SELECT id, sku_family FROM product_families")
                    sku_map = {row['sku_family']: row['id'] for row in cur.fetchall()}

                    cur.execute("SELECT id, sku FROM order_products")
                    order_map = {row['sku']: row['id'] for row in cur.fetchall()}

                created = 0
                errors = []
                for row_idx in range(2, ws.max_row + 1):
                    row = ws[row_idx]
                    row_values = [cell.value for cell in row]
                    if not any(v is not None and str(v).strip() for v in row_values):
                        continue

                    shop_name = (get_cell(row, 'shop_name') or '').strip()
                    brand_name = (get_cell(row, 'brand_name') or '').strip()
                    platform_type = (get_cell(row, 'platform_type') or '').strip()
                    sku_family = (get_cell(row, 'sku_family') or '').strip()
                    platform_sku = (get_cell(row, 'platform_sku') or '').strip()
                    parent_asin = (get_cell(row, 'parent_asin') or '').strip() or None
                    child_asin = (get_cell(row, 'child_asin') or '').strip() or None
                    fabric = (get_cell(row, 'fabric') or '').strip()
                    spec_name = (get_cell(row, 'spec_name') or '').strip()
                    order_sku_links = (get_cell(row, 'order_sku_links') or '').strip()

                    shop_id = shop_map.get((shop_name, brand_name, platform_type))
                    sku_family_id = sku_map.get(sku_family)
                    if not shop_id or not sku_family_id:
                        errors.append({'row': row_idx, 'error': 'Invalid shop or sku_family'})
                        continue

                    link_entries = []
                    for sku, qty in parse_links(order_sku_links):
                        order_id = order_map.get(sku)
                        if not order_id:
                            errors.append({'row': row_idx, 'error': f'Unknown order SKU: {sku}'})
                            link_entries = []
                            break
                        link_entries.append({'order_product_id': order_id, 'quantity': qty})
                    if not link_entries:
                        errors.append({'row': row_idx, 'error': 'Missing order_sku_links'})
                        continue

                    manual_platform_sku = bool(platform_sku)
                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, link_entries)
                    final_fabric = fabric or auto_fabric
                    final_spec_name = spec_name or auto_spec_name
                    final_platform_sku = platform_sku or auto_platform_sku

                    if not final_platform_sku:
                        errors.append({'row': row_idx, 'error': 'Platform SKU missing'})
                        continue

                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                INSERT INTO sales_products
                                (shop_id, sku_family_id, platform_sku, parent_asin, child_asin, fabric, spec_name)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                                """,
                                (shop_id, sku_family_id, final_platform_sku, parent_asin, child_asin, final_fabric, final_spec_name)
                            )
                            new_id = cur.lastrowid
                        self._replace_sales_order_links(conn, new_id, link_entries)
                        created += 1
                    except Exception as e:
                        errors.append({'row': row_idx, 'error': str(e)})

            return self.send_json({'status': 'success', 'created': created, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_api(self, environ, method, start_response):
        """销售产品管理 API（CRUD）"""
        try:
            self._ensure_sales_product_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        base_sql = """
                            SELECT
                                sp.id, sp.shop_id, sp.sku_family_id,
                                sp.platform_sku, sp.parent_asin, sp.child_asin,
                                sp.fabric, sp.spec_name, sp.created_at, sp.updated_at,
                                s.shop_name, pt.name AS platform_type_name, b.name AS brand_name,
                                pf.sku_family,
                                GROUP_CONCAT(CONCAT(op.id, ':', op.sku, ':', spol.quantity) ORDER BY op.id SEPARATOR '|') AS order_sku_links
                            FROM sales_products sp
                            LEFT JOIN shops s ON s.id = sp.shop_id
                            LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                            LEFT JOIN brands b ON b.id = s.brand_id
                            LEFT JOIN product_families pf ON pf.id = sp.sku_family_id
                            LEFT JOIN sales_product_order_links spol ON spol.sales_product_id = sp.id
                            LEFT JOIN order_products op ON op.id = spol.order_product_id
                        """
                        filters = []
                        params = []
                        if keyword:
                            filters.append("(sp.platform_sku LIKE %s OR pf.sku_family LIKE %s OR s.shop_name LIKE %s)")
                            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                        cur.execute(base_sql + where_sql + " GROUP BY sp.id ORDER BY sp.id DESC", params)
                        rows = cur.fetchall() or []
                for row in rows:
                    raw = row.get('order_sku_links') or ''
                    links = []
                    if raw:
                        for chunk in raw.split('|'):
                            parts = chunk.split(':', 2)
                            if len(parts) != 3:
                                continue
                            try:
                                links.append({
                                    'order_product_id': int(parts[0]),
                                    'sku': parts[1],
                                    'quantity': int(parts[2])
                                })
                            except Exception:
                                continue
                    row['order_sku_links'] = links
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                shop_id = self._parse_int(data.get('shop_id'))
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                parent_asin = (data.get('parent_asin') or '').strip() or None
                child_asin = (data.get('child_asin') or '').strip() or None
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not shop_id or not sku_family_id or not links:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)

                with self._get_db_connection() as conn:
                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    fabric = (data.get('fabric') or '').strip() or auto_fabric
                    spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    platform_sku = platform_sku_manual if manual_platform_sku else auto_platform_sku
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)
                    
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_products
                            (shop_id, sku_family_id, platform_sku, parent_asin, child_asin, fabric, spec_name)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (shop_id, sku_family_id, platform_sku, parent_asin, child_asin, fabric, spec_name)
                        )
                        new_id = cur.lastrowid
                    self._replace_sales_order_links(conn, new_id, links)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                shop_id = self._parse_int(data.get('shop_id'))
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                parent_asin = (data.get('parent_asin') or '').strip() or None
                child_asin = (data.get('child_asin') or '').strip() or None
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not item_id or not shop_id or not sku_family_id or not links:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)

                with self._get_db_connection() as conn:
                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    fabric = (data.get('fabric') or '').strip() or auto_fabric
                    spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    platform_sku = platform_sku_manual if manual_platform_sku else auto_platform_sku
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)
                    
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE sales_products
                            SET shop_id=%s, sku_family_id=%s,
                                platform_sku=%s, parent_asin=%s, child_asin=%s,
                                fabric=%s, spec_name=%s
                            WHERE id=%s
                            """,
                            (shop_id, sku_family_id, platform_sku, parent_asin, child_asin, fabric, spec_name, item_id)
                        )
                    self._replace_sales_order_links(conn, item_id, links)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_products WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '销售平台SKU已存在或关联数据无效'}, start_response)
            print("Sales product API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def serve_file(self, filepath, content_type, start_response):
        """提供文件"""
        try:
            full_path = os.path.join(self.base_path, filepath)
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()

            content_bytes = content.encode('utf-8')
            start_response('200 OK', [
                ('Content-Type', content_type + '; charset=utf-8'),
                ('Content-Length', str(len(content_bytes)))
            ])
            return [content_bytes]
        except FileNotFoundError:
            return self.send_error(404, 'File Not Found', start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def serve_static(self, path, start_response):
        """提供静态文件"""
        try:
            filepath = os.path.join(self.base_path, path.lstrip('/'))

            with open(filepath, 'rb') as f:
                content = f.read()

            content_type, _ = mimetypes.guess_type(filepath)
            if content_type is None:
                content_type = 'application/octet-stream'

            start_response('200 OK', [
                ('Content-Type', content_type),
                ('Content-Length', str(len(content)))
            ])
            return [content]
        except FileNotFoundError:
            return self.send_error(404, 'File Not Found', start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def send_json(self, data, start_response):
        """发送 JSON 响应（确保完全ASCII编码）"""
        try:
            response = json.dumps(data, ensure_ascii=True, default=str).encode('ascii')
            start_response('200 OK', [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(response)))
            ])
            return [response]
        except Exception as e:
            print("JSON encoding error: " + str(e))
            fallback = json.dumps({'status': 'error', 'message': 'encoding error'}).encode('ascii')
            start_response('200 OK', [
                ('Content-Type', 'application/json'),
                ('Content-Length', str(len(fallback)))
            ])
            return [fallback]
    
    def send_error(self, status_code, message, start_response):
        """发送错误响应"""
        status_text = {
            400: 'Bad Request',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            409: 'Conflict',
            500: 'Internal Server Error'
        }.get(status_code, 'Error')
        
        status = f'{status_code} {status_text}'
        
        error_html = f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>错误 {status_code}</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>{status}</h1>
            <p>{message}</p>
        </body>
        </html>
        '''.encode('utf-8')
        
        start_response(status, [
            ('Content-Type', 'text/html; charset=utf-8'),
            ('Content-Length', str(len(error_html)))
        ])
        return [error_html]

# WSGI 应用实例 - Web Station 会调用这个
application = WSGIApp()
