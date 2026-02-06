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
from datetime import datetime
import mimetypes
import base64
from pathlib import Path
import cgi
import tempfile
import zipfile
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

    def _b64_from_fs(self, value):
        """将文件系统路径/名称转为 Base64（保留原始字节）"""
        try:
            raw = os.fsencode(value)
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
            rel_bytes = os.fsencode(rel_path)
        except Exception:
            rel_bytes = str(rel_path).encode('utf-8', errors='surrogatepass')
        return os.path.join(RESOURCES_PATH_BYTES, rel_bytes)

    def _is_image_name(self, name):
        """判断是否为图片文件名（兼容 bytes/str）"""
        if isinstance(name, (bytes, bytearray)):
            try:
                name = os.fsdecode(name)
            except Exception:
                name = name.decode('utf-8', errors='ignore')
        return str(name).lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))
    
    def __call__(self, environ, start_response):
        """WSGI 应用入口"""
        try:
            path = environ['PATH_INFO']
            method = environ['REQUEST_METHOD']

            # 路由处理
            if path == '/' or path == '/index.html':
                return self.serve_file('templates/index.html', 'text/html', start_response)
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
            elif path.startswith('/api/hello'):
                return self.handle_hello_api(environ, path, method, start_response)
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
            elif path == '/api/certification':
                return self.handle_certification_api(environ, method, start_response)
            elif path == '/api/certification-images':
                return self.handle_certification_images_api(environ, start_response)
            elif path == '/api/order-product':
                return self.handle_order_product_api(environ, method, start_response)
            elif path == '/api/fabric-images':
                return self.handle_fabric_images_api(environ, start_response)
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
            
            if not path_b64:
                return self.send_error(400, 'Missing id parameter', start_response)
            
            # 解码Base64路径
            try:
                path = self._fs_from_b64(path_b64)
            except:
                return self.send_error(400, 'Invalid id', start_response)
            
            # 防止路径遍历
            if '..' in path or path.startswith('/'):
                return self.send_error(403, 'Invalid path', start_response)
            
            full_path = self._join_resources(path)
            
            # 验证路径安全性
            abs_path = os.path.abspath(full_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)
            
            if not os.path.exists(full_path):
                return self.send_error(404, 'File not found', start_response)
            
            # 读取图片
            with open(full_path, 'rb') as f:
                image_data = f.read()
            
            mime_path = os.fsdecode(full_path) if isinstance(full_path, (bytes, bytearray)) else full_path
            mime_type, _ = mimetypes.guess_type(mime_path)
            if not mime_type:
                mime_type = 'image/jpeg'
            
            start_response('200 OK', [
                ('Content-Type', mime_type),
                ('Content-Length', str(len(image_data)))
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
        create_sql = """
        CREATE TABLE IF NOT EXISTS fabric_materials (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            fabric_code VARCHAR(64) NOT NULL UNIQUE,
            fabric_name_en VARCHAR(128) NOT NULL,
            material_id INT UNSIGNED NULL,
            image_name VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_fabric_material (material_id),
            CONSTRAINT fk_fabric_material FOREIGN KEY (material_id)
                REFERENCES materials(id) ON DELETE SET NULL
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
            spec_qty TEXT NOT NULL,
            spec_qty_short VARCHAR(128) NOT NULL,
            dachene_yuncang_no VARCHAR(128) NULL,
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
            CONSTRAINT fk_order_products_sku_family FOREIGN KEY (sku_family_id)
                REFERENCES product_families(id) ON DELETE SET NULL,
            CONSTRAINT fk_order_products_fabric FOREIGN KEY (fabric_id)
                REFERENCES fabric_materials(id) ON DELETE SET NULL
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

        self._order_product_ready = True

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

    def _get_fabric_folder_bytes(self):
        return self._join_resources('『面料』')

    def _ensure_fabric_folder(self):
        folder = self._get_fabric_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _get_certification_folder_bytes(self):
        return self._join_resources('『认证』')

    def _ensure_certification_folder(self):
        folder = self._get_certification_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _ensure_fabric_image_name(self, image_name, fabric_code):
        """确保面料图片以面料编号命名，返回最终文件名"""
        if not image_name or not fabric_code:
            return image_name

        folder = self._ensure_fabric_folder()
        name = os.path.basename(image_name)
        if isinstance(name, (bytes, bytearray)):
            try:
                name = os.fsdecode(name)
            except Exception:
                name = name.decode('utf-8', errors='ignore')

        ext = os.path.splitext(name)[1]
        target_name = f"{fabric_code}{ext}"
        if name == target_name:
            return name

        src_path = os.path.join(folder, os.fsencode(name))
        dest_path = os.path.join(folder, os.fsencode(target_name))
        if not os.path.exists(src_path):
            return name
        if os.path.exists(dest_path):
            raise RuntimeError('Target image already exists')

        os.rename(src_path, dest_path)
        return target_name

    def handle_sku_api(self, environ, method, start_response):
        """货号管理 API（CRUD）"""
        try:
            self._ensure_product_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, sku_family, category, created_at
                                FROM product_families
                                WHERE sku_family LIKE %s OR category LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, sku_family, category, created_at
                                FROM product_families
                                ORDER BY id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                if not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing sku_family or category'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_families (sku_family, category) VALUES (%s, %s)",
                            (sku_family, category)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
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
        """上传面料图片（保存为面料编号命名）"""
        try:
            if environ['REQUEST_METHOD'] != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            form = cgi.FieldStorage(fp=environ['wsgi.input'], environ=environ, keep_blank_values=True)
            fabric_code = (form.getfirst('fabric_code', '') or '').strip()
            if not fabric_code:
                return self.send_json({'status': 'error', 'message': 'Missing fabric_code'}, start_response)

            if 'file' not in form:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)

            item = form['file']
            if not item.filename:
                return self.send_json({'status': 'error', 'message': 'Invalid file'}, start_response)

            filename = os.path.basename(item.filename)
            if not self._is_image_name(filename):
                return self.send_json({'status': 'error', 'message': 'Not an image'}, start_response)

            ext = os.path.splitext(filename)[1]
            target_name = f"{fabric_code}{ext}"
            folder = self._ensure_fabric_folder()
            dest_path = os.path.join(folder, os.fsencode(target_name))
            if os.path.exists(dest_path):
                return self.send_json({'status': 'error', 'message': 'Target image already exists'}, start_response)

            with open(dest_path, 'wb') as f:
                while True:
                    chunk = item.file.read(1024 * 1024)
                    if not chunk:
                        break
                    f.write(chunk)

            return self.send_json({'status': 'success', 'image_name': target_name}, start_response)
        except Exception as e:
            print("Fabric upload error: " + str(e))
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
                                        fm.image_name, fm.created_at
                                FROM fabric_materials fm
                                LEFT JOIN materials m ON fm.material_id = m.id
                                WHERE fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s OR m.name LIKE %s OR m.name_en LIKE %s
                                ORDER BY fm.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                    SELECT fm.id, fm.fabric_code, fm.fabric_name_en, fm.material_id,
                                        m.name AS material_name, m.name_en AS material_name_en,
                                        fm.image_name, fm.created_at
                                FROM fabric_materials fm
                                LEFT JOIN materials m ON fm.material_id = m.id
                                ORDER BY fm.id DESC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                material_id = self._parse_int(data.get('material_id'))
                image_name = (data.get('image_name') or '').strip()
                if not fabric_code or not fabric_name_en or not material_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                image_name = self._ensure_fabric_image_name(image_name, fabric_code)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO fabric_materials (fabric_code, fabric_name_en, material_id, image_name)
                            VALUES (%s, %s, %s, %s)
                            """,
                            (fabric_code, fabric_name_en, material_id, image_name)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id, 'image_name': image_name}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                fabric_code = (data.get('fabric_code') or '').strip()
                fabric_name_en = (data.get('fabric_name_en') or '').strip()
                material_id = self._parse_int(data.get('material_id'))
                image_name = (data.get('image_name') or '').strip()
                if not item_id or not fabric_code or not fabric_name_en or not material_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                image_name = self._ensure_fabric_image_name(image_name, fabric_code)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE fabric_materials
                            SET fabric_code=%s, fabric_name_en=%s, material_id=%s, image_name=%s
                            WHERE id=%s
                            """,
                            (fabric_code, fabric_name_en, material_id, image_name, item_id)
                        )
                return self.send_json({'status': 'success', 'image_name': image_name}, start_response)

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
                                    op.spec_qty, op.spec_qty_short, op.dachene_yuncang_no,
                                    op.finished_length_in, op.finished_width_in, op.finished_height_in,
                                    op.net_weight_lbs, op.package_length_in, op.package_width_in,
                                    op.package_height_in, op.gross_weight_lbs, op.cost_usd,
                                    op.carton_qty, op.package_size_class, op.last_mile_avg_freight_usd,
                                    op.created_at,
                                    pf.sku_family, pf.category,
                                    fm.fabric_code, fm.fabric_name_en,
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
                                    op.spec_qty, op.spec_qty_short, op.dachene_yuncang_no,
                                    op.finished_length_in, op.finished_width_in, op.finished_height_in,
                                    op.net_weight_lbs, op.package_length_in, op.package_width_in,
                                    op.package_height_in, op.gross_weight_lbs, op.cost_usd,
                                    op.carton_qty, op.package_size_class, op.last_mile_avg_freight_usd,
                                    op.created_at,
                                    pf.sku_family, pf.category,
                                    fm.fabric_code, fm.fabric_name_en,
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
                spec_qty = (data.get('spec_qty') or '').strip()
                spec_qty_short = (data.get('spec_qty_short') or '').strip()

                if not sku or not sku_family_id or not version_no or not fabric_id or not spec_qty or not spec_qty_short:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)

                payload = {
                    'sku': sku,
                    'sku_family_id': self._parse_int(sku_family_id),
                    'version_no': version_no,
                    'fabric_id': self._parse_int(fabric_id),
                    'spec_qty': spec_qty,
                    'spec_qty_short': spec_qty_short,
                    'dachene_yuncang_no': (data.get('dachene_yuncang_no') or '').strip() or None,
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
                                sku, sku_family_id, version_no, fabric_id, spec_qty, spec_qty_short,
                                dachene_yuncang_no, finished_length_in, finished_width_in, finished_height_in,
                                net_weight_lbs, package_length_in, package_width_in, package_height_in,
                                gross_weight_lbs, cost_usd, carton_qty, package_size_class, last_mile_avg_freight_usd
                            ) VALUES (
                                %(sku)s, %(sku_family_id)s, %(version_no)s, %(fabric_id)s, %(spec_qty)s, %(spec_qty_short)s,
                                %(dachene_yuncang_no)s, %(finished_length_in)s, %(finished_width_in)s, %(finished_height_in)s,
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
                spec_qty = (data.get('spec_qty') or '').strip()
                spec_qty_short = (data.get('spec_qty_short') or '').strip()

                if not item_id or not sku or not sku_family_id or not version_no or not fabric_id or not spec_qty or not spec_qty_short:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)

                payload = {
                    'id': item_id,
                    'sku': sku,
                    'sku_family_id': self._parse_int(sku_family_id),
                    'version_no': version_no,
                    'fabric_id': self._parse_int(fabric_id),
                    'spec_qty': spec_qty,
                    'spec_qty_short': spec_qty_short,
                    'dachene_yuncang_no': (data.get('dachene_yuncang_no') or '').strip() or None,
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
                                spec_qty=%(spec_qty)s,
                                spec_qty_short=%(spec_qty_short)s,
                                dachene_yuncang_no=%(dachene_yuncang_no)s,
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
