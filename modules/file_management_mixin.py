import os
import io
import cgi
import json
import base64
import re
import mimetypes
import tempfile
import zipfile
from datetime import datetime
from urllib.parse import parse_qs

try:
    from PIL import Image
except Exception:
    Image = None


def _resolve_resources_parent():
    env_parent = (os.environ.get('SITJOY_RESOURCES_PARENT') or '').strip()
    if env_parent:
        return env_parent

    # NAS 已迁移到存储空间3时优先使用 volume3
    preferred = [
        '/volume3/公共文件SITJOY',
        '/volume1/公共文件SITJOY',
    ]
    for p in preferred:
        if os.path.exists(p):
            return p

    # 兜底扫描 /volumeN/公共文件SITJOY
    try:
        vols = []
        for name in os.listdir('/'):
            if re.match(r'^volume\d+$', str(name or '')):
                vols.append(name)
        vols.sort(key=lambda x: int(re.sub(r'\D+', '', x) or '0'))
        for v in vols:
            p = f'/{v}/公共文件SITJOY'
            if os.path.exists(p):
                return p
    except Exception:
        pass
    return '/volume3/公共文件SITJOY'


_RESOURCES_PARENT = _resolve_resources_parent()
_RESOURCES_CHILD_B64 = '44CO5LiK5p626LWE5rqQ44CP'
_RESOURCES_PARENT_BYTES = _RESOURCES_PARENT.encode('utf-8', errors='surrogatepass')
_RESOURCES_CHILD_BYTES = base64.b64decode(_RESOURCES_CHILD_B64)
RESOURCES_PATH_BYTES = os.path.join(_RESOURCES_PARENT_BYTES, _RESOURCES_CHILD_BYTES)
RESOURCES_PATH = os.fsdecode(RESOURCES_PATH_BYTES)


class FileManagementMixin:
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
                # 列出当前卷下的文件夹帮助调试
                try:
                    parent_root = os.path.dirname(_RESOURCES_PARENT.rstrip('/'))
                    volume_contents = os.listdir(parent_root) if os.path.exists(parent_root) else []
                    folders_list = [f for f in volume_contents if os.path.isdir(os.path.join(parent_root, f))]
                    # 用Base64编码文件夹列表以避免编码问题
                    try:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='surrogatepass')).decode('ascii')
                    except Exception:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='ignore')).decode('ascii')
                    return self.send_json({
                        'status': 'error', 
                        'message': 'Path not found',
                        'resources_parent': _RESOURCES_PARENT,
                        'resources_path': RESOURCES_PATH,
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
            try:
                text = body.decode('utf-8', errors='surrogateescape')
            except Exception:
                text = body.decode('utf-8', errors='replace')
            data = json.loads(text)

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

            # 若该文件已入库（image_assets.storage_path），同步更新数据库记录
            db_updated = 0
            try:
                old_rel = str(old_path or '').strip().replace('\\', '/').lstrip('/')
                folder_rel = str(os.path.dirname(old_path) or '').strip().replace('\\', '/').lstrip('/')
                new_base = os.fsdecode(new_filename).replace('\\', '/')
                new_rel = f"{folder_rel}/{new_base}".lstrip('/') if folder_rel else new_base.lstrip('/')
                if old_rel and new_rel and hasattr(self, '_get_db_connection'):
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "UPDATE image_assets SET storage_path=%s WHERE storage_path=%s",
                                (new_rel, old_rel),
                            )
                            db_updated = int(cur.rowcount or 0)
            except Exception:
                db_updated = 0

            resp = {
                'status': 'success',
                'message': 'Renamed',
                'new_name': os.fsdecode(new_filename),
                'db_updated': db_updated,
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
            try:
                text = body.decode('utf-8', errors='surrogateescape')
            except Exception:
                text = body.decode('utf-8', errors='replace')
            data = json.loads(text)

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

    def handle_replace_api(self, environ, start_response):
        """替换单张图片：旧图移入回收站，新图覆盖原路径。"""
        try:
            if environ.get('REQUEST_METHOD') != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_error(400, 'Invalid content type', start_response)

            form = cgi.FieldStorage(fp=environ.get('wsgi.input'), environ=environ, keep_blank_values=True)
            path_b64 = (form.getfirst('id', '') or '').strip()
            if not path_b64:
                return self.send_error(400, 'Missing id', start_response)
            if 'file' not in form:
                return self.send_error(400, 'Missing file', start_response)

            file_item = form['file']
            if isinstance(file_item, list):
                file_item = file_item[0] if file_item else None
            if not file_item or not getattr(file_item, 'file', None):
                return self.send_error(400, 'Missing file', start_response)

            try:
                old_path = self._fs_from_b64(path_b64)
            except Exception:
                return self.send_error(400, 'Invalid id', start_response)
            if '..' in old_path:
                return self.send_error(403, 'Invalid path', start_response)

            full_old_path = self._join_resources(old_path)
            abs_old = os.path.abspath(full_old_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_old.startswith(abs_resources):
                return self.send_error(403, 'Access denied', start_response)
            if not os.path.exists(full_old_path):
                return self.send_error(404, 'File not found', start_response)

            old_base = os.path.basename(full_old_path)
            if not self._is_image_name(old_base):
                return self.send_error(400, 'Not an image', start_response)

            try:
                new_bytes = file_item.file.read() or b''
            except Exception:
                new_bytes = b''
            if not new_bytes:
                return self.send_error(400, 'Empty file', start_response)

            # Move old to recycle bin (best-effort)
            moved_ok = False
            try:
                if hasattr(self, '_move_file_to_listing_recycle_bin'):
                    moved_ok, _dst, _err = self._move_file_to_listing_recycle_bin(full_old_path, '替换')
            except Exception:
                moved_ok = False
            if not moved_ok:
                return self.send_error(500, 'Cannot move old file', start_response)

            # Write new bytes back to original path
            try:
                parent = os.path.dirname(full_old_path)
                if parent and not os.path.exists(parent):
                    os.makedirs(parent, exist_ok=True)
                with open(full_old_path, 'wb') as f:
                    f.write(new_bytes)
            except Exception as e:
                return self.send_error(500, f'Write failed: {e}', start_response)

            return self.send_json({'status': 'success'}, start_response)
        except Exception as e:
            print("Replace error: " + str(e))
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

    def handle_gallery_batch_delete_api(self, environ, start_response):
        """gallery 批量删除：把选中项移动到“同目录/回收站”子文件夹。"""
        try:
            if environ.get('REQUEST_METHOD') != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ) or {}
            items = data.get('items', []) if isinstance(data, dict) else []
            if not isinstance(items, (list, tuple)) or not items:
                return self.send_json({'status': 'error', 'message': 'No items selected'}, start_response)

            def safe_reason_prefix():
                return '删除__'

            def ensure_local_recycle_dir(parent_dir):
                # parent_dir: absolute bytes path
                recycle = os.path.join(parent_dir, os.fsencode('回收站'))
                try:
                    os.makedirs(recycle, exist_ok=True)
                except Exception:
                    pass
                return recycle

            def next_available_path(dst_dir, base_name_b):
                stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
                name_root, ext = os.path.splitext(base_name_b)
                for i in range(0, 200):
                    suffix = f'__{stamp}' + (f'_{i}' if i else '')
                    cand = name_root + os.fsencode(suffix) + ext
                    dst = os.path.join(dst_dir, cand)
                    try:
                        if os.path.exists(dst):
                            continue
                    except Exception:
                        continue
                    return dst
                return os.path.join(dst_dir, base_name_b)

            moved = 0
            skipped = 0
            failures = []

            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)

            for item in items[:800]:
                try:
                    path_b64 = item.get('path', '') if isinstance(item, dict) else ''
                    if not path_b64:
                        skipped += 1
                        continue
                    rel_path = self._fs_from_b64(path_b64)
                    if '..' in rel_path or rel_path.startswith('/'):
                        skipped += 1
                        continue
                    full_path = self._join_resources(rel_path)
                    abs_path = os.path.abspath(full_path)
                    if not abs_path.startswith(abs_resources):
                        skipped += 1
                        continue
                    if not os.path.exists(full_path):
                        skipped += 1
                        continue

                    parent_dir = os.path.dirname(full_path)
                    recycle_dir = ensure_local_recycle_dir(parent_dir)
                    src_base = os.path.basename(full_path)
                    try:
                        base_b = src_base if isinstance(src_base, (bytes, bytearray)) else os.fsencode(src_base)
                    except Exception:
                        base_b = str(src_base).encode('utf-8', errors='surrogatepass')
                    dst_name = os.fsencode(safe_reason_prefix()) + base_b
                    dst = next_available_path(recycle_dir, dst_name)
                    # Move file/folder into recycle
                    import shutil
                    shutil.move(full_path, dst)
                    moved += 1
                except Exception as e:
                    failures.append(str(e)[:220])

            return self.send_json({
                'status': 'success',
                'moved': moved,
                'skipped': skipped,
                'failures': failures[:12],
                'message': f'已移入同目录回收站：{moved} 项' + (f'（跳过 {skipped} 项）' if skipped else ''),
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_gallery_duplicate_check_api(self, environ, start_response):
        """gallery 重复检测：按 path 计算 sha256，并在 DB 中查找同 sha256 的已入库图片。"""
        try:
            if environ.get('REQUEST_METHOD') != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ) or {}
            path_b64 = str(data.get('id') or data.get('path') or '').strip()
            if not path_b64:
                return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

            rel_path = self._fs_from_b64(path_b64)
            if '..' in rel_path or rel_path.startswith('/'):
                return self.send_json({'status': 'error', 'message': 'Invalid path'}, start_response)

            full_path = self._join_resources(rel_path)
            abs_path = os.path.abspath(full_path)
            abs_resources = os.path.abspath(RESOURCES_PATH_BYTES)
            if not abs_path.startswith(abs_resources):
                return self.send_json({'status': 'error', 'message': 'Access denied'}, start_response)
            if not os.path.isfile(full_path):
                return self.send_json({'status': 'error', 'message': 'File not found'}, start_response)

            import hashlib
            h = hashlib.sha256()
            with open(full_path, 'rb') as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(chunk)
            sha256 = h.hexdigest()

            canonical = None
            try:
                with self._get_db_connection() as conn:
                    if not self._table_has_column(conn, 'image_assets', 'sha256'):
                        return self.send_json({'status': 'success', 'sha256': sha256, 'duplicate': False}, start_response)
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, storage_path, sha256 FROM image_assets WHERE sha256=%s ORDER BY id ASC LIMIT 1",
                            (sha256,),
                        )
                        row = cur.fetchone() or {}
                        if row.get('id'):
                            canonical = {
                                'image_asset_id': int(row.get('id') or 0),
                                'storage_path': str(row.get('storage_path') or '').strip(),
                                'sha256': str(row.get('sha256') or '').strip(),
                            }
            except Exception:
                canonical = None

            cur_rel = rel_path.replace('\\', '/').lstrip('/')
            can_rel = str((canonical or {}).get('storage_path') or '').replace('\\', '/').lstrip('/')
            is_dup = bool(canonical and canonical.get('storage_path') and can_rel and can_rel != cur_rel)

            def dirname(p):
                if not p:
                    return ''
                return p.rsplit('/', 1)[0] if '/' in p else ''

            same_folder = (dirname(cur_rel) == dirname(can_rel)) if (cur_rel and can_rel) else False

            return self.send_json({
                'status': 'success',
                'sha256': sha256,
                'duplicate': bool(is_dup),
                'same_folder': bool(same_folder),
                'current_path': cur_rel,
                'canonical': canonical or None,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)





