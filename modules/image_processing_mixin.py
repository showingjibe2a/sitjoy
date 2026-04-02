# -*- coding: utf-8 -*-
"""鍥剧墖澶勭悊 Mixin - 鍥剧墖鐩稿叧API鍜岃緟鍔╂柟娉?""

import os
import base64
import math
from urllib.parse import parse_qs

class ImageProcessingMixin:
    """鍥剧墖澶勭悊鍜屽垪琛ˋPI"""

    def _is_image_name(self, name):
        """鍒ゆ柇鏄惁涓哄浘鐗囨枃浠跺悕锛堝吋瀹?bytes/str锛?""
        if isinstance(name, (bytes, bytearray)):
            try:
                name = os.fsdecode(name)
            except Exception:
                name = name.decode('utf-8', errors='ignore')
        return str(name).lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'))

    def handle_images_api(self, environ, start_response):
        """鑾峰彇鍥剧墖鍒楄〃锛堢敤Base64缂栫爜璺緞閬垮厤缂栫爜闂锛?""
        images = []
        try:
            from app import RESOURCES_PATH_BYTES  # 瀵煎叆鍏ㄥ眬甯搁噺
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            page = int(query_params.get('page', ['1'])[0])
            per_page = min(int(query_params.get('per_page', ['100'])[0]), 200)
            
            # 妫€鏌ESOURCES_PATH鏄惁瀛樺湪
            if not os.path.exists(RESOURCES_PATH_BYTES):
                try:
                    resources_path_text = os.fsdecode(RESOURCES_PATH_BYTES)
                    root_dir = os.path.dirname(os.path.dirname(resources_path_text.rstrip('/')))
                    if not root_dir:
                        root_dir = '/'
                    volume_roots = []
                    for name in os.listdir(root_dir):
                        if str(name or '').startswith('volume'):
                            p = os.path.join(root_dir, name)
                            if os.path.isdir(p):
                                volume_roots.append(p)
                    folders_list = []
                    for vol in volume_roots:
                        for f in (os.listdir(vol) if os.path.exists(vol) else []):
                            if os.path.isdir(os.path.join(vol, f)):
                                folders_list.append(f'{os.path.basename(vol)}/{f}')
                    try:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='surrogatepass')).decode('ascii')
                    except Exception:
                        folders_b64 = base64.b64encode(str(folders_list).encode('utf-8', errors='ignore')).decode('ascii')
                    return self.send_json({
                        'status': 'error', 
                        'message': 'Path not found',
                        'resources_path': resources_path_text,
                        'available_folders_b64': folders_b64
                    }, start_response)
                except:
                    return self.send_json({
                        'status': 'error', 
                        'message': f'Path not found and cannot list volume'
                    }, start_response)
            
            # 鎵弿鏂囦欢
            count = 0
            for root, dirs, files in os.walk(RESOURCES_PATH_BYTES):
                for file in files:
                    if self._is_image_name(file):
                        try:
                            full_path = os.path.join(root, file)
                            rel_path = os.path.relpath(full_path, RESOURCES_PATH_BYTES)
                            
                            # 鐢˙ase64缂栫爜鎵€鏈夊唴瀹?
                            path_b64 = self._b64_from_fs(rel_path)
                            filename_b64 = self._b64_from_fs(file)
                            
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
            
            # 鍒嗛〉
            total = len(images)
            start_idx = (page - 1) * per_page
            end_idx = start_idx + per_page
            paginated = images[start_idx:end_idx]
            
            # 璁＄畻鎬婚〉鏁?
            total_pages = math.ceil(total / per_page) if total > 0 else 1
            
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
            return self.send_json({
                'status': 'error', 
                'message': f'Error: {type(e).__name__}'
            }, start_response)

    def handle_certification_images_api(self, environ, start_response):
        """鍒楀嚭璁よ瘉鏂囦欢澶瑰唴鍥剧墖"""
        try:
            folder = self._ensure_certification_folder()

            items = []
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        raw = entry.name
                        if isinstance(raw, str):
                            try:
                                raw_bytes = os.fsencode(raw)
                            except Exception:
                                raw_bytes = raw.encode('utf-8', errors='surrogatepass')
                        else:
                            raw_bytes = bytes(raw)

                        try:
                            name = os.fsdecode(raw_bytes)
                            name = name.encode('utf-8', errors='surrogatepass').decode('utf-8', errors='replace')
                        except Exception:
                            name = raw_bytes.decode('utf-8', errors='replace')

                        try:
                            folder_bytes = os.fsencode('銆庤璇併€?)
                        except Exception:
                            folder_bytes = '銆庤璇併€?.encode('utf-8', errors='surrogatepass')
                        rel_bytes = os.path.join(folder_bytes, raw_bytes)
                        items.append({
                            'name': name,
                            'name_raw_b64': base64.b64encode(raw_bytes).decode('ascii'),
                            'b64': base64.b64encode(rel_bytes).decode('ascii')
                        })

            try:
                items.sort(key=lambda x: (x.get('name') or '').lower())
            except Exception:
                pass
            return self.send_json({'status': 'success', 'items': items}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)



