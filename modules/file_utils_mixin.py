# -*- coding: utf-8 -*-
"""文件系统工具 Mixin - 文件操作、路径处理、文件夹管理"""

import os
import re
import tempfile
import zipfile
from datetime import datetime
import cgi

class FileUtilsMixin:
    """文件系统路径、面料命名与通用上传。"""

    # -------------------------------------------------------------------------
    # 面料图片命名 / 序号
    # -------------------------------------------------------------------------

    def _fabric_filename_part(self, text, default='文字卖点图'):
        value = str(text or '').strip() or default
        for ch in ('/', '\\', ':', '*', '?', '"', '<', '>', '|'):
            value = value.replace(ch, '-')
        return value.strip() or default

    def _fabric_target_filename(self, fabric_code, image_type, seq, ext):
        code = self._fabric_filename_part(fabric_code, 'FAB')
        typ = self._fabric_filename_part(image_type, '文字卖点图')
        ext_v = ext if str(ext or '').startswith('.') else f'.{ext or "jpg"}'
        return f"{code}-{typ}-{int(seq):02d}{ext_v}"

    def _next_fabric_image_seq(self, existing_names, fabric_code, image_type='文字卖点图'):
        code = re.escape(self._fabric_filename_part(fabric_code, 'FAB'))
        typ = re.escape(self._fabric_filename_part(image_type, '文字卖点图'))
        patterns = [
            re.compile(rf'^{code}-{typ}-(\d+)\.', re.I),
            re.compile(rf'^{code}_{typ}-(\d+)\.', re.I),
            re.compile(rf'^{code}_(\d+)\.', re.I),
        ]
        max_idx = 0
        for name in existing_names or []:
            base = os.path.basename(str(name or ''))
            if not base:
                continue
            for pat in patterns:
                m = pat.match(base)
                if m:
                    try:
                        max_idx = max(max_idx, int(m.group(1)))
                    except Exception:
                        pass
        return max_idx + 1

    # -------------------------------------------------------------------------
    # 上架资源路径 / 面料与认证目录
    # -------------------------------------------------------------------------

    def _join_resources(self, rel_path):
        """拼接资源目录（返回 bytes 路径）"""
        from app import RESOURCES_PATH_BYTES  # 导入全局常量
        if not rel_path:
            return RESOURCES_PATH_BYTES
        try:
            rel_bytes = self._safe_fsencode(rel_path)
        except Exception:
            rel_bytes = str(rel_path).encode('utf-8', errors='surrogatepass')
        return os.path.join(RESOURCES_PATH_BYTES, rel_bytes)

    def _ensure_fabric_folder(self):
        """获取或创建面料文件夹"""
        # Unified fabric folder
        folder = self._join_resources('『面料』')
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _ensure_certification_folder(self):
        """获取或创建认证文件夹"""
        folder = self._join_resources('『认证』')
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _fabric_image_src_from_payload(self, img, folder):
        """从保存 payload 定位面料目录中的图片（优先 image_name_raw_b64 原始字节）。"""
        raw_b64 = (img.get('image_name_raw_b64') or '').strip()
        if raw_b64:
            display, src_path = self._resolve_name_b64_in_folder(folder, raw_b64)
            if display and src_path:
                return display, src_path

        old_name = (img.get('image_name') or '').strip()
        if not old_name:
            return None, None
        src_path = os.path.join(folder, self._safe_fsencode(old_name))
        return old_name, src_path

    def _fabric_folder_existing_names(self, folder=None):
        """扫描『面料』目录已有文件名（str 集合）。"""
        folder = folder or self._ensure_fabric_folder()
        existing = set()
        try:
            with os.scandir(folder) as it:
                for entry in it:
                    if entry.is_file(follow_symlinks=False):
                        existing.add(self._decode_fs_name_bytes(self._entry_name_bytes(entry)))
        except Exception:
            pass
        return existing

    # -------------------------------------------------------------------------
    # 面料目录内绑定 / 外部路径导入
    # -------------------------------------------------------------------------

    def _fabric_allocate_bind_target(self, existing, fabric_code, image_type, ext):
        """绑定/导入时分配下一个目标文件名（编码-类型-序号.ext）。"""
        ext_v = ext if str(ext or '').startswith('.') else f'.{ext or "jpg"}'
        idx = self._next_fabric_image_seq(existing, fabric_code, image_type)
        return self._fabric_target_filename(fabric_code, image_type, idx, ext_v)

    def _fabric_bind_result_item(self, target_name, remark=None, old_b64=None):
        """绑定结果项：new_name + preview_b64（与 attach/import 响应一致）。"""
        _, preview_b64 = self._resources_rel_path_b64('『面料』', self._safe_fsencode(target_name))
        item = {'new_name': target_name, 'preview_b64': preview_b64}
        if remark:
            item['remark'] = remark
        if old_b64:
            item['old_b64'] = old_b64
        return item

    def _fabric_move_external_into_folder(self, src_b, folder, target_name):
        """将外部绝对路径文件移入『面料』目录（move 失败则 copy+unlink）。"""
        import shutil
        dst_b = os.path.join(folder, self._safe_fsencode(target_name))
        try:
            shutil.move(src_b, dst_b)
        except Exception:
            shutil.copy2(src_b, dst_b)
            try:
                os.unlink(src_b)
            except Exception:
                pass
        return dst_b

    def _fabric_bind_files_in_folder(self, folder, existing, fabric_code, image_type, raw_b64_items):
        """
        『面料』目录内未绑定文件：按编码-类型-序号重命名。
        用于「选择已有图片」/api/fabric-attach。
        """
        results = []
        existing = set(existing or [])
        image_type = (image_type or '文字卖点图').strip() or '文字卖点图'

        for raw_b64 in list(raw_b64_items or [])[:200]:
            _display, src = self._resolve_name_b64_in_folder(folder, raw_b64)
            if not src:
                continue

            base = os.path.basename(src)
            src_basename_str = self._decode_fs_name_bytes(
                base if isinstance(base, bytes) else self._safe_fsencode(str(base))
            )
            ext = os.path.splitext(src_basename_str)[1] or '.jpg'
            candidate = self._fabric_allocate_bind_target(existing, fabric_code, image_type, ext)
            dst = os.path.join(folder, self._safe_fsencode(candidate))
            try:
                os.rename(src, dst)
            except Exception as rename_err:
                return {'status': 'error', 'message': f'重命名失败: {rename_err}', 'items': results}

            existing.add(candidate)
            results.append(self._fabric_bind_result_item(
                candidate, remark=image_type, old_b64=str(raw_b64 or '').strip()
            ))

        return {'status': 'success', 'items': results}

    def _fabric_import_external_paths(self, folder, existing, fabric_code, image_type, source_files_b):
        """
        从 NAS/资源绝对路径移入『面料』并按规则命名。
        用于「云端关联」/api/fabric-import-by-path。
        """
        results = []
        existing = set(existing or [])
        image_type = (image_type or '文字卖点图').strip() or '文字卖点图'

        for src_b in list(source_files_b or [])[:200]:
            try:
                base = self._safe_fsdecode(os.path.basename(src_b))
            except Exception:
                base = 'image.jpg'
            ext = os.path.splitext(base)[1] or '.jpg'
            target_name = self._fabric_allocate_bind_target(existing, fabric_code, image_type, ext)
            try:
                self._fabric_move_external_into_folder(src_b, folder, target_name)
            except Exception as move_err:
                return {'status': 'error', 'message': f'移动失败: {move_err}', 'items': results}
            existing.add(target_name)
            results.append(self._fabric_bind_result_item(target_name, remark=image_type))

        return {'status': 'success', 'items': results, 'image_names': [r['new_name'] for r in results]}

    # -------------------------------------------------------------------------
    # API：通用图片上传
    # -------------------------------------------------------------------------

    def handle_upload_api(self, environ, start_response):
        """处理图片上传（multipart/form-data）"""
        try:
            from app import RESOURCES_PATH_BYTES  # 导入全局常量
            
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
