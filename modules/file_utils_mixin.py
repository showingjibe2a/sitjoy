# -*- coding: utf-8 -*-
"""文件系统工具 Mixin - 文件操作、路径处理、文件夹管理"""

import os
import re
import tempfile
import zipfile
from datetime import datetime
import cgi

class FileUtilsMixin:
    """文件系统和文件操作工具"""

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

    def _rename_fabric_image_with_remark(self, old_name, fabric_code, remark, index):
        if not old_name:
            return None
        ext = os.path.splitext(old_name)[1] or '.jpg'
        new_name = self._fabric_target_filename(fabric_code, remark, index, ext)
        if old_name == new_name:
            return old_name
        return new_name

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
        import base64

        raw_b64 = (img.get('image_name_raw_b64') or '').strip()
        if raw_b64:
            try:
                raw_bytes = base64.b64decode(raw_b64)
                src_path = os.path.join(folder, raw_bytes)
                if os.path.exists(src_path):
                    return self._decode_fs_name_bytes(raw_bytes), src_path
            except Exception:
                pass

        old_name = (img.get('image_name') or '').strip()
        if not old_name:
            return None, None
        src_path = os.path.join(folder, self._safe_fsencode(old_name))
        return old_name, src_path

    def _build_fabric_image_plan(self, images, fabric_code):
        """为面料图片生成重命名计划和最终入库数据"""
        folder = self._ensure_fabric_folder()
        remark_counters = {}
        planned_images = []
        rename_pairs = []
        missing = []
        not_ready = []

        for idx, img in enumerate(images):
            old_name, src_path = self._fabric_image_src_from_payload(img, folder)
            if not old_name or not src_path:
                continue

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

            remark = self._fabric_filename_part(img.get('remark'), '文字卖点图')
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
        import secrets
        
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
            
            return {'status': 'error', 'message': str(e)}

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
