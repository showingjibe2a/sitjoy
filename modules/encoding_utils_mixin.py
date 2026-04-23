# -*- coding: utf-8 -*-
"""编码和转换工具 Mixin - Unicode/Base64/文件系统编码处理"""

import base64
import unicodedata
import os
import shutil
import time

class EncodingUtilsMixin:
    """编码、转换和Unicode处理工具"""

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

    def _safe_fsencode(self, value):
        """安全的文件系统路径编码"""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        try:
            return os.fsencode(value)
        except Exception:
            return str(value).encode('utf-8', errors='surrogatepass')

    def _safe_fsdecode(self, value):
        """安全的文件系统路径解码"""
        if isinstance(value, str):
            return value
        try:
            return os.fsdecode(value)
        except Exception:
            return bytes(value).decode('utf-8', errors='surrogatepass')

    def _listing_resources_root_abs_b(self):
        """
        Absolute bytes path to the 『上架资源』 root (same as app.RESOURCES_PATH_BYTES when available).
        """
        try:
            from app import RESOURCES_PATH_BYTES  # type: ignore
            root = RESOURCES_PATH_BYTES
        except Exception:
            root = None
        if not root:
            try:
                if hasattr(self, '_join_resources'):
                    root = self._join_resources('')
            except Exception:
                root = None
        if not root:
            return b''
        try:
            return self._safe_fsencode(os.path.normpath(root))
        except Exception:
            return bytes(root) if isinstance(root, (bytes, bytearray)) else self._safe_fsencode(root)

    def _listing_recycle_bin_dir_abs_b(self):
        """Absolute bytes path to 『上架资源』/回收站 (created if missing)."""
        root = self._listing_resources_root_abs_b()
        if not root:
            return b''
        try:
            recycle = os.path.join(root, self._safe_fsencode('回收站'))
        except Exception:
            recycle = root + b'/' + self._safe_fsencode('回收站')
        try:
            os.makedirs(recycle, exist_ok=True)
        except Exception:
            pass
        return recycle

    def _move_file_to_listing_recycle_bin(self, src_abs):
        """
        Move a file into 『上架资源』/回收站 with a collision-safe name.
        Returns (ok: bool, dst_abs: bytes|str|None, err: str|None)
        """
        if not src_abs:
            return False, None, 'empty_path'
        src_b = self._safe_fsencode(src_abs)
        try:
            if not os.path.exists(src_b):
                return True, None, None
        except Exception:
            return False, None, 'stat_failed'

        recycle = self._listing_recycle_bin_dir_abs_b()
        if not recycle:
            return False, None, 'no_resources_root'

        try:
            base = os.path.basename(src_b)
        except Exception:
            base = b'file'

        stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime())
        ext = b''
        try:
            root_name, ext = os.path.splitext(base)
        except Exception:
            root_name, ext = base, b''

        for i in range(0, 200):
            suffix = f'__{stamp}' + (f'_{i}' if i else '')
            try:
                cand_name = root_name + self._safe_fsencode(suffix) + ext
            except Exception:
                cand_name = root_name + str(suffix).encode('utf-8', errors='ignore') + ext
            dst_b = recycle + b'/' + cand_name
            try:
                if os.path.exists(dst_b):
                    continue
            except Exception:
                continue
            try:
                shutil.move(src_b, dst_b)
                return True, dst_b, None
            except Exception as e:
                return False, None, str(e)
        return False, None, 'rename_exhausted'

    def _b64url_encode(self, raw):
        """URL安全的Base64编码"""
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    def _b64url_decode(self, text):
        """URL安全的Base64解码"""
        pad = '=' * (-len(text) % 4)
        return base64.urlsafe_b64decode((text + pad).encode('ascii'))

    def _add_name_and_b64_variants(self, bound_name_map, bound_b64_map, raw_name, fabric_id):
        """Add normalized string variants and base64-of-bytes variants for a given image name into maps."""
        if not raw_name:
            return
        try:
            base = raw_name.split('/')[-1].strip()
        except Exception:
            base = raw_name
        if not base:
            return
        try:
            nfc = unicodedata.normalize('NFC', base)
        except Exception:
            nfc = base
        try:
            nfd = unicodedata.normalize('NFD', base)
        except Exception:
            nfd = nfc

        for key in (nfc, nfc.lower(), nfd, nfd.lower()):
            if not key:
                continue
            if key not in bound_name_map:
                bound_name_map[key] = set()
            if fabric_id is not None:
                bound_name_map[key].add(int(fabric_id))

        # Add multiple byte-encoding variants for more robust matching
        for variant in (nfc, nfd):
            if not variant:
                continue
            encodings_to_try = []
            try:
                encodings_to_try.append(os.fsencode(variant))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('utf-8', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('gb18030', errors='surrogatepass'))
            except Exception:
                pass
            try:
                encodings_to_try.append(variant.encode('latin-1', errors='surrogatepass'))
            except Exception:
                pass

            # de-duplicate byte variants
            seen = set()
            for b in encodings_to_try:
                if not isinstance(b, (bytes, bytearray)):
                    continue
                if b in seen:
                    continue
                seen.add(b)
                try:
                    b64 = base64.b64encode(b).decode('ascii')
                    if b64 not in bound_b64_map:
                        bound_b64_map[b64] = set()
                    if fabric_id is not None:
                        bound_b64_map[b64].add(int(fabric_id))
                except Exception:
                    continue

    def _normalize_fabric_remark(self, remark):
        """标准化面料图片备注"""
        value = (remark or '').strip()
        allowed = {
            '原图',
            '主图·Swatch',
            '主图·卖点',
            'A+·电脑端',
            'A+·手机端',
            'A+·通用',
        }
        if value in allowed:
            return value
        if value in ('平面原图', '褶皱原图'):
            return '原图'
        if '卖点' in value:
            return '主图·卖点'
        if 'Swatch' in value or 'swatch' in value:
            return '主图·Swatch'
        if 'A+' in value or value.startswith('A＋'):
            if '电脑' in value:
                return 'A+·电脑端'
            if '手机' in value:
                return 'A+·手机端'
            return 'A+·通用'
        return '原图'

    def _to_int(self, value, default=None):
        """安全的整数转换"""
        try:
            return int(value)
        except Exception:
            return default
