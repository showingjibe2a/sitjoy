# -*- coding: utf-8 -*-
"""编码和转换工具 Mixin - Unicode/Base64/文件系统编码处理"""

import base64
import unicodedata
import os
import shutil
import time

class EncodingUtilsMixin:
    """编码、转换和 Unicode 处理工具。"""

    # -------------------------------------------------------------------------
    # Base64 ↔ 文件系统路径 / UTF-8 展示名
    # -------------------------------------------------------------------------

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
        return self._safe_fsdecode(raw)

    def _utf8_b64_to_str(self, value):
        """
        将 Base64 按 UTF-8 解码为 str（用于前端 TextEncoder / encodeURIComponent 发送的展示名）。
        与 _fs_from_b64 不同：后者用于 browse 返回的「文件系统原始字节」路径 id，不能混用。
        """
        if value is None:
            return ''
        s = str(value).strip()
        if not s:
            return ''
        raw = base64.b64decode(s)
        try:
            return raw.decode('utf-8', errors='strict').strip()
        except UnicodeDecodeError:
            return self._safe_fsdecode(raw).strip()

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
            pass
        try:
            raw = bytes(value)
        except Exception:
            return ''
        if not raw:
            return ''
        try:
            return raw.decode('utf-8', errors='surrogateescape')
        except Exception:
            try:
                return raw.decode('latin-1')
            except Exception:
                return ''

    # -------------------------------------------------------------------------
    # 上架资源路径等价判断 / 回收站
    # -------------------------------------------------------------------------

    def _listing_paths_equivalent(self, p1, p2):
        """
        Whether two paths denote the same filesystem location (bytes/str safe).
        Prevents os.replace / shutil.move from using identical source and destination,
        which can delete the only on-disk copy on some platforms.
        """
        if p1 is None or p2 is None:
            return False
        try:
            b1 = self._safe_fsencode(p1) if isinstance(p1, str) else bytes(p1)
            b2 = self._safe_fsencode(p2) if isinstance(p2, str) else bytes(p2)
        except Exception:
            return False
        if b1 == b2:
            return True
        try:
            a1 = os.path.normcase(os.path.normpath(os.path.abspath(b1)))
            a2 = os.path.normcase(os.path.normpath(os.path.abspath(b2)))
            if a1 == a2:
                return True
        except Exception:
            pass
        try:
            if os.path.exists(b1) and os.path.exists(b2):
                return bool(os.path.samefile(b1, b2))
        except Exception:
            pass
        return False

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

    def _move_file_to_listing_recycle_bin(self, src_abs, reason=None):
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

        # 在回收站文件名前增加原因前缀（便于追溯）：例如 “重复__xxx.jpg”
        reason_text = str(reason or '').strip()
        if reason_text:
            try:
                prefix = self._safe_fsencode(reason_text) + self._safe_fsencode('__')
            except Exception:
                prefix = str(reason_text).encode('utf-8', errors='ignore') + b'__'
            base = prefix + base

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

    # -------------------------------------------------------------------------
    # URL-safe Base64 / 面料文件名多编码变体
    # -------------------------------------------------------------------------

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
                encodings_to_try.append(self._safe_fsencode(variant))
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

    # -------------------------------------------------------------------------
    # 目录内按 Base64 文件名定位 / 资源相对路径
    # -------------------------------------------------------------------------

    def _entry_name_bytes(self, entry):
        raw = entry.name
        if isinstance(raw, str):
            return self._safe_fsencode(raw)
        return bytes(raw)

    def _b64decode_raw(self, value):
        """Base64 → bytes；无效输入返回 None。"""
        s = str(value or '').strip()
        if not s:
            return None
        try:
            return base64.b64decode(s)
        except Exception:
            return None

    def _resolve_name_b64_in_folder(self, folder, name_raw_b64):
        """
        在 folder 内按 name_raw_b64（文件系统原始字节）定位文件。
        返回 (display_name_str, abs_path_bytes) 或 (None, None)。
        """
        raw_bytes = self._b64decode_raw(name_raw_b64)
        if not raw_bytes:
            return None, None
        folder_b = folder if isinstance(folder, (bytes, bytearray)) else self._safe_fsencode(folder)

        candidates = [raw_bytes]
        name_str = self._decode_fs_name_bytes(raw_bytes)
        if name_str:
            try:
                enc = self._safe_fsencode(name_str)
                if enc not in candidates:
                    candidates.append(enc)
            except Exception:
                pass

        for cand in candidates:
            try:
                src = os.path.join(folder_b, cand)
            except Exception:
                continue
            try:
                if os.path.isfile(src):
                    base = os.path.basename(cand)
                    display = self._decode_fs_name_bytes(base) or name_str or ''
                    return display, src
            except Exception:
                continue
        return None, None

    def _decode_fs_name_bytes(self, raw_bytes):
        if raw_bytes is None:
            return ''
        if isinstance(raw_bytes, str):
            raw_bytes = self._safe_fsencode(raw_bytes)
        try:
            display = os.fsdecode(raw_bytes)
            return display.encode('utf-8', errors='surrogatepass').decode('utf-8', errors='replace')
        except Exception:
            pass
        for enc in ('utf-8', 'gb18030', 'latin-1'):
            try:
                return raw_bytes.decode(enc, errors='replace')
            except Exception:
                continue
        return repr(raw_bytes)

    def _resources_rel_path_b64(self, *parts):
        """相对『上架资源』根目录的路径 bytes → (rel_str, path_b64)。"""
        import base64
        chunks = []
        for part in parts:
            if part is None:
                continue
            if isinstance(part, str):
                text = part.replace('\\', '/').strip('/')
                if not text:
                    continue
                chunks.append(self._safe_fsencode(text))
            else:
                b = bytes(part).strip(b'/\\')
                if b:
                    chunks.append(b)
        if not chunks:
            return '', ''
        rel_b = chunks[0]
        for b in chunks[1:]:
            rel_b = rel_b + b'/' + b
        rel_str = self._safe_fsdecode(rel_b).replace('\\', '/')
        return rel_str, base64.b64encode(rel_b).decode('ascii')

    # -------------------------------------------------------------------------
    # 面料备注标准化 / 安全整数转换
    # -------------------------------------------------------------------------

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
