# -*- coding: utf-8 -*-
"""缂栫爜鍜岃浆鎹㈠伐鍏?Mixin - Unicode/Base64/鏂囦欢绯荤粺缂栫爜澶勭悊"""

import base64
import unicodedata
import os

class EncodingUtilsMixin:
    """缂栫爜銆佽浆鎹㈠拰Unicode澶勭悊宸ュ叿"""

    def _b64_from_fs(self, value):
        """灏嗘枃浠剁郴缁熻矾寰?鍚嶇О杞负 Base64锛堜繚鐣欏師濮嬪瓧鑺傦級"""
        try:
            raw = self._safe_fsencode(value)
        except Exception:
            raw = str(value).encode('utf-8', errors='surrogatepass')
        return base64.b64encode(raw).decode('ascii')

    def _fs_from_b64(self, value):
        """浠?Base64 杩樺師鏂囦欢绯荤粺璺緞/鍚嶇О"""
        raw = base64.b64decode(value)
        return os.fsdecode(raw)

    def _safe_fsencode(self, value):
        """瀹夊叏鐨勬枃浠剁郴缁熻矾寰勭紪鐮?""
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        try:
            return os.fsencode(value)
        except Exception:
            return str(value).encode('utf-8', errors='surrogatepass')

    def _safe_fsdecode(self, value):
        """瀹夊叏鐨勬枃浠剁郴缁熻矾寰勮В鐮?""
        if isinstance(value, str):
            return value
        try:
            return os.fsdecode(value)
        except Exception:
            return bytes(value).decode('utf-8', errors='surrogatepass')

    def _b64url_encode(self, raw):
        """URL瀹夊叏鐨凚ase64缂栫爜"""
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    def _b64url_decode(self, text):
        """URL瀹夊叏鐨凚ase64瑙ｇ爜"""
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
        """鏍囧噯鍖栭潰鏂欏浘鐗囧娉?""
        value = (remark or '').strip()
        allowed = {
            '鍘熷浘',
            '涓诲浘路Swatch',
            '涓诲浘路鍗栫偣',
            'A+路鐢佃剳绔?,
            'A+路鎵嬫満绔?,
            'A+路閫氱敤',
        }
        if value in allowed:
            return value
        if value in ('骞抽潰鍘熷浘', '瑜剁毐鍘熷浘'):
            return '鍘熷浘'
        if '鍗栫偣' in value:
            return '涓诲浘路鍗栫偣'
        if 'Swatch' in value or 'swatch' in value:
            return '涓诲浘路Swatch'
        if 'A+' in value or value.startswith('A锛?):
            if '鐢佃剳' in value:
                return 'A+路鐢佃剳绔?
            if '鎵嬫満' in value:
                return 'A+路鎵嬫満绔?
            return 'A+路閫氱敤'
        return '鍘熷浘'

    def _to_int(self, value, default=None):
        """瀹夊叏鐨勬暣鏁拌浆鎹?""
        try:
            return int(value)
        except Exception:
            return default



