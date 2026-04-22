import re
import io
import cgi
import os
import shutil
import json
import base64
import hashlib
import threading
from email import policy
from email.parser import BytesParser
from datetime import datetime
from urllib.parse import parse_qs

try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)

try:
    import pymysql
except Exception:
    pymysql = None


class SalesProductMixin:
    def _resources_root(self):
        """Return absolute resources root as bytes path."""
        return self._join_resources('')

    def _storage_path_from_abs(self, abs_path):
        """Compute image_assets.storage_path from an absolute resources path."""
        try:
            root = self._resources_root()
            rel_bytes = os.path.relpath(abs_path, root)
            return os.fsdecode(rel_bytes).replace('\\', '/')
        except Exception:
            try:
                return os.fsdecode(abs_path).replace('\\', '/')
            except Exception:
                return str(abs_path)

    def _abs_from_storage_path(self, storage_path):
        return self._join_resources((storage_path or '').strip().replace('\\', '/'))

    def _ensure_listing_sales_common_folder(self, sku_family):
        """Ensure 货号/主图/通用 exists. Return absolute folder path (bytes)."""
        sku_name = (sku_family or '').strip()
        if not sku_name:
            return None
        self._ensure_listing_sku_folder(sku_name)
        base_folder = self._ensure_listing_folder()
        sku_folder = os.path.join(base_folder, self._safe_fsencode(sku_name))
        main_folder = os.path.join(sku_folder, self._safe_fsencode('主图'))
        if not os.path.exists(main_folder):
            os.makedirs(main_folder, exist_ok=True)
        common_folder = os.path.join(main_folder, self._safe_fsencode('通用'))
        if not os.path.exists(common_folder):
            os.makedirs(common_folder, exist_ok=True)
        return common_folder

    def _choose_rehome_target(self, conn, asset_id):
        """
        Decide where an asset should live based on references:
        - If referenced by any fabric -> 『面料』/
        - Else if referenced by multiple variants -> <货号>/主图/通用/
        - Else keep as-is (usually in <货号>/主图/<规格-面料>/)
        Returns absolute folder path (bytes) or None.
        """
        aid = int(asset_id or 0)
        if aid <= 0:
            return None

        fabric_ref = 0
        variant_ids = []
        try:
            with conn.cursor() as cur:
                if self._has_required_tables(['fabric_image_mappings']):
                    cur.execute("SELECT COUNT(*) AS cnt FROM fabric_image_mappings WHERE image_asset_id=%s", (aid,))
                    fabric_ref = self._parse_int((cur.fetchone() or {}).get('cnt')) or 0
        except Exception:
            fabric_ref = 0

        try:
            with conn.cursor() as cur:
                if self._table_has_column(conn, 'sku_image_mappings', 'variant_id'):
                    cur.execute(
                        "SELECT DISTINCT variant_id FROM sku_image_mappings WHERE image_asset_id=%s AND variant_id IS NOT NULL AND variant_id>0",
                        (aid,),
                    )
                    variant_ids = [self._parse_int(r.get('variant_id')) for r in (cur.fetchall() or [])]
                    variant_ids = [v for v in variant_ids if v]
                else:
                    variant_ids = []
        except Exception:
            variant_ids = []

        if fabric_ref > 0:
            return self._join_resources('『面料』')

        if len(set(variant_ids)) > 1:
            # Pick one sku_family from any referenced variant and use its 通用 folder
            try:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT pf.sku_family
                        FROM sales_product_variants v
                        LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                        WHERE v.id=%s
                        LIMIT 1
                        """,
                        (variant_ids[0],),
                    )
                    row = cur.fetchone() or {}
                    sku_family = (row.get('sku_family') or '').strip()
                    if sku_family:
                        return self._ensure_listing_sales_common_folder(sku_family)
            except Exception:
                pass
        return None

    def _rehome_image_asset_if_needed(self, conn, asset_id):
        """
        Move the physical file to its target folder based on references, and update image_assets.storage_path.
        Best-effort: if move fails, keep current path.
        """
        aid = int(asset_id or 0)
        if aid <= 0:
            return None

        with conn.cursor() as cur:
            cur.execute("SELECT id, storage_path FROM image_assets WHERE id=%s LIMIT 1", (aid,))
            asset = cur.fetchone() or {}
        storage_path = (asset.get('storage_path') or '').strip()
        if not storage_path:
            return None
        src_abs = self._abs_from_storage_path(storage_path)
        if not os.path.exists(src_abs):
            return None

        target_folder = self._choose_rehome_target(conn, aid)
        if not target_folder:
            return None
        try:
            src_dir = os.path.dirname(src_abs)
            # Already under target folder
            if os.path.normcase(os.fsdecode(src_dir)) == os.path.normcase(os.fsdecode(target_folder)):
                return None
        except Exception:
            pass

        ext = os.path.splitext(os.path.basename(storage_path))[1] or '.jpg'
        orig = os.path.basename(storage_path)
        base_part = self._sanitize_filename_component(os.path.splitext(orig)[0], 80) or f"image_{aid}"
        filename = f"{base_part}{ext}"
        final_name = self._next_available_filename(target_folder, filename)
        dst_abs = os.path.join(target_folder, self._safe_fsencode(final_name))
        try:
            os.makedirs(os.path.dirname(dst_abs), exist_ok=True)
        except Exception:
            pass

        # Prefer move when src is within resources root (same NAS) to reduce IO.
        moved = False
        try:
            os.replace(src_abs, dst_abs)
            moved = True
        except Exception:
            moved = False

        if not moved:
            # Fallback: copy + keep old
            try:
                with open(src_abs, 'rb') as fsrc:
                    data = fsrc.read()
                with open(dst_abs, 'wb') as fdst:
                    fdst.write(data)
            except Exception:
                return None

        new_storage_path = self._storage_path_from_abs(dst_abs)
        with conn.cursor() as cur:
            cur.execute("UPDATE image_assets SET storage_path=%s WHERE id=%s", (new_storage_path, aid))
        return new_storage_path

    def _sanitize_filename_component(self, text, max_len=80):
        s = str(text or '').strip()
        if not s:
            return ''
        # Keep it filesystem-safe across platforms
        s = s.replace('\\', '-').replace('/', '-').replace('\x00', '')
        for ch in ['<', '>', ':', '"', '|', '?', '*']:
            s = s.replace(ch, '-')
        # Collapse whitespace
        s = re.sub(r'\s+', ' ', s).strip()
        if max_len and len(s) > max_len:
            s = s[:max_len].rstrip()
        return s

    def _next_available_filename(self, folder_abs, filename):
        """
        Ensure filename is unique inside folder_abs.
        Returns a filename (string) without path.
        """
        base = os.path.basename(filename or '').strip()
        if not base:
            base = 'image.jpg'
        name, ext = os.path.splitext(base)
        ext = ext or '.jpg'
        try_names = [base]
        for i in range(2, 1000):
            try_names.append(f"{name}_{i:02d}{ext}")
        for cand in try_names:
            try:
                cand_path = os.path.join(folder_abs, self._safe_fsencode(cand))
            except Exception:
                cand_path = os.path.join(folder_abs, cand.encode('utf-8', errors='surrogatepass'))
            if not os.path.exists(cand_path):
                return cand
        # Fallback
        return f"{name}_{int(datetime.now().timestamp())}{ext}"

    def _try_create_link(self, src_abs, dst_abs):
        """
        Best-effort: create a link/shortcut file in dst_abs pointing to src_abs.
        Prefer hardlink when possible, else symlink. If both fail, do nothing.
        """
        try:
            if os.path.exists(dst_abs):
                return True
        except Exception:
            pass
        # Try hardlink (same filesystem)
        try:
            os.link(src_abs, dst_abs)
            return True
        except Exception:
            pass
        # Try symlink
        try:
            # Make it relative when possible (more portable if folder moved)
            try:
                rel = os.path.relpath(src_abs, os.path.dirname(dst_abs))
            except Exception:
                rel = src_abs
            os.symlink(rel, dst_abs)
            return True
        except Exception:
            return False

    def _tx_begin(self, conn):
        """Begin a transaction even though default is autocommit=True."""
        try:
            conn.autocommit(False)
        except Exception:
            pass
        try:
            conn.begin()
        except Exception:
            # Some drivers start implicitly when autocommit=False
            pass

    def _tx_commit(self, conn):
        try:
            conn.commit()
        except Exception:
            pass
        try:
            conn.autocommit(True)
        except Exception:
            pass

    def _tx_rollback(self, conn):
        try:
            conn.rollback()
        except Exception:
            pass
        try:
            conn.autocommit(True)
        except Exception:
            pass

    def _safe_unlink(self, path_abs):
        try:
            if path_abs and os.path.exists(path_abs):
                os.remove(path_abs)
        except Exception:
            pass

    def _read_wsgi_request_body(self, environ):
        """Read request body bytes as reliably as possible for multipart uploads."""
        try:
            length = int(environ.get('CONTENT_LENGTH', 0) or 0)
        except Exception:
            length = 0
        stream = environ.get('wsgi.input')
        if not stream:
            return b''
        if length > 0:
            try:
                return stream.read(length) or b''
            except Exception:
                return b''
        # Chunked / missing CONTENT_LENGTH: read until EOF (best-effort).
        try:
            chunks = []
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b''.join(chunks)
        except Exception:
            return b''

    def _parse_multipart_uploads_fallback(self, content_type, raw_body):
        """
        Fallback multipart parser when cgi.FieldStorage fails to enumerate file parts.
        Returns list of dicts: {filename, content}
        """
        uploads = []
        if not raw_body:
            return uploads
        ct = (content_type or '').lower()
        if 'multipart/form-data' not in ct:
            return uploads
        boundary = None
        for part in (content_type or '').split(';'):
            part = part.strip()
            if part.lower().startswith('boundary='):
                boundary = part.split('=', 1)[1].strip().strip('"')
                break
        if not boundary:
            return uploads

        # RFC2046: boundary lines are prefixed with "--"
        delim = (b'--' + boundary.encode('utf-8', errors='ignore'))
        segments = raw_body.split(delim)
        for seg in segments:
            seg = seg.strip(b'\r\n')
            if not seg:
                continue
            if seg == b'--':
                continue
            header_blob, _, body_blob = seg.partition(b'\r\n\r\n')
            if not header_blob or body_blob is None:
                continue
            try:
                msg = BytesParser(policy=policy.default).parsebytes(header_blob + b'\r\n\r\n')
            except Exception:
                continue
            disp = (msg.get('Content-Disposition') or '').lower()
            if 'form-data' not in disp or 'filename=' not in disp:
                continue
            filename = ''
            m = re.search(r'filename\*=UTF-8\'\'([^;]+)', disp)
            if m:
                try:
                    from urllib.parse import unquote
                    filename = unquote(m.group(1).strip().strip('"'))
                except Exception:
                    filename = m.group(1).strip().strip('"')
            if not filename:
                m2 = re.search(r'filename="([^"]+)"', disp)
                if m2:
                    filename = m2.group(1)
                else:
                    m3 = re.search(r'filename=([^;]+)', disp)
                    if m3:
                        filename = m3.group(1).strip().strip('"')
            filename = (filename or '').strip()
            if not filename:
                continue
            content = body_blob
            if content.endswith(b'\r\n'):
                content = content[:-2]
            elif content.endswith(b'\n'):
                content = content[:-1]
            uploads.append({'filename': filename, 'content': content or b''})
        return uploads

    def _table_has_column(self, conn, table_name, column_name):
        cache = getattr(self, '_schema_column_exists_cache', None)
        if cache is None:
            cache = {}
            self._schema_column_exists_cache = cache
        key = (str(table_name), str(column_name))
        if key in cache:
            return cache[key]
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = %s
                  AND COLUMN_NAME = %s
                """,
                (table_name, column_name)
            )
            row = cur.fetchone() or {}
        exists = int(row.get('cnt') or 0) > 0
        cache[key] = exists
        return exists

    def _sales_product_shop_expr(self, has_shop_col, sales_alias='sp', parent_alias='p'):
        if has_shop_col:
            return f"COALESCE({parent_alias}.shop_id, {sales_alias}.shop_id)"
        return f"{parent_alias}.shop_id"

    def handle_parent_api(self, environ, method, start_response):
        """父体管理 API（CRUD）"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            def limited_text(value, max_len):
                text = (value or '').strip()
                if not text:
                    return None
                if len(text) > max_len:
                    raise ValueError(f'文本长度超限（>{max_len}）')
                return text

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = """
                            SELECT sp.id, sp.parent_code, sp.is_enabled, sp.shop_id, sp.sku_marker,
                                   estimated_refund_rate, estimated_discount_rate,
                                   commission_rate, estimated_acoas,
                                   sp.created_at, sp.updated_at,
                                   s.shop_name, b.name AS brand_name, pt.name AS platform_type_name
                            FROM sales_parents sp
                            LEFT JOIN shops s ON s.id = sp.shop_id
                            LEFT JOIN brands b ON b.id = s.brand_id
                            LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                        """
                        params = []
                        filters = []
                        if item_id:
                            filters.append("sp.id = %s")
                            params.append(item_id)
                        if keyword:
                            like_kw = f"%{keyword}%"
                            filters.append("(sp.parent_code LIKE %s OR sp.sku_marker LIKE %s)")
                            params.extend([like_kw, like_kw])
                        if filters:
                            sql += " WHERE " + " AND ".join(filters)
                        sql += " ORDER BY sp.id DESC"
                        cur.execute(sql, params)
                        rows = cur.fetchall() or []
                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                parent_code = (data.get('parent_code') or '').strip()
                if not parent_code:
                    return self.send_json({'status': 'error', 'message': 'Missing parent_code'}, start_response)
                is_enabled_raw = data.get('is_enabled', 1)
                is_enabled = 1 if str(is_enabled_raw).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                shop_id = self._parse_int(data.get('shop_id'))
                try:
                    sku_marker = limited_text(data.get('sku_marker'), 128)
                except ValueError as ve:
                    return self.send_json({'status': 'error', 'message': str(ve)}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_parents
                            (parent_code, is_enabled, shop_id, sku_marker, estimated_refund_rate, estimated_discount_rate, commission_rate, estimated_acoas)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                parent_code,
                                is_enabled,
                                shop_id,
                                sku_marker,
                                self._parse_float(data.get('estimated_refund_rate')),
                                self._parse_float(data.get('estimated_discount_rate')),
                                self._parse_float(data.get('commission_rate')),
                                self._parse_float(data.get('estimated_acoas'))
                            )
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                is_enabled_raw = data.get('is_enabled', 1)
                is_enabled = 1 if str(is_enabled_raw).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                shop_id = self._parse_int(data.get('shop_id'))
                try:
                    sku_marker = limited_text(data.get('sku_marker'), 128)
                except ValueError as ve:
                    return self.send_json({'status': 'error', 'message': str(ve)}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE sales_parents
                            SET parent_code=%s,
                                is_enabled=%s,
                                shop_id=%s,
                                sku_marker=%s,
                                estimated_refund_rate=%s,
                                estimated_discount_rate=%s,
                                commission_rate=%s,
                                estimated_acoas=%s
                            WHERE id=%s
                            """,
                            (
                                (data.get('parent_code') or '').strip(),
                                is_enabled,
                                shop_id,
                                sku_marker,
                                self._parse_float(data.get('estimated_refund_rate')),
                                self._parse_float(data.get('estimated_discount_rate')),
                                self._parse_float(data.get('commission_rate')),
                                self._parse_float(data.get('estimated_acoas')),
                                item_id
                            )
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_parents WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_template_api(self, environ, method, start_response):
        """销售产品模板下载"""
        try:
            if method not in ('GET', 'POST'):
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
            
            from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
            from openpyxl.worksheet.datavalidation import DataValidation

            def _append_ids_from_value(container, value):
                if isinstance(value, list):
                    for v in value:
                        _append_ids_from_value(container, v)
                    return
                text = str(value or '').strip()
                if not text:
                    return
                for token in re.split(r'[,，;；\s]+', text):
                    if not token:
                        continue
                    item_id = self._parse_int(token)
                    if item_id and item_id not in container:
                        container.append(item_id)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            selected_ids = []
            for raw in query_params.get('ids', []):
                _append_ids_from_value(selected_ids, raw)

            if method == 'POST':
                body = self._read_json_body(environ) or {}
                _append_ids_from_value(selected_ids, body.get('ids'))
            
            wb = Workbook()
            ws = wb.active
            ws.title = 'sales_products'

            # 获取可选项
            with self._get_db_connection() as conn:
                sp_has_shop_col = self._table_has_column(conn, 'sales_products', 'shop_id')
                shop_expr = self._sales_product_shop_expr(sp_has_shop_col, sales_alias='sp', parent_alias='pa')

                def _load_sales_template_options():
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, shop_name FROM shops ORDER BY shop_name")
                        shop_options_local = [row for row in (cur.fetchall() or []) if row.get('shop_name')]
                        cur.execute("SELECT parent_code FROM sales_parents ORDER BY parent_code")
                        parent_codes_local = [row['parent_code'] for row in cur.fetchall()]
                        cur.execute("SELECT sku_family FROM product_families ORDER BY sku_family")
                        sku_family_local = [str(row['sku_family']).strip() for row in (cur.fetchall() or []) if row.get('sku_family')]
                        cur.execute("SELECT DISTINCT spec_name FROM sales_product_variants WHERE spec_name IS NOT NULL AND TRIM(spec_name) <> '' ORDER BY spec_name")
                        spec_name_local = [str(row.get('spec_name') or '').strip() for row in (cur.fetchall() or []) if str(row.get('spec_name') or '').strip()]
                        if self._table_has_column(conn, 'sales_product_variants', 'fabric'):
                            cur.execute("SELECT DISTINCT fabric FROM sales_product_variants WHERE fabric IS NOT NULL AND TRIM(fabric) <> '' ORDER BY fabric")
                            fabric_local = [str(row['fabric']).strip() for row in (cur.fetchall() or []) if row.get('fabric')]
                        else:
                            fabric_local = []
                    return (shop_options_local, parent_codes_local, sku_family_local, spec_name_local, fabric_local)

                shop_options, parent_codes, sku_family_options, spec_name_options, fabric_options = self._get_cached_template_options(
                    'sales_product_template_options_v2',
                    _load_sales_template_options,
                    ttl_seconds=180
                )

                export_rows = []
                if selected_ids:
                    placeholders = ','.join(['%s'] * len(selected_ids))
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT sp.id, sp.product_status, sh.shop_name, pa.parent_code, pa.sku_marker,
                                sp.platform_sku, sp.child_code,
                                pf.sku_family, v.spec_name, {('COALESCE(fm.fabric_code, v.fabric)' if (self._table_has_column(conn,'sales_product_variants','fabric_id') and self._table_has_column(conn,'sales_product_variants','fabric')) else ('fm.fabric_code' if self._table_has_column(conn,'sales_product_variants','fabric_id') else ('v.fabric' if self._table_has_column(conn,'sales_product_variants','fabric') else "''")))} AS fabric,
                                v.sale_price_usd
                            FROM sales_products sp
                            LEFT JOIN sales_parents pa ON pa.id = sp.parent_id
                            LEFT JOIN shops sh ON sh.id = {shop_expr}
                            LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                            LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                            {("LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if self._table_has_column(conn,'sales_product_variants','fabric_id') else "")}
                            WHERE sp.id IN ({placeholders})
                            ORDER BY sp.id DESC
                            """,
                            selected_ids
                        )
                        rows = cur.fetchall() or []
                        cur.execute(
                            f"""
                            SELECT sp.id AS sales_product_id, op.sku, l.quantity
                            FROM sales_products sp
                            JOIN sales_variant_order_links l ON l.variant_id = sp.variant_id
                            JOIN order_products op ON op.id = l.order_product_id
                            WHERE sp.id IN ({placeholders})
                            ORDER BY sp.id, op.sku
                            """,
                            selected_ids
                        )
                        link_rows = cur.fetchall() or []
                    link_map = {}
                    for link in link_rows:
                        sp_id = self._parse_int(link.get('sales_product_id')) or 0
                        if not sp_id:
                            continue
                        sku = str(link.get('sku') or '').strip()
                        qty = self._parse_int(link.get('quantity')) or 1
                        if not sku:
                            continue
                        link_map.setdefault(sp_id, []).append(f"{sku}*{qty}")
                    for row in rows:
                        row_id = self._parse_int(row.get('id')) or 0
                        export_rows.append([
                            {'enabled': '启用', 'retained': '留用', 'discarded': '弃用'}.get(str(row.get('product_status') or '').strip(), '启用'),
                            row.get('shop_name') or '',
                            row.get('parent_code') or '',
                            row.get('sku_marker') or '',
                            row.get('platform_sku') or '',
                            row.get('child_code') or '',
                            row.get('sku_family') or '',
                            row.get('spec_name') or '',
                            row.get('fabric') or '',
                            '\n'.join(link_map.get(row_id, [])),
                            row.get('sale_price_usd') or ''
                        ])
            
            # 第1行：模块标题（合并单元格）
            section_headers = [
                ('产品状态', 1, 1),
                ('父体关联', 2, 4),
                ('基础信息', 5, 9),
                ('销售信息', 10, 10)
            ]
            # 第2行：字段标题
            cn_headers = [
                '产品状态(启用/留用/弃用)',
                '店铺(必填)', '父体编号', '新父体SKU标识(父体不存在时选填)',
                '销售平台SKU', '子体编号', '货号', '规格名称', '面料',
                '关联下单SKU及数量(必填，支持换行|;分隔，示例:MS01A-Brown*2)',
                '售价(USD)'
            ]

            ws.append([''] * len(cn_headers))
            ws.append(cn_headers)
            header_font = Font(bold=True, color='2A2420', size=11)
            header_alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            thin_border = Border(
                left=Side(style='thin', color='B7AEA4'),
                right=Side(style='thin', color='B7AEA4'),
                top=Side(style='thin', color='B7AEA4'),
                bottom=Side(style='thin', color='B7AEA4')
            )

            header_fill_by_col = ['D3D3D3'] * len(cn_headers)
            for col in range(1, len(cn_headers) + 1):
                cell = ws.cell(row=1, column=col)
                cell.font = header_font
                cell.alignment = header_alignment
                cell.border = thin_border

            for idx, (title, start_col, end_col) in enumerate(section_headers):
                if end_col > start_col:
                    ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=end_col)
                ws.cell(row=1, column=start_col).value = title
                if hasattr(self, '_get_morandi_section_color_pair'):
                    title_color, sub_header_color = self._get_morandi_section_color_pair(idx)
                else:
                    palette = [('A8B9A5', 'DDE7DB'), ('D7C894', 'ECE5CE')]
                    title_color, sub_header_color = palette[idx % len(palette)]
                fill = PatternFill(start_color=title_color, end_color=title_color, fill_type='solid')
                for col in range(start_col, end_col + 1):
                    header_fill_by_col[col - 1] = sub_header_color
                    ws.cell(row=1, column=col).fill = fill
                    ws.cell(row=1, column=col).border = thin_border

            for idx, cell in enumerate(ws[2], start=1):
                header_color = header_fill_by_col[idx - 1] if idx - 1 < len(header_fill_by_col) else 'D3D3D3'
                header_fill = PatternFill(start_color=header_color, end_color=header_color, fill_type='solid')
                cell.fill = header_fill
                cell.font = header_font
                cell.alignment = header_alignment
                cell.border = thin_border
            
            # 第3行固定为示例行，勾选导出数据从第4行起追加，避免覆盖示例
            ws.append([
                '启用',
                '',
                'PARENT-001',
                'MS01-MARKER',
                'MS01-Brown-1A',
                'CHILD-001',
                'MS01',
                'A款',
                '棕色/Brown',
                'Recliner Sofa for Living Room',
                'MS01A-Brown*2\nMS01B-Gray',
                199.99
            ])
            example_fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
            example_font = Font(italic=True, color='888888')
            for cell in ws[3]:
                cell.fill = example_fill
                cell.font = example_font
            if export_rows:
                for row in export_rows:
                    ws.append(row)
            
            # 添加数据验证
            status_validation = DataValidation(type='list', formula1='"启用,留用,弃用"', allow_blank=True)
            ws.add_data_validation(status_validation)
            max_validation_row = 400
            for row in range(4, max_validation_row + 1):
                status_validation.add(f'A{row}')

            if shop_options:
                shop_names = [str(row.get('shop_name')).strip() for row in shop_options if row.get('shop_name')]
                shop_names = [name for name in shop_names if name]
                if shop_names:
                    shop_validation = DataValidation(type='list', formula1=f'"{",".join(shop_names[:100])}"', allow_blank=False)
                    ws.add_data_validation(shop_validation)
                    for row in range(4, max_validation_row + 1):
                        shop_validation.add(f'B{row}')

            if sku_family_options:
                sku_validation = DataValidation(type='list', formula1=f'"{",".join(sku_family_options[:100])}"', allow_blank=True)
                ws.add_data_validation(sku_validation)
                for row in range(4, max_validation_row + 1):
                    sku_validation.add(f'G{row}')

            if spec_name_options:
                spec_validation = DataValidation(type='list', formula1=f'"{",".join(spec_name_options[:100])}"', allow_blank=True)
                ws.add_data_validation(spec_validation)
                for row in range(4, max_validation_row + 1):
                    spec_validation.add(f'H{row}')

            if fabric_options:
                fabric_validation = DataValidation(type='list', formula1=f'"{",".join(fabric_options[:100])}"', allow_blank=True)
                ws.add_data_validation(fabric_validation)
                for row in range(4, max_validation_row + 1):
                    fabric_validation.add(f'I{row}')

            if parent_codes:
                parent_validation = DataValidation(type='list', formula1=f'"{",".join(parent_codes[:100])}"', allow_blank=True)
                ws.add_data_validation(parent_validation)
                for row in range(4, max_validation_row + 1):
                    parent_validation.add(f'C{row}')
            
            
            # 设置列宽
            ws.column_dimensions['A'].width = 16
            ws.column_dimensions['B'].width = 12
            ws.column_dimensions['G'].width = 14
            ws.column_dimensions['D'].width = 22
            ws.column_dimensions['I'].width = 16
            ws.column_dimensions['J'].width = 34
            ws.column_dimensions['K'].width = 14
            ws.column_dimensions['P'].width = 14
            ws.column_dimensions['Q'].width = 14
            ws.column_dimensions['R'].width = 14
            ws.column_dimensions['S'].width = 14
            ws.column_dimensions['T'].width = 14
            
            ws.freeze_panes = 'A4'
            
            return self._send_excel_workbook(wb, 'sales_product_template.xlsx', start_response)
        except Exception as e:
            # 下载接口兜底：即使数据查询异常，也返回可打开的模板文件，避免浏览器进入 500 错误页
            try:
                if Workbook is not None:
                    wb = Workbook()
                    ws = wb.active
                    ws.title = 'sales_products'
                    ws.append(['提示'])
                    ws.append(['模板已降级生成，请联系管理员检查服务器日志'])
                    ws.append([f'错误信息: {str(e)}'])
                    return self._send_excel_workbook(wb, 'sales_product_template_fallback.xlsx', start_response)
            except Exception:
                pass
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_import_api(self, environ, method, start_response):
        """销售产品批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            preview_mode = str((query_params.get('preview', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            file_bytes = self._sanitize_xlsx_bool_cells(file_bytes)

            try:
                wb = load_workbook(io.BytesIO(file_bytes))
            except Exception as e:
                if 'Cannot be converted to bool' in str(e):
                    wb = self._rebuild_workbook_from_xlsx_xml(file_bytes)
                    if wb is None:
                        diag = self._scan_xlsx_invalid_bool_cells(file_bytes)
                        return self.send_json({
                            'status': 'error',
                            'message': (
                                '导入失败：文件中存在异常布尔字段且无法自动修复，'
                                '请另存为新的xlsx后重试'
                            ),
                            'debug': {
                                'cause': 'Cannot be converted to bool',
                                'invalid_bool_cells': diag.get('count', 0),
                                'samples': diag.get('samples', [])
                            }
                        }, start_response)
                else:
                    return self.send_json({'status': 'error', 'message': str(e)}, start_response)

            for sheet in wb.worksheets:
                for row in sheet.iter_rows():
                    for cell in row:
                        if cell.data_type == 'b' and not isinstance(cell.value, bool):
                            cell.data_type = 's'
                            cell.value = str(cell.value)

            ws = wb.active

            # 智能检测标题行：扫描前5行，找到包含关键字段的行作为标题行
            header_row_idx = 1
            key_indicators = ['店铺', '销售平台SKU', '父体编号', '关联下单SKU', 'shop', 'platform_sku', 'parent_code']
            for row_check in range(1, min(6, ws.max_row + 1)):
                row_cells = [str(cell.value or '').strip() for cell in ws[row_check]]
                row_text = '|'.join(row_cells).lower()
                # 检查是否包含关键指示字段
                if any(key.lower() in row_text for key in key_indicators):
                    header_row_idx = row_check
                    break
            
            headers = [cell.value for cell in ws[header_row_idx]]
            
            # 中文标签到字段代码的映射
            label_to_code = {
                '产品状态(启用/留用/弃用)': 'product_status',
                '店铺(必填)': 'shop_name',
                '店铺(可选)': 'shop_name',
                '店铺': 'shop_name',
                '平台SKU': 'platform_sku',
                '销售平台SKU': 'platform_sku',
                '父体编号': 'parent_code',
                '新父体SKU标识(父体不存在时选填)': 'parent_sku_marker',
                '子体编号': 'child_code',
                '货号': 'sku_family',
                '面料(选填)': 'fabric',
                '规格名(选填)': 'spec_name',
                '面料': 'fabric',
                '规格名称': 'spec_name',
                '关联下单SKU\n(支持换行|;分隔)': 'order_sku_links',
                '关联下单SKU及数量(必填，支持换行|;分隔，示例:MS01A-Brown*2)': 'order_sku_links',
                '售价(USD)': 'sale_price_usd',
                '组装后长(in)': 'finished_length_in',
                '组装后宽(in)': 'finished_width_in',
                '组装后高(in)': 'finished_height_in',
                # 兼容旧字段名
                'shop_name': 'shop_name',
                'brand_name': 'brand_name',
                'platform_type': 'platform_type',
                'product_status': 'product_status',
                'platform_sku': 'platform_sku',
                'parent_asin': 'parent_code',
                'child_asin': 'child_code',
                'sku_family': 'sku_family',
                'fabric': 'fabric',
                'spec_name': 'spec_name',
                'sale_price_usd': 'sale_price_usd',
                'finished_length_in': 'finished_length_in',
                'finished_width_in': 'finished_width_in',
                'finished_height_in': 'finished_height_in',
                'assembled_length_in': 'finished_length_in',
                'assembled_width_in': 'finished_width_in',
                'assembled_height_in': 'finished_height_in',
                'order_sku_links': 'order_sku_links'
            }
            
            # 构建列映射，支持中文和旧格式
            header_map = {}
            for idx, h in enumerate(headers):
                if h is not None:
                    h_str = str(h).strip()
                    if h_str:  # 只处理非空的列标题
                        field_code = label_to_code.get(h_str, h_str)
                        if field_code not in header_map:  # 避免后面的重复列覆盖前面的
                            header_map[field_code] = idx
            
            # 诊断：保存所有读到的列（含None和空值）供调试
            detected_headers = [str(h).strip() if h else '[空]' for h in headers]
            detected_headers_non_empty = [h for h in detected_headers if h != '[空]']
            has_shop_name_column = 'shop_name' in header_map

            # 如果预检发现没有shop_name列，立即返回诊断信息
            if not has_shop_name_column:
                return self.send_json({
                    'status': 'error',
                    'message': (
                        f'导入失败：找不到店铺列。系统在第 {header_row_idx} 行检测到了以下列标题：\n'
                        f'{", ".join(detected_headers_non_empty) if detected_headers_non_empty else "[无有效列标题]"}\n\n'
                        f'请确保Excel中包含"店铺(必填)"或"店铺"列。'
                        f'如果列标题位置与预期不符，请重新下载模板并按照模板格式整理数据。'
                    ),
                    'detected_headers': detected_headers,
                    'detected_header_row': header_row_idx,
                    'detected_headers_count': len(detected_headers_non_empty),
                    'expected_shop_column_names': ['店铺(必填)', '店铺(可选)', '店铺', 'shop_name']
                }, start_response)

            def get_cell(row, key):
                idx = header_map.get(key)
                if idx is None:
                    return None
                return row[idx].value

            def parse_links(raw):
                """解析 order_sku_links：支持换行/分号/竖线/逗号分隔，重复SKU自动汇总数量"""
                if raw is None:
                    return []
                text = str(raw).strip()
                if not text:
                    return []
                
                # 支持换行符、分号、竖线、逗号分隔
                parts = [t.strip() for t in re.split(r'[\n\r;；|,，]+', text) if t.strip()]
                sku_qty_map = {}
                
                for part in parts:
                    if '*' in part:
                        sku, qty = part.split('*', 1)
                    else:
                        sku, qty = part, None
                    
                    sku = sku.strip()
                    if not sku:
                        continue
                    
                    if qty is None:
                        qty_val = 1
                    else:
                        qty = qty.strip()
                        try:
                            qty_val = int(qty) if qty else 1
                        except Exception:
                            qty_val = 1

                    sku_qty_map[sku] = sku_qty_map.get(sku, 0) + max(1, qty_val)

                return [(sku, qty) for sku, qty in sku_qty_map.items() if qty > 0]

            with self._get_db_connection() as conn:
                sp_has_shop_col = self._table_has_column(conn, 'sales_products', 'shop_id')

                tx_enabled = False
                if not preview_mode:
                    try:
                        conn.autocommit(False)
                        tx_enabled = True
                    except Exception:
                        tx_enabled = False

                with conn.cursor() as cur:
                    cur.execute("SELECT id, parent_code, shop_id FROM sales_parents")
                    parent_map = {
                        (int(row.get('shop_id') or 0), str(row.get('parent_code') or '').strip()): row
                        for row in (cur.fetchall() or []) if row.get('parent_code')
                    }

                    cur.execute("SELECT id, shop_name FROM shops")
                    shop_map = {str(row['shop_name']).strip(): row['id'] for row in (cur.fetchall() or []) if row.get('shop_name')}

                    cur.execute(
                        """
                        SELECT op.id, op.sku, op.sku_family_id, op.spec_qty_short,
                               op.cost_usd, op.last_mile_avg_freight_usd,
                               op.finished_length_in, op.finished_width_in, op.finished_height_in,
                               op.package_length_in, op.package_width_in, op.package_height_in,
                               op.net_weight_lbs, op.gross_weight_lbs,
                               fm.fabric_code, fm.fabric_name_en
                        FROM order_products op
                        LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                        """
                    )
                    order_rows = cur.fetchall() or []
                    order_map = {row['sku']: row['id'] for row in order_rows if row.get('sku')}
                    order_detail_by_id = {row['id']: row for row in order_rows if row.get('id')}

                    cur.execute("SELECT id, sku_family FROM product_families")
                    sku_family_rows = cur.fetchall() or []
                    sku_family_map = {str(row['sku_family']).strip(): row['id'] for row in sku_family_rows if row.get('sku_family')}
                    sku_family_code_map = {row['id']: (row.get('sku_family') or '').strip() for row in sku_family_rows if row.get('id')}

                    if sp_has_shop_col:
                        cur.execute("SELECT id, shop_id, platform_sku FROM sales_products")
                    else:
                        cur.execute(
                            """
                            SELECT sp.id, p.shop_id, sp.platform_sku
                            FROM sales_products sp
                            LEFT JOIN sales_parents p ON p.id = sp.parent_id
                            """
                        )
                    sales_map = {(int(row.get('shop_id') or 0), str(row.get('platform_sku') or '').strip()): int(row.get('id') or 0) for row in (cur.fetchall() or []) if row.get('platform_sku')}

                    cur.execute("SELECT id, sku_family_id, spec_name, fabric FROM sales_product_variants")
                    variant_identity_map = {
                        (int(row.get('sku_family_id') or 0), str(row.get('spec_name') or '').strip(), str(row.get('fabric') or '').strip()): int(row.get('id') or 0)
                        for row in (cur.fetchall() or []) if row.get('id')
                    }

                created = 0
                updated = 0
                unchanged = 0
                relation_created = 0
                relation_deleted = 0
                total_rows = 0
                errors = []
                data_start_row = header_row_idx + 2

                with conn.cursor() as row_cur:
                    for row_idx in range(data_start_row, ws.max_row + 1):
                        row = ws[row_idx]
                        row_values = [cell.value for cell in row]
                        if not any(v is not None and str(v).strip() for v in row_values):
                            continue
                        total_rows += 1

                        # 支持两种格式：新的合并列 vs 旧的分开列
                        platform_sku = (get_cell(row, 'platform_sku') or '').strip()
                        product_status_text = (get_cell(row, 'product_status') or '').strip()
                        status_map = {'启用': 'enabled', '留用': 'retained', '弃用': 'discarded'}
                        product_status = status_map.get(product_status_text, (product_status_text or 'enabled').lower())
                        if product_status not in ('enabled', 'retained', 'discarded'):
                            product_status = 'enabled'
                        parent_code = (get_cell(row, 'parent_code') or '').strip() or None
                        parent_sku_marker = (get_cell(row, 'parent_sku_marker') or '').strip() or None
                        child_code = (get_cell(row, 'child_code') or '').strip() or None
                        sku_family_name = (get_cell(row, 'sku_family') or '').strip() or None
                        fabric = (get_cell(row, 'fabric') or '').strip()
                        spec_name = (get_cell(row, 'spec_name') or '').strip()
                        sale_price_usd = self._parse_float(get_cell(row, 'sale_price_usd'))
                        order_sku_links = (get_cell(row, 'order_sku_links') or '').strip()

                        shop_name_text = (get_cell(row, 'shop_name') or '').strip()
                        if not shop_name_text:
                            errors.append({'row': row_idx, 'error': 'Missing shop_name'})
                            continue
                        shop_id_from_file = shop_map.get(shop_name_text)
                        if not shop_id_from_file:
                            errors.append({'row': row_idx, 'error': f'Unknown shop_name: {shop_name_text}'})
                            continue

                        parent_row = None
                        parent_id = None
                        if parent_code:
                            parent_key = (int(shop_id_from_file), parent_code)
                            parent_row = parent_map.get(parent_key)
                            if not parent_row:
                                if preview_mode:
                                    parent_row = {'id': None, 'parent_code': parent_code, 'shop_id': shop_id_from_file}
                                    parent_map[parent_key] = parent_row
                                else:
                                    row_cur.execute(
                                        """
                                        INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                        VALUES (%s, %s, %s)
                                        """,
                                        (parent_code, shop_id_from_file, parent_sku_marker)
                                    )
                                    new_parent_id = row_cur.lastrowid
                                    parent_row = {'id': new_parent_id, 'parent_code': parent_code, 'shop_id': shop_id_from_file}
                                    parent_map[parent_key] = parent_row

                            shop_id = parent_row.get('shop_id')
                            if not shop_id:
                                if (not preview_mode) and parent_row.get('id'):
                                    row_cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_from_file, parent_row['id']))
                                shop_id = shop_id_from_file
                                parent_row['shop_id'] = shop_id
                            elif int(shop_id) != int(shop_id_from_file):
                                errors.append({'row': row_idx, 'error': f'Parent/shop mismatch: {parent_code} -> {shop_name_text}'})
                                continue

                            parent_id = parent_row.get('id')
                        else:
                            shop_id = shop_id_from_file

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

                        derived = self._derive_sales_cost_size(conn, link_entries)
                        auto_fabric, auto_spec_name, _auto_platform = self._derive_sales_fields(conn, derived.get('sku_family_id'), link_entries)
                        sku_family_id = sku_family_map.get(sku_family_name) if sku_family_name else derived.get('sku_family_id')
                        if sku_family_name and not sku_family_id:
                            errors.append({'row': row_idx, 'error': f'Unknown sku_family: {sku_family_name}'})
                            continue
                        if not sku_family_id:
                            errors.append({'row': row_idx, 'error': '无法根据订单SKU推断归属货号'})
                            continue

                        auto_platform_sku = ''
                        sku_family_code = sku_family_code_map.get(sku_family_id) or ''
                        if sku_family_code and auto_fabric and auto_spec_name:
                            auto_platform_sku = self._build_sales_platform_sku(sku_family_code, auto_spec_name, auto_fabric)

                        final_fabric = fabric or auto_fabric
                        final_spec_name = spec_name or auto_spec_name
                        final_platform_sku = platform_sku or auto_platform_sku

                        if not final_platform_sku:
                            errors.append({'row': row_idx, 'error': 'Platform SKU missing'})
                            continue

                        variant_key = (int(sku_family_id), str(final_spec_name or '').strip(), str(final_fabric or '').strip())
                        if preview_mode:
                            if sales_map.get((int(shop_id), final_platform_sku)):
                                updated += 1
                            else:
                                created += 1
                            continue

                        try:
                            variant_id = variant_identity_map.get(variant_key)
                            if not variant_id:
                                variant_id = self._get_or_create_sales_variant(conn, sku_family_id, final_spec_name, final_fabric, sale_price_usd)
                                variant_identity_map[variant_key] = variant_id
                            else:
                                with conn.cursor() as vcur:
                                    vcur.execute("UPDATE sales_product_variants SET sale_price_usd=COALESCE(%s, sale_price_usd) WHERE id=%s", (sale_price_usd, variant_id))

                            target_id = sales_map.get((int(shop_id), final_platform_sku))
                            if target_id:
                                update_fields = [
                                    "platform_sku=%s",
                                    "product_status=%s",
                                    "variant_id=%s",
                                    "parent_id=%s",
                                    "child_code=%s"
                                ]
                                update_values = [final_platform_sku, product_status, variant_id, parent_id, child_code]
                                if sp_has_shop_col:
                                    update_fields.insert(0, "shop_id=%s")
                                    update_values.insert(0, shop_id)
                                update_values.append(target_id)
                                row_cur.execute(
                                    f"UPDATE sales_products SET {', '.join(update_fields)} WHERE id=%s",
                                    update_values
                                )
                                updated += 1
                            else:
                                insert_columns = []
                                insert_values = []
                                if sp_has_shop_col:
                                    insert_columns.append('shop_id')
                                    insert_values.append(shop_id)
                                insert_columns.extend(['platform_sku', 'product_status'])
                                insert_values.extend([final_platform_sku, product_status])
                                insert_columns.extend(['variant_id', 'parent_id', 'child_code'])
                                insert_values.extend([variant_id, parent_id, child_code])
                                placeholders_insert = ', '.join(['%s'] * len(insert_columns))
                                row_cur.execute(
                                    f"INSERT INTO sales_products ({', '.join(insert_columns)}) VALUES ({placeholders_insert})",
                                    insert_values
                                )
                                target_id = row_cur.lastrowid
                                sales_map[(int(shop_id), final_platform_sku)] = target_id
                                created += 1
                            self._replace_sales_variant_order_links(conn, variant_id, link_entries)
                            relation_created += len(link_entries)
                                    
                        except Exception as e:
                            errors.append({'row': row_idx, 'error': str(e)})

                if tx_enabled:
                    conn.commit()
                    conn.autocommit(True)

            return self.send_json({
                'status': 'success',
                'preview': 1 if preview_mode else 0,
                'total_rows': total_rows,
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'relation_created': relation_created,
                'relation_added': relation_created,
                'relation_deleted': relation_deleted,
                'errors': errors
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)


    def handle_sales_product_api(self, environ, method, start_response):
        """销售产品管理 API（CRUD）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                include_links = str((query_params.get('include_links', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                with self._get_db_connection() as conn:
                    sp_has_shop_col = self._table_has_column(conn, 'sales_products', 'shop_id')
                    shop_expr = self._sales_product_shop_expr(sp_has_shop_col)
                    with conn.cursor() as cur:
                        has_fabric_id = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
                        has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                        fabric_join = "LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if has_fabric_id else ""
                        if has_fabric_id and has_fabric_text:
                            fabric_select = "COALESCE(fm.fabric_code, v.fabric)"
                        elif has_fabric_id:
                            fabric_select = "fm.fabric_code"
                        else:
                            fabric_select = "v.fabric" if has_fabric_text else "''"
                        base_sql = """
                            SELECT
                                sp.id,
                                {shop_expr} AS shop_id,
                                sp.platform_sku,
                                sp.product_status,
                                sp.parent_id,
                                sp.child_code,
                                sp.variant_id,
                                v.sku_family_id,
                                pf.sku_family,
                                v.spec_name,
                                {fabric_select} AS fabric,
                                {fabric_id_select} AS fabric_id,
                                v.sale_price_usd,
                                sp.created_at,
                                sp.updated_at,
                                s.shop_name,
                                pt.name AS platform_type_name,
                                b.name AS brand_name,
                                p.parent_code
                            FROM sales_products sp
                            LEFT JOIN sales_parents p ON p.id = sp.parent_id
                            LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                            LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                            {fabric_join}
                            LEFT JOIN shops s ON s.id = {shop_expr}
                            LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                            LEFT JOIN brands b ON b.id = s.brand_id
                        """.format(
                            shop_expr=shop_expr,
                            fabric_join=fabric_join,
                            fabric_select=fabric_select,
                            fabric_id_select=("v.fabric_id" if has_fabric_id else "NULL"),
                        )
                        filters = []
                        params = []
                        if item_id:
                            filters.append("sp.id = %s")
                            params.append(item_id)
                        if keyword:
                            text_filters = [
                                "sp.platform_sku LIKE %s",
                                "s.shop_name LIKE %s",
                                "p.parent_code LIKE %s",
                                "sp.child_code LIKE %s",
                                "pf.sku_family LIKE %s",
                                "v.spec_name LIKE %s",
                                f"{fabric_select} LIKE %s",
                            ]
                            params.extend([f"%{keyword}%"] * 7)
                            if has_fabric_text:
                                text_filters.append("v.fabric LIKE %s")
                                params.append(f"%{keyword}%")
                            filters.append("(" + " OR ".join(text_filters) + ")")
                        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
                        cur.execute(base_sql + where_sql + " ORDER BY sp.id DESC", params)
                        rows = cur.fetchall() or []
                variant_ids = [int(r.get('variant_id') or 0) for r in rows if int(r.get('variant_id') or 0) > 0]
                metrics_map = {}
                if variant_ids:
                    with self._get_db_connection() as conn:
                        metrics_map = self._load_sales_variant_metrics(conn, variant_ids, include_links=include_links)

                for row in rows:
                    variant_id = int(row.get('variant_id') or 0)
                    metrics = metrics_map.get(variant_id, {}) if variant_id else {}
                    row['warehouse_cost_usd'] = metrics.get('warehouse_cost_usd', 0.0)
                    row['last_mile_cost_usd'] = metrics.get('last_mile_cost_usd', 0.0)
                    row['package_length_in'] = metrics.get('package_length_in', 0.0)
                    row['package_width_in'] = metrics.get('package_width_in', 0.0)
                    row['package_height_in'] = metrics.get('package_height_in', 0.0)
                    row['net_weight_lbs'] = metrics.get('net_weight_lbs', 0.0)
                    row['gross_weight_lbs'] = metrics.get('gross_weight_lbs', 0.0)
                    if include_links:
                        row['order_sku_links'] = metrics.get('order_sku_links', [])
                    elif item_id:
                        row['order_sku_links'] = []

                # Variant preview image (first 白底图) for table list
                if not item_id:
                    try:
                        vid_list = [int(r.get('variant_id') or 0) for r in rows if int(r.get('variant_id') or 0) > 0]
                        preview_map = {}
                        if vid_list:
                            with self._get_db_connection() as conn:
                                preview_map = self._load_variant_first_image_preview(conn, vid_list, type_name='白底图')
                        for r in rows:
                            vid = int(r.get('variant_id') or 0)
                            r['preview_image_b64'] = preview_map.get(vid, '') if vid else ''
                    except Exception:
                        for r in rows:
                            r['preview_image_b64'] = ''

                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                product_status = (data.get('product_status') or 'enabled').strip().lower()
                if product_status not in ('enabled', 'retained', 'discarded'):
                    product_status = 'enabled'
                sku_family_id_input = self._parse_int(data.get('sku_family_id'))
                shop_id_input = self._parse_int(data.get('shop_id'))
                parent_code = (data.get('parent_code') or '').strip() or None
                parent_sku_marker = (data.get('parent_sku_marker') or '').strip() or None
                child_code = (data.get('child_code') or '').strip() or None
                sale_price_usd = self._parse_float(data.get('sale_price_usd'))
                fabric_id_input = self._parse_int(data.get('fabric_id'))
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not links:
                    return self.send_json({'status': 'error', 'message': '关联下单SKU及数量为必填'}, start_response)

                with self._get_db_connection() as conn:
                    sp_has_shop_col = self._table_has_column(conn, 'sales_products', 'shop_id')
                    derived = self._derive_sales_cost_size(conn, links)
                    sku_family_id = sku_family_id_input or derived.get('sku_family_id')
                    if not sku_family_id:
                        return self.send_json({'status': 'error', 'message': '无法根据下单SKU推断归属货号'}, start_response)

                    sku_family_code = ''
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                        sku_row = cur.fetchone()
                        if sku_row:
                            sku_family_code = (sku_row.get('sku_family') or '').strip()

                    parent_id = None
                    parent_shop_id = None
                    if parent_code:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, shop_id FROM sales_parents WHERE parent_code=%s AND shop_id=%s LIMIT 1", (parent_code, shop_id_input))
                            row = cur.fetchone()
                            if row:
                                parent_id = row['id']
                                parent_shop_id = row.get('shop_id')
                                if (not parent_shop_id) and shop_id_input:
                                    cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_input, parent_id))
                                    parent_shop_id = shop_id_input
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                    VALUES (%s, %s, %s)
                                    """,
                                    (parent_code, shop_id_input, parent_sku_marker)
                                )
                                parent_id = cur.lastrowid
                                parent_shop_id = shop_id_input
                    final_shop_id = parent_shop_id if parent_id else shop_id_input
                    if not final_shop_id:
                        return self.send_json({'status': 'error', 'message': 'Missing required field: shop_id'}, start_response)

                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    final_fabric = (data.get('fabric') or '').strip() or auto_fabric
                    final_spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    # Prefer fabric_id when provided; fallback to derived first fabric by code lookup
                    resolved_fabric_id = fabric_id_input or None
                    if not resolved_fabric_id and final_fabric:
                        try:
                            with conn.cursor() as fcur:
                                fcur.execute("SELECT id FROM fabric_materials WHERE fabric_code=%s LIMIT 1", (self._code_before_dash(final_fabric),))
                                frow = fcur.fetchone() or {}
                                resolved_fabric_id = self._parse_int(frow.get('id')) or None
                        except Exception:
                            resolved_fabric_id = None
                    variant_id = self._get_or_create_sales_variant(conn, sku_family_id, final_spec_name, final_fabric, sale_price_usd, fabric_id=resolved_fabric_id)
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    if manual_platform_sku:
                        platform_sku = platform_sku_manual
                    else:
                        platform_sku = auto_platform_sku or self._build_sales_platform_sku(sku_family_code, final_spec_name, final_fabric)
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)
                    
                    with conn.cursor() as cur:
                        insert_columns = []
                        insert_values = []
                        if sp_has_shop_col:
                            insert_columns.append('shop_id')
                            insert_values.append(final_shop_id)
                        insert_columns.extend(['platform_sku', 'product_status'])
                        insert_values.extend([platform_sku, product_status])
                        insert_columns.extend(['variant_id', 'parent_id', 'child_code'])
                        insert_values.extend([variant_id, parent_id, child_code])
                        placeholders_insert = ', '.join(['%s'] * len(insert_columns))
                        cur.execute(
                            f"INSERT INTO sales_products ({', '.join(insert_columns)}) VALUES ({placeholders_insert})",
                            insert_values
                        )
                        new_id = cur.lastrowid
                    self._replace_sales_variant_order_links(conn, variant_id, links)
                    fabric_folder_part = self._resolve_fabric_folder_part(conn, resolved_fabric_id, final_fabric)
                    self._ensure_listing_sales_variant_folder(sku_family_code, final_spec_name, fabric_folder_part)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                platform_sku_manual = (data.get('platform_sku') or '').strip()
                product_status = (data.get('product_status') or 'enabled').strip().lower()
                if product_status not in ('enabled', 'retained', 'discarded'):
                    product_status = 'enabled'
                sku_family_id_input = self._parse_int(data.get('sku_family_id'))
                shop_id_input = self._parse_int(data.get('shop_id'))
                parent_code = (data.get('parent_code') or '').strip() or None
                parent_sku_marker = (data.get('parent_sku_marker') or '').strip() or None
                child_code = (data.get('child_code') or '').strip() or None
                sale_price_usd = self._parse_float(data.get('sale_price_usd'))
                fabric_id_input = self._parse_int(data.get('fabric_id'))
                confirm_new_variant_folder = bool(data.get('confirm_new_variant_folder'))
                links = self._normalize_sales_order_links(data.get('order_sku_links'))
                
                # 检查是否手动编辑了platform_sku
                manual_platform_sku = bool(data.get('manual_platform_sku'))
                
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing required field: id'}, start_response)
                if not links:
                    return self.send_json({'status': 'error', 'message': '关联下单SKU及数量为必填'}, start_response)

                with self._get_db_connection() as conn:
                    sp_has_shop_col = self._table_has_column(conn, 'sales_products', 'shop_id')
                    derived = self._derive_sales_cost_size(conn, links)
                    sku_family_id = sku_family_id_input or derived.get('sku_family_id')
                    if not sku_family_id:
                        return self.send_json({'status': 'error', 'message': '无法根据下单SKU推断归属货号'}, start_response)

                    sku_family_code = ''
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                        sku_row = cur.fetchone()
                        if sku_row:
                            sku_family_code = (sku_row.get('sku_family') or '').strip()

                    parent_id = None
                    parent_shop_id = None
                    if parent_code:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, shop_id FROM sales_parents WHERE parent_code=%s AND shop_id=%s LIMIT 1", (parent_code, shop_id_input))
                            row = cur.fetchone()
                            if row:
                                parent_id = row['id']
                                parent_shop_id = row.get('shop_id')
                                if (not parent_shop_id) and shop_id_input:
                                    cur.execute("UPDATE sales_parents SET shop_id=%s WHERE id=%s", (shop_id_input, parent_id))
                                    parent_shop_id = shop_id_input
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO sales_parents (parent_code, shop_id, sku_marker)
                                    VALUES (%s, %s, %s)
                                    """,
                                    (parent_code, shop_id_input, parent_sku_marker)
                                )
                                parent_id = cur.lastrowid
                                parent_shop_id = shop_id_input
                    final_shop_id = parent_shop_id if parent_id else shop_id_input
                    if not final_shop_id:
                        return self.send_json({'status': 'error', 'message': 'Missing required field: shop_id'}, start_response)

                    auto_fabric, auto_spec_name, auto_platform_sku = self._derive_sales_fields(conn, sku_family_id, links)
                    final_fabric = (data.get('fabric') or '').strip() or auto_fabric
                    final_spec_name = (data.get('spec_name') or '').strip() or auto_spec_name
                    resolved_fabric_id = fabric_id_input or None
                    if not resolved_fabric_id and final_fabric:
                        try:
                            with conn.cursor() as fcur:
                                fcur.execute("SELECT id FROM fabric_materials WHERE fabric_code=%s LIMIT 1", (self._code_before_dash(final_fabric),))
                                frow = fcur.fetchone() or {}
                                resolved_fabric_id = self._parse_int(frow.get('id')) or None
                        except Exception:
                            resolved_fabric_id = None
                    variant_id = self._get_or_create_sales_variant(conn, sku_family_id, final_spec_name, final_fabric, sale_price_usd, fabric_id=resolved_fabric_id)
                    
                    # 如果没有手动编辑，使用自动生成的platform_sku；否则使用手动输入的
                    if manual_platform_sku:
                        platform_sku = platform_sku_manual
                    else:
                        platform_sku = auto_platform_sku or self._build_sales_platform_sku(sku_family_code, final_spec_name, final_fabric)
                    
                    if not platform_sku:
                        return self.send_json({'status': 'error', 'message': '无法生成销售平台SKU，请手动输入'}, start_response)

                    with conn.cursor() as cur:
                        has_fabric_id = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
                        has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                        fabric_join = "LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if has_fabric_id else ""
                        if has_fabric_id and has_fabric_text:
                            fabric_select = "COALESCE(fm.fabric_code, v.fabric) AS fabric"
                        elif has_fabric_id:
                            fabric_select = "fm.fabric_code AS fabric"
                        else:
                            fabric_select = ("v.fabric AS fabric" if has_fabric_text else "'' AS fabric")
                        cur.execute(
                            f"""
                            SELECT v.spec_name, {fabric_select}
                            FROM sales_products sp
                            LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                            {fabric_join}
                            WHERE sp.id=%s
                            """,
                            (item_id,)
                        )
                        current_row = cur.fetchone() or {}
                    old_spec_name = (current_row.get('spec_name') or '').strip()
                    old_fabric = (current_row.get('fabric') or '').strip()
                    spec_or_fabric_changed = (old_spec_name != (final_spec_name or '').strip()) or (old_fabric != (final_fabric or '').strip())
                    if spec_or_fabric_changed and not confirm_new_variant_folder:
                        return self.send_json({'status': 'error', 'message': '修改规格名称或面料将新建主图文件夹，请二次确认后重试'}, start_response)
                    
                    with conn.cursor() as cur:
                        update_fields = [
                            "platform_sku=%s",
                            "product_status=%s",
                            "variant_id=%s",
                            "parent_id=%s",
                            "child_code=%s"
                        ]
                        update_values = [platform_sku, product_status, variant_id, parent_id, child_code]
                        if sp_has_shop_col:
                            update_fields.insert(0, "shop_id=%s")
                            update_values.insert(0, final_shop_id)
                        update_values.append(item_id)
                        cur.execute(
                            f"UPDATE sales_products SET {', '.join(update_fields)} WHERE id=%s",
                            update_values
                        )
                    self._replace_sales_variant_order_links(conn, variant_id, links)
                    if spec_or_fabric_changed:
                        fabric_folder_part = self._resolve_fabric_folder_part(conn, resolved_fabric_id, final_fabric)
                        self._ensure_listing_sales_variant_folder(sku_family_code, final_spec_name, fabric_folder_part)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'PATCH':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                product_status = (data.get('product_status') or '').strip().lower()
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                if product_status not in ('enabled', 'retained', 'discarded'):
                    return self.send_json({'status': 'error', 'message': 'Invalid product_status'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE sales_products SET product_status=%s WHERE id=%s AND product_status<>%s", (product_status, item_id, product_status))
                        changed = int(cur.rowcount or 0)
                return self.send_json({'status': 'success', 'changed': changed}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
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

    def _ensure_listing_sales_variant_folder(self, sku_family, spec_name, fabric_code):
        sku_name = (sku_family or '').strip()
        if not sku_name:
            return
        self._ensure_listing_sku_folder(sku_name)
        base_folder = self._ensure_listing_folder()
        sku_folder = os.path.join(base_folder, self._safe_fsencode(sku_name))
        main_folder = os.path.join(sku_folder, self._safe_fsencode('主图'))
        if not os.path.exists(main_folder):
            os.makedirs(main_folder, exist_ok=True)

        spec_part = (spec_name or '').strip().replace('/', '-').replace('\\', '-')
        # Folder naming rule: 规格名称-面料英文名称（fallback to legacy fabric code/text if name_en missing）
        fabric_part = (fabric_code or '').strip().replace('/', '-').replace('\\', '-')
        if not fabric_part:
            fabric_part = self._code_before_dash(fabric_code).replace('/', '-').replace('\\', '-')
        if not (spec_part and fabric_part):
            return
        variant_folder_name = f"{spec_part}-{fabric_part}"
        variant_folder = os.path.join(main_folder, self._safe_fsencode(variant_folder_name))
        if not os.path.exists(variant_folder):
            os.makedirs(variant_folder, exist_ok=True)

    def _resolve_fabric_folder_part(self, conn, fabric_id=None, fabric_text=''):
        """Return folder-safe fabric part; prefer fabric_name_en, fallback to legacy fabric code/text."""
        name_en = ''
        fid = self._parse_int(fabric_id) or 0
        if fid:
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT fabric_name_en FROM fabric_materials WHERE id=%s LIMIT 1", (fid,))
                    row = cur.fetchone() or {}
                    name_en = str(row.get('fabric_name_en') or '').strip()
            except Exception:
                name_en = ''
        if name_en:
            return name_en.replace('/', '-').replace('\\', '-').strip()
        return self._code_before_dash(fabric_text).replace('/', '-').replace('\\', '-').strip()

    def _get_sales_product_image_assets_folder(self):
        folder = self._join_resources('『销售产品图片』/assets')
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _sha256_hex(self, data_bytes):
        return hashlib.sha256(data_bytes or b'').hexdigest()

    def _guess_image_ext(self, filename, content):
        ext = os.path.splitext(os.path.basename(filename or ''))[1].lower()
        if ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.tif', '.tiff'):
            return ext
        if content.startswith(b'\xff\xd8\xff'):
            return '.jpg'
        if content.startswith(b'\x89PNG'):
            return '.png'
        if content.startswith(b'GIF8'):
            return '.gif'
        if content.startswith(b'RIFF') and b'WEBP' in content[:16]:
            return '.webp'
        return '.jpg'

    def _unc_share_key(self, path_text):
        """
        Return UNC share key like '\\\\server\\share' (case-insensitive).
        If not UNC, return ''.
        """
        try:
            p = str(path_text or '').strip()
        except Exception:
            return ''
        if not p.startswith('\\\\'):
            return ''
        # \\server\share\rest...
        parts = p.lstrip('\\').split('\\')
        if len(parts) < 2:
            return ''
        server = parts[0].strip()
        share = parts[1].strip()
        if not (server and share):
            return ''
        return ('\\\\' + server + '\\' + share).lower()



    def handle_sales_product_main_images_import_by_path_api(self, environ, method, start_response):
        """
        从 NAS 路径导入销售产品主图。自动检测文件位置，优先移动以优化性能。
        POST /api/sales-product-main-images-import-by-path
        入参：sales_product_id, source_path, image_type_name(可选，默认文字卖点图)
        """
        try:
            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ)
            sales_product_id = self._parse_int(data.get('sales_product_id'))
            source_path_text = str(data.get('source_path') or '').strip()
            image_type_name = str(data.get('image_type_name') or '').strip() or '文字卖点图'
            delete_source = bool(data.get('delete_source'))  # optional: try delete source after successful commit (best-effort)
            require_move = str(data.get('require_move') or '').strip().lower() in ('1', 'true', 'yes', 'on')

            if not sales_product_id:
                return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)
            if not source_path_text:
                return self.send_json({'status': 'error', 'message': 'Missing source_path'}, start_response)

            source_path = os.path.normpath(os.path.abspath(source_path_text))
            if not os.path.exists(source_path):
                return self.send_json({'status': 'error', 'message': '源路径不存在', 'source_path': source_path}, start_response)

            source_files = []
            if os.path.isfile(source_path):
                if self._is_image_name(os.path.basename(source_path)):
                    source_files = [source_path]
            else:
                try:
                    for name in os.listdir(source_path):
                        abs_file = os.path.join(source_path, name)
                        if os.path.isfile(abs_file) and self._is_image_name(name):
                            source_files.append(abs_file)
                except Exception:
                    source_files = []
            source_files = sorted(set(source_files))
            if not source_files:
                return self.send_json({'status': 'error', 'message': '源路径下无图片文件'}, start_response)

            with self._get_db_connection() as conn:
                image_type_id = self._get_image_type_id_by_name(conn, image_type_name)
                if not image_type_id:
                    return self.send_json({'status': 'error', 'message': f'未知图片类型: {image_type_name}'}, start_response)

                start_sort = self._get_sales_product_image_sort_start(conn, sales_product_id)
                created_assets = 0
                moved_count = 0
                copied_count = 0
                linked_count = 0
                items = []
                folder_info = self._resolve_sales_product_variant_folder(sales_product_id, ensure_folder=True)
                target_folder_abs = folder_info.get('folder_path')
                if not target_folder_abs or not os.path.exists(target_folder_abs):
                    return self.send_json({'status': 'error', 'message': '无法定位主图文件夹，请确认货号/规格/面料信息完整'}, start_response)
                variant_id = 0
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (sales_product_id,))
                        row = cur.fetchone() or {}
                        variant_id = self._parse_int(row.get('variant_id')) or 0
                except Exception:
                    variant_id = 0

                # ---- Stage files first (atomic batch) ----
                staged_moves = []   # [(src, tmp)] source moved to tmp; rollback moves back
                staged_files = []   # [(final_abs, tmp_abs_or_none, src_or_none)] used for cleanup
                db_new_assets = []  # [{sha256, storage_path, filename, ext, file_size}]
                reuse_assets = []   # [{asset_id}]
                move_failures = []  # [{src, reason}]

                target_share = self._unc_share_key(target_folder_abs)

                for idx, source_file in enumerate(source_files, start=1):
                    filename = os.path.basename(source_file)
                    try:
                        with open(source_file, 'rb') as f:
                            content = f.read()
                        if not content:
                            continue
                        sha256 = self._sha256_hex(content)
                    except Exception:
                        continue

                    asset = self._find_image_asset_by_sha256(conn, sha256)
                    if asset:
                        reuse_assets.append({'asset_id': asset.get('id'), 'idx': idx})
                    else:
                        ext = self._guess_image_ext(filename, content)
                        type_part = self._sanitize_filename_component(image_type_name, 32) or '图片'
                        base_part = self._sanitize_filename_component(os.path.splitext(filename)[0], 80) or sha256[:12]
                        final_name = self._next_available_filename(target_folder_abs, f"{type_part}-{base_part}{ext}")
                        abs_path = os.path.join(target_folder_abs, self._safe_fsencode(final_name))

                        # Stage: try move to a temp file first so we can rollback on DB failure.
                        tmp_abs = abs_path + (f".__tmp__{int(time.time()*1000)}_{idx}")
                        wrote_final = False
                        src_share = self._unc_share_key(source_file)
                        try:
                            # Only expect server-side atomic move when in the same UNC share.
                            if src_share and target_share and src_share == target_share:
                                os.replace(source_file, tmp_abs)
                            else:
                                raise RuntimeError('not_same_unc_share')
                            staged_moves.append((source_file, tmp_abs))
                            moved_count += 1
                        except Exception as e_move1:
                            # Fallback 1: try shutil.move (works across volumes/shares via copy+delete)
                            try:
                                import shutil
                                shutil.move(source_file, tmp_abs)
                                staged_moves.append((source_file, tmp_abs))
                                moved_count += 1
                            except Exception as e_move2:
                                # Fallback 2: write temp by bytes (keep source intact)
                                try:
                                    with open(tmp_abs, 'wb') as f:
                                        f.write(content or b'')
                                    copied_count += 1
                                except Exception:
                                    # Can't persist => skip this file
                                    self._safe_unlink(tmp_abs)
                                    continue
                                move_failures.append({'src': str(source_file), 'reason': str(e_move2)[:120] or str(e_move1)[:120]})

                        if require_move and copied_count > 0:
                            # We copied at least one file in this batch; enforce "must move" semantics.
                            # Clean up the tmp file we just created (best-effort) and abort.
                            try:
                                self._safe_unlink(tmp_abs)
                            except Exception:
                                pass
                            return self.send_json({
                                'status': 'error',
                                'message': '要求移动(require_move=1)但当前路径无法移动（可能是不同 share 或无删除权限）。',
                                'source_path': source_path,
                                'target_folder': target_folder_abs,
                                'target_share': target_share,
                                'move_failures': move_failures[:5],
                            }, start_response)

                        # Promote temp -> final path
                        try:
                            os.replace(tmp_abs, abs_path)
                            wrote_final = True
                        except Exception:
                            # Rollback staging for this file immediately
                            self._safe_unlink(tmp_abs)
                            # If we moved source to tmp_abs earlier, try move back
                            for src, tmp in list(staged_moves):
                                if tmp == tmp_abs:
                                    try:
                                        if os.path.exists(tmp):
                                            os.replace(tmp, src)
                                    except Exception:
                                        pass
                                    try:
                                        staged_moves.remove((src, tmp))
                                    except Exception:
                                        pass
                            continue

                        if not wrote_final or not os.path.exists(abs_path):
                            continue

                        storage_path = self._storage_path_from_abs(abs_path)
                        staged_files.append((abs_path, None, source_file))
                        db_new_assets.append({
                            'sha256': sha256,
                            'storage_path': storage_path,
                            'filename': filename,
                            'ext': ext,
                            'file_size': len(content or b''),
                            'idx': idx,
                        })

                    sort_order = start_sort + idx
                    # Defer DB mapping inserts until after all files staged successfully (atomic batch)
                    items.append({'filename': filename, 'sha256': sha256[:12], 'sort_order': sort_order, 'idx': idx, 'sha256_full': sha256})

                # If nothing to process, exit early
                if not db_new_assets and not reuse_assets:
                    return self.send_json({'status': 'error', 'message': '未检测到可导入的图片（可能均为空/不支持）'}, start_response)

                # ---- Transaction: write DB for the whole batch ----
                created_asset_ids = []
                try:
                    self._tx_begin(conn)

                    # Insert new assets
                    sha_to_id = {}
                    for rec in db_new_assets:
                        with conn.cursor() as cur:
                            aid = self._insert_image_asset_dynamic(
                                conn,
                                cur,
                                {
                                    'sha256': rec['sha256'],
                                    'storage_path': rec['storage_path'],
                                    'filename': rec['filename'],
                                    'ext': rec['ext'],
                                    'file_size': rec['file_size'],
                                    'image_type_id': image_type_id,
                                },
                            )
                        sha_to_id[rec['sha256']] = aid
                        created_asset_ids.append((aid, rec['storage_path']))
                        created_assets += 1

                    # Map reuse asset ids (already existed)
                    for r in reuse_assets:
                        sha_to_id.setdefault(f"reuse:{r['asset_id']}", int(r['asset_id'] or 0))

                    # Insert mappings
                    for row in items:
                        sort_order = row.get('sort_order')
                        sha = row.get('sha256_full')
                        asset_id = sha_to_id.get(sha)
                        if not asset_id:
                            # It may be a reused asset (we didn't keep sha); skip mapping for unknown
                            continue
                        with conn.cursor() as cur:
                            self._execute_sku_mapping_upsert(
                                conn, cur, asset_id, sort_order, image_type_id, variant_id, sales_product_id, None
                            )
                        linked_count += 1

                    self._tx_commit(conn)
                except Exception as e:
                    self._tx_rollback(conn)
                    # Cleanup files created in this batch (do not touch existing assets)
                    for abs_path, _, _ in staged_files:
                        self._safe_unlink(abs_path)
                    # Restore moved sources when possible (best-effort)
                    for src, tmp in reversed(staged_moves):
                        try:
                            if os.path.exists(tmp):
                                os.replace(tmp, src)
                        except Exception:
                            pass
                    return self.send_json({'status': 'error', 'message': f'导入失败，已回滚：{str(e)}'}, start_response)

                # Optional: after commit, delete source files for those that were copied (best-effort).
                # We only attempt this when explicitly requested, to avoid accidental data loss.
                deleted_source_count = 0
                if delete_source:
                    try:
                        # Any source that wasn't moved into staged_moves is still at source_file.
                        moved_sources = set()
                        for src, _tmp in staged_moves:
                            moved_sources.add(src)
                        for source_file in source_files:
                            if source_file in moved_sources:
                                continue
                            try:
                                if os.path.exists(source_file):
                                    os.remove(source_file)
                                    deleted_source_count += 1
                            except Exception:
                                pass
                    except Exception:
                        deleted_source_count = deleted_source_count or 0

                # After commit: apply rehome rules best-effort
                try:
                    for aid, _ in created_asset_ids:
                        self._rehome_image_asset_if_needed(conn, aid)
                except Exception:
                    pass

                return self.send_json({
                    'status': 'success',
                    'source_path': source_path,
                    'files': [x['filename'] for x in items],
                    'file_count': len(items),
                    'created_assets': created_assets,
                    'moved': moved_count,
                    'copied': copied_count,
                    'deleted_source': (deleted_source_count if delete_source else None),
                    'linked': linked_count
                }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _ensure_image_type_scope_columns(self, conn):
        """Ensure image_types scope columns exist for filtering by target modules."""
        cols = [
            ('applies_fabric', 'TINYINT(1) NOT NULL DEFAULT 1'),
            ('applies_sales', 'TINYINT(1) NOT NULL DEFAULT 1'),
            ('applies_aplus', 'TINYINT(1) NOT NULL DEFAULT 1'),
        ]
        for col, ddl in cols:
            if not self._table_has_column(conn, 'image_types', col):
                with conn.cursor() as cur:
                    cur.execute(f"ALTER TABLE image_types ADD COLUMN {col} {ddl}")

    def _parse_bool_flag(self, value, default=False):
        if value is None:
            return bool(default)
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'on', 'y'):
            return True
        if text in ('0', 'false', 'no', 'off', 'n'):
            return False
        return bool(default)

    def _handle_image_type_api_core(self, environ, method, start_response):
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            usage = (query_params.get('usage', [''])[0] or '').strip().lower()
            keyword = (query_params.get('q', [''])[0] or '').strip()
            include_disabled = self._parse_bool_flag((query_params.get('include_disabled', ['0'])[0] or '0'), default=False)

            if method == 'GET':
                with self._get_db_connection() as conn:
                    self._ensure_image_type_scope_columns(conn)
                    with conn.cursor() as cur:
                        where_parts = []
                        params = []
                        if not include_disabled:
                            where_parts.append('is_enabled=1')
                        if keyword:
                            where_parts.append('name LIKE %s')
                            params.append(f"%{keyword}%")

                        usage_col = {
                            'sales': 'applies_sales',
                            'fabric': 'applies_fabric',
                            'aplus': 'applies_aplus',
                        }.get(usage)
                        if usage_col:
                            where_parts.append(f"{usage_col}=1")

                        where_sql = f"WHERE {' AND '.join(where_parts)}" if where_parts else ''
                        cur.execute(
                            f"""
                            SELECT id, name, is_enabled,
                                   applies_fabric, applies_sales, applies_aplus,
                                   created_at, updated_at
                            FROM image_types
                            {where_sql}
                            ORDER BY sort_order ASC, id ASC
                            """,
                            tuple(params),
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = str(data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                if len(name) > 64:
                    return self.send_json({'status': 'error', 'message': '类型名称长度不能超过64个字符'}, start_response)

                applies_fabric = int(self._parse_bool_flag(data.get('applies_fabric'), default=True))
                applies_sales = int(self._parse_bool_flag(data.get('applies_sales'), default=True))
                applies_aplus = int(self._parse_bool_flag(data.get('applies_aplus'), default=True))

                with self._get_db_connection() as conn:
                    self._ensure_image_type_scope_columns(conn)
                    with conn.cursor() as cur:
                        cur.execute("SELECT id, is_enabled FROM image_types WHERE name=%s LIMIT 1", (name,))
                        exists = cur.fetchone() or {}
                        if exists.get('id'):
                            cur.execute(
                                """
                                UPDATE image_types
                                SET is_enabled=1,
                                    applies_fabric=%s,
                                    applies_sales=%s,
                                    applies_aplus=%s
                                WHERE id=%s
                                """,
                                (applies_fabric, applies_sales, applies_aplus, exists.get('id')),
                            )
                            return self.send_json({'status': 'success', 'id': exists.get('id'), 'reused': True}, start_response)

                        cur.execute(
                            """
                            INSERT INTO image_types (name, is_enabled, applies_fabric, applies_sales, applies_aplus)
                            VALUES (%s, 1, %s, %s, %s)
                            """,
                            (name, applies_fabric, applies_sales, applies_aplus),
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method in ('PUT', 'PATCH'):
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                sets = []
                vals = []
                for key in ('is_enabled', 'applies_fabric', 'applies_sales', 'applies_aplus'):
                    if key in data:
                        sets.append(f"{key}=%s")
                        vals.append(int(self._parse_bool_flag(data.get(key), default=False)))
                if 'name' in data:
                    name = str(data.get('name') or '').strip()
                    if not name:
                        return self.send_json({'status': 'error', 'message': '类型名称不能为空'}, start_response)
                    if len(name) > 64:
                        return self.send_json({'status': 'error', 'message': '类型名称长度不能超过64个字符'}, start_response)
                    sets.append('name=%s')
                    vals.append(name)
                if not sets:
                    return self.send_json({'status': 'error', 'message': 'No updatable fields'}, start_response)

                with self._get_db_connection() as conn:
                    self._ensure_image_type_scope_columns(conn)
                    with conn.cursor() as cur:
                        cur.execute(f"UPDATE image_types SET {', '.join(sets)} WHERE id=%s", tuple(vals + [item_id]))
                return self.send_json({'status': 'success', 'id': item_id}, start_response)

            if method == 'DELETE':
                return self.send_json({'status': 'error', 'message': '图片类型不支持删除，请改为禁用'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '图片类型已存在'}, start_response)
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_image_type_api(self, environ, method, start_response):
        """通用图片类型 API：支持按 usage 过滤和适用范围开关管理。"""
        return self._handle_image_type_api_core(environ, method, start_response)

    def handle_sales_image_type_api(self, environ, method, start_response):
        """兼容旧路由 /api/sales-image-type，内部复用通用图片类型 API。"""
        return self._handle_image_type_api_core(environ, method, start_response)

    def _get_image_type_id_by_name(self, conn, type_name):
        name = (type_name or '').strip()
        if not name:
            name = '文字卖点图'
        self._ensure_image_type_scope_columns(conn)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM image_types WHERE name=%s AND is_enabled=1 LIMIT 1", (name,))
            row = cur.fetchone() or {}
            if row.get('id'):
                return self._parse_int(row.get('id'))
            cur.execute("SELECT id, is_enabled FROM image_types WHERE name=%s LIMIT 1", (name,))
            existing = cur.fetchone() or {}
            if existing.get('id'):
                if self._parse_int(existing.get('is_enabled')) != 1:
                    cur.execute("UPDATE image_types SET is_enabled=1 WHERE id=%s", (existing.get('id'),))
                return self._parse_int(existing.get('id'))
            cur.execute(
                """
                INSERT INTO image_types (name, is_enabled, applies_fabric, applies_sales, applies_aplus)
                VALUES (%s, 1, 1, 1, 1)
                """,
                (name,),
            )
            if cur.lastrowid:
                return self._parse_int(cur.lastrowid)
            cur.execute("SELECT id FROM image_types WHERE is_enabled=1 ORDER BY id ASC LIMIT 1")
            fallback = cur.fetchone() or {}
        return self._parse_int(fallback.get('id'))

    def _get_sales_product_image_sort_start(self, conn, sales_product_id):
        """
        Return the current max sort_order for the target sales product.
        Compatible with both schemas:
        - legacy: sku_image_mappings.sales_product_id
        - new:    sku_image_mappings.variant_id (sales_products.variant_id)
        """
        spid = int(sales_product_id or 0)
        if not spid:
            return 0
        has_sim_spid = self._table_has_column(conn, 'sku_image_mappings', 'sales_product_id')
        has_sim_vid = self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
        with conn.cursor() as cur:
            if has_sim_spid:
                cur.execute(
                    "SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM sku_image_mappings WHERE sales_product_id=%s",
                    (spid,)
                )
                row = cur.fetchone() or {}
                return max(0, self._parse_int(row.get('max_sort')) or 0)
            if has_sim_vid:
                cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (spid,))
                r = cur.fetchone() or {}
                vid = self._parse_int(r.get('variant_id')) or 0
                if not vid:
                    return 0
                cur.execute(
                    "SELECT COALESCE(MAX(sort_order), 0) AS max_sort FROM sku_image_mappings WHERE variant_id=%s",
                    (vid,)
                )
                row = cur.fetchone() or {}
                return max(0, self._parse_int(row.get('max_sort')) or 0)
        return 0

    def _load_variant_first_image_preview(self, conn, variant_ids, type_name='白底图'):
        """
        Return {variant_id: image_b64} for the first image (by sort_order) of a given type.
        Uses image_assets.image_type_id if available; falls back to sku_image_mappings.image_type_id.
        """
        vids = [int(v or 0) for v in (variant_ids or []) if int(v or 0) > 0]
        if not vids:
            return {}

        has_variant = self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
        if not has_variant:
            return {}

        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_sim_tid = self._table_has_column(conn, 'sku_image_mappings', 'image_type_id')
        if not (has_ia_tid or has_sim_tid):
            return {}

        # Prefer matching image type name; fallback to first image if none match
        preferred_names = []
        base_name = str(type_name or '').strip() or '白底图'
        preferred_names.append(base_name)
        # Common legacy / renamed variants
        for cand in ('主图·白底图', '主图白底图', '白底', 'White'):
            if cand not in preferred_names:
                preferred_names.append(cand)

        join_it = ""
        where_type = ""
        params = []
        if has_ia_tid:
            # LEFT JOIN so assets with NULL image_type_id don't get excluded prematurely.
            join_it = "LEFT JOIN image_types it ON it.id = ia.image_type_id"
            where_type = "AND it.name IN ({})".format(",".join(["%s"] * len(preferred_names)))
            params.extend(preferred_names)
        else:
            join_it = "JOIN image_types it ON it.id = sim.image_type_id"
            where_type = "AND it.name IN ({})".format(",".join(["%s"] * len(preferred_names)))
            params.extend(preferred_names)

        placeholders = ",".join(["%s"] * len(vids))
        has_ia_ofn = self._table_has_column(conn, 'image_assets', 'original_filename')
        ofn_sel = "ia.original_filename" if has_ia_ofn else "'' AS original_filename"
        sql = f"""
            SELECT sim.variant_id, ia.storage_path, {ofn_sel}, sim.sort_order, sim.id
            FROM sku_image_mappings sim
            JOIN image_assets ia ON ia.id = sim.image_asset_id
            {join_it}
            WHERE sim.variant_id IN ({placeholders})
              {where_type}
            ORDER BY sim.variant_id ASC, sim.sort_order ASC, sim.id ASC
        """
        with conn.cursor() as cur:
            cur.execute(sql, tuple(vids) + tuple(params))
            rows = cur.fetchall() or []

        # If no rows match preferred white-background types, fallback to first image per variant
        if not rows:
            sql2 = f"""
                SELECT sim.variant_id, ia.storage_path, {ofn_sel}, sim.sort_order, sim.id
                FROM sku_image_mappings sim
                JOIN image_assets ia ON ia.id = sim.image_asset_id
                WHERE sim.variant_id IN ({placeholders})
                ORDER BY sim.variant_id ASC, sim.sort_order ASC, sim.id ASC
            """
            with conn.cursor() as cur:
                cur.execute(sql2, tuple(vids))
                rows = cur.fetchall() or []

        out = {}
        for row in rows:
            vid = int(row.get('variant_id') or 0)
            if not vid or vid in out:
                continue
            storage_path = (row.get('storage_path') or '').strip()
            if not storage_path:
                continue
            if isinstance(storage_path, str):
                try:
                    rel_bytes = os.fsencode(storage_path)
                except Exception:
                    rel_bytes = storage_path.encode('utf-8', errors='surrogatepass')
            else:
                rel_bytes = storage_path
            out[vid] = base64.b64encode(rel_bytes).decode('ascii') if rel_bytes else ''
        return out

    def _read_fabric_image_items(self, conn, fabric_id):
        """Read fabric-related images (readonly) for UI preview grids."""
        fid = int(fabric_id or 0)
        if not fid or not self._has_required_tables(['fabric_image_mappings', 'image_assets']):
            return []

        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        join_it = "LEFT JOIN image_types it ON it.id = ia.image_type_id" if has_ia_tid else ""
        tname_sel = "it.name AS image_type_name" if has_ia_tid else "'' AS image_type_name"
        dep_expr = "COALESCE(ia.is_deprecated,0)" if self._table_has_column(conn, 'image_assets', 'is_deprecated') else "0"
        has_ia_ofn = self._table_has_column(conn, 'image_assets', 'original_filename')
        ofn_sel = "ia.original_filename AS original_filename" if has_ia_ofn else "'' AS original_filename"

        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT fim.sort_order, ia.storage_path, {ofn_sel}, ia.description, {tname_sel}
                FROM fabric_image_mappings fim
                JOIN image_assets ia ON ia.id = fim.image_asset_id
                {join_it}
                WHERE fim.fabric_id=%s
                ORDER BY {dep_expr} ASC, fim.sort_order ASC, fim.id ASC
                """,
                (fid,),
            )
            rows = cur.fetchall() or []

        items = []
        for row in rows:
            storage_path = (row.get('storage_path') or '').strip()
            image_name = (row.get('original_filename') or '').strip() or os.path.basename(storage_path)
            if isinstance(storage_path, str):
                try:
                    rel_bytes = os.fsencode(storage_path)
                except Exception:
                    rel_bytes = storage_path.encode('utf-8', errors='surrogatepass')
            else:
                rel_bytes = storage_path
            image_b64 = base64.b64encode(rel_bytes).decode('ascii') if rel_bytes else ''
            items.append({
                'image_name': image_name,
                'image_b64': image_b64,
                'description': row.get('description') or '',
                'image_type_name': row.get('image_type_name') or '',
                'sort_order': self._parse_int(row.get('sort_order')) or 0,
            })
        return items

    def _find_image_asset_by_sha256(self, conn, sha256):
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM image_assets WHERE sha256=%s LIMIT 1",
                (sha256,)
            )
            return cur.fetchone() or None

    def _save_image_asset_file(self, storage_path, content):
        abs_path = self._join_resources(storage_path)
        folder = os.path.dirname(abs_path)
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        with open(abs_path, 'wb') as f:
            f.write(content or b'')
        return abs_path

    def _insert_image_asset_dynamic(self, conn, cur, rec):
        """Insert image_assets; optional legacy columns if still present post-migration."""
        cols = ['sha256', 'storage_path']
        vals = [
            rec.get('sha256'),
            rec.get('storage_path'),
        ]
        # Include original_filename only if column still exists (pre-migration)
        if self._table_has_column(conn, 'image_assets', 'original_filename'):
            cols.append('original_filename')
            vals.append((rec.get('original_filename') or rec.get('filename') or ''))
        if self._table_has_column(conn, 'image_assets', 'description'):
            cols.append('description')
            vals.append(rec.get('description', '') or '')
        tid = rec.get('image_type_id')
        if tid and self._table_has_column(conn, 'image_assets', 'image_type_id'):
            cols.append('image_type_id')
            vals.append(int(tid))
        if self._table_has_column(conn, 'image_assets', 'is_deprecated'):
            cols.append('is_deprecated')
            vals.append(int(rec.get('is_deprecated') or 0))
        ext = rec.get('ext')
        fs = rec.get('file_size')
        for c, v in (('file_ext', ext or ''), ('mime_type', 'image/*'), ('file_size', fs)):
            if self._table_has_column(conn, 'image_assets', c):
                cols.append(c)
                vals.append(int(v or 0) if c == 'file_size' else v)
        # Ensure created_by is written if user_id is provided and column exists
        uid = rec.get('created_by')
        if self._table_has_column(conn, 'image_assets', 'created_by'):
            if uid:
                cols.append('created_by')
                vals.append(int(uid))
            # If uid is None/empty and column exists, default to current user if available
            # Otherwise let the column remain NULL (default behavior)
        ph = ', '.join(['%s'] * len(cols))
        cur.execute(f"INSERT INTO image_assets ({', '.join(cols)}) VALUES ({ph})", tuple(vals))
        return cur.lastrowid

    def _execute_sku_mapping_upsert(self, conn, cur, aid, sort_order, image_type_id, variant_id, sales_product_id, user_id):
        """Upsert sku_image_mappings; image_type_id only included if column still exists (pre-migration)."""
        has_var = bool(variant_id) and self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
        key_col = 'variant_id' if has_var else 'sales_product_id'
        key_val = int(variant_id if has_var else (sales_product_id or 0))
        cols = [key_col, 'image_asset_id']
        vals = [key_val, int(aid)]
        has_sim_tid = self._table_has_column(conn, 'sku_image_mappings', 'image_type_id')
        if has_sim_tid:
            cols.append('image_type_id')
            vals.append(int(image_type_id or 0))
        cols.append('sort_order')
        vals.append(sort_order)
        if self._table_has_column(conn, 'sku_image_mappings', 'created_by'):
            cols.append('created_by')
            vals.append(int(user_id) if user_id else None)
        dup_parts = ['sort_order=%s']
        dup_vals = [sort_order]
        if has_sim_tid:
            dup_parts.append('image_type_id=%s')
            dup_vals.append(int(image_type_id or 0))
        ph = ', '.join(['%s'] * len(vals))
        sql = (
            f"INSERT INTO sku_image_mappings ({', '.join(cols)}) VALUES ({ph}) "
            f"ON DUPLICATE KEY UPDATE {', '.join(dup_parts)}"
        )
        cur.execute(sql, tuple(vals + dup_vals))
        if self._table_has_column(conn, 'image_assets', 'image_type_id') and image_type_id:
            cur.execute(
                "UPDATE image_assets SET image_type_id=%s WHERE id=%s",
                (int(image_type_id), int(aid)),
            )

    def _read_sales_product_image_items(self, conn, sales_product_id=None, variant_id=None):
        has_variant = self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
        has_sales_product_id = self._table_has_column(conn, 'sku_image_mappings', 'sales_product_id')
        has_sim_tid = self._table_has_column(conn, 'sku_image_mappings', 'image_type_id')
        has_ia_tid = self._table_has_column(conn, 'image_assets', 'image_type_id')
        has_ia_dep = self._table_has_column(conn, 'image_assets', 'is_deprecated')
        use_variant = bool(variant_id) and has_variant
        # If legacy sales_product_id column is gone, we must query by variant_id.
        if not has_sales_product_id and not use_variant:
            return []
        where_col = "sim.variant_id" if use_variant else "sim.sales_product_id"
        where_val = int(variant_id) if use_variant else int(sales_product_id or 0)
        dep_expr = "COALESCE(ia.is_deprecated,0)" if has_ia_dep else "0"
        if has_ia_tid:
            join_types = "LEFT JOIN image_types it ON it.id = ia.image_type_id"
            type_name_expr = "it.name"
            type_id_expr = "ia.image_type_id"
        elif has_sim_tid:
            join_types = "LEFT JOIN image_types it ON it.id = sim.image_type_id"
            type_name_expr = "it.name"
            type_id_expr = "sim.image_type_id"
        else:
            join_types = ""
            type_name_expr = "NULL"
            type_id_expr = "NULL"
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sim.id AS mapping_id, sim.sort_order,
                       ia.id AS image_asset_id, ia.sha256, ia.storage_path,
                       ia.description,
                       {type_id_expr} AS image_type_id,
                       {type_name_expr} AS image_type_name,
                       {dep_expr} AS is_deprecated
                FROM sku_image_mappings sim
                JOIN image_assets ia ON ia.id = sim.image_asset_id
                {join_types}
                WHERE {where_col}=%s
                ORDER BY {dep_expr} ASC, sim.sort_order ASC, sim.id ASC
                """,
                (where_val,)
            )
            rows = cur.fetchall() or []
        items = []
        for row in rows:
            storage_path = (row.get('storage_path') or '').strip()
            image_name = os.path.basename(storage_path) if storage_path else ''
            # On some Windows/Python setups, the filesystem encoding may effectively behave like ASCII.
            # Avoid crashing JSON responses when storage_path contains Chinese or other non-ASCII chars.
            if isinstance(storage_path, str):
                try:
                    rel_bytes = os.fsencode(storage_path)
                except Exception:
                    rel_bytes = storage_path.encode('utf-8', errors='surrogatepass')
            else:
                rel_bytes = storage_path
            image_b64 = base64.b64encode(rel_bytes).decode('ascii') if rel_bytes else ''
            items.append({
                'mapping_id': row.get('mapping_id'),
                'image_asset_id': row.get('image_asset_id'),
                'image_name': image_name,
                'image_b64': image_b64,
                'description': row.get('description') or '',
                'image_type_id': row.get('image_type_id'),
                'image_type_name': row.get('image_type_name') or '',
                'sort_order': row.get('sort_order') or 0,
                'group_sort': None,
                'is_deprecated': int(row.get('is_deprecated') or 0),
                'sha256': row.get('sha256') or '',
                'file_size': 0,
            })
        return items

    def _resolve_sales_product_variant_folder(self, sales_product_id, ensure_folder=False):
        if not sales_product_id:
            raise RuntimeError('Missing sales_product_id')
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                has_fabric_id = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
                has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                fabric_join = "LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if has_fabric_id else ""
                if has_fabric_id and has_fabric_text:
                    fabric_select = "COALESCE(fm.fabric_code, v.fabric) AS fabric"
                elif has_fabric_id:
                    fabric_select = "fm.fabric_code AS fabric"
                else:
                    fabric_select = ("v.fabric AS fabric" if has_fabric_text else "'' AS fabric")
                cur.execute(
                    f"""
                    SELECT sp.id, v.spec_name, {fabric_select}, pf.sku_family,
                           {("fm.fabric_name_en AS fabric_name_en, v.fabric_id AS fabric_id" if has_fabric_id else "'' AS fabric_name_en, 0 AS fabric_id")}
                    FROM sales_products sp
                    LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                    LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                    {fabric_join}
                    WHERE sp.id=%s
                    """,
                    (sales_product_id,)
                )
                row = cur.fetchone() or {}
            if not row.get('id'):
                raise RuntimeError('销售产品不存在')

            sku_name = (row.get('sku_family') or '').strip()
            spec_part = (row.get('spec_name') or '').strip().replace('/', '-').replace('\\', '-')
            fabric_part = str(row.get('fabric_name_en') or '').strip().replace('/', '-').replace('\\', '-')
            if not fabric_part:
                fabric_part = self._resolve_fabric_folder_part(conn, row.get('fabric_id'), row.get('fabric'))
            if not (sku_name and spec_part and fabric_part):
                raise RuntimeError('当前销售产品缺少货号/规格/面料，无法定位主图文件夹')

            if ensure_folder:
                self._ensure_listing_sales_variant_folder(sku_name, spec_part, fabric_part)
            base_folder = self._ensure_listing_folder()
            variant_folder_name = f"{spec_part}-{fabric_part}"
            folder_path = os.path.join(
                base_folder,
                self._safe_fsencode(sku_name),
                self._safe_fsencode('主图'),
                self._safe_fsencode(variant_folder_name)
            )
            return {
                'sales_product_id': int(row.get('id')),
                'sku_family': sku_name,
                'spec_name': spec_part,
                'fabric_folder_part': fabric_part,
                'fabric_id': self._parse_int(row.get('fabric_id')) or 0,
                'fabric_name_en': str(row.get('fabric_name_en') or '').strip(),
                'variant_folder': variant_folder_name,
                'folder_path': folder_path,
            }

    def handle_sales_product_main_images_api(self, environ, method, start_response):
        try:
            if method == 'GET':
                query_params = parse_qs(environ.get('QUERY_STRING', ''))
                sales_product_id = self._parse_int(query_params.get('sales_product_id', [''])[0] or query_params.get('id', [''])[0])
                if not sales_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)

                with self._get_db_connection() as conn:
                    variant_id = 0
                    fabric_id = 0
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (sales_product_id,))
                            row = cur.fetchone() or {}
                            variant_id = self._parse_int(row.get('variant_id')) or 0
                    except Exception:
                        variant_id = 0
                    if variant_id and self._table_has_column(conn, 'sku_image_mappings', 'variant_id'):
                        items = self._read_sales_product_image_items(conn, sales_product_id=None, variant_id=variant_id)
                    else:
                        items = self._read_sales_product_image_items(conn, sales_product_id=sales_product_id)
                    folder_info = self._resolve_sales_product_variant_folder(sales_product_id, ensure_folder=True)
                    # Prefer fabric_id obtained while resolving folder (same variant join),
                    # fallback to direct query only if missing.
                    fabric_id = self._parse_int(folder_info.get('fabric_id')) or 0
                    if not fabric_id:
                        try:
                            with conn.cursor() as cur:
                                if self._table_has_column(conn, 'sales_product_variants', 'fabric_id'):
                                    cur.execute("SELECT fabric_id FROM sales_product_variants WHERE id=%s", (variant_id,))
                                    frow = cur.fetchone() or {}
                                    fabric_id = self._parse_int(frow.get('fabric_id')) or 0
                        except Exception:
                            fabric_id = 0
                    # Final fallback: resolve fabric_id from fabric_name_en / folder part
                    if not fabric_id:
                        try:
                            name_en = str(folder_info.get('fabric_name_en') or '').strip()
                            folder_part = str(folder_info.get('fabric_folder_part') or '').strip()
                            probe = name_en or folder_part
                            if probe:
                                with conn.cursor() as cur:
                                    cur.execute(
                                        "SELECT id FROM fabric_materials WHERE fabric_name_en=%s LIMIT 1",
                                        (probe,),
                                    )
                                    prow = cur.fetchone() or {}
                                    fabric_id = self._parse_int(prow.get('id')) or 0
                                    if not fabric_id:
                                        cur.execute(
                                            "SELECT id FROM fabric_materials WHERE fabric_code=%s LIMIT 1",
                                            (self._code_before_dash(probe),),
                                        )
                                        prow = cur.fetchone() or {}
                                        fabric_id = self._parse_int(prow.get('id')) or 0
                        except Exception:
                            fabric_id = fabric_id or 0
                    fabric_items = []
                    if fabric_id and self._has_required_tables(['fabric_image_mappings', 'image_assets']):
                        try:
                            fabric_items = self._read_fabric_image_items(conn, fabric_id)
                        except Exception:
                            fabric_items = []

                return self.send_json({
                    'status': 'success',
                    'items': items,
                    'fabric_items': fabric_items,
                    'folder': {
                        'sku_family': folder_info.get('sku_family') or '',
                        'variant_folder': folder_info.get('variant_folder') or ''
                    }
                }, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                sales_product_id = self._parse_int(data.get('sales_product_id'))
                image_name = str(data.get('image_name') or '').strip()
                description = str(data.get('description') or '').strip()
                image_type_name = str(data.get('image_type_name') or '').strip()
                sort_order = self._parse_int(data.get('sort_order'))
                if not sales_product_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id or image_name'}, start_response)

                with self._get_db_connection() as conn:
                    variant_id = 0
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (sales_product_id,))
                            row = cur.fetchone() or {}
                            variant_id = self._parse_int(row.get('variant_id')) or 0
                    except Exception:
                        variant_id = 0
                    with conn.cursor() as cur:
                        has_sim_vid = self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
                        has_sim_spid = self._table_has_column(conn, 'sku_image_mappings', 'sales_product_id')
                        if not has_sim_vid and not has_sim_spid:
                            return self.send_json({'status': 'error', 'message': '图片映射表缺少 variant_id / sales_product_id 字段，无法定位图片'}, start_response)
                        if has_sim_vid and variant_id:
                            where_key = "sim.variant_id"
                            where_val = variant_id
                        elif has_sim_spid:
                            where_key = "sim.sales_product_id"
                            where_val = sales_product_id
                        else:
                            return self.send_json({'status': 'error', 'message': '当前销售产品缺少 variant_id，无法定位图片'}, start_response)
                        cur.execute(
                            """
                            SELECT sim.id, sim.image_asset_id, sim.sort_order, ia.storage_path
                            FROM sku_image_mappings sim
                            JOIN image_assets ia ON ia.id = sim.image_asset_id
                            WHERE {where_key}=%s AND (ia.storage_path=%s OR ia.storage_path LIKE %s)
                            ORDER BY sim.sort_order ASC, sim.id ASC
                            LIMIT 1
                            """.format(where_key=where_key),
                            (where_val, image_name, f'%/{image_name}')
                        )
                        mapping = cur.fetchone() or {}
                        if not mapping.get('id'):
                            return self.send_json({'status': 'error', 'message': '图片不存在'}, start_response)

                        aid = mapping.get('image_asset_id')
                        ia_sets = []
                        ia_params = []
                        if description is not None:
                            ia_sets.append('description=%s')
                            ia_params.append(description)
                        if image_type_name and self._table_has_column(conn, 'image_assets', 'image_type_id'):
                            tid = self._get_image_type_id_by_name(conn, image_type_name)
                            if tid:
                                ia_sets.append('image_type_id=%s')
                                ia_params.append(tid)
                        if ia_sets:
                            cur.execute(
                                f"UPDATE image_assets SET {', '.join(ia_sets)} WHERE id=%s",
                                tuple(ia_params + [aid]),
                            )
                        if sort_order is not None:
                            cur.execute(
                                "UPDATE sku_image_mappings SET sort_order=%s WHERE id=%s",
                                (max(1, sort_order), mapping.get('id')),
                            )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                sales_product_id = self._parse_int(data.get('sales_product_id'))
                image_name = str(data.get('image_name') or '').strip()
                if not sales_product_id or not image_name:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id or image_name'}, start_response)

                with self._get_db_connection() as conn:
                    variant_id = 0
                    try:
                        with conn.cursor() as cur:
                            cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (sales_product_id,))
                            row = cur.fetchone() or {}
                            variant_id = self._parse_int(row.get('variant_id')) or 0
                    except Exception:
                        variant_id = 0
                    with conn.cursor() as cur:
                        has_sim_vid = self._table_has_column(conn, 'sku_image_mappings', 'variant_id')
                        has_sim_spid = self._table_has_column(conn, 'sku_image_mappings', 'sales_product_id')
                        if not has_sim_vid and not has_sim_spid:
                            return self.send_json({'status': 'error', 'message': '图片映射表缺少 variant_id / sales_product_id 字段，无法定位图片'}, start_response)
                        if has_sim_vid and variant_id:
                            where_key = "sim.variant_id"
                            where_val = variant_id
                        elif has_sim_spid:
                            where_key = "sim.sales_product_id"
                            where_val = sales_product_id
                        else:
                            return self.send_json({'status': 'error', 'message': '当前销售产品缺少 variant_id，无法定位图片'}, start_response)
                        cur.execute(
                            """
                            SELECT sim.id, sim.image_asset_id, ia.storage_path
                            FROM sku_image_mappings sim
                            JOIN image_assets ia ON ia.id = sim.image_asset_id
                            WHERE {where_key}=%s AND (ia.storage_path=%s OR ia.storage_path LIKE %s)
                            ORDER BY sim.sort_order ASC, sim.id ASC
                            LIMIT 1
                            """.format(where_key=where_key),
                            (where_val, image_name, f'%/{image_name}')
                        )
                        mapping = cur.fetchone() or {}
                        if not mapping.get('id'):
                            return self.send_json({'status': 'error', 'message': '图片文件不存在'}, start_response)
                        image_asset_id = mapping.get('image_asset_id')
                        cur.execute("DELETE FROM sku_image_mappings WHERE id=%s", (mapping.get('id'),))
                        cur.execute("SELECT COUNT(*) AS cnt FROM sku_image_mappings WHERE image_asset_id=%s", (image_asset_id,))
                        remain_sku = self._parse_int((cur.fetchone() or {}).get('cnt')) or 0
                        remain_fabric = 0
                        if self._has_required_tables(['fabric_image_mappings']):
                            cur.execute("SELECT COUNT(*) AS cnt FROM fabric_image_mappings WHERE image_asset_id=%s", (image_asset_id,))
                            remain_fabric = self._parse_int((cur.fetchone() or {}).get('cnt')) or 0
                        remain_total = remain_sku + remain_fabric
                        if remain_total <= 0:
                            cur.execute("SELECT storage_path FROM image_assets WHERE id=%s", (image_asset_id,))
                            asset_row = cur.fetchone() or {}
                            storage_path = (asset_row.get('storage_path') or '').strip()
                            if storage_path:
                                try:
                                    abs_path = self._join_resources(storage_path)
                                    if os.path.exists(abs_path):
                                        os.remove(abs_path)
                                except Exception:
                                    pass
                            cur.execute("DELETE FROM image_assets WHERE id=%s", (image_asset_id,))
                            return self.send_json(
                                {
                                    'status': 'success',
                                    'asset_deleted': True,
                                    'remaining_refs': 0,
                                    'message': '图片已完全删除（无面料/规格关联）',
                                },
                                start_response,
                            )
                return self.send_json(
                    {
                        'status': 'success',
                        'asset_deleted': False,
                        'remaining_refs': int(remain_total),
                        'message': '图片已从当前规格解绑，但仍被其他面料/规格引用，未做物理删除',
                    },
                    start_response,
                )

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_main_images_upload_api(self, environ, start_response):
        try:
            method = environ['REQUEST_METHOD']
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            check_only = str((query_params.get('check_only', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            def _multipart_debug_payload(note, raw_body_len=None):
                try:
                    cl_hdr = int(environ.get('CONTENT_LENGTH', 0) or 0)
                except Exception:
                    cl_hdr = 0
                ct_hdr = str(environ.get('CONTENT_TYPE', '') or '')
                return {
                    'status': 'error',
                    'duplicate_count': 0,
                    'duplicates': [],
                    'file_count': 0,
                    'message': note,
                    'debug': {
                        'wsgi_request_method': str(method or ''),
                        'content_type': ct_hdr,
                        'content_length_header': cl_hdr,
                        'raw_body_bytes': raw_body_len,
                    },
                }

            # Allow GET requests only when check_only is enabled (for duplicate checking without upload)
            if method == 'GET':
                if not check_only:
                    return self.send_json({'status': 'error', 'message': 'Method not allowed. Use POST for uploads or GET with check_only=1 for duplicate checking.'}, start_response)
                # For GET with check_only, we need parameters from query string
                sales_product_id = self._parse_int((query_params.get('sales_product_id', [''])[0] or '').strip())
                if not sales_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)
                image_type_name = (query_params.get('image_type_name', [''])[0] or '').strip() or '文字卖点图'
                # GET cannot carry multipart file bodies; treat this as a client misuse instead of a "successful" empty upload.
                # NOTE: Browsers will issue GET when opening a URL in the address bar.
                # This endpoint cannot perform duplicate checks without file bytes, so return a non-fatal "info"
                # payload (HTTP 200) to avoid looking like a broken API while still guiding correct usage.
                return self.send_json(
                    {
                        'status': 'info',
                        'duplicate_count': 0,
                        'duplicates': [],
                        'file_count': 0,
                        'message': 'check_only 预检需要 POST + multipart/form-data 携带图片文件；在地址栏 GET 打开该 URL 不会上传/不会预检文件内容。',
                    },
                    start_response,
                )

            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            allow_duplicate = str((query_params.get('allow_duplicate', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            raw_body = self._read_wsgi_request_body(environ)
            form = None
            if raw_body:
                env_copy = dict(environ)
                env_copy['CONTENT_LENGTH'] = str(len(raw_body))
                form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            else:
                # Some servers/proxies may omit CONTENT_LENGTH (e.g., chunked transfer).
                # Fall back to streaming parse; cgi.FieldStorage will read from wsgi.input.
                form = cgi.FieldStorage(fp=environ.get('wsgi.input'), environ=environ, keep_blank_values=True)

            sales_product_id = self._parse_int((form.getfirst('sales_product_id', '') or '').strip()) if form else 0
            if not sales_product_id:
                sales_product_id = self._parse_int((query_params.get('sales_product_id', [''])[0] or '').strip())
            if not sales_product_id:
                return self.send_json({'status': 'error', 'message': 'Missing sales_product_id'}, start_response)

            image_type_name = ((form.getfirst('image_type_name', '') if form else '') or '').strip()
            if not image_type_name:
                image_type_name = (query_params.get('image_type_name', [''])[0] or '').strip()
            image_type_name = image_type_name or '文字卖点图'

            uploads = []
            for p in getattr(form, 'list', []) or []:
                if getattr(p, 'filename', None):
                    try:
                        content = p.file.read() or b''
                    except Exception:
                        content = b''
                    uploads.append({'filename': p.filename, 'content': content})
            if not uploads and raw_body:
                uploads = self._parse_multipart_uploads_fallback(content_type, raw_body)
            if not uploads:
                if check_only:
                    return self.send_json(
                        _multipart_debug_payload(
                            '预检失败：未解析到任何图片文件字段。请确认请求体为 multipart/form-data 且字段名为 file；如经过 nginx 301/302 重定向，POST 可能被降级为 GET。',
                            raw_body_len=len(raw_body) if raw_body is not None else 0,
                        ),
                        start_response,
                    )
                return self.send_json({'status': 'error', 'message': 'No valid images uploaded'}, start_response)

            with self._get_db_connection() as conn:
                image_type_id = self._get_image_type_id_by_name(conn, image_type_name)
                if not image_type_id:
                    return self.send_json({'status': 'error', 'message': f'未知图片类型: {image_type_name}'}, start_response)

                user_id = None
                try:
                    user_id = self._get_session_user(environ)
                except Exception as e:
                    # Failed to get session user
                    return self.send_json({'status': 'error', 'message': f'无法验证用户身份，请确保已登录。错误：{str(e)}'}, start_response)
                
                if not user_id:
                    return self.send_json({'status': 'error', 'message': '必须登录才能上传图片'}, start_response)

                duplicates = []
                normalized = []
                skipped_files = []
                for item in uploads:
                    filename = os.path.basename(item.get('filename') or '')
                    content = item.get('content') or b''
                    if not filename:
                        skipped_files.append({'filename': '', 'reason': 'empty_name'})
                        continue
                    if not content:
                        skipped_files.append({'filename': filename, 'reason': 'empty_file'})
                        continue
                    if not self._is_image_name(filename):
                        skipped_files.append({'filename': filename, 'reason': 'unsupported_type'})
                        continue
                    sha256 = self._sha256_hex(content)
                    asset = self._find_image_asset_by_sha256(conn, sha256)
                    normalized.append({
                        'filename': filename,
                        'content': content,
                        'sha256': sha256,
                        'asset': asset,
                    })
                    if asset:
                        duplicates.append({
                            'filename': filename,
                            'sha256': sha256,
                            'image_asset_id': asset.get('id'),
                            'storage_path': asset.get('storage_path') or '',
                            'description': asset.get('description') or ''
                        })

                if not normalized:
                    return self.send_json({
                        'status': 'error',
                        'message': '未检测到可上传图片：仅支持 jpg/jpeg/png/gif/bmp/webp',
                        'file_count': 0,
                        'skipped_files': skipped_files,
                    }, start_response)

                if check_only:
                    return self.send_json({
                        'status': 'success',
                        'mode': 'preflight',
                        'persisted': False,
                        'duplicate_count': len(duplicates),
                        'duplicates': duplicates,
                        'file_count': len(normalized)
                    }, start_response)

                if duplicates and not allow_duplicate:
                    return self.send_json({
                        'status': 'duplicate',
                        'message': '检测到重复图片，请确认是否复用已有图片',
                        'duplicate_count': len(duplicates),
                        'duplicates': duplicates,
                        'file_count': len(normalized)
                    }, start_response)

                # Target folder: 货号/主图/规格-面料
                folder_info = self._resolve_sales_product_variant_folder(sales_product_id, ensure_folder=True)
                target_folder_abs = folder_info.get('folder_path')
                if not target_folder_abs or not os.path.exists(target_folder_abs):
                    return self.send_json({'status': 'error', 'message': '无法定位主图文件夹，请确认货号/规格/面料信息完整'}, start_response)

                # Resolve variant_id for variant-level mapping (preferred)
                variant_id = 0
                try:
                    with conn.cursor() as cur:
                        cur.execute("SELECT variant_id FROM sales_products WHERE id=%s", (sales_product_id,))
                        row = cur.fetchone() or {}
                        variant_id = self._parse_int(row.get('variant_id')) or 0
                except Exception:
                    variant_id = 0

                start_sort = self._get_sales_product_image_sort_start(conn, sales_product_id)
                created_assets = 0
                reused_assets = 0
                linked = 0
                results = []
                created_files = []   # abs paths to delete on rollback
                deferred_links = []  # (src_abs, dst_abs)
                to_insert_assets = []  # dicts for new assets: {sha256, storage_path, filename, ext, file_size, abs_path}

                for idx, item in enumerate(normalized, start=1):
                    filename = item['filename']
                    content = item['content']
                    sha256 = item['sha256']
                    asset = item['asset']
                    ext = self._guess_image_ext(filename, content)
                    if asset:
                        asset_id = asset.get('id')
                        reused_assets += 1
                        # Defer link creation until after DB commit (atomic batch)
                        try:
                            src_abs = self._join_resources(asset.get('storage_path') or '')
                            if src_abs and os.path.exists(src_abs):
                                type_part = self._sanitize_filename_component(image_type_name, 32) or '图片'
                                base_part = self._sanitize_filename_component(os.path.splitext(filename)[0], 80) or 'image'
                                link_name = self._next_available_filename(target_folder_abs, f"{type_part}-{base_part}{ext}")
                                dst_abs = os.path.join(target_folder_abs, self._safe_fsencode(link_name))
                                deferred_links.append((src_abs, dst_abs))
                        except Exception:
                            pass
                    else:
                        # Save into: 货号/主图/规格-面料/ <类型>-<原文件名>[_xx].ext
                        type_part = self._sanitize_filename_component(image_type_name, 32) or '图片'
                        base_part = self._sanitize_filename_component(os.path.splitext(filename)[0], 80) or sha256[:12]
                        final_name = self._next_available_filename(target_folder_abs, f"{type_part}-{base_part}{ext}")
                        abs_path = os.path.join(target_folder_abs, self._safe_fsencode(final_name))
                        try:
                            with open(abs_path, 'wb') as f:
                                f.write(content or b'')
                        except Exception:
                            # If we cannot persist the file, do not write DB rows.
                            raise RuntimeError(f'写入图片文件失败: {filename}')
                        created_files.append(abs_path)

                        # Compute storage_path relative to RESOURCES root
                        try:
                            res_root = self._join_resources('')
                            rel_bytes = os.path.relpath(abs_path, res_root)
                            storage_path = os.fsdecode(rel_bytes).replace('\\', '/')
                        except Exception:
                            storage_path = ''
                        to_insert_assets.append({
                            'sha256': sha256,
                            'storage_path': storage_path,
                            'filename': filename,
                            'ext': ext,
                            'file_size': len(content or b''),
                            'abs_path': abs_path,
                        })
                        asset_id = None

                    sort_order = start_sort + idx
                    results.append({
                        'filename': filename,
                        'sha256': sha256,
                        'image_asset_id': asset_id,
                        'sort_order': sort_order,
                    })

                # ---- Transaction: write DB for the whole batch ----
                try:
                    self._tx_begin(conn)

                    sha_to_asset_id = {}
                    for rec in to_insert_assets:
                        with conn.cursor() as cur:
                            aid = self._insert_image_asset_dynamic(
                                conn,
                                cur,
                                {
                                    'sha256': rec['sha256'],
                                    'storage_path': rec['storage_path'],
                                    'filename': rec['filename'],
                                    'ext': rec['ext'],
                                    'file_size': rec['file_size'],
                                    'image_type_id': image_type_id,
                                    'created_by': user_id,
                                },
                            )
                        sha_to_asset_id[rec['sha256']] = aid
                        created_assets += 1

                    # Resolve reused assets again inside tx (stable)
                    for item in normalized:
                        if item.get('asset') and item.get('sha256'):
                            sha_to_asset_id.setdefault(item['sha256'], int(item['asset'].get('id') or 0))

                    # Insert mappings (variant preferred)
                    for idx, row in enumerate(results, start=1):
                        sha = row.get('sha256')
                        aid = sha_to_asset_id.get(sha) or 0
                        if not aid:
                            raise RuntimeError('无法解析 image_asset_id')
                        row['image_asset_id'] = aid
                        sort_order = row.get('sort_order')
                        with conn.cursor() as cur:
                            self._execute_sku_mapping_upsert(
                                conn, cur, aid, sort_order, image_type_id, variant_id, sales_product_id, user_id
                            )
                        linked += 1

                    self._tx_commit(conn)
                except Exception as e:
                    self._tx_rollback(conn)
                    # Cleanup any newly written files
                    for p in created_files:
                        self._safe_unlink(p)
                    # Also cleanup any links we may have created (we deferred, so none here)
                    return self.send_json({'status': 'error', 'message': f'上传失败，已回滚：{str(e)}'}, start_response)

                # After commit: create deferred links best-effort
                for src_abs, dst_abs in deferred_links:
                    try:
                        self._try_create_link(src_abs, dst_abs)
                    except Exception:
                        pass
                # After commit: apply rehome best-effort
                try:
                    for row in results:
                        self._rehome_image_asset_if_needed(conn, row.get('image_asset_id'))
                except Exception:
                    pass

                return self.send_json({
                    'status': 'success',
                    'mode': 'upload',
                    'persisted': True,
                    'files': [x['filename'] for x in results],
                    'created_assets': created_assets,
                    'reused_assets': reused_assets,
                    'linked': linked,
                    'duplicates': duplicates
                }, start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_api(self, environ, method, start_response):
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            def _resolve_sales_product_id(conn, value):
                item_id = self._parse_int(value)
                if item_id:
                    return item_id
                sku = str(value or '').strip()
                if not sku:
                    return None
                with conn.cursor() as cur:
                    cur.execute("SELECT id FROM sales_products WHERE platform_sku=%s LIMIT 1", (sku,))
                    row = cur.fetchone() or {}
                return self._parse_int(row.get('id'))

            def _normalize_date_text(value):
                if value is None:
                    return ''
                if isinstance(value, datetime):
                    return value.strftime('%Y-%m-%d')
                text = str(value).strip()
                if not text:
                    return ''
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return text[:10]

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())
                page_size = min(1000, max(10, self._parse_int((query_params.get('page_size', ['50'])[0] or '50')) or 50))
                page = max(1, self._parse_int((query_params.get('page', ['1'])[0] or '1')) or 1)
                limit = min(5000, max(1, self._parse_int((query_params.get('limit', [str(page_size)])[0] or str(page_size))) or page_size))
                page_size = min(page_size, limit)
                offset = (page - 1) * page_size

                base_sql = """
                    FROM sales_product_performances spp
                    JOIN sales_products sp ON sp.id = spp.sales_product_id
                    LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                    LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                """
                data_sql = """
                    SELECT spp.*, sp.platform_sku, v.sku_family_id AS sku_family_id, pf.sku_family
                """
                params = []
                filters = []
                if item_id:
                    filters.append('spp.id=%s')
                    params.append(item_id)
                if keyword:
                    like_kw = f'%{keyword}%'
                    filters.append('(sp.platform_sku LIKE %s OR pf.sku_family LIKE %s)')
                    params.extend([like_kw, like_kw])
                if filters:
                    where_sql = ' WHERE ' + ' AND '.join(filters)
                else:
                    where_sql = ''

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if item_id:
                            cur.execute(data_sql + base_sql + where_sql + ' ORDER BY spp.record_date DESC, spp.id DESC LIMIT 1', params)
                            rows = cur.fetchall() or []
                            return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)

                        cur.execute('SELECT COUNT(1) AS cnt ' + base_sql + where_sql, params)
                        total = int((cur.fetchone() or {}).get('cnt') or 0)

                        data_params = list(params)
                        data_params.extend([offset, page_size])
                        cur.execute(
                            data_sql + base_sql + where_sql + ' ORDER BY spp.record_date DESC, spp.id DESC LIMIT %s, %s',
                            data_params
                        )
                        rows = cur.fetchall() or []
                return self.send_json({
                    'status': 'success',
                    'items': rows,
                    'page': page,
                    'page_size': page_size,
                    'total': total,
                    'total_pages': (total + page_size - 1) // page_size if page_size else 1
                }, start_response)

            if method in ('POST', 'PUT'):
                data = self._read_json_body(environ)
                performance_id = self._parse_int(data.get('id'))
                sales_product_ref = data.get('sales_product_id') or data.get('platform_sku')
                record_date = _normalize_date_text(data.get('record_date'))
                if not record_date:
                    return self.send_json({'status': 'error', 'message': 'Missing record_date'}, start_response)

                with self._get_db_connection() as conn:
                    sales_product_id = _resolve_sales_product_id(conn, sales_product_ref)
                    if not sales_product_id:
                        return self.send_json({'status': 'error', 'message': '无法根据销售平台SKU找到销售产品'}, start_response)

                    values = {
                        'sales_qty': self._parse_int(data.get('sales_qty')) or 0,
                        'net_sales_amount': self._parse_float(data.get('net_sales_amount')) or 0,
                        'order_qty': self._parse_int(data.get('order_qty')) or 0,
                        'session_total': self._parse_int(data.get('session_total')) or 0,
                        'ad_impressions': self._parse_int(data.get('ad_impressions')) or 0,
                        'ad_clicks': self._parse_int(data.get('ad_clicks')) or 0,
                        'ad_orders': self._parse_int(data.get('ad_orders')) or 0,
                        'ad_spend': self._parse_float(data.get('ad_spend')) or 0,
                        'ad_sales_amount': self._parse_float(data.get('ad_sales_amount')) or 0,
                        'refund_amount': self._parse_float(data.get('refund_amount')) or 0,
                        'sub_category_rank': self._parse_int(data.get('sub_category_rank')),
                    }

                    if performance_id and method == 'PUT':
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE sales_product_performances
                                SET sales_product_id=%s, record_date=%s, sales_qty=%s, net_sales_amount=%s,
                                    order_qty=%s, session_total=%s, ad_impressions=%s, ad_clicks=%s,
                                    ad_orders=%s, ad_spend=%s, ad_sales_amount=%s, refund_amount=%s,
                                    sub_category_rank=%s
                                WHERE id=%s
                                """,
                                (
                                    sales_product_id, record_date, values['sales_qty'], values['net_sales_amount'],
                                    values['order_qty'], values['session_total'], values['ad_impressions'], values['ad_clicks'],
                                    values['ad_orders'], values['ad_spend'], values['ad_sales_amount'], values['refund_amount'],
                                    values['sub_category_rank'], performance_id
                                )
                            )
                        return self.send_json({'status': 'success', 'id': performance_id}, start_response)

                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sales_product_performances
                            (sales_product_id, record_date, sales_qty, net_sales_amount, order_qty, session_total,
                             ad_impressions, ad_clicks, ad_orders, ad_spend, ad_sales_amount, refund_amount, sub_category_rank)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                sales_qty=VALUES(sales_qty),
                                net_sales_amount=VALUES(net_sales_amount),
                                order_qty=VALUES(order_qty),
                                session_total=VALUES(session_total),
                                ad_impressions=VALUES(ad_impressions),
                                ad_clicks=VALUES(ad_clicks),
                                ad_orders=VALUES(ad_orders),
                                ad_spend=VALUES(ad_spend),
                                ad_sales_amount=VALUES(ad_sales_amount),
                                refund_amount=VALUES(refund_amount),
                                sub_category_rank=VALUES(sub_category_rank)
                            """,
                            (
                                sales_product_id, record_date, values['sales_qty'], values['net_sales_amount'],
                                values['order_qty'], values['session_total'], values['ad_impressions'], values['ad_clicks'],
                                values['ad_orders'], values['ad_spend'], values['ad_sales_amount'], values['refund_amount'],
                                values['sub_category_rank']
                            )
                        )
                        return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_product_performances WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT platform_sku FROM sales_products ORDER BY platform_sku")
                    sku_rows = cur.fetchall() or []
            sku_values = [str(row.get('platform_sku') or '').strip() for row in sku_rows if str(row.get('platform_sku') or '').strip()]

            wb = Workbook()
            ws = wb.active
            ws.title = 'sales_product_performance'

            headers = [
                'MSKU/ASIN/子ASIN*', '日期*', '销量*', '净销售额(USD)*', '订单量*', 'Sessions-Total*',
                '(广告)展示*', '(广告)点击*', '(广告)订单量*', '(广告)花费(USD)*', '(广告)销售额(USD)*',
                '退款金额(USD)*', '小类排名*'
            ]
            ws.append(headers)
            ws.append([
                '示例SKU_请删除此行',
                '示例日期_请删除此行',
                12,
                999.99,
                10,
                480,
                2500,
                88,
                6,
                120.50,
                899.90,
                0.00,
                'Living Room Chairs:5633'
            ])

            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            for cell in ws[2]:
                cell.fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
                cell.font = Font(italic=True, color='888888')

            widths = [24, 14, 10, 14, 10, 12, 12, 12, 12, 14, 14, 12, 12]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width

            options_ws = wb.create_sheet('options')
            options_ws.sheet_state = 'hidden'
            options_ws.cell(row=1, column=1, value='sales_platform_sku')
            for idx, sku in enumerate(sku_values, start=2):
                options_ws.cell(row=idx, column=1, value=sku)

            if sku_values:
                sku_validation = DataValidation(type='list', formula1=f'=options!$A$2:$A${len(sku_values) + 1}', allow_blank=False)
                ws.add_data_validation(sku_validation)
                for row_idx in range(3, 1000):
                    sku_validation.add(f'A{row_idx}')

            ws.freeze_panes = 'A3'
            return self._send_excel_workbook(wb, 'sales_product_performance_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_performance_import_api(self, environ, method, start_response):
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            mode = str((query_params.get('mode', [''])[0] or '')).strip().lower()
            task_id = str((query_params.get('task_id', [''])[0] or '')).strip()
            async_import = str((query_params.get('async', [''])[0] or '')).strip().lower() in ('1', 'true', 'yes', 'on')
            temp_token = str((query_params.get('from_temp', [''])[0] or '')).strip()

            import tempfile

            def _safe_task_id(raw):
                t = str(raw or '').strip()
                if not t:
                    return ''
                if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', t):
                    return ''
                return t

            def _progress_file_path(tid):
                progress_dir = os.path.join(tempfile.gettempdir(), 'sitjoy_import_progress')
                try:
                    os.makedirs(progress_dir, exist_ok=True)
                except Exception:
                    pass
                return os.path.join(progress_dir, f'sales_product_performance_{tid}.json')

            def _temp_upload_path(token):
                temp_dir = os.path.join(tempfile.gettempdir(), 'sitjoy_import_temp')
                try:
                    os.makedirs(temp_dir, exist_ok=True)
                except Exception:
                    pass
                return os.path.join(temp_dir, f'spp_{token}.bin')

            def _write_progress(tid, payload):
                if not tid:
                    return
                path = _progress_file_path(tid)
                tmp_path = path + '.tmp'
                try:
                    with open(tmp_path, 'w', encoding='utf-8') as f:
                        json.dump(payload, f, ensure_ascii=False)
                    os.replace(tmp_path, path)
                except Exception:
                    pass

            def _read_progress(tid):
                if not tid:
                    return None
                path = _progress_file_path(tid)
                if not os.path.exists(path):
                    return None
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except Exception:
                    return None

            safe_task_id = _safe_task_id(task_id)

            if method == 'GET' and mode == 'progress':
                data = _read_progress(safe_task_id)
                if not data:
                    return self.send_json({
                        'status': 'success',
                        'task_id': safe_task_id,
                        'state': 'pending',
                        'processed_rows': 0,
                        'total_rows': 0,
                        'created': 0,
                        'message': '等待任务开始'
                    }, start_response)
                data.setdefault('status', 'success')
                data.setdefault('task_id', safe_task_id)
                return self.send_json(data, start_response)

            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
            check_only = str((query_params.get('check_only', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')

            if not safe_task_id:
                safe_task_id = hashlib.md5(f"{datetime.now().isoformat()}_{os.getpid()}".encode('utf-8')).hexdigest()[:16]

            file_bytes = b''
            if temp_token:
                temp_path = _temp_upload_path(temp_token)
                if not os.path.exists(temp_path):
                    return self.send_json({'status': 'error', 'message': '临时文件不存在，任务可能已过期'}, start_response)
                with open(temp_path, 'rb') as f:
                    file_bytes = f.read() or b''
                if not file_bytes:
                    return self.send_json({'status': 'error', 'message': '临时文件为空'}, start_response)
            else:
                content_type = environ.get('CONTENT_TYPE', '')
                if 'multipart/form-data' not in content_type:
                    return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

                content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
                raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
                env_copy = dict(environ)
                env_copy['CONTENT_LENGTH'] = str(len(raw_body))
                form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
                file_item = form['file'] if 'file' in form else None
                if file_item is None or getattr(file_item, 'file', None) is None:
                    return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
                file_bytes = file_item.file.read() or b''
                if not file_bytes:
                    return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            # 正式导入默认异步，避免网关504；预检保持同步
            if (not check_only) and (not temp_token):
                if not async_import:
                    async_import = True
                if async_import:
                    temp_token = safe_task_id
                    temp_path = _temp_upload_path(temp_token)
                    with open(temp_path, 'wb') as f:
                        f.write(file_bytes)

                    _write_progress(safe_task_id, {
                        'status': 'success',
                        'task_id': safe_task_id,
                        'state': 'pending',
                        'processed_rows': 0,
                        'total_rows': 0,
                        'created': 0,
                        'message': '任务已创建，准备开始处理'
                    })

                    def _bg_worker():
                        try:
                            q = f"task_id={safe_task_id}&check_only=0&async=0&from_temp={temp_token}"
                            bg_env = {
                                'QUERY_STRING': q,
                                'CONTENT_TYPE': '',
                                'CONTENT_LENGTH': '0',
                                'wsgi.input': io.BytesIO(b''),
                            }
                            self.handle_sales_product_performance_import_api(bg_env, 'POST', lambda *args, **kwargs: None)
                        except Exception as _e:
                            _write_progress(safe_task_id, {
                                'status': 'error',
                                'task_id': safe_task_id,
                                'state': 'error',
                                'processed_rows': 0,
                                'total_rows': 0,
                                'created': 0,
                                'message': str(_e)[:200]
                            })
                        finally:
                            try:
                                if os.path.exists(temp_path):
                                    os.remove(temp_path)
                            except Exception:
                                pass

                    t = threading.Thread(target=_bg_worker, daemon=True)
                    t.start()
                    return self.send_json({
                        'status': 'success',
                        'async': True,
                        'task_id': safe_task_id,
                        'message': '导入任务已启动，请通过进度接口轮询结果'
                    }, start_response)

            # 全程只读模式，降低大文件导入时CPU和内存开销
            wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
            ws = wb.active
            total_rows_hint = max(0, int((ws.max_row or 1)) - 1)

            # 读取第一行作为headers（read_only模式下避免ws[1]）
            header_row = next(ws.iter_rows(min_row=1, max_row=1, values_only=True), None)
            headers = [str(x or '').strip() for x in (header_row or [])]

            def normalize_header(text):
                t = str(text or '').strip().lower()
                t = t.replace('\ufeff', '')
                t = t.replace('*', '')
                t = t.replace('（', '(').replace('）', ')')
                t = t.replace('：', ':')
                t = re.sub(r'[\s\-_/\\|()\[\]{}:]+', '', t)
                return t

            alias_groups = {
                'identifier': ['销售平台sku', '销售平台sku/msku/asin/子asin', 'msku/asin/子asin', 'platformsku', 'sku', 'msku', 'asin', '子asin', '子体asin', 'childasin', '子体编码', '子体编号'],
                'record_date': ['日期', 'date', 'recorddate'],
                'sales_qty': ['销量', 'salesqty', 'salesquantity'],
                'net_sales_amount': ['净销售额(usd)', '净销售额', '销售额', 'netsales', 'netsalesamount', 'salesamount'],
                'order_qty': ['订单量', 'orderqty', 'orderquantity'],
                'session_total': ['session-total', 'sessions-total', 'sessiontotal', 'sessionstotal'],
                'ad_impressions': ['(广告)展示', '广告展示', '展示', 'adimpressions', 'impressions'],
                'ad_clicks': ['(广告)点击', '广告点击', '点击', 'adclicks', 'clicks'],
                'ad_orders': ['(广告)订单量', '广告订单量', 'adorders', 'ordersfromad'],
                'ad_spend': ['(广告)花费(usd)', '(广告)花费', '广告花费(usd)', '广告花费', 'adspend', 'spend'],
                'ad_sales_amount': ['(广告)销售额(usd)', '(广告)销售额', '广告销售额(usd)', '广告销售额', 'adsales', 'adsalesamount'],
                'refund_amount': ['退款金额(usd)', '退款金额', 'refundamount'],
                'sub_category_rank': ['小类排名', 'categoryrank', 'subcategoryrank']
            }

            normalized_headers = [normalize_header(h) for h in headers]
            resolved_col = {}
            for key, aliases in alias_groups.items():
                found = None
                alias_set = set([normalize_header(x) for x in aliases])
                for idx, norm_name in enumerate(normalized_headers):
                    if norm_name in alias_set:
                        found = idx
                        break
                resolved_col[key] = found

            if resolved_col.get('identifier') is None:
                return self.send_json({'status': 'error', 'message': '模板缺少标识列（销售平台SKU/MSKU/ASIN/子ASIN）'}, start_response)
            if resolved_col.get('record_date') is None:
                return self.send_json({'status': 'error', 'message': '模板缺少日期列'}, start_response)

            def get_cell(row, field_key):
                idx = resolved_col.get(field_key)
                if idx is None or idx >= len(row):
                    return None
                return row[idx]

            def normalize_date(value):
                if value is None:
                    return ''
                if isinstance(value, datetime):
                    return value.strftime('%Y-%m-%d')
                text = str(value).strip()
                if not text:
                    return ''
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return text[:10]

            def parse_number_flexible(value, as_int=False):
                if value is None:
                    return 0 if as_int else 0.0
                if isinstance(value, (int, float)):
                    if as_int:
                        try:
                            return int(round(float(value)))
                        except Exception:
                            return 0
                    return float(value)
                text = str(value).strip()
                if not text:
                    return 0 if as_int else 0.0
                text = text.replace('，', ',').replace('$', '').replace('￥', '')
                text = text.replace(',', '')
                m = re.search(r'-?\d+(?:\.\d+)?', text)
                if not m:
                    return 0 if as_int else 0.0
                num = float(m.group(0))
                if as_int:
                    return int(round(num))
                return num

            def parse_rank(value):
                if value is None:
                    return None
                text = str(value).strip()
                if not text:
                    return None
                m = re.search(r'(\d+)\s*$', text)
                if m:
                    return int(m.group(1))
                m2 = re.search(r'(\d+)', text)
                if m2:
                    return int(m2.group(1))
                return None

            def row_signature(payload):
                return '|'.join([
                    str(payload.get('sales_qty') or 0),
                    str(payload.get('net_sales_amount') or 0),
                    str(payload.get('order_qty') or 0),
                    str(payload.get('session_total') or 0),
                    str(payload.get('ad_impressions') or 0),
                    str(payload.get('ad_clicks') or 0),
                    str(payload.get('ad_orders') or 0),
                    str(payload.get('ad_spend') or 0),
                    str(payload.get('ad_sales_amount') or 0),
                    str(payload.get('refund_amount') or 0),
                    str(payload.get('sub_category_rank') or ''),
                ])

            created = 0
            updated = 0
            unchanged = 0
            errors = []
            skipped_empty_identifier = 0
            skipped_unmatched_sku = 0
            skipped_invalid_date = 0
            skipped_template_sample = 0
            upserted = 0

            _write_progress(safe_task_id, {
                'status': 'success',
                'task_id': safe_task_id,
                'state': 'running',
                'processed_rows': 0,
                'total_rows': total_rows_hint,
                'created': 0,
                'message': '开始处理...'
            })

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    # 一次性加载SKU/ASIN映射，避免双遍Excel扫描导致总时长翻倍
                    sku_map = {}
                    asin_map = {}
                    cur.execute("SELECT id, platform_sku, child_code FROM sales_products")
                    for row in (cur.fetchall() or []):
                        rid = int(row.get('id') or 0)
                        sku = str(row.get('platform_sku') or '').strip().lower()
                        child_code = str(row.get('child_code') or '').strip().lower()
                        if rid and sku:
                            sku_map[sku] = rid
                        if rid and child_code:
                            asin_map[child_code] = rid
                    
                    # 初始化批处理变量
                    batch_rows = []
                    batch_size = 300
                    upsert_sql = (
                        "INSERT INTO sales_product_performances "
                        "(sales_product_id,record_date,sales_qty,net_sales_amount,order_qty,session_total,"
                        "ad_impressions,ad_clicks,ad_orders,ad_spend,ad_sales_amount,refund_amount,sub_category_rank) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                        "ON DUPLICATE KEY UPDATE "
                        "sales_qty=VALUES(sales_qty),"
                        "net_sales_amount=VALUES(net_sales_amount),"
                        "order_qty=VALUES(order_qty),"
                        "session_total=VALUES(session_total),"
                        "ad_impressions=VALUES(ad_impressions),"
                        "ad_clicks=VALUES(ad_clicks),"
                        "ad_orders=VALUES(ad_orders),"
                        "ad_spend=VALUES(ad_spend),"
                        "ad_sales_amount=VALUES(ad_sales_amount),"
                        "refund_amount=VALUES(refund_amount),"
                        "sub_category_rank=VALUES(sub_category_rank)"
                    )
                    
                    def flush_batch_data():
                        if not batch_rows:
                            return 0
                        try:
                            cur.executemany(upsert_sql, batch_rows)
                            conn.commit()
                            return len(batch_rows)
                        except Exception as e:
                            conn.rollback()
                            raise RuntimeError(f"批量写入失败: {str(e)[:180]}")
                        finally:
                            batch_rows.clear()

                    # 预检模式：只检查前100行用于快速验证；正式模式：处理全部行
                    process_limit = 100 if check_only else 999999
                    processed_count = 0
                    row_count = 0

                    # 使用iter_rows避免遍历max_row导致的超时问题
                    for row in ws.iter_rows(min_row=2, values_only=True):
                        # 达到预检限制时提前退出
                        if check_only and processed_count >= process_limit:
                            break

                        row_count += 1

                        if not any(cell is not None and str(cell).strip() for cell in row):
                            continue

                        processed_count += 1

                        try:
                            identifier = str(get_cell(row, 'identifier') or '').strip()
                            if not identifier:
                                # 缺少标识，直接跳过（不计入errors）
                                skipped_empty_identifier += 1
                                continue

                            low_identifier = identifier.lower()
                            if any(x in low_identifier for x in ('示例', 'sample', 'demo', 'template', '请删除')):
                                skipped_template_sample += 1
                                continue
                            sales_product_id = sku_map.get(low_identifier)
                            if not sales_product_id:
                                sales_product_id = asin_map.get(low_identifier)

                            # SKU无法匹配时，直接跳过该行（不计入errors，不中断流程）
                            if not sales_product_id:
                                skipped_unmatched_sku += 1
                                continue

                            record_date = normalize_date(get_cell(row, 'record_date'))
                            if not record_date:
                                # 日期格式错误，直接跳过
                                skipped_invalid_date += 1
                                continue

                            # 兼容历史模板样例行保护（避免误导入示例数据）
                            if record_date == '2026-04-07':
                                skipped_template_sample += 1
                                continue

                            # 预检模式：只计算统计，不入库
                            if check_only:
                                created += 1
                            else:
                                batch_rows.append((
                                    sales_product_id,
                                    record_date,
                                    parse_number_flexible(get_cell(row, 'sales_qty'), True),
                                    parse_number_flexible(get_cell(row, 'net_sales_amount'), False),
                                    parse_number_flexible(get_cell(row, 'order_qty'), True),
                                    parse_number_flexible(get_cell(row, 'session_total'), True),
                                    parse_number_flexible(get_cell(row, 'ad_impressions'), True),
                                    parse_number_flexible(get_cell(row, 'ad_clicks'), True),
                                    parse_number_flexible(get_cell(row, 'ad_orders'), True),
                                    parse_number_flexible(get_cell(row, 'ad_spend'), False),
                                    parse_number_flexible(get_cell(row, 'ad_sales_amount'), False),
                                    parse_number_flexible(get_cell(row, 'refund_amount'), False),
                                    parse_rank(get_cell(row, 'sub_category_rank')),
                                ))
                                created += 1

                                # 达到batch_size则执行
                                if len(batch_rows) >= batch_size:
                                    upserted += flush_batch_data()
                        except Exception as batch_err:
                            errors.append(f"第{row_count+1}行处理失败: {str(batch_err)[:100]}")

                        if row_count % 50 == 0:
                            _write_progress(safe_task_id, {
                                'status': 'success',
                                'task_id': safe_task_id,
                                'state': 'running',
                                'processed_rows': row_count,
                                'total_rows': total_rows_hint,
                                'created': created,
                                'message': f'正在处理第 {row_count} 行'
                            })

                    # 导入完成后，flush最后的batch数据
                    if not check_only:
                        upserted += flush_batch_data()
                        conn.commit()  # 最终确保commit

            if not check_only and upserted <= 0:
                msg = (
                    f"未成功写入任何数据：处理行{row_count}，"
                    f"匹配行{created}，空标识跳过{skipped_empty_identifier}，"
                    f"未匹配SKU跳过{skipped_unmatched_sku}，日期无效跳过{skipped_invalid_date}。"
                    f"示例行跳过{skipped_template_sample}。"
                    "请检查模板SKU是否能匹配 sales_products.platform_sku/child_code。"
                )
                _write_progress(safe_task_id, {
                    'status': 'error',
                    'task_id': safe_task_id,
                    'state': 'error',
                    'processed_rows': row_count,
                    'total_rows': total_rows_hint,
                    'created': created,
                    'message': msg
                })
                return self.send_json({
                    'status': 'error',
                    'task_id': safe_task_id,
                    'message': msg,
                    'stats': {
                        'processed_rows': row_count,
                        'matched_rows': created,
                        'upserted_rows': upserted,
                        'skipped_empty_identifier': skipped_empty_identifier,
                        'skipped_unmatched_sku': skipped_unmatched_sku,
                        'skipped_invalid_date': skipped_invalid_date
                        , 'skipped_template_sample': skipped_template_sample
                    },
                    'errors': errors[:100]
                }, start_response)

            _write_progress(safe_task_id, {
                'status': 'success',
                'task_id': safe_task_id,
                'state': 'success',
                'processed_rows': row_count,
                'total_rows': total_rows_hint,
                'created': created,
                'upserted': upserted,
                'skipped_empty_identifier': skipped_empty_identifier,
                'skipped_unmatched_sku': skipped_unmatched_sku,
                'skipped_invalid_date': skipped_invalid_date,
                'skipped_template_sample': skipped_template_sample,
                'errors': errors[:100],
                'message': f'处理完成，匹配 {created} 条，写入 {upserted} 条'
            })

            return self.send_json({
                'status': 'success',
                'task_id': safe_task_id,
                'check_only': check_only,
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'upserted': upserted,
                'skipped_empty_identifier': skipped_empty_identifier,
                'skipped_unmatched_sku': skipped_unmatched_sku,
                'skipped_invalid_date': skipped_invalid_date,
                'skipped_template_sample': skipped_template_sample,
                'errors': errors,
                'total_rows': created + updated + unchanged + len(errors),
                'message': (
                    f"成功处理：匹配{created}条，写入{upserted}条，"
                    f"未匹配SKU{skipped_unmatched_sku}条，示例行{skipped_template_sample}条"
                ) if not check_only else f"预检完成，预计可识别{created}条数据"
            }, start_response)
        except Exception as e:
            import traceback
            try:
                _write_progress(safe_task_id if 'safe_task_id' in locals() else '', {
                    'status': 'error',
                    'task_id': safe_task_id if 'safe_task_id' in locals() else '',
                    'state': 'error',
                    'processed_rows': 0,
                    'total_rows': 0,
                    'created': 0,
                    'message': str(e)[:200]
                })
            except Exception:
                pass
            error_str = str(e).lower()
            
            if 'sales_product_performances' in error_str or 'table' in error_str and 'doesn\'t exist' in error_str:
                return self.send_json({
                    'status': 'error',
                    'message': '❌ 表不存在：请先在数据库执行 scripts/sql/20260404_00_sales_product_performance.sql'
                }, start_response)
            
            if 'connection' in error_str or 'timeout' in error_str:
                return self.send_json({
                    'status': 'error',
                    'message': f'❌ 数据库连接错误：{str(e)[:100]}'
                }, start_response)
            
            tb = traceback.format_exc()
            return self.send_json({
                'status': 'error',
                'message': str(e)[:200],
                'detail': tb.split('\n')[-3:-1] if check_only else None
            }, start_response)

    def handle_sales_product_performance_dashboard_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            mode = str((query_params.get('mode', ['dashboard'])[0] or 'dashboard')).strip().lower()

            def parse_csv_text(name):
                raw_list = query_params.get(name, [])
                tokens = []
                for raw in raw_list:
                    for token in re.split(r'[,，;；\s]+', str(raw or '').strip()):
                        t = token.strip()
                        if t and t not in tokens:
                            tokens.append(t)
                return tokens

            def parse_csv_int(name):
                values = []
                for token in parse_csv_text(name):
                    val = self._parse_int(token)
                    if val and val not in values:
                        values.append(val)
                return values

            def parse_date(value):
                text = str(value or '').strip()
                if not text:
                    return ''
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return text[:10]

            metric_defs = [
                {'key': 'sales_qty', 'label': '销量', 'color': '#5b6aa8', 'agg': 'sum'},
                {'key': 'net_sales_amount', 'label': '净销售额', 'color': '#b85c5c', 'agg': 'sum'},
                {'key': 'order_qty', 'label': '订单量', 'color': '#bc7a3f', 'agg': 'sum'},
                {'key': 'session_total', 'label': 'Sessions-Total', 'color': '#44798c', 'agg': 'sum'},
                {'key': 'ad_impressions', 'label': '广告展示', 'color': '#7e8a57', 'agg': 'sum'},
                {'key': 'ad_clicks', 'label': '广告点击', 'color': '#8b6f9c', 'agg': 'sum'},
                {'key': 'ad_orders', 'label': '广告订单量', 'color': '#4d7ea8', 'agg': 'sum'},
                {'key': 'ad_spend', 'label': '广告花费', 'color': '#b96f3d', 'agg': 'sum'},
                {'key': 'ad_sales_amount', 'label': '广告销售额', 'color': '#6a8f4e', 'agg': 'sum'},
                {'key': 'refund_amount', 'label': '退款金额', 'color': '#9b4a4a', 'agg': 'sum'},
                {'key': 'sub_category_rank', 'label': '小类排名', 'color': '#6d7485', 'agg': 'avg'},
            ]

            with self._get_db_connection() as conn:
                if mode == 'filters':
                    has_fabric_id = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
                    has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                    fabric_join = "LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if has_fabric_id else ""
                    if has_fabric_id and has_fabric_text:
                        fabric_expr = "COALESCE(fm.fabric_code, v.fabric)"
                    elif has_fabric_id:
                        fabric_expr = "fm.fabric_code"
                    else:
                        fabric_expr = ("v.fabric" if has_fabric_text else "''")
                    with conn.cursor() as cur:
                        cur.execute(
                            f"""
                            SELECT sp.id, sp.platform_sku, {fabric_expr} AS fabric, v.spec_name,
                                pf.id AS sku_family_id, pf.sku_family,
                                   sh.id AS shop_id, sh.shop_name,
                                   pt.id AS platform_type_id, pt.name AS platform_type_name
                            FROM sales_products sp
                            LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                            LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                            LEFT JOIN shops sh ON sh.id = sp.shop_id
                            LEFT JOIN platform_types pt ON pt.id = sh.platform_type_id
                            {fabric_join}
                            ORDER BY pf.sku_family ASC, sp.platform_sku ASC
                            """
                        )
                        rows = cur.fetchall() or []

                        cur.execute("SELECT id, name FROM amazon_ad_operation_types ORDER BY id ASC")
                        op_types = cur.fetchall() or []

                    sku_families = []
                    sku_family_seen = set()
                    platform_skus = []
                    fabrics = []
                    specs = []
                    shops = []
                    platforms = []
                    f_seen = set()
                    s_seen = set()
                    shop_seen = set()
                    platform_seen = set()

                    for r in rows:
                        sf_id = self._parse_int(r.get('sku_family_id'))
                        sf = str(r.get('sku_family') or '').strip()
                        if sf_id and sf and sf_id not in sku_family_seen:
                            sku_family_seen.add(sf_id)
                            sku_families.append({'id': sf_id, 'name': sf})
                        sku = str(r.get('platform_sku') or '').strip()
                        if sku:
                            platform_skus.append({'id': self._parse_int(r.get('id')), 'name': sku})
                        fabric = str(r.get('fabric') or '').strip()
                        spec = str(r.get('spec_name') or '').strip()
                        if fabric and fabric not in f_seen:
                            f_seen.add(fabric)
                            fabrics.append(fabric)
                        if spec and spec not in s_seen:
                            s_seen.add(spec)
                            specs.append(spec)

                        shop_id = self._parse_int(r.get('shop_id'))
                        shop_name = str(r.get('shop_name') or '').strip()
                        if shop_id and shop_name and shop_id not in shop_seen:
                            shop_seen.add(shop_id)
                            shops.append({'id': shop_id, 'name': shop_name})

                        platform_id = self._parse_int(r.get('platform_type_id'))
                        platform_name = str(r.get('platform_type_name') or '').strip()
                        if platform_id and platform_name and platform_id not in platform_seen:
                            platform_seen.add(platform_id)
                            platforms.append({'id': platform_id, 'name': platform_name})

                    return self.send_json({
                        'status': 'success',
                        'filters': {
                            'sku_families': sku_families,
                            'platform_skus': platform_skus,
                            'fabrics': fabrics,
                            'spec_names': specs,
                            'shops': shops,
                            'platform_types': platforms,
                            'metrics': metric_defs,
                            'ad_operation_types': [{'id': self._parse_int(x.get('id')), 'name': x.get('name') or ''} for x in op_types]
                        }
                    }, start_response)

                import time
                perf_t_start = time.time()
                perf_timings = {}
                
                start_date = parse_date((query_params.get('start_date', [''])[0] or ''))
                end_date = parse_date((query_params.get('end_date', [''])[0] or ''))
                sku_family_ids = parse_csv_int('sku_family_ids')
                platform_skus = parse_csv_text('platform_skus')
                fabrics = parse_csv_text('fabrics')
                spec_names = parse_csv_text('spec_names')
                shop_ids = parse_csv_int('shop_ids')
                platform_type_ids = parse_csv_int('platform_type_ids')
                metric_keys = parse_csv_text('metric_keys')
                if not metric_keys:
                    metric_keys = ['sales_qty', 'net_sales_amount', 'order_qty', 'ad_spend', 'ad_sales_amount']
                include_todos = str((query_params.get('include_todos', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                include_ads = str((query_params.get('include_ads', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                ad_operation_type_ids = parse_csv_int('ad_operation_type_ids')
                perf_timings['params'] = time.time() - perf_t_start

                # === 优化1：数据库端聚合图表数据（GROUP BY + SUM/AVG）===
                perf_t_a = time.time()
                agg_columns = "DATE(spp.record_date) as record_date"
                for key in metric_keys:
                    metric = next((m for m in metric_defs if m['key'] == key), None)
                    if metric:
                        agg = metric['agg']
                        if agg == 'sum':
                            agg_columns += f", SUM(spp.{key}) as {key}"
                        elif agg == 'avg':
                            agg_columns += f", AVG(spp.{key}) as {key}"
                
                agg_sql = [
                    f"""
                    SELECT {agg_columns}
                    FROM sales_product_performances spp
                    JOIN sales_products sp ON sp.id = spp.sales_product_id
                    LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                    LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                    LEFT JOIN shops sh ON sh.id = sp.shop_id
                    LEFT JOIN platform_types pt ON pt.id = sh.platform_type_id
                    WHERE 1=1
                    """
                ]
                agg_params = []
                has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                if start_date:
                    agg_sql.append(' AND spp.record_date >= %s')
                    agg_params.append(start_date)
                if end_date:
                    agg_sql.append(' AND spp.record_date <= %s')
                    agg_params.append(end_date)
                if sku_family_ids:
                    agg_sql.append(f" AND v.sku_family_id IN ({','.join(['%s'] * len(sku_family_ids))})")
                    agg_params.extend(sku_family_ids)
                if platform_skus:
                    agg_sql.append(f" AND sp.platform_sku IN ({','.join(['%s'] * len(platform_skus))})")
                    agg_params.extend(platform_skus)
                if fabrics:
                    if has_fabric_text:
                        agg_sql.append(f" AND v.fabric IN ({','.join(['%s'] * len(fabrics))})")
                        agg_params.extend(fabrics)
                if spec_names:
                    agg_sql.append(f" AND v.spec_name IN ({','.join(['%s'] * len(spec_names))})")
                    agg_params.extend(spec_names)
                if shop_ids:
                    agg_sql.append(f" AND sp.shop_id IN ({','.join(['%s'] * len(shop_ids))})")
                    agg_params.extend(shop_ids)
                if platform_type_ids:
                    agg_sql.append(f" AND sh.platform_type_id IN ({','.join(['%s'] * len(platform_type_ids))})")
                    agg_params.extend(platform_type_ids)
                agg_sql.append(' GROUP BY DATE(spp.record_date) ORDER BY record_date DESC LIMIT 365')
                
                with conn.cursor() as cur:
                    cur.execute(''.join(agg_sql), tuple(agg_params))
                    agg_rows = cur.fetchall() or []
                
                chart_items = []
                for row in agg_rows:
                    item = {'record_date': row.get('record_date')}
                    for key in metric_keys:
                        val = row.get(key)
                        item[key] = round(float(val), 2) if val is not None else 0
                    chart_items.append(item)
                perf_timings['chart_agg'] = time.time() - perf_t_a

                # === 优化2：获取货号分组数据有 LIMIT 限制 ===
                perf_t_g = time.time()
                has_fabric_id = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
                has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
                fabric_join = "LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id" if has_fabric_id else ""
                if has_fabric_id and has_fabric_text:
                    fabric_expr = "COALESCE(fm.fabric_code, v.fabric)"
                elif has_fabric_id:
                    fabric_expr = "fm.fabric_code"
                else:
                    fabric_expr = ("v.fabric" if has_fabric_text else "''")
                sql = [
                    f"""
                    SELECT spp.*, sp.id as sp_id, sp.platform_sku, {fabric_expr} AS fabric, v.spec_name, v.sku_family_id,
                              pf.sku_family, sh.id AS shop_id, sh.shop_name,
                              pt.id AS platform_type_id, pt.name AS platform_type_name
                    FROM sales_product_performances spp
                    JOIN sales_products sp ON sp.id = spp.sales_product_id
                    LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                    LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                    LEFT JOIN shops sh ON sh.id = sp.shop_id
                    LEFT JOIN platform_types pt ON pt.id = sh.platform_type_id
                    {fabric_join}
                    WHERE 1=1
                    """
                ]
                params = []
                # has_fabric_text already computed above
                if start_date:
                    sql.append(' AND spp.record_date >= %s')
                    params.append(start_date)
                if end_date:
                    sql.append(' AND spp.record_date <= %s')
                    params.append(end_date)
                if sku_family_ids:
                    sql.append(f" AND v.sku_family_id IN ({','.join(['%s'] * len(sku_family_ids))})")
                    params.extend(sku_family_ids)
                if platform_skus:
                    sql.append(f" AND sp.platform_sku IN ({','.join(['%s'] * len(platform_skus))})")
                    params.extend(platform_skus)
                if fabrics:
                    if has_fabric_text:
                        sql.append(f" AND v.fabric IN ({','.join(['%s'] * len(fabrics))})")
                        params.extend(fabrics)
                if spec_names:
                    sql.append(f" AND v.spec_name IN ({','.join(['%s'] * len(spec_names))})")
                    params.extend(spec_names)
                if shop_ids:
                    sql.append(f" AND sp.shop_id IN ({','.join(['%s'] * len(shop_ids))})")
                    params.extend(shop_ids)
                if platform_type_ids:
                    sql.append(f" AND sh.platform_type_id IN ({','.join(['%s'] * len(platform_type_ids))})")
                    params.extend(platform_type_ids)
                sql.append(' ORDER BY pf.sku_family ASC, sp.platform_sku ASC, spp.record_date DESC LIMIT 5000')

                with conn.cursor() as cur:
                    cur.execute(''.join(sql), tuple(params))
                    rows = cur.fetchall() or []

                group_map = {}
                target_sp_ids = set()
                target_sf_ids = set()
                for row in rows:
                    sp_id = self._parse_int(row.get('sp_id'))
                    sf_id = self._parse_int(row.get('sku_family_id'))
                    sf_name = str(row.get('sku_family') or '未分组货号').strip() or '未分组货号'
                    sku = str(row.get('platform_sku') or '').strip()
                    target_sp_ids.add(sp_id)
                    if sf_id:
                        target_sf_ids.add(sf_id)
                    gkey = f"{sf_id or 0}:{sf_name}"
                    group = group_map.setdefault(gkey, {
                        'sku_family_id': sf_id,
                        'sku_family': sf_name,
                        'items_map': {}
                    })
                    item = group['items_map'].setdefault(sp_id, {
                        'sales_product_id': sp_id,
                        'platform_sku': sku,
                        'fabric': row.get('fabric') or '',
                        'spec_name': row.get('spec_name') or '',
                        'records': []
                    })
                    item['records'].append({
                        'record_date': str(row.get('record_date') or ''),
                        'sales_qty': row.get('sales_qty') or 0,
                        'net_sales_amount': row.get('net_sales_amount') or 0,
                        'order_qty': row.get('order_qty') or 0,
                        'session_total': row.get('session_total') or 0,
                        'ad_impressions': row.get('ad_impressions') or 0,
                        'ad_clicks': row.get('ad_clicks') or 0,
                        'ad_orders': row.get('ad_orders') or 0,
                        'ad_spend': row.get('ad_spend') or 0,
                        'ad_sales_amount': row.get('ad_sales_amount') or 0,
                        'refund_amount': row.get('refund_amount') or 0,
                        'sub_category_rank': row.get('sub_category_rank')
                    })

                groups = []
                for g in group_map.values():
                    items = list(g['items_map'].values())
                    items.sort(key=lambda x: x.get('platform_sku') or '')
                    groups.append({
                        'sku_family_id': g.get('sku_family_id'),
                        'sku_family': g.get('sku_family') or '',
                        'items': items[:50]
                    })
                groups = groups[:500]
                groups.sort(key=lambda x: x.get('sku_family') or '')
                perf_timings['groups'] = time.time() - perf_t_g

                events = []
                perf_timings['events'] = 0
                
                # 禁用 todos/ads 即时查询（改为前端异步加载，加快响应）
                # if include_todos and (target_sp_ids or target_sf_ids):
                #     ... todos 查询代码 ...
                # if include_ads and (target_sp_ids or target_sf_ids):
                #     ... ads 查询代码 ...

                ad_type_options = []
                with conn.cursor() as cur:
                    cur.execute("SELECT id, name FROM amazon_ad_operation_types ORDER BY id ASC LIMIT 100")
                    ad_type_options = [{'id': self._parse_int(x.get('id')), 'name': x.get('name') or ''} for x in (cur.fetchall() or [])]

                events.sort(key=lambda x: (x.get('event_date') or '', x.get('event_datetime') or '', x.get('event_type') or ''))
                
                perf_timings['total'] = time.time() - perf_t_start
                
                return self.send_json({
                    'status': 'success',
                    'groups': groups,
                    'chart_items': chart_items,
                    'metric_defs': metric_defs,
                    'events': events,
                    'ad_operation_types': ad_type_options,
                    '_perf': {
                        'total_ms': round(perf_timings['total'] * 1000, 1),
                        'breakdown': {
                            'params_ms': round(perf_timings['params'] * 1000, 1),
                            'chart_agg_ms': round(perf_timings['chart_agg'] * 1000, 1),
                            'groups_ms': round(perf_timings['groups'] * 1000, 1),
                            'events_ms': round(perf_timings['events'] * 1000, 1)
                        }
                    }
                }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _normalize_sales_order_links(self, links):
        items = []
        if not isinstance(links, list):
            return items
        qty_by_order_id = {}
        for entry in links:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            if not order_product_id:
                continue
            qty_by_order_id[order_product_id] = qty_by_order_id.get(order_product_id, 0) + max(1, quantity)

        for order_product_id, quantity in qty_by_order_id.items():
            items.append({'order_product_id': order_product_id, 'quantity': max(1, quantity)})
        return items

    def _get_or_create_sales_variant(self, conn, sku_family_id, spec_name, fabric, sale_price_usd=None, fabric_id=None):
        family_id = self._parse_int(sku_family_id)
        if not family_id:
            raise ValueError('Missing sku_family_id')
        spec = str(spec_name or '').strip()
        fab = str(fabric or '').strip()
        fid = self._parse_int(fabric_id) or None
        with conn.cursor() as cur:
            has_fid = self._table_has_column(conn, 'sales_product_variants', 'fabric_id')
            has_fabric_text = self._table_has_column(conn, 'sales_product_variants', 'fabric')
            if has_fid:
                cols = ["sku_family_id", "spec_name", "fabric_id", "sale_price_usd"]
                vals = [family_id, spec, fid, sale_price_usd]
                if has_fabric_text:
                    cols.insert(3, "fabric")
                    vals.insert(3, fab)
                ph = ", ".join(["%s"] * len(cols))
                updates = [
                    "sale_price_usd = COALESCE(VALUES(sale_price_usd), sale_price_usd)",
                    "fabric_id = COALESCE(VALUES(fabric_id), fabric_id)",
                    "updated_at = CURRENT_TIMESTAMP",
                ]
                if has_fabric_text:
                    updates.insert(2, "fabric = COALESCE(NULLIF(VALUES(fabric), ''), fabric)")
                cur.execute(
                    f"""
                    INSERT INTO sales_product_variants ({', '.join(cols)})
                    VALUES ({ph})
                    ON DUPLICATE KEY UPDATE
                        {', '.join(updates)}
                    """,
                    tuple(vals),
                )
                cur.execute(
                    """
                    SELECT id FROM sales_product_variants
                    WHERE sku_family_id=%s AND spec_name=%s AND COALESCE(fabric_id,0)=COALESCE(%s,0)
                    LIMIT 1
                    """,
                    (family_id, spec, fid)
                )
            else:
                cur.execute(
                    """
                    INSERT INTO sales_product_variants (sku_family_id, spec_name, fabric, sale_price_usd)
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE
                        sale_price_usd = COALESCE(VALUES(sale_price_usd), sale_price_usd),
                        updated_at = CURRENT_TIMESTAMP
                    """,
                    (family_id, spec, fab, sale_price_usd)
                )
                cur.execute(
                    """
                    SELECT id FROM sales_product_variants
                    WHERE sku_family_id=%s AND spec_name=%s AND fabric=%s
                    LIMIT 1
                    """,
                    (family_id, spec, fab)
                )
            row = cur.fetchone() or {}
        variant_id = self._parse_int(row.get('id'))
        if not variant_id:
            raise RuntimeError('创建或读取销售变体失败')
        return variant_id

    def _replace_sales_variant_order_links(self, conn, variant_id, links):
        if not variant_id:
            raise ValueError('Invalid variant_id')
        merged_links = self._normalize_sales_order_links(links)
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sales_variant_order_links WHERE variant_id=%s", (variant_id,))
            if not merged_links:
                return
            placeholders = ','.join(['(%s, %s, %s)'] * len(merged_links))
            values = []
            for entry in merged_links:
                values.extend([variant_id, entry['order_product_id'], entry['quantity']])
            cur.execute(
                f"""
                INSERT INTO sales_variant_order_links (variant_id, order_product_id, quantity)
                VALUES {placeholders}
                """,
                values
            )

    def _load_sales_variant_metrics(self, conn, variant_ids, include_links=False):
        ids = sorted({self._parse_int(v) for v in (variant_ids or []) if self._parse_int(v)})
        if not ids:
            return {}
        placeholders = ','.join(['%s'] * len(ids))
        metrics = {v: {
            'warehouse_cost_usd': 0.0,
            'last_mile_cost_usd': 0.0,
            'package_length_in': 0.0,
            'package_width_in': 0.0,
            'package_height_in': 0.0,
            'net_weight_lbs': 0.0,
            'gross_weight_lbs': 0.0,
            'order_sku_links': []
        } for v in ids}

        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    l.variant_id,
                    l.order_product_id,
                    l.quantity,
                    op.sku,
                    op.cost_usd,
                    op.last_mile_avg_freight_usd,
                    op.package_length_in,
                    op.package_width_in,
                    op.package_height_in,
                    op.net_weight_lbs,
                    op.gross_weight_lbs
                FROM sales_variant_order_links l
                JOIN order_products op ON op.id = l.order_product_id
                WHERE l.variant_id IN ({placeholders})
                ORDER BY l.variant_id ASC, op.id ASC
                """,
                ids
            )
            rows = cur.fetchall() or []

        for row in rows:
            variant_id = self._parse_int(row.get('variant_id'))
            if not variant_id or variant_id not in metrics:
                continue
            qty = max(1, self._parse_int(row.get('quantity')) or 1)
            bucket = metrics[variant_id]
            bucket['warehouse_cost_usd'] += float(row.get('cost_usd') or 0) * qty
            bucket['last_mile_cost_usd'] += float(row.get('last_mile_avg_freight_usd') or 0) * qty
            bucket['package_length_in'] = max(bucket['package_length_in'], float(row.get('package_length_in') or 0))
            bucket['package_width_in'] = max(bucket['package_width_in'], float(row.get('package_width_in') or 0))
            bucket['package_height_in'] = max(bucket['package_height_in'], float(row.get('package_height_in') or 0))
            bucket['net_weight_lbs'] += float(row.get('net_weight_lbs') or 0) * qty
            bucket['gross_weight_lbs'] += float(row.get('gross_weight_lbs') or 0) * qty
            if include_links:
                bucket['order_sku_links'].append({
                    'order_product_id': self._parse_int(row.get('order_product_id')),
                    'sku': row.get('sku') or '',
                    'quantity': qty
                })

        for variant_id in metrics.keys():
            bucket = metrics[variant_id]
            bucket['warehouse_cost_usd'] = round(bucket['warehouse_cost_usd'], 2)
            bucket['last_mile_cost_usd'] = round(bucket['last_mile_cost_usd'], 2)
            bucket['package_length_in'] = round(bucket['package_length_in'], 2)
            bucket['package_width_in'] = round(bucket['package_width_in'], 2)
            bucket['package_height_in'] = round(bucket['package_height_in'], 2)
            bucket['net_weight_lbs'] = round(bucket['net_weight_lbs'], 2)
            bucket['gross_weight_lbs'] = round(bucket['gross_weight_lbs'], 2)
        return metrics

    def _replace_sales_order_links(self, conn, sales_product_id, links):
        """兼容旧调用：按 sales_product_id 转换为 variant_id 后写入新表。"""
        if not sales_product_id:
            raise ValueError('Invalid sales_product_id')
        with conn.cursor() as cur:
            cur.execute("SELECT variant_id FROM sales_products WHERE id=%s LIMIT 1", (sales_product_id,))
            row = cur.fetchone() or {}
        variant_id = self._parse_int(row.get('variant_id'))
        if not variant_id:
            return
        self._replace_sales_variant_order_links(conn, variant_id, links)

    def _derive_sales_fields(self, conn, sku_family_id, links):
        if not links:
            return '', '', ''

        sku_family_code = ''
        if sku_family_id:
            with conn.cursor() as cur:
                cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (sku_family_id,))
                row = cur.fetchone()
                if row:
                    sku_family_code = (row.get('sku_family') or '').strip()

        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT op.id, op.sku, op.spec_qty_short, fm.fabric_code, fm.fabric_name_en
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
            fabric_code = self._code_before_dash(row.get('fabric_code'))
            if not fabric_code:
                fabric_code = self._code_before_dash(row.get('fabric_name_en'))
            if fabric_code and fabric_code not in fabrics:
                fabrics.append(fabric_code)
            spec_short = (row.get('spec_qty_short') or '').strip()
            if spec_short:
                spec_parts.append(f"{entry['quantity']}{spec_short}")

        fabric = ' / '.join(fabrics)
        spec_name = ''.join(spec_parts)

        platform_sku = ''
        if sku_family_code and fabric and spec_name:
            first_fabric = fabrics[0] if fabrics else ''
            platform_sku = self._build_sales_platform_sku(sku_family_code, spec_name, first_fabric)

        return fabric, spec_name, platform_sku

    def _derive_sales_cost_size(self, conn, links):
        if not links:
            return {
                'warehouse_cost_usd': 0.0,
                'last_mile_cost_usd': 0.0,
                'package_length_in': 0.0,
                'package_width_in': 0.0,
                'package_height_in': 0.0,
                'net_weight_lbs': 0.0,
                'gross_weight_lbs': 0.0,
                'sku_family_id': None
            }

        id_list = [entry['order_product_id'] for entry in links]
        placeholders = ','.join(['%s'] * len(id_list))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, sku_family_id,
                       cost_usd, last_mile_avg_freight_usd,
                       package_length_in, package_width_in, package_height_in,
                       net_weight_lbs, gross_weight_lbs
                FROM order_products
                WHERE id IN ({placeholders})
                """,
                id_list
            )
            rows = cur.fetchall() or []

        row_map = {row['id']: row for row in rows}
        warehouse_cost_usd = 0.0
        last_mile_cost_usd = 0.0
        package_length_in = 0.0
        package_width_in = 0.0
        package_height_in = 0.0
        net_weight_lbs = 0.0
        gross_weight_lbs = 0.0
        sku_family_id = None

        for entry in links:
            row = row_map.get(entry['order_product_id'])
            if not row:
                continue
            qty = max(1, int(entry.get('quantity') or 1))
            if sku_family_id is None:
                sku_family_id = row.get('sku_family_id')

            warehouse_cost_usd += float(row.get('cost_usd') or 0) * qty
            last_mile_cost_usd += float(row.get('last_mile_avg_freight_usd') or 0) * qty
            package_length_in = max(package_length_in, float(row.get('package_length_in') or 0))
            package_width_in = max(package_width_in, float(row.get('package_width_in') or 0))
            package_height_in = max(package_height_in, float(row.get('package_height_in') or 0))
            net_weight_lbs += float(row.get('net_weight_lbs') or 0) * qty
            gross_weight_lbs += float(row.get('gross_weight_lbs') or 0) * qty

        return {
            'warehouse_cost_usd': round(warehouse_cost_usd, 2),
            'last_mile_cost_usd': round(last_mile_cost_usd, 2),
            'package_length_in': round(package_length_in, 2),
            'package_width_in': round(package_width_in, 2),
            'package_height_in': round(package_height_in, 2),
            'net_weight_lbs': round(net_weight_lbs, 2),
            'gross_weight_lbs': round(gross_weight_lbs, 2),
            'sku_family_id': sku_family_id
        }

    def _code_before_dash(self, value):
        text = (value or '').strip()
        if not text:
            return ''
        return text.split('-', 1)[0].strip() or text

    def _build_sales_platform_sku(self, sku_family_code, spec_name, fabric_code):
        sku_part = (sku_family_code or '').strip()
        spec_part = (spec_name or '').strip()
        fabric_part = self._code_before_dash(fabric_code)
        if not (sku_part and spec_part and fabric_part):
            return ''
        return f"{sku_part}-{spec_part}-{fabric_part}"

