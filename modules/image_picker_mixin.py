# -*- coding: utf-8 -*-
"""全局「选择已有图片」：按上下文列出未绑定图片，支持面料库 / 销售主图 / 下单配件图目录。"""

import os
import base64
from urllib.parse import parse_qs


class ImagePickerMixin:
    """image-picker API：浏览允许目录下、未被当前实体绑定的图片。"""

    def _b64_rel_path(self, rel_text):
        if isinstance(rel_text, bytes):
            rel_bytes = rel_text
        else:
            rel_bytes = self._safe_fsencode(str(rel_text or ''))
        return base64.b64encode(rel_bytes).decode('ascii')

    def _rel_from_b64(self, path_b64):
        if not path_b64:
            return b''
        return self._fs_from_b64(path_b64)

    def _abs_allowed_under_roots(self, rel_path, root_rel_paths):
        rel_norm = (rel_path or '').replace('\\', '/').strip('/')
        rel_b = self._safe_fsencode(rel_norm) if rel_norm else b''
        for root in root_rel_paths:
            root_norm = (root or '').replace('\\', '/').strip('/')
            root_b = self._safe_fsencode(root_norm) if root_norm else b''
            if not root_b:
                continue
            if not rel_b:
                return False
            if rel_b == root_b or rel_b.startswith(root_b + b'/'):
                return True
        return False

    def _image_picker_bound_asset_ids(self, conn, context, fabric_id=None, variant_id=None, order_product_id=None):
        bound = set()
        cur = conn.cursor()
        ctx = (context or '').strip().lower()
        if ctx == 'fabric':
            if self._has_required_tables(['fabric_image_mappings', 'image_assets']):
                cur.execute("SELECT DISTINCT image_asset_id FROM fabric_image_mappings WHERE image_asset_id IS NOT NULL")
                for row in cur.fetchall() or []:
                    aid = self._parse_int(row.get('image_asset_id'))
                    if aid:
                        bound.add(aid)
        elif ctx in ('sales_variant', 'sales', 'spec'):
            vid = self._parse_int(variant_id)
            if vid and self._has_required_tables(['sales_variant_image_mappings']):
                cur.execute(
                    "SELECT DISTINCT image_asset_id FROM sales_variant_image_mappings "
                    "WHERE variant_id=%s AND image_asset_id IS NOT NULL",
                    (vid,)
                )
                for row in cur.fetchall() or []:
                    aid = self._parse_int(row.get('image_asset_id'))
                    if aid:
                        bound.add(aid)
        elif ctx == 'order_product':
            opid = self._parse_int(order_product_id)
            if opid and self._has_required_tables(['order_product_image_mappings']):
                cur.execute(
                    "SELECT DISTINCT image_asset_id FROM order_product_image_mappings "
                    "WHERE order_product_id=%s AND image_asset_id IS NOT NULL",
                    (opid,)
                )
                for row in cur.fetchall() or []:
                    aid = self._parse_int(row.get('image_asset_id'))
                    if aid:
                        bound.add(aid)
        return bound

    def _image_picker_asset_id_by_rel(self, cur, rel_path):
        rel = (rel_path or '').strip().replace('\\', '/')
        if not rel:
            return None
        if not self._has_required_tables(['image_assets']):
            return None
        cur.execute("SELECT id FROM image_assets WHERE storage_path=%s LIMIT 1", (rel,))
        row = cur.fetchone()
        if row:
            return self._parse_int(row.get('id'))
        like = rel + '/%'
        cur.execute("SELECT id FROM image_assets WHERE storage_path LIKE %s LIMIT 1", (like,))
        row = cur.fetchone()
        return self._parse_int(row.get('id')) if row else None

    def _image_picker_roots_for_context(self, context, fabric_id=None, variant_id=None, order_product_id=None):
        ctx = (context or '').strip().lower()
        roots = []
        if ctx == 'fabric':
            roots.append({
                'label': '『面料』',
                'path': '『面料』',
                'path_b64': self._b64_rel_path('『面料』'),
            })
            return roots

        if ctx in ('sales_variant', 'sales', 'spec'):
            vid = self._parse_int(variant_id)
            if not vid:
                return []
            info = self._resolve_sales_variant_folder_by_variant_id(vid, ensure_folder=False)
            sku = str(info.get('sku_family') or '').strip()
            folder_path = info.get('folder_path')
            if folder_path:
                rel = self._storage_path_from_abs(self._safe_fsdecode(folder_path))
                if rel:
                    label = f"主图/{info.get('variant_folder') or '规格-面料'}"
                    roots.append({'label': label, 'path': rel, 'path_b64': self._b64_rel_path(rel)})
            if sku:
                common_abs = self._ensure_listing_sales_common_folder(sku)
                if common_abs:
                    rel_c = self._storage_path_from_abs(self._safe_fsdecode(common_abs))
                    if rel_c:
                        roots.append({'label': f'{sku}/主图/通用', 'path': rel_c, 'path_b64': self._b64_rel_path(rel_c)})
            return roots

        if ctx == 'order_product':
            opid = self._parse_int(order_product_id)
            if not opid:
                return []
            info = self._resolve_order_product_main_image_folder(opid, ensure_folder=False)
            folder_path = info.get('folder_path')
            sku = str(info.get('sku_family') or '').strip()
            if folder_path:
                rel = self._storage_path_from_abs(self._safe_fsdecode(folder_path))
                if rel:
                    vf = str(info.get('variant_folder') or '配件图')
                    roots.append({'label': f'配件图/{vf}', 'path': rel, 'path_b64': self._b64_rel_path(rel)})
            if sku:
                common_abs = self._ensure_order_product_common_folder(sku)
                if common_abs:
                    rel_c = self._storage_path_from_abs(self._safe_fsdecode(common_abs))
                    if rel_c:
                        roots.append({'label': f'{sku}/配件图/通用', 'path': rel_c, 'path_b64': self._b64_rel_path(rel_c)})
            return roots

        return roots

    def _entry_display_name(self, entry):
        return self._decode_fs_name_bytes(self._entry_name_bytes(entry))

    def _image_picker_breadcrumbs(self, rel_path, roots):
        rel_norm = (rel_path or '').replace('\\', '/').strip('/')
        if not rel_norm:
            if roots:
                r0 = roots[0]
                return [{
                    'label': r0.get('label') or '根',
                    'path': r0.get('path') or '',
                    'path_b64': r0.get('path_b64') or '',
                }]
            return [{'label': '根', 'path': '', 'path_b64': ''}]
        root_path = ''
        root_label = '根'
        if roots:
            root_path = (roots[0].get('path') or '').replace('\\', '/').strip('/')
            root_label = roots[0].get('label') or root_label
        crumbs = [{
            'label': root_label,
            'path': root_path,
            'path_b64': roots[0].get('path_b64') if roots else '',
        }]
        if root_path and rel_norm == root_path:
            return crumbs
        tail = rel_norm
        if root_path and rel_norm.startswith(root_path + '/'):
            tail = rel_norm[len(root_path) + 1:]
        parts = [p for p in tail.split('/') if p]
        acc = root_path
        for part in parts:
            acc = f'{acc}/{part}' if acc else part
            crumbs.append({'label': part, 'path': acc, 'path_b64': self._b64_rel_path(acc)})
        return crumbs

    def _image_picker_scan_folder(self, conn, cur, rel_path, bound_ids, keyword=''):
        rel_norm = (rel_path or '').replace('\\', '/').strip('/')
        abs_path = self._join_resources(rel_norm)
        if not os.path.isdir(abs_path):
            return [], []

        kw = (keyword or '').strip().lower()
        folders = []
        items = []

        try:
            with os.scandir(abs_path) as it:
                for entry in it:
                    display = self._entry_display_name(entry)
                    if not display or display.startswith('.') or display.startswith('@'):
                        continue
                    name_b = self._entry_name_bytes(entry)
                    if rel_norm:
                        child_rel, path_b64 = self._resources_rel_path_b64(rel_norm, name_b)
                    else:
                        child_rel, path_b64 = self._resources_rel_path_b64(name_b)
                    if entry.is_dir(follow_symlinks=False):
                        folders.append({
                            'name': self._b64_from_fs(name_b),
                            'display': display,
                            'path': child_rel,
                            'path_b64': path_b64,
                        })
                    elif entry.is_file(follow_symlinks=False) and self._is_image_name(entry.name):
                        if kw and kw not in display.lower():
                            continue
                        aid = self._image_picker_asset_id_by_rel(cur, child_rel)
                        if aid and aid in bound_ids:
                            continue
                        items.append({
                            'name': display,
                            'display': display,
                            'name_raw_b64': base64.b64encode(name_b).decode('ascii'),
                            'path': child_rel,
                            'path_b64': path_b64,
                            'b64': path_b64,
                            'image_asset_id': aid or 0,
                        })
        except Exception:
            return [], []

        folders.sort(key=lambda x: (x.get('display') or '').lower())
        items.sort(key=lambda x: (x.get('display') or '').lower())
        return folders, items

    def handle_image_picker_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', '') or '')
            context = (query_params.get('context', [''])[0] or '').strip().lower()
            path_b64 = (query_params.get('path', [''])[0] or query_params.get('path_b64', [''])[0] or '').strip()
            keyword = (query_params.get('q', [''])[0] or '').strip()
            fabric_id = self._parse_int((query_params.get('fabric_id', [''])[0] or '').strip())
            variant_id = self._parse_int((query_params.get('variant_id', [''])[0] or '').strip())
            order_product_id = self._parse_int((query_params.get('order_product_id', [''])[0] or '').strip())
            sales_product_id = self._parse_int((query_params.get('sales_product_id', [''])[0] or '').strip())
            if not variant_id and sales_product_id:
                variant_id = sales_product_id

            if context not in ('fabric', 'sales_variant', 'sales', 'spec', 'order_product'):
                return self.send_json({'status': 'error', 'message': '无效 context'}, start_response)

            roots = self._image_picker_roots_for_context(
                context, fabric_id=fabric_id, variant_id=variant_id, order_product_id=order_product_id
            )
            if not roots:
                return self.send_json({
                    'status': 'success',
                    'context': context,
                    'roots': [],
                    'path': '',
                    'path_b64': '',
                    'breadcrumbs': [{'label': '根', 'path': '', 'path_b64': ''}],
                    'folders': [],
                    'items': [],
                }, start_response)

            root_paths = [r['path'] for r in roots]
            rel_path = self._rel_from_b64(path_b64) if path_b64 else ''
            rel_str = self._safe_fsdecode(rel_path) if isinstance(rel_path, bytes) else str(rel_path or '')
            rel_str = rel_str.replace('\\', '/').strip('/')
            # 空路径会落到上架资源根目录；面料等上下文应默认进入指定根（如『面料』）
            if not rel_str or not self._abs_allowed_under_roots(rel_str, root_paths):
                rel_str = (roots[0].get('path') or '').replace('\\', '/').strip('/')
                path_b64 = roots[0].get('path_b64') or ''

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    bound_ids = self._image_picker_bound_asset_ids(
                        conn, context,
                        fabric_id=fabric_id,
                        variant_id=variant_id,
                        order_product_id=order_product_id,
                    )
                    folders, items = self._image_picker_scan_folder(conn, cur, rel_str, bound_ids, keyword=keyword)

            return self.send_json({
                'status': 'success',
                'context': context,
                'roots': roots,
                'path': rel_str,
                'path_b64': self._b64_rel_path(rel_str) if rel_str else '',
                'breadcrumbs': self._image_picker_breadcrumbs(rel_str, roots),
                'folders': folders,
                'items': items,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
