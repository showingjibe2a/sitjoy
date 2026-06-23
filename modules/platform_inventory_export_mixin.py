"""销售平台库存导出：Amazon txt / Wayfair csv 智能成套计算。"""

import cgi
import csv
import io
import json
import math
from datetime import datetime
from urllib.parse import quote


class PlatformInventoryExportMixin:
    _WAYFAIR_HEADERS = {
        'supplier id': 'supplier_id',
        'supplier part#': 'part',
        'in stock': 'in_stock',
    }

    def _send_text_attachment(self, content_bytes, filename, start_response, content_type='text/plain; charset=utf-8'):
        data = content_bytes if isinstance(content_bytes, (bytes, bytearray)) else str(content_bytes or '').encode('utf-8')
        safe_name = str(filename or 'export.txt').replace('\r', '').replace('\n', '')
        encoded_name = quote(safe_name)
        start_response('200 OK', [
            ('Content-Type', content_type),
            ('Content-Disposition', f"attachment; filename*=UTF-8''{encoded_name}"),
            ('Content-Length', str(len(data))),
        ])
        return [data]

    def _platform_type_matches_export(self, platform_name, platform_key):
        p = str(platform_name or '').strip().lower()
        key = str(platform_key or '').strip().lower()
        if key == 'amazon':
            return ('amazon' in p) or ('亚马逊' in str(platform_name or ''))
        if key == 'wayfair':
            return 'wayfair' in p
        return False

    def _normalize_inventory_export_options(self, raw):
        data = raw if isinstance(raw, dict) else {}
        calc_mode = str(data.get('calc_mode') or 'strict_sets').strip().lower()
        if calc_mode not in ('strict_sets', 'flexible'):
            legacy = calc_mode
            calc_mode = 'flexible' if legacy in ('exclude_out_of_stock', 'only_in_stock_parts') else 'strict_sets'
        try:
            max_missing_parts = max(0, int(data.get('max_missing_parts', 2)))
        except Exception:
            max_missing_parts = 2
        try:
            min_in_stock_parts = max(0, int(data.get('min_in_stock_parts', 2)))
        except Exception:
            min_in_stock_parts = 2
        flex_logic = str(data.get('flex_logic') or 'and').strip().lower()
        if flex_logic not in ('and', 'or'):
            flex_logic = 'and'
        cap_enabled = self._parse_bool_flag(data.get('cap_enabled'), default=False)
        try:
            cap_max = max(0, int(data.get('cap_max', 20)))
        except Exception:
            cap_max = 20
        spec_gap_enabled = self._parse_bool_flag(data.get('spec_gap_enabled'), default=False)
        try:
            spec_gap_per_part = max(0, int(data.get('spec_gap_per_part', 1)))
        except Exception:
            spec_gap_per_part = 1
        try:
            spec_gap_min = max(0, int(data.get('spec_gap_min', 0)))
        except Exception:
            spec_gap_min = 0
        try:
            min_nosync_qty = max(0, int(data.get('min_nosync_qty', 0)))
        except Exception:
            min_nosync_qty = 0
        shop_id = self._parse_int(data.get('shop_id'))
        use_fabric_share = self._parse_bool_flag(data.get('use_fabric_share'), default=True)
        try:
            fabric_share_min_qty = max(0, int(data.get('fabric_share_min_qty', 0)))
        except Exception:
            fabric_share_min_qty = 0
        return {
            'calc_mode': calc_mode,
            'max_missing_parts': max_missing_parts,
            'min_in_stock_parts': min_in_stock_parts,
            'flex_logic': flex_logic,
            'cap_enabled': cap_enabled,
            'cap_max': cap_max,
            'spec_gap_enabled': spec_gap_enabled,
            'spec_gap_per_part': spec_gap_per_part,
            'spec_gap_min': spec_gap_min,
            'min_nosync_qty': min_nosync_qty,
            'shop_id': shop_id,
            'use_fabric_share': use_fabric_share,
            'fabric_share_min_qty': fabric_share_min_qty,
        }

    def _sales_product_status_exportable(self, status):
        """仅「启用」状态参与系统生成库存；留用/弃用导出为 0。"""
        return str(status or 'enabled').strip().lower() == 'enabled'

    @staticmethod
    def _bom_units_for_links(links):
        total = 0
        for _oid, qp in (links or []):
            total += max(1, int(qp or 1))
        return total

    def _compute_platform_inventory_qty(
        self, bom_links, inv_by_op, opts,
        bom_units=0, fabric_share_ratio=1.0,
    ):
        """按 BOM 与选项计算可售套数。"""
        qty, _notes = self._compute_platform_inventory_qty_detail(
            bom_links, inv_by_op, opts,
            bom_units=bom_units, fabric_share_ratio=fabric_share_ratio,
        )
        return qty

    def _compute_platform_inventory_qty_detail(
        self, bom_links, inv_by_op, opts,
        bom_units=0, fabric_share_ratio=1.0,
    ):
        """按 BOM 与选项计算可售套数，并返回备注说明。"""
        opts = opts or {}
        notes = []
        calc_mode = opts.get('calc_mode') or 'strict_sets'
        links = [(int(oid), max(1, int(qp or 1))) for oid, qp in (bom_links or []) if self._parse_int(oid)]
        if not links:
            notes.append('无 BOM 配件')
            return 0, notes

        if calc_mode == 'strict_sets':
            parts = []
            missing = 0
            for oid, qp in links:
                qty = int(inv_by_op.get(oid, 0) or 0)
                part_sets = (qty // qp) if qty > 0 else 0
                parts.append(part_sets)
                if qty <= 0:
                    missing += 1
            sellable = min(parts) if parts else 0
            if sellable <= 0 and missing > 0:
                notes.append('严格成套：配件缺货')
        else:
            in_stock_count = 0
            out_of_stock_count = 0
            parts_with_stock = []
            for oid, qp in links:
                qty = int(inv_by_op.get(oid, 0) or 0)
                if qty > 0:
                    in_stock_count += 1
                    parts_with_stock.append(qty // qp)
                else:
                    out_of_stock_count += 1
            max_missing = max(0, int(opts.get('max_missing_parts') or 0))
            min_in_stock = max(0, int(opts.get('min_in_stock_parts') or 0))
            cond_missing = out_of_stock_count <= max_missing
            cond_in_stock = in_stock_count >= min_in_stock
            if str(opts.get('flex_logic') or 'and').lower() == 'or':
                allow_flex = cond_missing or cond_in_stock
            else:
                allow_flex = cond_missing and cond_in_stock
            if not allow_flex:
                notes.append('部分缺货：条件不满足')
                sellable = 0
            elif not parts_with_stock:
                notes.append('部分缺货：无有货配件')
                sellable = 0
            else:
                sellable = min(parts_with_stock)

        if opts.get('spec_gap_enabled') and int(sellable) > 0:
            gap = int(opts.get('spec_gap_per_part') or 0)
            retain_min = max(0, int(opts.get('spec_gap_min') or 0))
            extra_units = max(0, int(bom_units) - 1)
            if extra_units > 0 and gap > 0:
                base = int(sellable)
                deducted = base - extra_units * gap
                if base > retain_min:
                    sellable = max(retain_min, deducted)
                else:
                    sellable = max(0, deducted)
                if int(sellable) != base:
                    notes.append(f'大规格扣减 {base - int(sellable)} 套（BOM {int(bom_units)} 件）')

        if opts.get('cap_enabled'):
            cap_max = int(opts.get('cap_max') or 0)
            before_cap = int(sellable)
            sellable = min(before_cap, cap_max)
            if before_cap > cap_max:
                notes.append(f'库存上限 {cap_max}')

        if opts.get('use_fabric_share') and int(sellable) > 0:
            try:
                share = float(fabric_share_ratio if fabric_share_ratio is not None else 1.0)
            except Exception:
                share = 1.0
            share = max(0.0, min(1.0, share))
            base_before_share = int(sellable)
            allocated = int(math.floor(base_before_share * share))
            fab_min = max(0, int(opts.get('fabric_share_min_qty') or 0))
            uplifted = False
            if fab_min > 0 and allocated < fab_min and base_before_share >= fab_min:
                allocated = fab_min
                uplifted = True
            if share < 0.9999:
                pct = int(round(share * 100))
                notes.append(f'面料比例 {pct}%')
            if uplifted:
                notes.append(f'比例最小库存抬升至 {allocated}')
            sellable = allocated

        min_nosync = max(0, int(opts.get('min_nosync_qty') or 0))
        before_nosync = int(sellable)
        if min_nosync > 0 and before_nosync <= min_nosync:
            if before_nosync > 0:
                notes.append(f'≤最小不同步阈值 {min_nosync}')
            sellable = 0
        return max(0, int(sellable)), notes

    def _inventory_export_expand_op_ids_with_substitute_items(self, conn, order_product_ids):
        """展开替代发货方案中的 substitute SKU；不含迭代继承。"""
        ids = sorted({int(x) for x in (order_product_ids or []) if self._parse_int(x)})
        if not ids:
            return [], {}
        plans_by_owner = self._forecast_load_all_substitute_plans_by_owner(conn, ids)
        expanded = set(ids)
        for plans in plans_by_owner.values():
            for grp in plans:
                for sid, _ in grp.get('items') or []:
                    sid = self._parse_int(sid)
                    if sid:
                        expanded.add(int(sid))
        return sorted(expanded), plans_by_owner

    def _inventory_export_effective_overseas_by_op(
        self, conn, order_product_ids, wayfair_id=None, wayfair_matrix=None,
    ):
        """下单 SKU 海外仓可用件数：本体库存 + 全部替代发货方案各自成套后相加（与销量预测一致，不含迭代）。"""
        base_ids = sorted({int(x) for x in (order_product_ids or []) if self._parse_int(x)})
        out = {i: 0 for i in base_ids}
        if not base_ids:
            return out
        load_ids, plans_by_owner = self._inventory_export_expand_op_ids_with_substitute_items(conn, base_ids)
        wid = str(wayfair_id or '').strip()
        if wid:
            matrix = wayfair_matrix if isinstance(wayfair_matrix, dict) else self._load_overseas_qty_wayfair_matrix(conn, load_ids)
            inv_by_op = {}
            for oid in load_ids:
                tier = self._forecast_inventory_zero()
                tier['overseas_qty'] = int(matrix.get((wid, oid), 0) or 0)
                inv_by_op[oid] = tier
        else:
            inv_by_op = self._forecast_load_inventory_by_order_product(conn, load_ids)
        for oid in base_ids:
            owner_qty = int((inv_by_op.get(oid) or {}).get('overseas_qty') or 0)
            plans = plans_by_owner.get(oid) or []
            if plans:
                sub_qty = int(
                    self._forecast_inventory_assembled_from_substitute_plans(inv_by_op, plans).get('overseas_qty') or 0
                )
                out[oid] = owner_qty + sub_qty
            else:
                out[oid] = owner_qty
        return out

    def _load_overseas_qty_wayfair_matrix(self, conn, order_product_ids):
        """批量加载 (wayfair_id, order_product_id) -> 可用库存，供 Wayfair 导出复用。"""
        ids = sorted({int(x) for x in (order_product_ids or []) if self._parse_int(x)})
        out = {}
        if not ids:
            return out
        ph = ','.join(['%s'] * len(ids))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT oi.order_product_id,
                       TRIM(COALESCE(w.wayfair_id, '')) AS wayfair_id,
                       COALESCE(SUM(oi.available_qty), 0) AS q
                FROM logistics_overseas_inventory oi
                INNER JOIN logistics_overseas_warehouses w ON w.id = oi.warehouse_id
                WHERE oi.order_product_id IN ({ph})
                  AND COALESCE(w.is_enabled, 1) = 1
                  AND TRIM(COALESCE(w.wayfair_id, '')) <> ''
                GROUP BY oi.order_product_id, TRIM(COALESCE(w.wayfair_id, ''))
                """,
                tuple(ids),
            )
            for rr in cur.fetchall() or []:
                wid = str(rr.get('wayfair_id') or '').strip()
                oid = self._parse_int(rr.get('order_product_id'))
                if wid and oid:
                    out[(wid, oid)] = int(float(rr.get('q') or 0))
        return out

    def _overseas_qty_by_wayfair_id(self, order_product_ids, wayfair_id, wayfair_matrix=None):
        ids = sorted({int(x) for x in (order_product_ids or []) if self._parse_int(x)})
        wid = str(wayfair_id or '').strip()
        out = {i: 0 for i in ids}
        if not ids or not wid:
            return out
        matrix = wayfair_matrix if isinstance(wayfair_matrix, dict) else {}
        for oid in ids:
            out[oid] = int(matrix.get((wid, oid), 0) or 0)
        return out

    def _load_overseas_qty_by_wayfair_id(self, conn, order_product_ids, wayfair_id):
        return self._inventory_export_effective_overseas_by_op(
            conn, order_product_ids, wayfair_id=wayfair_id,
        )

    def _load_overseas_qty_all_warehouses(self, conn, order_product_ids):
        return self._inventory_export_effective_overseas_by_op(conn, order_product_ids)

    def _load_sales_products_platform_sku_index(self, conn, platform_key, shop_id=None):
        sp_has_shop = self._table_has_column(conn, 'sales_products', 'shop_id')
        shop_expr = self._sales_product_shop_expr(sp_has_shop)
        filter_shop_id = self._parse_int(shop_id)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sp.id, sp.platform_sku, sp.variant_id, sp.product_status,
                       {shop_expr} AS shop_id, pt.name AS platform_type_name
                FROM sales_products sp
                LEFT JOIN sales_parents p ON p.id = sp.parent_id
                LEFT JOIN shops s ON s.id = {shop_expr}
                LEFT JOIN platform_types pt ON pt.id = s.platform_type_id
                WHERE sp.platform_sku IS NOT NULL AND TRIM(sp.platform_sku) <> ''
                ORDER BY sp.id ASC
                """
            )
            rows = cur.fetchall() or []
        out = {}
        for row in rows:
            if filter_shop_id and self._parse_int(row.get('shop_id')) != filter_shop_id:
                continue
            if not self._platform_type_matches_export(row.get('platform_type_name'), platform_key):
                continue
            key = str(row.get('platform_sku') or '').strip()
            if not key:
                continue
            vid = self._parse_int(row.get('variant_id'))
            if not vid:
                continue
            prev = out.get(key)
            if not prev or (str(prev.get('product_status') or '') != 'enabled' and str(row.get('product_status') or '') == 'enabled'):
                out[key] = {
                    'id': self._parse_int(row.get('id')),
                    'platform_sku': key,
                    'variant_id': vid,
                    'product_status': row.get('product_status'),
                    'shop_id': self._parse_int(row.get('shop_id')),
                }
        return out

    def _inventory_export_bom_meta(self, conn, variant_ids):
        ids = sorted({int(x) for x in (variant_ids or []) if self._parse_int(x)})
        links_by_vid = self._forecast_load_variant_order_links_for_inventory(conn, ids) if ids else {}
        bom_units_by_vid = {
            vid: self._bom_units_for_links(links_by_vid.get(vid) or [])
            for vid in ids
        }
        fabric_shares = self._fabric_share_map_for_variants(conn, ids)
        return links_by_vid, bom_units_by_vid, fabric_shares

    def _export_variant_qty(
        self, rec, variant_id, links, inv_by_op, opts,
        bom_units_by_vid, fabric_shares,
    ):
        qty, _notes = self._export_variant_qty_detail(
            rec, variant_id, links, inv_by_op, opts,
            bom_units_by_vid, fabric_shares,
        )
        return qty

    def _export_variant_qty_detail(
        self, rec, variant_id, links, inv_by_op, opts,
        bom_units_by_vid, fabric_shares,
    ):
        notes = []
        if rec and not self._sales_product_status_exportable(rec.get('product_status')):
            status = str(rec.get('product_status') or '').strip().lower()
            label = {'retained': '留用', 'discarded': '弃用'}.get(status, status or '非启用')
            notes.append(f'产品状态：{label}')
            return 0, notes
        vid = self._parse_int(variant_id)
        if not vid:
            notes.append('无变体')
            return 0, notes
        share_ratio = fabric_shares.get(vid, 1.0) if opts.get('use_fabric_share') else 1.0
        return self._compute_platform_inventory_qty_detail(
            links or [],
            inv_by_op,
            opts,
            bom_units=bom_units_by_vid.get(vid, 0),
            fabric_share_ratio=share_ratio,
        )

    def _attach_preview_images(self, conn, rows):
        if not rows:
            return rows
        variant_ids = sorted({
            int(r.get('variant_id') or 0)
            for r in rows
            if int(r.get('variant_id') or 0) > 0
        })
        preview_map = {}
        if variant_ids:
            try:
                preview_map = self._load_variant_first_image_preview(conn, variant_ids, type_name='白底纯图') or {}
            except Exception:
                preview_map = {}
        out = []
        for row in rows:
            vid = int(row.get('variant_id') or 0)
            item = dict(row)
            item.pop('variant_id', None)
            item['preview_image_b64'] = preview_map.get(vid, '') if vid else ''
            out.append(item)
        return out

    def _amazon_inventory_preview(self, conn, opts, sku_list=None):
        shop_id = self._parse_int((opts or {}).get('shop_id'))
        sku_map = self._load_sales_products_platform_sku_index(conn, 'amazon', shop_id=shop_id)
        if shop_id and not sku_map:
            raise ValueError('所选店铺下无亚马逊销售产品')
        target_skus = sorted(sku_list) if sku_list else sorted(sku_map.keys())
        if not target_skus:
            return []
        variant_ids = sorted({
            sku_map[s]['variant_id']
            for s in target_skus
            if s in sku_map and sku_map[s].get('variant_id')
        })
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, variant_ids)
        all_op_ids = sorted({
            int(oid)
            for links in links_by_vid.values()
            for oid, _ in (links or [])
            if self._parse_int(oid)
        })
        inv_by_op = self._load_overseas_qty_all_warehouses(conn, all_op_ids)
        raw_rows = []
        for sku in target_skus:
            rec = sku_map.get(sku)
            if not rec:
                raw_rows.append({
                    'sku': sku,
                    'warehouse': '-',
                    'qty': 0,
                    'remark': '未匹配销售 SKU',
                    'variant_id': 0,
                })
                continue
            vid = rec['variant_id']
            links = links_by_vid.get(vid) or []
            qty, notes = self._export_variant_qty_detail(
                rec, vid, links, inv_by_op, opts,
                bom_units_by_vid, fabric_shares,
            )
            raw_rows.append({
                'sku': sku,
                'warehouse': '-',
                'qty': qty,
                'remark': '；'.join(notes),
                'variant_id': vid,
            })
        return self._attach_preview_images(conn, raw_rows)

    def _wayfair_inventory_preview(self, conn, file_bytes, opts):
        text = (file_bytes or b'').decode('utf-8-sig', errors='replace')
        if not str(text or '').strip():
            raise ValueError('上传文件为空')
        lines = text.splitlines()
        delim = self._detect_csv_delimiter(lines[0] if lines else '')
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        rows = list(reader)
        if not rows:
            raise ValueError('上传文件无有效行')
        header_idx = None
        col_map = None
        for i, row in enumerate(rows[:30]):
            col_map = self._map_wayfair_header_indices(row)
            if col_map:
                header_idx = i
                break
        if header_idx is None or not col_map:
            raise ValueError('未找到 Wayfair 表头（需含 Supplier ID、Supplier Part#、In Stock）')

        row_jobs = []
        parts_needed = set()
        for row in rows[header_idx + 1:]:
            if not row or not any(str(c or '').strip() for c in row):
                continue
            while len(row) <= max(col_map.values()):
                row.append('')
            sid = str(row[col_map['supplier_id']] or '').strip()
            part = str(row[col_map['part']] or '').strip()
            if not sid or not part:
                continue
            parts_needed.add(part)
            row_jobs.append((sid, part))

        sku_map_all = self._load_sales_products_platform_sku_index(conn, 'wayfair')
        sku_map = {part: sku_map_all[part] for part in parts_needed if part in sku_map_all}
        variant_ids = sorted({rec['variant_id'] for rec in sku_map.values() if rec.get('variant_id')})
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, variant_ids)
        all_op_ids = sorted({
            int(oid)
            for links in links_by_vid.values()
            for oid, _ in (links or [])
            if self._parse_int(oid)
        })
        load_ids, _plans = self._inventory_export_expand_op_ids_with_substitute_items(conn, all_op_ids)
        wayfair_matrix = self._load_overseas_qty_wayfair_matrix(conn, load_ids)
        qty_cache = {}
        raw_rows = []
        for sid, part in row_jobs:
            rec = sku_map.get(part)
            if not rec:
                raw_rows.append({
                    'sku': part,
                    'warehouse': sid,
                    'qty': 0,
                    'remark': '未匹配销售 SKU',
                    'variant_id': 0,
                })
                continue
            vid = rec['variant_id']
            links = links_by_vid.get(vid) or []
            cache_key = (vid, sid)
            if cache_key not in qty_cache:
                op_ids = [int(oid) for oid, _ in links]
                inv_by_op = self._inventory_export_effective_overseas_by_op(
                    conn, op_ids, wayfair_id=sid, wayfair_matrix=wayfair_matrix,
                )
                qty_cache[cache_key] = self._export_variant_qty_detail(
                    rec, vid, links, inv_by_op, opts,
                    bom_units_by_vid, fabric_shares,
                )
            qty, notes = qty_cache[cache_key]
            raw_rows.append({
                'sku': part,
                'warehouse': sid,
                'qty': qty,
                'remark': '；'.join(notes),
                'variant_id': vid,
            })
        return self._attach_preview_images(conn, raw_rows)

    def _inventory_export_qty_for_variant(self, conn, variant_id, opts, wayfair_id=None):
        vid = self._parse_int(variant_id)
        if not vid:
            return 0
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, [vid])
        links = links_by_vid.get(vid) or []
        if not links:
            return 0
        op_ids = [int(oid) for oid, _ in links]
        if wayfair_id:
            inv_by_op = self._load_overseas_qty_by_wayfair_id(conn, op_ids, wayfair_id)
        else:
            inv_by_op = self._load_overseas_qty_all_warehouses(conn, op_ids)
        share_ratio = fabric_shares.get(vid, 1.0) if opts.get('use_fabric_share') else 1.0
        return self._compute_platform_inventory_qty(
            links, inv_by_op, opts,
            bom_units=bom_units_by_vid.get(vid, 0),
            fabric_share_ratio=share_ratio,
        )

    def _parse_export_multipart(self, environ):
        content_type = environ.get('CONTENT_TYPE', '')
        options = {}
        file_bytes = None
        filename = ''
        mode = 'generate'
        if 'multipart/form-data' not in content_type:
            body = self._read_json_body(environ) or {}
            options = self._normalize_inventory_export_options(body)
            mode = str(body.get('mode') or 'generate').strip().lower()
            return options, file_bytes, filename, mode

        raw_body = self._read_wsgi_request_body(environ)
        env_copy = dict(environ)
        env_copy['CONTENT_LENGTH'] = str(len(raw_body))
        form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)

        options_text = str(form.getfirst('options', '') or '').strip()
        if options_text:
            try:
                payload = json.loads(options_text)
                mode = str(payload.get('mode') or mode).strip().lower()
                options = self._normalize_inventory_export_options(payload)
            except Exception:
                options = {}

        file_item = form['file'] if 'file' in form else None
        if file_item is not None and getattr(file_item, 'file', None) is not None:
            file_bytes = file_item.file.read() or b''
            filename = str(getattr(file_item, 'filename', '') or '').strip()

        if not options:
            options = self._normalize_inventory_export_options({})
        if file_bytes and mode not in ('fill', 'generate'):
            mode = 'fill'
        return options, file_bytes, filename, mode

    def _amazon_inventory_lines(self, conn, opts):
        shop_id = self._parse_int((opts or {}).get('shop_id'))
        sku_map = self._load_sales_products_platform_sku_index(conn, 'amazon', shop_id=shop_id)
        if shop_id and not sku_map:
            raise ValueError('所选店铺下无亚马逊销售产品')
        variant_ids = sorted({v['variant_id'] for v in sku_map.values() if v.get('variant_id')})
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, variant_ids)
        all_op_ids = sorted({
            int(oid)
            for links in links_by_vid.values()
            for oid, _ in (links or [])
            if self._parse_int(oid)
        })
        inv_by_op = self._load_overseas_qty_all_warehouses(conn, all_op_ids)
        rows = []
        for sku in sorted(sku_map.keys()):
            rec = sku_map[sku]
            if not self._sales_product_status_exportable(rec.get('product_status')):
                continue
            vid = rec['variant_id']
            links = links_by_vid.get(vid) or []
            qty = self._export_variant_qty(
                rec, vid, links, inv_by_op, opts,
                bom_units_by_vid, fabric_shares,
            )
            rows.append((sku, qty))
        return rows

    def _amazon_inventory_txt_bytes(self, rows):
        lines = ['sku\tquantity']
        for sku, qty in rows:
            lines.append(f"{sku}\t{int(qty)}")
        return ('\n'.join(lines) + '\n').encode('utf-8')

    def _parse_amazon_inventory_upload(self, file_bytes):
        text = (file_bytes or b'').decode('utf-8-sig', errors='replace')
        lines = [ln for ln in text.splitlines() if str(ln or '').strip()]
        if not lines:
            return []
        delim = '\t' if '\t' in lines[0] else ','
        header_parts = [str(x or '').strip().lower() for x in lines[0].split(delim)]
        sku_idx = next((i for i, h in enumerate(header_parts) if h in ('sku', 'seller-sku', 'seller sku')), 0)
        qty_idx = next((i for i, h in enumerate(header_parts) if h in ('quantity', 'qty', 'available')), 1 if len(header_parts) > 1 else 0)
        out = []
        for ln in lines[1:]:
            parts = ln.split(delim)
            if not parts:
                continue
            sku = str(parts[sku_idx] if sku_idx < len(parts) else parts[0]).strip()
            if not sku:
                continue
            out.append(sku)
        return out

    def _fill_amazon_inventory_upload(self, conn, file_bytes, opts):
        sku_list = self._parse_amazon_inventory_upload(file_bytes)
        if not sku_list:
            raise ValueError('上传文件无有效 SKU 行')
        sku_map = self._load_sales_products_platform_sku_index(conn, 'amazon')
        variant_ids = sorted({
            sku_map[s]['variant_id']
            for s in sku_list
            if s in sku_map and sku_map[s].get('variant_id')
        })
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, variant_ids)
        all_op_ids = sorted({
            int(oid)
            for links in links_by_vid.values()
            for oid, _ in (links or [])
            if self._parse_int(oid)
        })
        inv_by_op = self._load_overseas_qty_all_warehouses(conn, all_op_ids)
        qty_by_sku = {}
        for sku in sku_list:
            rec = sku_map.get(sku)
            if not rec:
                qty_by_sku[sku] = 0
                continue
            vid = rec['variant_id']
            links = links_by_vid.get(vid) or []
            qty_by_sku[sku] = self._export_variant_qty(
                rec, vid, links, inv_by_op, opts,
                bom_units_by_vid, fabric_shares,
            )
        text = (file_bytes or b'').decode('utf-8-sig', errors='replace')
        lines = text.splitlines()
        if not lines:
            return self._amazon_inventory_txt_bytes([(s, qty_by_sku.get(s, 0)) for s in sku_list])
        delim = '\t' if '\t' in lines[0] else ','
        header_parts = lines[0].split(delim)
        header_lower = [str(x or '').strip().lower() for x in header_parts]
        sku_idx = next((i for i, h in enumerate(header_lower) if h in ('sku', 'seller-sku', 'seller sku')), 0)
        qty_idx = next((i for i, h in enumerate(header_lower) if h in ('quantity', 'qty', 'available')), len(header_parts))
        if qty_idx >= len(header_parts):
            header_parts.append('quantity')
            qty_idx = len(header_parts) - 1
            lines[0] = delim.join(header_parts)
        out_lines = [lines[0]]
        for ln in lines[1:]:
            if not str(ln or '').strip():
                out_lines.append(ln)
                continue
            parts = ln.split(delim)
            while len(parts) <= qty_idx:
                parts.append('')
            sku = str(parts[sku_idx] if sku_idx < len(parts) else '').strip()
            parts[qty_idx] = str(int(qty_by_sku.get(sku, 0)))
            out_lines.append(delim.join(parts))
        body = '\n'.join(out_lines)
        if not body.endswith('\n'):
            body += '\n'
        return body.encode('utf-8')

    def _detect_csv_delimiter(self, first_line):
        line = str(first_line or '')
        if '\t' in line and line.count('\t') >= line.count(','):
            return '\t'
        return ','

    def _map_wayfair_header_indices(self, header_row):
        mapping = {}
        for idx, cell in enumerate(header_row or []):
            key = str(cell or '').strip().lower()
            if key in self._WAYFAIR_HEADERS:
                mapping[self._WAYFAIR_HEADERS[key]] = idx
        if {'supplier_id', 'part', 'in_stock'}.issubset(set(mapping.keys())):
            return mapping
        return None

    def _fill_wayfair_inventory_csv(self, conn, file_bytes, opts):
        text = (file_bytes or b'').decode('utf-8-sig', errors='replace')
        if not str(text or '').strip():
            raise ValueError('上传文件为空')
        lines = text.splitlines()
        delim = self._detect_csv_delimiter(lines[0] if lines else '')
        reader = csv.reader(io.StringIO(text), delimiter=delim)
        rows = list(reader)
        if not rows:
            raise ValueError('上传文件无有效行')
        header_idx = None
        col_map = None
        for i, row in enumerate(rows[:30]):
            col_map = self._map_wayfair_header_indices(row)
            if col_map:
                header_idx = i
                break
        if header_idx is None or not col_map:
            raise ValueError('未找到 Wayfair 表头（需含 Supplier ID、Supplier Part#、In Stock）')

        row_jobs = []
        parts_needed = set()
        for row in rows[header_idx + 1:]:
            if not row or not any(str(c or '').strip() for c in row):
                continue
            while len(row) <= max(col_map.values()):
                row.append('')
            sid = str(row[col_map['supplier_id']] or '').strip()
            part = str(row[col_map['part']] or '').strip()
            if not sid or not part:
                continue
            parts_needed.add(part)
            row_jobs.append((row, sid, part))

        sku_map_all = self._load_sales_products_platform_sku_index(conn, 'wayfair')
        sku_map = {part: sku_map_all[part] for part in parts_needed if part in sku_map_all}
        variant_ids = sorted({rec['variant_id'] for rec in sku_map.values() if rec.get('variant_id')})
        links_by_vid, bom_units_by_vid, fabric_shares = self._inventory_export_bom_meta(conn, variant_ids)
        all_op_ids = sorted({
            int(oid)
            for links in links_by_vid.values()
            for oid, _ in (links or [])
            if self._parse_int(oid)
        })
        load_ids, _plans = self._inventory_export_expand_op_ids_with_substitute_items(conn, all_op_ids)
        wayfair_matrix = self._load_overseas_qty_wayfair_matrix(conn, load_ids)
        qty_cache = {}
        filled = 0
        for row, sid, part in row_jobs:
            rec = sku_map.get(part)
            if not rec:
                continue
            if not self._sales_product_status_exportable(rec.get('product_status')):
                row[col_map['in_stock']] = '0'
                filled += 1
                continue
            vid = rec['variant_id']
            links = links_by_vid.get(vid) or []
            cache_key = (vid, sid)
            if cache_key not in qty_cache:
                op_ids = [int(oid) for oid, _ in links]
                inv_by_op = self._inventory_export_effective_overseas_by_op(
                    conn, op_ids, wayfair_id=sid, wayfair_matrix=wayfair_matrix,
                )
                qty_cache[cache_key] = self._export_variant_qty(
                    rec, vid, links, inv_by_op, opts,
                    bom_units_by_vid, fabric_shares,
                )
            row[col_map['in_stock']] = str(int(qty_cache[cache_key]))
            filled += 1
        out_buf = io.StringIO()
        writer = csv.writer(out_buf, delimiter=delim, lineterminator='\n')
        for row in rows:
            writer.writerow(row)
        body = out_buf.getvalue()
        if not body.endswith('\n'):
            body += '\n'
        return body.encode('utf-8'), filled

    def handle_sales_product_amazon_inventory_export_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            options, file_bytes, _filename, mode = self._parse_export_multipart(environ)
            if mode not in ('fill', 'generate'):
                mode = 'fill' if file_bytes else 'generate'
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            with self._get_db_connection() as conn:
                if mode == 'fill':
                    if not file_bytes:
                        return self.send_json({'status': 'error', 'message': '请上传 Amazon 库存 txt 模板'}, start_response)
                    content = self._fill_amazon_inventory_upload(conn, file_bytes, options)
                    return self._send_text_attachment(content, f'amazon_inventory_{ts}.txt', start_response)
                if not self._parse_int(options.get('shop_id')):
                    return self.send_json({'status': 'error', 'message': '请选择店铺'}, start_response)
                rows = self._amazon_inventory_lines(conn, options)
                content = self._amazon_inventory_txt_bytes(rows)
                return self._send_text_attachment(content, f'amazon_inventory_{ts}.txt', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_wayfair_inventory_export_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            options, file_bytes, _filename, _mode = self._parse_export_multipart(environ)
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': '请先上传 Wayfair 库存 csv 模板'}, start_response)
            with self._get_db_connection() as conn:
                content, _filled = self._fill_wayfair_inventory_csv(conn, file_bytes, options)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            return self._send_text_attachment(content, f'wayfair_inventory_{ts}.csv', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_product_inventory_export_preview_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            options, file_bytes, _filename, mode = self._parse_export_multipart(environ)
            platform = str(options.get('platform') or '').strip().lower()
            if platform not in ('amazon', 'wayfair'):
                return self.send_json({'status': 'error', 'message': '缺少或无效的平台参数'}, start_response)
            with self._get_db_connection() as conn:
                if platform == 'amazon':
                    mode = str(mode or 'generate').strip().lower()
                    if mode == 'fill':
                        if not file_bytes:
                            return self.send_json({'status': 'error', 'message': '请上传 Amazon txt 模板'}, start_response)
                        sku_list = self._parse_amazon_inventory_upload(file_bytes)
                        if not sku_list:
                            return self.send_json({'status': 'error', 'message': '上传文件无有效 SKU 行'}, start_response)
                        items = self._amazon_inventory_preview(conn, options, sku_list=sku_list)
                    else:
                        if not self._parse_int(options.get('shop_id')):
                            return self.send_json({'status': 'error', 'message': '请选择亚马逊店铺'}, start_response)
                        items = self._amazon_inventory_preview(conn, options)
                else:
                    if not file_bytes:
                        return self.send_json({'status': 'error', 'message': '请先上传 Wayfair csv 模板'}, start_response)
                    items = self._wayfair_inventory_preview(conn, file_bytes, options)
            qty_sum = sum(int(x.get('qty') or 0) for x in (items or []))
            return self.send_json({
                'status': 'success',
                'platform': platform,
                'items': items or [],
                'total': len(items or []),
                'qty_sum': qty_sum,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
