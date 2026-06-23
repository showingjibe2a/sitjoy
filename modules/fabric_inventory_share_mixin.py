"""面料库存展示比例：按货号关联历史销量统计与维护。"""

from datetime import datetime
from urllib.parse import parse_qs


class FabricInventoryShareMixin:
    def _fabric_share_hist_month_range(self, months):
        try:
            n = max(1, min(36, int(months or 12)))
        except Exception:
            n = 12
        today = datetime.now()
        y, m = today.year, today.month
        end_month = f'{y:04d}-{m:02d}-01'
        for _ in range(n - 1):
            m -= 1
            if m < 1:
                m = 12
                y -= 1
        start_month = f'{y:04d}-{m:02d}-01'
        end_exclusive = self._forecast_history_end_exclusive(end_month)
        return start_month, end_month, end_exclusive, n

    def _fabric_share_rows_for_family(self, conn, sku_family_id, start_month, end_exclusive):
        sfid = self._parse_int(sku_family_id)
        if not sfid:
            return []
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT fpf.fabric_id,
                       fm.fabric_code,
                       fm.fabric_name_en,
                       fpf.inventory_share_ratio,
                       COALESCE(SUM(m.sales_qty), 0) AS history_sales_qty
                FROM fabric_product_families fpf
                INNER JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                LEFT JOIN sales_product_variants v
                       ON v.sku_family_id = %s AND v.fabric_id = fpf.fabric_id
                LEFT JOIN sales_products sp ON sp.variant_id = v.id
                LEFT JOIN sales_perf_agg_month m
                       ON m.sales_product_id = sp.id
                      AND m.month_start >= %s
                      AND m.month_start < %s
                WHERE fpf.sku_family_id = %s
                GROUP BY fpf.fabric_id, fm.fabric_code, fm.fabric_name_en, fpf.inventory_share_ratio
                ORDER BY fm.fabric_code ASC, fpf.fabric_id ASC
                """,
                (sfid, start_month, end_exclusive, sfid),
            )
            return cur.fetchall() or []

    def _fabric_share_apply_computed_ratios(self, rows):
        items = []
        max_sales = 0.0
        for row in rows or []:
            qty = float(row.get('history_sales_qty') or 0)
            if qty > max_sales:
                max_sales = qty
            items.append({
                'fabric_id': self._parse_int(row.get('fabric_id')),
                'fabric_code': str(row.get('fabric_code') or '').strip(),
                'fabric_name_en': str(row.get('fabric_name_en') or '').strip(),
                'history_sales_qty': int(qty),
                'inventory_share_ratio': row.get('inventory_share_ratio'),
            })
        for item in items:
            qty = float(item.get('history_sales_qty') or 0)
            if max_sales > 0:
                item['suggested_ratio'] = round(qty / max_sales, 6)
            else:
                item['suggested_ratio'] = 1.0
            stored = item.get('inventory_share_ratio')
            if stored is not None and str(stored).strip() != '':
                try:
                    item['inventory_share_ratio'] = round(max(0.0, min(1.0, float(stored))), 6)
                except Exception:
                    item['inventory_share_ratio'] = item['suggested_ratio']
            else:
                item['inventory_share_ratio'] = item['suggested_ratio']
        return items, max_sales

    def _fabric_share_save_items(self, conn, sku_family_id, items):
        sfid = self._parse_int(sku_family_id)
        if not sfid:
            raise ValueError('缺少货号 ID')
        saved = 0
        with conn.cursor() as cur:
            for raw in items or []:
                fid = self._parse_int((raw or {}).get('fabric_id'))
                if not fid:
                    continue
                try:
                    ratio = float((raw or {}).get('inventory_share_ratio'))
                except Exception:
                    continue
                ratio = round(max(0.0, min(1.0, ratio)), 6)
                cur.execute(
                    """
                    UPDATE fabric_product_families
                    SET inventory_share_ratio=%s
                    WHERE sku_family_id=%s AND fabric_id=%s
                    """,
                    (ratio, sfid, fid),
                )
                saved += int(cur.rowcount or 0)
        return saved

    def _fabric_share_map_for_variants(self, conn, variant_ids):
        ids = sorted({int(x) for x in (variant_ids or []) if self._parse_int(x)})
        if not ids:
            return {}
        ph = ','.join(['%s'] * len(ids))
        out = {}
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT v.id AS variant_id,
                       COALESCE(fpf.inventory_share_ratio, 1.0) AS share_ratio
                FROM sales_product_variants v
                LEFT JOIN fabric_product_families fpf
                       ON fpf.sku_family_id = v.sku_family_id
                      AND fpf.fabric_id = v.fabric_id
                WHERE v.id IN ({ph})
                """,
                tuple(ids),
            )
            for row in cur.fetchall() or []:
                vid = self._parse_int(row.get('variant_id'))
                if not vid:
                    continue
                try:
                    ratio = float(row.get('share_ratio') or 1.0)
                except Exception:
                    ratio = 1.0
                out[vid] = max(0.0, min(1.0, ratio))
        return out

    def handle_fabric_inventory_share_api(self, environ, method, start_response):
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                sku_family_id = self._parse_int(query_params.get('sku_family_id', [''])[0])
                if not sku_family_id:
                    return self.send_json({'status': 'error', 'message': '请选择货号'}, start_response)
                try:
                    months = max(1, min(36, int(query_params.get('months', ['12'])[0] or 12)))
                except Exception:
                    months = 12
                start_month, end_month, end_exclusive, months = self._fabric_share_hist_month_range(months)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, sku_family, category FROM product_families WHERE id=%s LIMIT 1",
                            (sku_family_id,),
                        )
                        family = cur.fetchone()
                    if not family:
                        return self.send_json({'status': 'error', 'message': '货号不存在'}, start_response)
                    rows = self._fabric_share_rows_for_family(conn, sku_family_id, start_month, end_exclusive)
                items, max_sales = self._fabric_share_apply_computed_ratios(rows)
                return self.send_json({
                    'status': 'success',
                    'sku_family_id': sku_family_id,
                    'sku_family': family.get('sku_family'),
                    'category': family.get('category'),
                    'history_months': months,
                    'history_start_month': start_month,
                    'history_end_month': end_month,
                    'max_history_sales_qty': int(max_sales),
                    'items': items,
                }, start_response)

            if method == 'POST':
                data = self._read_json_body(environ) or {}
                action = str(data.get('action') or 'calculate').strip().lower()
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                if not sku_family_id:
                    return self.send_json({'status': 'error', 'message': '请选择货号'}, start_response)
                try:
                    months = max(1, min(36, int(data.get('months') or 12)))
                except Exception:
                    months = 12

                if action == 'save':
                    with self._get_db_connection() as conn:
                        saved = self._fabric_share_save_items(conn, sku_family_id, data.get('items') or [])
                    return self.send_json({'status': 'success', 'saved': saved}, start_response)

                start_month, end_month, end_exclusive, months = self._fabric_share_hist_month_range(months)
                with self._get_db_connection() as conn:
                    rows = self._fabric_share_rows_for_family(conn, sku_family_id, start_month, end_exclusive)
                items, max_sales = self._fabric_share_apply_computed_ratios(rows)
                for item in items:
                    item['inventory_share_ratio'] = item.get('suggested_ratio')
                return self.send_json({
                    'status': 'success',
                    'sku_family_id': sku_family_id,
                    'history_months': months,
                    'history_start_month': start_month,
                    'history_end_month': end_month,
                    'max_history_sales_qty': int(max_sales),
                    'items': items,
                }, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
