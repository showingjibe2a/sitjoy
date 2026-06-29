# -*- coding: utf-8 -*-
"""面料库存展示比例：按货号关联历史销量统计与维护。"""

from datetime import datetime
from urllib.parse import parse_qs


class FabricInventoryShareMixin:
    """面料库存比例 Mixin：按货号×面料统计历史销量并维护 inventory_share_ratio。"""

    def _fabric_share_parse_months(self, raw, default=12):
        """历史统计月数：1–36，默认 12。"""
        try:
            return max(1, min(36, int(raw if raw is not None else default)))
        except Exception:
            return default

    def _fabric_share_clamp_ratio(self, value):
        """比例限制在 [0, 1]，保留 6 位小数；无效时返回 None。"""
        try:
            return round(max(0.0, min(1.0, float(value))), 6)
        except Exception:
            return None

    def _fabric_share_hist_month_range(self, months):
        """返回 (start_month, end_month, end_exclusive, months) 供 agg_month 查询。"""
        n = self._fabric_share_parse_months(months)
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
        """货号下各面料的历史销量与已存比例。"""
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
        """按历史销量计算 suggested_ratio，并与已存比例合并。"""
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
            ratio_persisted = stored is not None and str(stored).strip() != ''
            saved_ratio = self._fabric_share_clamp_ratio(stored) if ratio_persisted else None
            if ratio_persisted and saved_ratio is None:
                ratio_persisted = False
            item['ratio_persisted'] = bool(ratio_persisted)
            item['saved_ratio'] = saved_ratio
            item['inventory_share_ratio'] = saved_ratio if ratio_persisted else item['suggested_ratio']
        return items, max_sales

    def _fabric_share_items_as_suggested(self, items):
        """重算模式：展示 suggested_ratio，不沿用已存值。"""
        out = []
        for item in items or []:
            row = dict(item)
            row['inventory_share_ratio'] = row.get('suggested_ratio')
            row['ratio_persisted'] = False
            row['saved_ratio'] = None
            out.append(row)
        return out

    def _fabric_share_json_payload(
        self, sku_family_id, family, months, start_month, end_month, items, max_sales,
    ):
        payload = {
            'status': 'success',
            'sku_family_id': sku_family_id,
            'history_months': months,
            'history_start_month': start_month,
            'history_end_month': end_month,
            'max_history_sales_qty': int(max_sales),
            'items': items,
        }
        if family:
            payload['sku_family'] = family.get('sku_family')
            payload['category'] = family.get('category')
        return payload

    def _fabric_share_load_family_calculate(
        self, conn, sku_family_id, months, *, use_suggested_only=False,
    ):
        """加载货号、查询历史销量并计算比例项。"""
        start_month, end_month, end_exclusive, months = self._fabric_share_hist_month_range(months)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, sku_family, category FROM product_families WHERE id=%s LIMIT 1",
                (sku_family_id,),
            )
            family = cur.fetchone()
        if not family:
            return None, None, None, None, None, None
        rows = self._fabric_share_rows_for_family(conn, sku_family_id, start_month, end_exclusive)
        items, max_sales = self._fabric_share_apply_computed_ratios(rows)
        if use_suggested_only:
            items = self._fabric_share_items_as_suggested(items)
        return family, items, max_sales, start_month, end_month, months

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
                ratio = self._fabric_share_clamp_ratio((raw or {}).get('inventory_share_ratio'))
                if ratio is None:
                    continue
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
        """变体 id → 面料库存展示比例（平台库存导出读取）。"""
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
                ratio = self._fabric_share_clamp_ratio(row.get('share_ratio'))
                out[vid] = ratio if ratio is not None else 1.0
        return out

    def handle_fabric_inventory_share_api(self, environ, method, start_response):
        """面料库存比例：GET 加载 / POST calculate 重算 / POST save 保存。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                sku_family_id = self._parse_int(query_params.get('sku_family_id', [''])[0])
                if not sku_family_id:
                    return self.send_json({'status': 'error', 'message': '请选择货号'}, start_response)
                months = self._fabric_share_parse_months(query_params.get('months', ['12'])[0])
                with self._get_db_connection() as conn:
                    family, items, max_sales, start_month, end_month, months = (
                        self._fabric_share_load_family_calculate(
                            conn, sku_family_id, months, use_suggested_only=False,
                        )
                    )
                if not family:
                    return self.send_json({'status': 'error', 'message': '货号不存在'}, start_response)
                return self.send_json(
                    self._fabric_share_json_payload(
                        sku_family_id, family, months, start_month, end_month, items, max_sales,
                    ),
                    start_response,
                )

            if method == 'POST':
                data = self._read_json_body(environ) or {}
                action = str(data.get('action') or 'calculate').strip().lower()
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                if not sku_family_id:
                    return self.send_json({'status': 'error', 'message': '请选择货号'}, start_response)
                months = self._fabric_share_parse_months(data.get('months'))

                if action == 'save':
                    with self._get_db_connection() as conn:
                        saved = self._fabric_share_save_items(conn, sku_family_id, data.get('items') or [])
                    return self.send_json({'status': 'success', 'saved': saved}, start_response)

                with self._get_db_connection() as conn:
                    family, items, max_sales, start_month, end_month, months = (
                        self._fabric_share_load_family_calculate(
                            conn, sku_family_id, months, use_suggested_only=True,
                        )
                    )
                if not family:
                    return self.send_json({'status': 'error', 'message': '货号不存在'}, start_response)
                return self.send_json(
                    self._fabric_share_json_payload(
                        sku_family_id, family, months, start_month, end_month, items, max_sales,
                    ),
                    start_response,
                )

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
