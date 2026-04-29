import io
import cgi
import re
from datetime import datetime
from urllib.parse import parse_qs

try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)


class SalesManagementMixin:
    def _registration_get_replacement_options(self, conn, base_order_product_ids):
        """按基础发货 SKU 加载替代方案及方案明细。"""
        result = {}
        ids = [self._parse_int(x) for x in (base_order_product_ids or []) if self._parse_int(x)]
        if not ids:
            return result

        placeholders = ','.join(['%s'] * len(ids))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT ops.id, ops.order_product_id, ops.plan_name
                FROM order_product_shipping_plans ops
                WHERE ops.order_product_id IN ({placeholders})
                ORDER BY ops.order_product_id ASC, ops.plan_name ASC, ops.id ASC
                """,
                tuple(ids)
            )
            plan_rows = cur.fetchall() or []

            plan_ids = [self._parse_int(x.get('id')) for x in plan_rows if self._parse_int(x.get('id'))]
            plan_item_map = {}
            if plan_ids:
                plan_placeholders = ','.join(['%s'] * len(plan_ids))
                cur.execute(
                    f"""
                    SELECT
                        opsi.shipping_plan_id,
                        opsi.substitute_order_product_id,
                        opsi.quantity,
                        opsi.sort_order,
                        op.sku
                    FROM order_product_shipping_plan_items opsi
                    JOIN order_products op ON op.id = opsi.substitute_order_product_id
                    WHERE opsi.shipping_plan_id IN ({plan_placeholders})
                    ORDER BY opsi.shipping_plan_id ASC, opsi.sort_order ASC, opsi.id ASC
                    """,
                    tuple(plan_ids)
                )
                for row in (cur.fetchall() or []):
                    pid = self._parse_int(row.get('shipping_plan_id'))
                    if not pid:
                        continue
                    plan_item_map.setdefault(pid, []).append({
                        'order_product_id': self._parse_int(row.get('substitute_order_product_id')),
                        'order_sku': (row.get('sku') or '').strip(),
                        'quantity': max(1, self._parse_int(row.get('quantity')) or 1)
                    })

            for row in plan_rows:
                base_id = self._parse_int(row.get('order_product_id'))
                plan_id = self._parse_int(row.get('id'))
                if not base_id or not plan_id:
                    continue
                result.setdefault(base_id, []).append({
                    'plan_id': plan_id,
                    'plan_name': (row.get('plan_name') or '').strip(),
                    'items': plan_item_map.get(plan_id, [])
                })

        return result

    def _bool_from_any(self, value, default=0):
        if value is None:
            return 1 if default else 0
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'y', '是', 'on'):
            return 1
        if text in ('0', 'false', 'no', 'n', '否', 'off'):
            return 0
        return 1 if default else 0

    def _validate_us_phone_zip(self, phone, zip_code):
        phone_text = (phone or '').strip()
        zip_text = (zip_code or '').strip()
        if phone_text:
            digits = re.sub(r'\D+', '', phone_text)
            if len(digits) == 11 and digits.startswith('1'):
                digits = digits[1:]
            if len(digits) != 10:
                raise ValueError('电话格式无效，请填写美国电话（10位数字，可含+1）')
        if zip_text and not re.match(r'^\d{5}(-\d{4})?$', zip_text):
            raise ValueError('邮编格式无效，请填写美国邮编（5位或5+4）')

    def _normalize_registration_platform_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for entry in items:
            if not isinstance(entry, dict):
                continue
            platform_sku = (entry.get('platform_sku') or '').strip()
            sales_product_id = self._parse_int(entry.get('sales_product_id'))
            quantity = self._parse_int(entry.get('quantity')) or 1
            shipping_plan_id = self._parse_int(entry.get('shipping_plan_id'))
            if not platform_sku and not sales_product_id:
                continue
            normalized.append({
                'sales_product_id': sales_product_id,
                'platform_sku': platform_sku,
                'quantity': max(1, quantity),
                'shipping_plan_id': shipping_plan_id
            })
        return normalized

    def _normalize_registration_shipment_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for entry in items:
            if not isinstance(entry, dict):
                continue
            order_product_id = self._parse_int(entry.get('order_product_id'))
            order_sku = (entry.get('order_sku') or '').strip()
            quantity = self._parse_int(entry.get('quantity')) or 1
            shipping_plan_id = self._parse_int(entry.get('shipping_plan_id'))
            source_type = (entry.get('source_type') or 'manual').strip().lower()
            if source_type not in ('manual', 'auto', 'plan'):
                source_type = 'manual'
            if not order_product_id and not order_sku:
                continue
            normalized.append({
                'order_product_id': order_product_id,
                'order_sku': order_sku,
                'quantity': max(1, quantity),
                'source_type': source_type,
                'shipping_plan_id': shipping_plan_id
            })
        return normalized

    def _normalize_registration_logistics_items(self, items):
        normalized = []
        if not isinstance(items, list):
            return normalized
        for index, entry in enumerate(items, start=1):
            if not isinstance(entry, dict):
                continue
            shipping_carrier = (entry.get('shipping_carrier') or '').strip()
            tracking_no = (entry.get('tracking_no') or '').strip()
            sort_order = self._parse_int(entry.get('sort_order')) or index
            if not shipping_carrier and not tracking_no:
                continue
            normalized.append({
                'shipping_carrier': shipping_carrier or None,
                'tracking_no': tracking_no or None,
                'sort_order': max(1, sort_order)
            })
        return normalized

    def _resolve_registration_auto_shipments(self, conn, platform_items):
        aggregate = {}
        if not platform_items:
            return []

        with conn.cursor() as cur:
            for item in platform_items:
                qty = max(1, self._parse_int(item.get('quantity')) or 1)
                shipping_plan_id = self._parse_int(item.get('shipping_plan_id'))

                if shipping_plan_id:
                    cur.execute(
                        """
                        SELECT op.id AS order_product_id, op.sku, opsi.quantity
                        FROM order_product_shipping_plan_items opsi
                        JOIN order_products op ON op.id = opsi.substitute_order_product_id
                        WHERE opsi.shipping_plan_id=%s
                        ORDER BY opsi.sort_order ASC, opsi.id ASC
                        """,
                        (shipping_plan_id,)
                    )
                    rels = cur.fetchall() or []
                    for rel in rels:
                        key = int(rel.get('order_product_id'))
                        aggregate.setdefault(key, {
                            'order_product_id': key,
                            'order_sku': rel.get('sku') or '',
                            'quantity': 0,
                            'source_type': 'plan',
                            'shipping_plan_id': shipping_plan_id
                        })
                        aggregate[key]['quantity'] += qty * (self._parse_int(rel.get('quantity')) or 1)
                    continue

                sales_product_id = self._parse_int(item.get('sales_product_id'))
                platform_sku = (item.get('platform_sku') or '').strip()
                if not sales_product_id and platform_sku:
                    cur.execute("SELECT id FROM sales_products WHERE platform_sku=%s LIMIT 1", (platform_sku,))
                    row = cur.fetchone() or {}
                    sales_product_id = self._parse_int(row.get('id'))
                if not sales_product_id:
                    continue

                cur.execute(
                    """
                    SELECT op.id AS order_product_id, op.sku, svol.quantity
                    FROM sales_products sp
                    JOIN sales_variant_order_links svol ON svol.variant_id = sp.variant_id
                    JOIN order_products op ON op.id = svol.order_product_id
                    WHERE sp.id=%s
                    """,
                    (sales_product_id,)
                )
                rels = cur.fetchall() or []
                for rel in rels:
                    key = int(rel.get('order_product_id'))
                    aggregate.setdefault(key, {
                        'order_product_id': key,
                        'order_sku': rel.get('sku') or '',
                        'quantity': 0,
                        'source_type': 'auto',
                        'shipping_plan_id': None
                    })
                    aggregate[key]['quantity'] += qty * (self._parse_int(rel.get('quantity')) or 1)

        items = list(aggregate.values())
        items.sort(key=lambda x: (x.get('order_sku') or '', x.get('order_product_id') or 0))
        return items

    def _registration_parse_date(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        text = str(value).strip()
        if not text:
            return None
        for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S'):
            try:
                return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
            except Exception:
                continue
        return None

    def _registration_parse_item_text(self, raw_text):
        items = []
        if raw_text is None:
            return items
        text = str(raw_text).strip()
        if not text:
            return items
        for token in re.split(r'[\n;；|]+', text):
            token = (token or '').strip()
            if not token:
                continue
            if '*' in token:
                left, right = token.split('*', 1)
                sku = (left or '').strip()
                qty = self._parse_int(right)
                qty = max(1, qty or 1)
            else:
                sku = token
                qty = 1
            if not sku:
                continue
            items.append({'sku': sku, 'quantity': qty})
        return items

    def _registration_parse_logistics_text(self, raw_text):
        items = []
        if raw_text is None:
            return items
        text = str(raw_text).strip()
        if not text:
            return items
        for index, token in enumerate(re.split(r'[\n;；|]+', text), start=1):
            token = (token or '').strip()
            if not token:
                continue
            if ':' in token:
                carrier, tracking = token.split(':', 1)
            else:
                carrier, tracking = '', token
            items.append({
                'shipping_carrier': (carrier or '').strip() or None,
                'tracking_no': (tracking or '').strip() or None,
                'sort_order': index
            })
        return items

    def _registration_save_children(self, conn, registration_id, platform_items, shipment_items, logistics_items):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sales_order_registration_platform_items WHERE registration_id=%s", (registration_id,))
            cur.execute("DELETE FROM sales_order_registration_shipment_items WHERE registration_id=%s", (registration_id,))
            cur.execute("DELETE FROM sales_order_registration_logistics_items WHERE registration_id=%s", (registration_id,))

            if platform_items:
                cur.executemany(
                    """
                    INSERT INTO sales_order_registration_platform_items
                        (registration_id, sales_product_id, platform_sku, quantity, shipping_plan_id)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            registration_id,
                            self._parse_int(item.get('sales_product_id')),
                            (item.get('platform_sku') or '').strip(),
                            max(1, self._parse_int(item.get('quantity')) or 1),
                            self._parse_int(item.get('shipping_plan_id'))
                        )
                        for item in platform_items
                    ]
                )

            if shipment_items:
                cur.executemany(
                    """
                    INSERT INTO sales_order_registration_shipment_items
                        (registration_id, order_product_id, order_sku, quantity, source_type, shipping_plan_id)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    [
                        (
                            registration_id,
                            self._parse_int(item.get('order_product_id')),
                            (item.get('order_sku') or '').strip(),
                            max(1, self._parse_int(item.get('quantity')) or 1),
                            (item.get('source_type') or 'manual').strip().lower() if (item.get('source_type') or '').strip().lower() in ('manual', 'auto', 'plan') else 'manual',
                            self._parse_int(item.get('shipping_plan_id'))
                        )
                        for item in shipment_items
                    ]
                )

            if logistics_items:
                cur.executemany(
                    """
                    INSERT INTO sales_order_registration_logistics_items
                        (registration_id, shipping_carrier, tracking_no, sort_order)
                    VALUES (%s, %s, %s, %s)
                    """,
                    [
                        (
                            registration_id,
                            (item.get('shipping_carrier') or '').strip() or None,
                            (item.get('tracking_no') or '').strip() or None,
                            max(1, self._parse_int(item.get('sort_order')) or 1)
                        )
                        for item in logistics_items
                    ]
                )

    def _registration_fill_item_ids(self, conn, platform_items, shipment_items):
        with conn.cursor() as cur:
            sku_to_sales_id = {}
            if platform_items:
                platform_skus = sorted({(x.get('platform_sku') or '').strip() for x in platform_items if (x.get('platform_sku') or '').strip()})
                if platform_skus:
                    placeholders = ','.join(['%s'] * len(platform_skus))
                    cur.execute(f"SELECT id, platform_sku FROM sales_products WHERE platform_sku IN ({placeholders})", tuple(platform_skus))
                    for row in (cur.fetchall() or []):
                        sku_to_sales_id[(row.get('platform_sku') or '').strip()] = self._parse_int(row.get('id'))
                for item in platform_items:
                    if not self._parse_int(item.get('sales_product_id')):
                        item['sales_product_id'] = sku_to_sales_id.get((item.get('platform_sku') or '').strip())

            sku_to_order_id = {}
            if shipment_items:
                order_skus = sorted({(x.get('order_sku') or '').strip() for x in shipment_items if (x.get('order_sku') or '').strip()})
                if order_skus:
                    placeholders = ','.join(['%s'] * len(order_skus))
                    cur.execute(f"SELECT id, sku FROM order_products WHERE sku IN ({placeholders})", tuple(order_skus))
                    for row in (cur.fetchall() or []):
                        sku_to_order_id[(row.get('sku') or '').strip()] = self._parse_int(row.get('id'))
                for item in shipment_items:
                    if not self._parse_int(item.get('order_product_id')):
                        item['order_product_id'] = sku_to_order_id.get((item.get('order_sku') or '').strip())

    def _registration_fetch_detail(self, conn, item_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT r.*, s.shop_name
                FROM sales_order_registrations r
                LEFT JOIN shops s ON s.id = r.shop_id
                WHERE r.id=%s
                LIMIT 1
                """,
                (item_id,)
            )
            row = cur.fetchone() or None
            if not row:
                return None

            cur.execute(
                """
                SELECT id, sales_product_id, platform_sku, quantity, shipping_plan_id
                FROM sales_order_registration_platform_items
                WHERE registration_id=%s
                ORDER BY id ASC
                """,
                (item_id,)
            )
            row['platform_items'] = cur.fetchall() or []

            cur.execute(
                """
                SELECT id, order_product_id, order_sku, quantity, source_type, shipping_plan_id
                FROM sales_order_registration_shipment_items
                WHERE registration_id=%s
                ORDER BY id ASC
                """,
                (item_id,)
            )
            row['shipment_items'] = cur.fetchall() or []

            cur.execute(
                """
                SELECT id, shipping_carrier, tracking_no, sort_order
                FROM sales_order_registration_logistics_items
                WHERE registration_id=%s
                ORDER BY sort_order ASC, id ASC
                """,
                (item_id,)
            )
            row['logistics_items'] = cur.fetchall() or []

            return row

    def handle_sales_order_registration_api(self, environ, method, start_response):
        perf_ctx = self._perf_begin('sales_order_registration_api', environ, {'entry_method': method})
        try:
            self._perf_mark(perf_ctx, 'ensure_sales_order_registration_tables')
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query_params.get('action', [''])[0] or '').strip().lower()
            self._perf_mark(perf_ctx, f'parse_query_action:{action or "none"}')

            if method == 'GET' and action == 'options':
                scope = (query_params.get('scope', ['all'])[0] or 'all').strip().lower()
                limit = max(50, min(self._parse_int(query_params.get('limit', ['300'])[0]) or 300, 1000))
                def _load_options_payload():
                    payload = {'status': 'success'}
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            if scope in ('all', 'shops'):
                                cur.execute("SELECT id, shop_name FROM shops ORDER BY shop_name ASC LIMIT %s", (limit,))
                                payload['shops'] = cur.fetchall() or []
                            if scope == 'all':
                                cur.execute("SELECT id, platform_sku FROM sales_products ORDER BY platform_sku ASC LIMIT %s", (limit,))
                                payload['sales_products'] = cur.fetchall() or []
                                cur.execute("SELECT id, sku FROM order_products WHERE COALESCE(is_reship_accessory, 0)=0 ORDER BY sku ASC LIMIT %s", (limit,))
                                payload['order_products'] = cur.fetchall() or []
                                try:
                                    cur.execute(
                                        """
                                        SELECT ops.id, op.sku AS order_sku, ops.plan_name
                                        FROM order_product_shipping_plans ops
                                        JOIN order_products op ON op.id = ops.order_product_id
                                        WHERE COALESCE(op.is_reship_accessory, 0)=0
                                        ORDER BY op.sku ASC, ops.plan_name ASC
                                        LIMIT %s
                                        """,
                                        (limit,)
                                    )
                                    payload['shipping_plans'] = cur.fetchall() or []
                                except Exception:
                                    payload['shipping_plans'] = []
                    return payload
                payload = self._get_cached_template_options(f'sales_order_registration_options_{scope}_{limit}', _load_options_payload, ttl_seconds=1800)
                self._perf_mark(perf_ctx, 'get_options_payload')
                return self.send_json(payload, start_response)

            if method == 'POST' and action == 'shipment_preview':
                data = self._read_json_body(environ)
                platform_items = self._normalize_registration_platform_items(data.get('platform_items'))
                if not platform_items:
                    return self.send_json({'status': 'success', 'auto_shipments': [], 'replacement_options': {}}, start_response)

                with self._get_db_connection() as conn:
                    self._registration_fill_item_ids(conn, platform_items, [])
                    auto_shipments = self._resolve_registration_auto_shipments(conn, platform_items)
                    base_ids = [self._parse_int(x.get('order_product_id')) for x in auto_shipments if self._parse_int(x.get('order_product_id'))]
                    replacement_options = self._registration_get_replacement_options(conn, base_ids)

                return self.send_json({
                    'status': 'success',
                    'auto_shipments': auto_shipments,
                    'replacement_options': replacement_options
                }, start_response)

            if method == 'POST' and action == 'quick_update':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                updatable = {}
                if 'shipping_status' in data:
                    status = (data.get('shipping_status') or 'pending').strip().lower()
                    if status not in ('pending', 'unshipped', 'shipped', 'cancelled'):
                        return self.send_json({'status': 'error', 'message': '无效运输状态'}, start_response)
                    updatable['shipping_status'] = status
                if 'is_review_invited' in data:
                    updatable['is_review_invited'] = self._bool_from_any(data.get('is_review_invited'))
                if 'is_logistics_emailed' in data:
                    updatable['is_logistics_emailed'] = self._bool_from_any(data.get('is_logistics_emailed'))
                if 'compensation_action' in data:
                    updatable['compensation_action'] = (data.get('compensation_action') or '').strip() or None
                if 'remark' in data:
                    updatable['remark'] = (data.get('remark') or '').strip() or None

                if not updatable:
                    return self.send_json({'status': 'error', 'message': 'No fields to update'}, start_response)

                set_sql = []
                params = []
                for key, val in updatable.items():
                    set_sql.append(f"{key}=%s")
                    params.append(val)
                set_sql.append("updated_at=CURRENT_TIMESTAMP")
                params.append(item_id)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE sales_order_registrations SET " + ', '.join(set_sql) + " WHERE id=%s",
                            tuple(params)
                        )
                        if cur.rowcount <= 0:
                            return self.send_json({'status': 'error', 'message': '记录不存在或未变更'}, start_response)

                return self.send_json({'status': 'success', 'id': item_id}, start_response)

            if method == 'GET' and action == 'summaries':
                ids = []
                for raw in query_params.get('ids', []):
                    for token in re.split(r'[,，;；\s]+', str(raw or '').strip()):
                        val = self._parse_int(token)
                        if val:
                            ids.append(val)
                ids = list(dict.fromkeys(ids))
                if not ids:
                    return self.send_json({'status': 'success', 'items': []}, start_response)

                with self._get_db_connection() as conn:
                    self._perf_mark(perf_ctx, 'db_connected_for_summaries')
                    with conn.cursor() as cur:
                        placeholders = ','.join(['%s'] * len(ids))
                        cur.execute(
                            f"""
                            SELECT registration_id, platform_sku, quantity
                            FROM sales_order_registration_platform_items
                            WHERE registration_id IN ({placeholders})
                            ORDER BY registration_id ASC, id ASC
                            """,
                            tuple(ids)
                        )
                        platform_rows = cur.fetchall() or []

                        cur.execute(
                            f"""
                            SELECT registration_id, order_sku, quantity
                            FROM sales_order_registration_shipment_items
                            WHERE registration_id IN ({placeholders})
                            ORDER BY registration_id ASC, id ASC
                            """,
                            tuple(ids)
                        )
                        shipment_rows = cur.fetchall() or []

                        cur.execute(
                            f"""
                            SELECT registration_id, shipping_carrier, tracking_no
                            FROM sales_order_registration_logistics_items
                            WHERE registration_id IN ({placeholders})
                            ORDER BY registration_id ASC, sort_order ASC, id ASC
                            """,
                            tuple(ids)
                        )
                        logistics_rows = cur.fetchall() or []
                    self._perf_mark(perf_ctx, 'load_summaries_rows')

                out = {int(i): {'id': int(i), 'platform_summary': [], 'shipment_summary': [], 'logistics_summary': []} for i in ids}
                for row in platform_rows:
                    rid = self._parse_int(row.get('registration_id'))
                    if rid in out:
                        out[rid]['platform_summary'].append(f"{(row.get('platform_sku') or '').strip()}*{self._parse_int(row.get('quantity')) or 1}")
                for row in shipment_rows:
                    rid = self._parse_int(row.get('registration_id'))
                    if rid in out:
                        out[rid]['shipment_summary'].append(f"{(row.get('order_sku') or '').strip()}*{self._parse_int(row.get('quantity')) or 1}")
                for row in logistics_rows:
                    rid = self._parse_int(row.get('registration_id'))
                    if rid in out:
                        carrier = (row.get('shipping_carrier') or '').strip()
                        tracking = (row.get('tracking_no') or '').strip()
                        out[rid]['logistics_summary'].append(f"{carrier}:{tracking}" if carrier else tracking)

                return self.send_json({'status': 'success', 'items': [out[x] for x in ids]}, start_response)

            if method == 'GET':
                item_id = self._parse_int(query_params.get('id', [''])[0])
                keyword = (query_params.get('q', [''])[0] or '').strip()
                include_summaries = str(query_params.get('include_summaries', ['1'])[0] or '1').strip().lower() not in ('0', 'false', 'no', 'off')
                page = max(1, self._parse_int(query_params.get('page', ['1'])[0]) or 1)
                page_size = max(20, min(self._parse_int(query_params.get('page_size', ['50'])[0]) or 50, 200))
                offset = (page - 1) * page_size

                with self._get_db_connection() as conn:
                    self._perf_mark(perf_ctx, 'db_connected_for_get')
                    if item_id:
                        item = self._registration_fetch_detail(conn, item_id)
                        self._perf_mark(perf_ctx, 'fetch_detail')
                        return self.send_json({'status': 'success', 'item': item}, start_response)

                    with conn.cursor() as cur:
                        filters = []
                        params = []
                        if keyword:
                            like = f"%{keyword}%"
                            filters.append("(r.order_no LIKE %s OR r.customer_name LIKE %s OR r.phone LIKE %s OR s.shop_name LIKE %s)")
                            params.extend([like, like, like, like])
                        where_sql = (' WHERE ' + ' AND '.join(filters)) if filters else ''

                        cur.execute(
                            "SELECT COUNT(*) AS total FROM sales_order_registrations r LEFT JOIN shops s ON s.id = r.shop_id" + where_sql,
                            tuple(params)
                        )
                        total = int((cur.fetchone() or {}).get('total') or 0)
                        self._perf_mark(perf_ctx, 'list_count_query')

                        if include_summaries:
                            cur.execute(
                                """
                                SELECT r.id, r.shop_id, r.order_no, r.order_date, r.customer_name, r.shipping_status,
                                        r.is_review_invited, r.is_logistics_emailed, r.compensation_action, r.remark,
                                       r.created_at, r.updated_at, s.shop_name, s.shop_name AS shop_display_name,
                                       (
                                           SELECT GROUP_CONCAT(CONCAT(COALESCE(p.platform_sku, ''), '*', COALESCE(p.quantity, 1)) ORDER BY p.id ASC SEPARATOR '\n')
                                           FROM sales_order_registration_platform_items p
                                           WHERE p.registration_id = r.id
                                       ) AS platform_summary_text,
                                       (
                                           SELECT GROUP_CONCAT(CONCAT(COALESCE(si.order_sku, ''), '*', COALESCE(si.quantity, 1)) ORDER BY si.id ASC SEPARATOR '\n')
                                           FROM sales_order_registration_shipment_items si
                                           WHERE si.registration_id = r.id
                                       ) AS shipment_summary_text,
                                       (
                                           SELECT GROUP_CONCAT(
                                               CASE
                                                   WHEN COALESCE(li.shipping_carrier, '') <> ''
                                                   THEN CONCAT(li.shipping_carrier, ':', COALESCE(li.tracking_no, ''))
                                                   ELSE COALESCE(li.tracking_no, '')
                                               END
                                               ORDER BY li.sort_order ASC, li.id ASC SEPARATOR '\n'
                                           )
                                           FROM sales_order_registration_logistics_items li
                                           WHERE li.registration_id = r.id
                                       ) AS logistics_summary_text
                                FROM sales_order_registrations r
                                LEFT JOIN shops s ON s.id = r.shop_id
                                """ + where_sql + " ORDER BY r.id DESC LIMIT %s OFFSET %s",
                                tuple(params + [page_size, offset])
                            )
                        else:
                            cur.execute(
                                """
                                SELECT r.id, r.shop_id, r.order_no, r.order_date, r.customer_name, r.shipping_status,
                                        r.is_review_invited, r.is_logistics_emailed, r.compensation_action, r.remark,
                                       r.created_at, r.updated_at, s.shop_name, s.shop_name AS shop_display_name
                                FROM sales_order_registrations r
                                LEFT JOIN shops s ON s.id = r.shop_id
                                """ + where_sql + " ORDER BY r.id DESC LIMIT %s OFFSET %s",
                                tuple(params + [page_size, offset])
                            )
                        rows = cur.fetchall() or []
                        self._perf_mark(perf_ctx, 'list_rows_query')

                for row in rows:
                    if include_summaries:
                        platform_text = (row.get('platform_summary_text') or '').strip()
                        shipment_text = (row.get('shipment_summary_text') or '').strip()
                        logistics_text = (row.get('logistics_summary_text') or '').strip()
                        row['platform_summary'] = [x for x in platform_text.split('\n') if x] if platform_text else []
                        row['shipment_summary'] = [x for x in shipment_text.split('\n') if x] if shipment_text else []
                        row['logistics_summary'] = [x for x in logistics_text.split('\n') if x] if logistics_text else []
                        row.pop('platform_summary_text', None)
                        row.pop('shipment_summary_text', None)
                        row.pop('logistics_summary_text', None)
                    else:
                        row['platform_summary'] = []
                        row['shipment_summary'] = []
                        row['logistics_summary'] = []
                self._perf_mark(perf_ctx, 'list_rows_transform')

                return self.send_json(
                    {'status': 'success', 'items': rows, 'page': page, 'page_size': page_size, 'total': total},
                    start_response
                )

            data = self._read_json_body(environ)

            if method in ('POST', 'PUT'):
                if method == 'PUT':
                    item_id = self._parse_int(data.get('id'))
                    if not item_id:
                        return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                else:
                    item_id = None

                order_no = (data.get('order_no') or '').strip()
                if not order_no:
                    return self.send_json({'status': 'error', 'message': '订单号必填'}, start_response)

                shop_id = self._parse_int(data.get('shop_id'))
                order_date = self._registration_parse_date(data.get('order_date'))
                customer_name = (data.get('customer_name') or '').strip() or None
                phone = (data.get('phone') or '').strip() or None
                zip_code = (data.get('zip_code') or '').strip() or None
                address = (data.get('address') or '').strip() or None
                city = (data.get('city') or '').strip() or None
                state = (data.get('state') or '').strip() or None
                shipping_status = (data.get('shipping_status') or 'pending').strip() or 'pending'
                compensation_action = (data.get('compensation_action') or '').strip() or None
                remark = (data.get('remark') or '').strip() or None

                self._validate_us_phone_zip(phone, zip_code)

                platform_items = self._normalize_registration_platform_items(data.get('platform_items'))
                if not platform_items:
                    return self.send_json({'status': 'error', 'message': '请至少填写1条销售平台SKU'}, start_response)
                shipment_items = self._normalize_registration_shipment_items(data.get('shipment_items'))
                logistics_items = self._normalize_registration_logistics_items(data.get('logistics_items'))

                with self._get_db_connection() as conn:
                    self._perf_mark(perf_ctx, 'db_connected_for_write')
                    self._registration_fill_item_ids(conn, platform_items, shipment_items)
                    if not shipment_items:
                        shipment_items = self._resolve_registration_auto_shipments(conn, platform_items)
                    self._perf_mark(perf_ctx, 'prepare_write_payload')

                    with conn.cursor() as cur:
                        if method == 'POST':
                            cur.execute(
                                """
                                INSERT INTO sales_order_registrations
                                    (shop_id, order_no, order_date, customer_name, phone, zip_code, address, city, state,
                                     shipping_status, is_review_invited, is_logistics_emailed, compensation_action, remark)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                                (
                                    shop_id,
                                    order_no,
                                    order_date,
                                    customer_name,
                                    phone,
                                    zip_code,
                                    address,
                                    city,
                                    state,
                                    shipping_status,
                                    self._bool_from_any(data.get('is_review_invited')),
                                    self._bool_from_any(data.get('is_logistics_emailed')),
                                    compensation_action,
                                    remark
                                )
                            )
                            item_id = cur.lastrowid
                        else:
                            cur.execute(
                                """
                                UPDATE sales_order_registrations
                                SET shop_id=%s,
                                    order_no=%s,
                                    order_date=%s,
                                    customer_name=%s,
                                    phone=%s,
                                    zip_code=%s,
                                    address=%s,
                                    city=%s,
                                    state=%s,
                                    shipping_status=%s,
                                    is_review_invited=%s,
                                    is_logistics_emailed=%s,
                                    compensation_action=%s,
                                    remark=%s
                                WHERE id=%s
                                """,
                                (
                                    shop_id,
                                    order_no,
                                    order_date,
                                    customer_name,
                                    phone,
                                    zip_code,
                                    address,
                                    city,
                                    state,
                                    shipping_status,
                                    self._bool_from_any(data.get('is_review_invited')),
                                    self._bool_from_any(data.get('is_logistics_emailed')),
                                    compensation_action,
                                    remark,
                                    item_id
                                )
                            )

                    self._registration_save_children(conn, item_id, platform_items, shipment_items, logistics_items)
                    self._perf_mark(perf_ctx, 'write_registration_and_children')

                return self.send_json({'status': 'success', 'id': item_id}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_order_registrations WHERE id=%s", (item_id,))
                self._perf_mark(perf_ctx, 'delete_registration')
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except ValueError as ve:
            return self.send_json({'status': 'error', 'message': str(ve)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        finally:
            self._perf_end(perf_ctx)

    def handle_sales_order_registration_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            wb = Workbook()
            ws = wb.active
            ws.title = 'orders'

            headers = [
                '店铺', '订单号', '订单日期', '订单状态（原运输状态）',
                '销售平台SKU', '实际发货SKU',
                '姓名', '电话(US)', '地址', '城市', '州', '邮编(US)', '跟踪号（可多条）',
                '是否已发物流邮件（是/否）', '是否邀评（是/否）', '补偿措施', '备注'
            ]
            groups = [
                ('订单基础信息', 1, 4),
                ('SKU信息', 5, 6),
                ('物流信息', 7, 13),
                ('售后状态', 14, 17),
            ]
            group_colors = [
                ('A8B9A5', 'DDE7DB'),
                ('D7C894', 'ECE5CE'),
                ('B8C3D6', 'E3E8F2'),
                ('D8B7C5', 'F0E3E8'),
            ]

            header_font = Font(bold=True, color='2A2420')
            example_font = Font(italic=True, color='7B8088')
            thin_border = Border(
                left=Side(style='thin', color='B7AEA4'),
                right=Side(style='thin', color='B7AEA4'),
                top=Side(style='thin', color='B7AEA4'),
                bottom=Side(style='thin', color='B7AEA4')
            )

            header_fill_by_col = ['DDE7DB'] * len(headers)
            for idx, (title, start_col, end_col) in enumerate(groups):
                title_color, sub_header_color = group_colors[idx % len(group_colors)]
                ws.merge_cells(start_row=1, start_column=start_col, end_row=1, end_column=end_col)
                cell = ws.cell(row=1, column=start_col, value=title)
                cell.fill = PatternFill(start_color=title_color, end_color=title_color, fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                for col in range(start_col, end_col + 1):
                    header_fill_by_col[col - 1] = sub_header_color

            for col, title in enumerate(headers, start=1):
                cell = ws.cell(row=2, column=col, value=title)
                cell.fill = PatternFill(start_color=header_fill_by_col[col - 1], end_color=header_fill_by_col[col - 1], fill_type='solid')
                cell.font = header_font
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
                cell.border = thin_border
                width = 18
                if col in (1, 2):
                    width = 16
                if col in (5, 6, 13):
                    width = 24
                if col in (9, 17):
                    width = 28
                ws.column_dimensions[get_column_letter(col)].width = width

            ws.append([
                '示例店铺', 'SO-20250101-001', '2025-01-01', 'pending',
                'MS01-Brown-1A*1|MS01-Gray-1A*1', '',
                'John Doe', '+1 415-888-9999', '123 Main St', 'Los Angeles', 'CA', '90001', 'UPS:1Z123|FedEx:999',
                '否', '是', '示例补偿', '示例备注'
            ])
            for cell in ws[3]:
                cell.fill = PatternFill(start_color='ECECEC', end_color='ECECEC', fill_type='solid')
                cell.font = example_font
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            dv_yes_no = DataValidation(type='list', formula1='"是,否"', allow_blank=True)
            ws.add_data_validation(dv_yes_no)
            for row in range(4, 1201):
                dv_yes_no.add(f'N{row}')
                dv_yes_no.add(f'O{row}')

            ws.freeze_panes = 'A4'
            return self._send_excel_workbook(wb, 'sales_order_registration_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_order_registration_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

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

            wb = load_workbook(io.BytesIO(file_bytes), data_only=True)
            ws = wb.active
            first_row = [str(x.value or '').strip() for x in ws[1]]
            module_titles = {'订单基础信息', 'SKU信息', '物流信息', '售后状态'}
            header_row_idx = 2 if any(cell in module_titles for cell in first_row) else 1
            data_start_row = 4 if header_row_idx == 2 else 2
            headers = [str(x.value or '').strip() for x in ws[header_row_idx]]
            index_map = {name: idx for idx, name in enumerate(headers) if name}

            alias_map = {
                'shop_name': ['店铺'],
                'order_no': ['订单号'],
                'order_date': ['订单日期', '下单日期(YYYY-MM-DD)'],
                'customer_name': ['姓名', '客户姓名'],
                'phone': ['电话(US)', '电话'],
                'zip_code': ['邮编(US)', '邮编'],
                'address': ['地址'],
                'city': ['城市'],
                'state': ['州'],
                'shipping_status': ['订单状态（原运输状态）', '发货状态(pending/shipped/delivered/cancelled)'],
                'is_logistics_emailed': ['是否已发物流邮件（是/否）', '是否已发物流邮件', '物流已邮件(0/1)'],
                'is_review_invited': ['是否邀评（是/否）', '是否邀评', '邀评(0/1)'],
                'compensation_action': ['补偿措施', '赔偿处理'],
                'remark': ['备注'],
                'platform_text': ['销售平台SKU', '平台SKU明细(平台SKU*数量, 用|分隔)'],
                'shipment_text': ['实际发货SKU', '发货SKU明细(下单SKU*数量, 用|分隔, 留空则自动计算)'],
                'logistics_text': ['跟踪号（可多条）', '跟踪号（原物流行，可多条）', '物流明细(承运商:单号, 用|分隔)']
            }

            def get_val(row_values, aliases, default=None):
                for key in aliases:
                    idx = index_map.get(key)
                    if idx is None or idx >= len(row_values):
                        continue
                    value = row_values[idx]
                    if value is None:
                        continue
                    if str(value).strip() == '':
                        continue
                    return value
                return default

            required_aliases = [
                ('订单号', alias_map['order_no']),
                ('销售平台SKU', alias_map['platform_text'])
            ]
            for label, aliases in required_aliases:
                if not any(alias in index_map for alias in aliases):
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {label}'}, start_response)

            def _aggregate_sku_items(parsed_items):
                qty_by_sku = {}
                sku_order = []
                for item in (parsed_items or []):
                    sku = str((item or {}).get('sku') or '').strip()
                    if not sku:
                        continue
                    qty = max(1, self._parse_int((item or {}).get('quantity')) or 1)
                    if sku not in qty_by_sku:
                        qty_by_sku[sku] = 0
                        sku_order.append(sku)
                    qty_by_sku[sku] += qty
                return [{'sku': sku, 'quantity': qty_by_sku[sku]} for sku in sku_order]

            created = 0
            updated = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, shop_name FROM shops")
                    shop_map = {str(x.get('shop_name') or '').strip(): self._parse_int(x.get('id')) for x in (cur.fetchall() or [])}

                staged_map = {}
                staged_keys = []

                for row_idx in range(data_start_row, ws.max_row + 1):
                    row_values = [cell.value for cell in ws[row_idx]]
                    if not any(v is not None and str(v).strip() for v in row_values):
                        continue
                    try:
                        shop_name = str(get_val(row_values, alias_map['shop_name']) or '').strip()
                        order_no = str(get_val(row_values, alias_map['order_no']) or '').strip()
                        if not order_no:
                            raise ValueError('订单号必填')

                        shop_id = shop_map.get(shop_name) if shop_name else None
                        order_date = self._registration_parse_date(get_val(row_values, alias_map['order_date']))
                        customer_name = str(get_val(row_values, alias_map['customer_name']) or '').strip() or None
                        phone = str(get_val(row_values, alias_map['phone']) or '').strip() or None
                        zip_code = str(get_val(row_values, alias_map['zip_code']) or '').strip() or None
                        address = str(get_val(row_values, alias_map['address']) or '').strip() or None
                        city = str(get_val(row_values, alias_map['city']) or '').strip() or None
                        state = str(get_val(row_values, alias_map['state']) or '').strip() or None
                        shipping_status = str(get_val(row_values, alias_map['shipping_status'], 'pending') or 'pending').strip() or 'pending'
                        is_review_invited = self._bool_from_any(get_val(row_values, alias_map['is_review_invited']))
                        is_logistics_emailed = self._bool_from_any(get_val(row_values, alias_map['is_logistics_emailed']))
                        compensation_action = str(get_val(row_values, alias_map['compensation_action']) or '').strip() or None
                        remark = str(get_val(row_values, alias_map['remark']) or '').strip() or None

                        self._validate_us_phone_zip(phone, zip_code)

                        platform_text = get_val(row_values, alias_map['platform_text'])
                        shipment_text = get_val(row_values, alias_map['shipment_text'])
                        logistics_text = get_val(row_values, alias_map['logistics_text'])

                        parsed_platform = self._registration_parse_item_text(platform_text)
                        if not parsed_platform:
                            raise ValueError('平台SKU明细必填')
                        parsed_shipment = self._registration_parse_item_text(shipment_text)
                        parsed_logistics = self._registration_parse_logistics_text(logistics_text)

                        group_key = (
                            shop_id or 0,
                            order_no,
                            order_date or '',
                            customer_name or '',
                            phone or '',
                            zip_code or '',
                            address or '',
                            city or '',
                            state or '',
                            shipping_status or 'pending',
                            int(is_review_invited or 0),
                            int(is_logistics_emailed or 0),
                            compensation_action or '',
                            remark or ''
                        )

                        if group_key not in staged_map:
                            staged_map[group_key] = {
                                'row': row_idx,
                                'shop_id': shop_id,
                                'order_no': order_no,
                                'order_date': order_date,
                                'customer_name': customer_name,
                                'phone': phone,
                                'zip_code': zip_code,
                                'address': address,
                                'city': city,
                                'state': state,
                                'shipping_status': shipping_status,
                                'is_review_invited': is_review_invited,
                                'is_logistics_emailed': is_logistics_emailed,
                                'compensation_action': compensation_action,
                                'remark': remark,
                                'platform_parsed': [],
                                'shipment_parsed': [],
                                'logistics_items': []
                            }
                            staged_keys.append(group_key)

                        staged_map[group_key]['platform_parsed'].extend(parsed_platform)
                        staged_map[group_key]['shipment_parsed'].extend(parsed_shipment)
                        staged_map[group_key]['logistics_items'].extend(parsed_logistics)
                    except Exception as row_error:
                        errors.append({'row': row_idx, 'error': str(row_error)})

                for key in staged_keys:
                    staged = staged_map.get(key) or {}
                    try:
                        platform_agg = _aggregate_sku_items(staged.get('platform_parsed'))
                        if not platform_agg:
                            raise ValueError('平台SKU明细必填')
                        shipment_agg = _aggregate_sku_items(staged.get('shipment_parsed'))

                        platform_items = [
                            {
                                'sales_product_id': None,
                                'platform_sku': x['sku'],
                                'quantity': x['quantity'],
                                'shipping_plan_id': None
                            }
                            for x in platform_agg
                        ]
                        shipment_items = [
                            {
                                'order_product_id': None,
                                'order_sku': x['sku'],
                                'quantity': x['quantity'],
                                'source_type': 'manual',
                                'shipping_plan_id': None
                            }
                            for x in shipment_agg
                        ]

                        logistics_items = []
                        for item in (staged.get('logistics_items') or []):
                            shipping_carrier = (item.get('shipping_carrier') or '').strip()
                            tracking_no = (item.get('tracking_no') or '').strip()
                            if not shipping_carrier and not tracking_no:
                                continue
                            logistics_items.append({
                                'shipping_carrier': shipping_carrier or None,
                                'tracking_no': tracking_no or None,
                                'sort_order': len(logistics_items) + 1
                            })

                        self._registration_fill_item_ids(conn, platform_items, shipment_items)
                        if not shipment_items:
                            shipment_items = self._resolve_registration_auto_shipments(conn, platform_items)

                        with conn.cursor() as cur:
                            if staged.get('shop_id'):
                                cur.execute(
                                    "SELECT id FROM sales_order_registrations WHERE order_no=%s AND shop_id=%s LIMIT 1",
                                    (staged.get('order_no'), staged.get('shop_id'))
                                )
                            else:
                                cur.execute(
                                    "SELECT id FROM sales_order_registrations WHERE order_no=%s AND shop_id IS NULL LIMIT 1",
                                    (staged.get('order_no'),)
                                )
                            existing = cur.fetchone() or {}
                            existing_id = self._parse_int(existing.get('id'))

                            if existing_id:
                                cur.execute(
                                    """
                                    UPDATE sales_order_registrations
                                    SET shop_id=%s, order_date=%s, customer_name=%s, phone=%s, zip_code=%s, address=%s, city=%s, state=%s,
                                        shipping_status=%s, is_review_invited=%s, is_logistics_emailed=%s, compensation_action=%s, remark=%s
                                    WHERE id=%s
                                    """,
                                    (
                                        staged.get('shop_id'), staged.get('order_date'), staged.get('customer_name'), staged.get('phone'),
                                        staged.get('zip_code'), staged.get('address'), staged.get('city'), staged.get('state'),
                                        staged.get('shipping_status'), staged.get('is_review_invited'), staged.get('is_logistics_emailed'),
                                        staged.get('compensation_action'), staged.get('remark'), existing_id
                                    )
                                )
                                registration_id = existing_id
                                updated += 1
                            else:
                                cur.execute(
                                    """
                                    INSERT INTO sales_order_registrations
                                        (shop_id, order_no, order_date, customer_name, phone, zip_code, address, city, state,
                                         shipping_status, is_review_invited, is_logistics_emailed, compensation_action, remark)
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                    """,
                                    (
                                        staged.get('shop_id'), staged.get('order_no'), staged.get('order_date'), staged.get('customer_name'),
                                        staged.get('phone'), staged.get('zip_code'), staged.get('address'), staged.get('city'), staged.get('state'),
                                        staged.get('shipping_status'), staged.get('is_review_invited'), staged.get('is_logistics_emailed'),
                                        staged.get('compensation_action'), staged.get('remark')
                                    )
                                )
                                registration_id = cur.lastrowid
                                created += 1

                        self._registration_save_children(conn, registration_id, platform_items, shipment_items, logistics_items)
                    except Exception as group_error:
                        errors.append({'row': staged.get('row') or 0, 'error': str(group_error)})

            return self.send_json({'status': 'success', 'created': created, 'updated': updated, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    # ==============================================
    # 销量预测（Sales Forecast）
    # ==============================================

    FORECAST_MODES = ('platform', 'spec', 'order')

    def _forecast_normalize_month(self, value):
        """将输入归一化为本月首日的 YYYY-MM-01 字符串。支持 YYYY-MM、YYYY-MM-DD、YYYY/MM。"""
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        candidates = ('%Y-%m', '%Y/%m', '%Y-%m-%d', '%Y/%m/%d')
        for fmt in candidates:
            try:
                dt = datetime.strptime(text, fmt)
                return dt.strftime('%Y-%m-01')
            except Exception:
                continue
        match = re.match(r'^(\d{4})\D+(\d{1,2})', text)
        if match:
            try:
                year = int(match.group(1))
                month = int(match.group(2))
                if 1 <= month <= 12:
                    return f'{year:04d}-{month:02d}-01'
            except Exception:
                pass
        return None

    def _forecast_parse_months(self, raw):
        """解析 months=YYYY-MM,YYYY-MM,... 形式参数，去重并按时间顺序排序。"""
        results = []
        seen = set()
        if raw is None:
            return results
        if isinstance(raw, (list, tuple, set)):
            tokens = []
            for item in raw:
                if item is None:
                    continue
                tokens.extend(str(item).split(','))
        else:
            tokens = str(raw).split(',')
        for token in tokens:
            month_str = self._forecast_normalize_month(token)
            if month_str and month_str not in seen:
                seen.add(month_str)
                results.append(month_str)
        results.sort()
        return results

    def _forecast_default_future_months(self, count=6):
        """默认返回从“本月”起的 count 个月（含本月）。"""
        today = datetime.now()
        months = []
        year = today.year
        month = today.month
        for _ in range(max(1, int(count or 0))):
            months.append(f'{year:04d}-{month:02d}-01')
            month += 1
            if month > 12:
                month = 1
                year += 1
        return months

    def _forecast_history_month_range(self, raw_start, raw_end, default_months=12):
        """将历史月份范围解析为 [start_month, end_month]，闭区间（每个值是月首日）。

        默认：以“上个月”作为 end，向前回溯 default_months 个月作为 start。"""
        end_month = self._forecast_normalize_month(raw_end)
        start_month = self._forecast_normalize_month(raw_start)
        if not end_month:
            today = datetime.now()
            year = today.year
            month = today.month - 1
            if month < 1:
                month = 12
                year -= 1
            end_month = f'{year:04d}-{month:02d}-01'
        if not start_month:
            try:
                end_dt = datetime.strptime(end_month, '%Y-%m-%d')
            except Exception:
                end_dt = datetime.now()
            year = end_dt.year
            month = end_dt.month - (default_months - 1)
            while month < 1:
                month += 12
                year -= 1
            start_month = f'{year:04d}-{month:02d}-01'
        if start_month > end_month:
            start_month, end_month = end_month, start_month
        return start_month, end_month

    def _forecast_iter_months(self, start_month, end_month):
        if not start_month or not end_month:
            return []
        try:
            sd = datetime.strptime(start_month, '%Y-%m-%d')
            ed = datetime.strptime(end_month, '%Y-%m-%d')
        except Exception:
            return []
        months = []
        y, m = sd.year, sd.month
        while True:
            current = f'{y:04d}-{m:02d}-01'
            months.append(current)
            if y > ed.year or (y == ed.year and m >= ed.month):
                break
            m += 1
            if m > 12:
                m = 1
                y += 1
        return months

    def _forecast_format_dt(self, value):
        if value is None:
            return None
        if hasattr(value, 'strftime'):
            try:
                return value.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                return str(value)
        return str(value)

    def _forecast_month_to_str(self, value, fallback=None):
        if hasattr(value, 'strftime'):
            try:
                return value.strftime('%Y-%m-01')
            except Exception:
                pass
        if value:
            text = str(value)[:7]
            if len(text) == 7:
                return text + '-01'
        return fallback

    def _forecast_normalize_mode(self, raw):
        text = str(raw or '').strip().lower()
        if text in self.FORECAST_MODES:
            return text
        if text in ('platform_sku', 'platformsku', 'sku'):
            return 'platform'
        if text in ('spec_fabric', 'specfabric', 'variant'):
            return 'spec'
        if text in ('order_sku', 'ordersku', 'order_product'):
            return 'order'
        return 'spec'

    def _forecast_load_variants(self, conn, query_params=None):
        """加载预测页所需的规格列表（含货号/规格/面料/关联下单SKU）。"""
        sku_keyword = ''
        spec_keyword = ''
        fabric_keyword = ''
        if query_params:
            sku_keyword = (query_params.get('sku', [''])[0] or '').strip()
            spec_keyword = (query_params.get('spec', [''])[0] or '').strip()
            fabric_keyword = (query_params.get('fabric', [''])[0] or '').strip()

        clauses = ["1=1"]
        params = []
        if sku_keyword:
            clauses.append("pf.sku_family LIKE %s")
            params.append(f"%{sku_keyword}%")
        if spec_keyword:
            clauses.append("v.spec_name LIKE %s")
            params.append(f"%{spec_keyword}%")
        if fabric_keyword:
            clauses.append("(fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s)")
            params.append(f"%{fabric_keyword}%")
            params.append(f"%{fabric_keyword}%")

        where_sql = ' AND '.join(clauses)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT v.id AS variant_id,
                       v.sku_family_id,
                       v.spec_name,
                       v.fabric_id,
                       pf.sku_family,
                       fm.fabric_code,
                       fm.fabric_name_en,
                       fm.representative_color
                FROM sales_product_variants v
                LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id
                WHERE {where_sql}
                ORDER BY pf.sku_family ASC, v.spec_name ASC, v.id ASC
                """,
                tuple(params)
            )
            variants = cur.fetchall() or []

            variant_ids = [self._parse_int(v.get('variant_id')) for v in variants if self._parse_int(v.get('variant_id'))]
            order_links_by_variant = {}
            order_products_map = {}
            if variant_ids:
                placeholders = ','.join(['%s'] * len(variant_ids))
                cur.execute(
                    f"""
                    SELECT l.variant_id, l.order_product_id, l.quantity,
                           op.sku, op.spec_qty_short, op.contents_desc_en, op.is_on_market
                    FROM sales_variant_order_links l
                    JOIN order_products op ON op.id = l.order_product_id
                    WHERE l.variant_id IN ({placeholders})
                    ORDER BY l.variant_id ASC, op.sku ASC
                    """,
                    tuple(variant_ids)
                )
                for row in (cur.fetchall() or []):
                    vid = self._parse_int(row.get('variant_id'))
                    op_id = self._parse_int(row.get('order_product_id'))
                    qty = max(1, self._parse_int(row.get('quantity')) or 1)
                    if not vid or not op_id:
                        continue
                    order_links_by_variant.setdefault(vid, []).append({
                        'order_product_id': op_id,
                        'quantity': qty,
                        'sku': row.get('sku') or '',
                    })
                    order_products_map[op_id] = {
                        'order_product_id': op_id,
                        'sku': row.get('sku') or '',
                        'spec_qty_short': row.get('spec_qty_short') or '',
                        'contents_desc_en': row.get('contents_desc_en') or '',
                        'is_on_market': self._parse_int(row.get('is_on_market')) or 0,
                    }

        for v in variants:
            vid = self._parse_int(v.get('variant_id'))
            v['order_links'] = order_links_by_variant.get(vid, [])
        return variants, order_products_map

    def _forecast_history_end_exclusive(self, end_month):
        try:
            ed_dt = datetime.strptime(end_month, '%Y-%m-%d')
            year = ed_dt.year
            month = ed_dt.month + 1
            if month > 12:
                month = 1
                year += 1
            return f'{year:04d}-{month:02d}-01'
        except Exception:
            return None

    def _forecast_load_platform_sku_dim(self, conn, query_params=None):
        """加载平台SKU维度行：sales_products + variant + family + fabric + 在售标识。"""
        sku_keyword = ''
        spec_keyword = ''
        fabric_keyword = ''
        if query_params:
            sku_keyword = (query_params.get('sku', [''])[0] or '').strip()
            spec_keyword = (query_params.get('spec', [''])[0] or '').strip()
            fabric_keyword = (query_params.get('fabric', [''])[0] or '').strip()

        clauses = ["1=1"]
        params = []
        if sku_keyword:
            clauses.append("(sp.platform_sku LIKE %s OR pf.sku_family LIKE %s)")
            like_val = f"%{sku_keyword}%"
            params.extend([like_val, like_val])
        if spec_keyword:
            clauses.append("v.spec_name LIKE %s")
            params.append(f"%{spec_keyword}%")
        if fabric_keyword:
            clauses.append("(fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s)")
            like_val = f"%{fabric_keyword}%"
            params.extend([like_val, like_val])

        where_sql = ' AND '.join(clauses)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sp.id AS sales_product_id,
                       sp.platform_sku,
                       sp.product_status,
                       sp.shop_id,
                       sh.shop_name,
                       sh.platform_type_id,
                       v.id AS variant_id,
                       v.sku_family_id,
                       v.spec_name,
                       v.fabric_id,
                       pf.sku_family,
                       fm.fabric_code,
                       fm.fabric_name_en,
                       fm.representative_color
                FROM sales_products sp
                JOIN sales_product_variants v ON v.id = sp.variant_id
                LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id
                LEFT JOIN shops sh ON sh.id = sp.shop_id
                WHERE {where_sql}
                ORDER BY pf.sku_family ASC, v.spec_name ASC, sp.platform_sku ASC, sp.id ASC
                """,
                tuple(params)
            )
            return [dict(row) for row in (cur.fetchall() or [])]

    def _forecast_load_variant_dim(self, conn, query_params=None):
        """加载规格+面料 维度行（variant 行）。"""
        sku_keyword = ''
        spec_keyword = ''
        fabric_keyword = ''
        if query_params:
            sku_keyword = (query_params.get('sku', [''])[0] or '').strip()
            spec_keyword = (query_params.get('spec', [''])[0] or '').strip()
            fabric_keyword = (query_params.get('fabric', [''])[0] or '').strip()

        clauses = ["1=1"]
        params = []
        if sku_keyword:
            clauses.append("pf.sku_family LIKE %s")
            params.append(f"%{sku_keyword}%")
        if spec_keyword:
            clauses.append("v.spec_name LIKE %s")
            params.append(f"%{spec_keyword}%")
        if fabric_keyword:
            clauses.append("(fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s)")
            like_val = f"%{fabric_keyword}%"
            params.extend([like_val, like_val])

        where_sql = ' AND '.join(clauses)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT v.id AS variant_id,
                       v.sku_family_id,
                       v.spec_name,
                       v.fabric_id,
                       pf.sku_family,
                       fm.fabric_code,
                       fm.fabric_name_en,
                       fm.representative_color
                FROM sales_product_variants v
                LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                LEFT JOIN fabric_materials fm ON fm.id = v.fabric_id
                WHERE {where_sql}
                ORDER BY pf.sku_family ASC, v.spec_name ASC, v.id ASC
                """,
                tuple(params)
            )
            return [dict(row) for row in (cur.fetchall() or [])]

    def _forecast_load_variant_platform_skus(self, conn, variant_ids):
        """variant_id -> [{sales_product_id, platform_sku, shop_name}]"""
        out = {}
        if not variant_ids:
            return out
        placeholders = ','.join(['%s'] * len(variant_ids))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sp.id AS sales_product_id,
                       sp.platform_sku,
                       sp.variant_id,
                       sh.shop_name
                FROM sales_products sp
                LEFT JOIN shops sh ON sh.id = sp.shop_id
                WHERE sp.variant_id IN ({placeholders})
                ORDER BY sp.platform_sku ASC, sp.id ASC
                """,
                tuple(variant_ids)
            )
            for row in (cur.fetchall() or []):
                vid = self._parse_int(row.get('variant_id'))
                if not vid:
                    continue
                out.setdefault(vid, []).append({
                    'sales_product_id': self._parse_int(row.get('sales_product_id')),
                    'platform_sku': row.get('platform_sku') or '',
                    'shop_name': row.get('shop_name') or '',
                })
        return out

    def _forecast_load_order_dim(self, conn, query_params=None):
        """加载下单SKU 维度行 + 关联 variant/规格信息。"""
        sku_keyword = ''
        spec_keyword = ''
        fabric_keyword = ''
        if query_params:
            sku_keyword = (query_params.get('sku', [''])[0] or '').strip()
            spec_keyword = (query_params.get('spec', [''])[0] or '').strip()
            fabric_keyword = (query_params.get('fabric', [''])[0] or '').strip()

        clauses = ["1=1"]
        params = []
        if sku_keyword:
            clauses.append("(op.sku LIKE %s OR pf.sku_family LIKE %s)")
            like_val = f"%{sku_keyword}%"
            params.extend([like_val, like_val])
        if spec_keyword:
            clauses.append("op.spec_qty_short LIKE %s")
            params.append(f"%{spec_keyword}%")
        if fabric_keyword:
            clauses.append("(fm.fabric_code LIKE %s OR fm.fabric_name_en LIKE %s)")
            like_val = f"%{fabric_keyword}%"
            params.extend([like_val, like_val])

        where_sql = ' AND '.join(clauses)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT op.id AS order_product_id,
                       op.sku,
                       op.sku_family_id,
                       op.spec_qty_short,
                       op.contents_desc_en,
                       op.is_on_market,
                       op.is_iteration,
                       op.fabric_id,
                       pf.sku_family,
                       fm.fabric_code,
                       fm.fabric_name_en,
                       fm.representative_color
                FROM order_products op
                LEFT JOIN product_families pf ON pf.id = op.sku_family_id
                LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                WHERE {where_sql}
                  AND COALESCE(op.is_reship_accessory, 0) = 0
                ORDER BY pf.sku_family ASC, op.sku ASC, op.id ASC
                """,
                tuple(params)
            )
            rows = [dict(row) for row in (cur.fetchall() or [])]

            order_ids = [self._parse_int(r.get('order_product_id')) for r in rows if self._parse_int(r.get('order_product_id'))]
            links_by_op = {}
            if order_ids:
                placeholders = ','.join(['%s'] * len(order_ids))
                cur.execute(
                    f"""
                    SELECT l.order_product_id,
                           l.variant_id,
                           l.quantity,
                           v.spec_name,
                           pf.sku_family
                    FROM sales_variant_order_links l
                    LEFT JOIN sales_product_variants v ON v.id = l.variant_id
                    LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                    WHERE l.order_product_id IN ({placeholders})
                    """,
                    tuple(order_ids)
                )
                for link in (cur.fetchall() or []):
                    op_id = self._parse_int(link.get('order_product_id'))
                    vid = self._parse_int(link.get('variant_id'))
                    if not op_id or not vid:
                        continue
                    links_by_op.setdefault(op_id, []).append({
                        'variant_id': vid,
                        'quantity': max(1, self._parse_int(link.get('quantity')) or 1),
                        'spec_name': link.get('spec_name') or '',
                        'sku_family': link.get('sku_family') or '',
                    })
        for r in rows:
            op_id = self._parse_int(r.get('order_product_id'))
            r['variant_links'] = links_by_op.get(op_id, [])
        return rows

    def _forecast_load_variant_thumb_b64(self, conn, variant_ids):
        """variant_id -> 预览图 b64（优先白底纯图，其次白底图，再次任意图）"""
        out = {}
        ids = [self._parse_int(x) for x in (variant_ids or []) if self._parse_int(x)]
        if not ids:
            return out
        placeholders = ','.join(['%s'] * len(ids))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sim.variant_id,
                       ia.storage_path,
                       sim.sort_order,
                       sim.id AS sim_id,
                       COALESCE(it_ia.name, '') AS image_type_name
                FROM sales_variant_image_mappings sim
                JOIN image_assets ia ON ia.id = sim.image_asset_id
                LEFT JOIN image_types it_ia ON it_ia.id = ia.image_type_id
                WHERE sim.variant_id IN ({placeholders})
                ORDER BY sim.variant_id ASC, sim.sort_order ASC, sim.id ASC
                """,
                tuple(ids)
            )
            rows = cur.fetchall() or []

        best = {}
        for row in rows:
            vid = self._parse_int(row.get('variant_id'))
            if not vid:
                continue
            storage_path = str(row.get('storage_path') or '').strip()
            if not storage_path:
                continue
            tname = str(row.get('image_type_name') or '').strip()
            if tname == '白底纯图':
                score = 0
            elif tname == '白底图':
                score = 1
            else:
                score = 2
            sort_order = self._parse_int(row.get('sort_order')) or 0
            sim_id = self._parse_int(row.get('sim_id')) or 0
            key = (score, sort_order, sim_id)
            if vid not in best or key < best[vid][0]:
                b64 = self._b64_from_fs(storage_path.replace('\\', '/').lstrip('/'))
                best[vid] = (key, b64)

        for vid, pair in best.items():
            out[vid] = pair[1]
        return out

    def _forecast_load_platform_cells(self, conn, sales_product_ids, months):
        if not sales_product_ids or not months:
            return {}
        placeholders_p = ','.join(['%s'] * len(sales_product_ids))
        placeholders_m = ','.join(['%s'] * len(months))
        params = list(sales_product_ids) + list(months)
        out = {}
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, sales_product_id, forecast_month,
                       initial_qty, prev_qty, latest_qty,
                       created_at, prev_updated_at, latest_updated_at
                FROM sales_forecast_platform_sku_monthly
                WHERE sales_product_id IN ({placeholders_p})
                  AND forecast_month IN ({placeholders_m})
                """,
                tuple(params)
            )
            for row in (cur.fetchall() or []):
                spid = self._parse_int(row.get('sales_product_id'))
                month_str = self._forecast_month_to_str(row.get('forecast_month'))
                if not spid or not month_str:
                    continue
                out[(spid, month_str)] = self._forecast_serialize_cell(row, month_str, extra_keys={'sales_product_id': spid})
        return out

    def _forecast_load_spec_cells(self, conn, variant_ids, months):
        if not variant_ids or not months:
            return {}
        placeholders_v = ','.join(['%s'] * len(variant_ids))
        placeholders_m = ','.join(['%s'] * len(months))
        params = list(variant_ids) + list(months)
        out = {}
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, variant_id, forecast_month,
                       initial_qty, prev_qty, latest_qty,
                       created_at, prev_updated_at, latest_updated_at
                FROM sales_forecast_spec_monthly
                WHERE variant_id IN ({placeholders_v})
                  AND forecast_month IN ({placeholders_m})
                """,
                tuple(params)
            )
            for row in (cur.fetchall() or []):
                vid = self._parse_int(row.get('variant_id'))
                month_str = self._forecast_month_to_str(row.get('forecast_month'))
                if not vid or not month_str:
                    continue
                out[(vid, month_str)] = self._forecast_serialize_cell(row, month_str, extra_keys={'variant_id': vid})
        return out

    def _forecast_load_order_cells(self, conn, order_product_ids, months):
        if not order_product_ids or not months:
            return {}
        placeholders_o = ','.join(['%s'] * len(order_product_ids))
        placeholders_m = ','.join(['%s'] * len(months))
        params = list(order_product_ids) + list(months)
        out = {}
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, order_product_id, forecast_month,
                       initial_qty, prev_qty, latest_qty,
                       created_at, prev_updated_at, latest_updated_at
                FROM sales_forecast_order_sku_monthly
                WHERE order_product_id IN ({placeholders_o})
                  AND forecast_month IN ({placeholders_m})
                """,
                tuple(params)
            )
            for row in (cur.fetchall() or []):
                op_id = self._parse_int(row.get('order_product_id'))
                month_str = self._forecast_month_to_str(row.get('forecast_month'))
                if not op_id or not month_str:
                    continue
                out[(op_id, month_str)] = self._forecast_serialize_cell(row, month_str, extra_keys={'order_product_id': op_id})
        return out

    def _forecast_serialize_cell(self, row, month_str, extra_keys=None):
        payload = {
            'id': self._parse_int(row.get('id')),
            'forecast_month': month_str,
            'initial_qty': self._parse_int(row.get('initial_qty')) or 0,
            'prev_qty': None if row.get('prev_qty') is None else self._parse_int(row.get('prev_qty')),
            'latest_qty': self._parse_int(row.get('latest_qty')) or 0,
            'created_at': self._forecast_format_dt(row.get('created_at')),
            'prev_updated_at': self._forecast_format_dt(row.get('prev_updated_at')),
            'latest_updated_at': self._forecast_format_dt(row.get('latest_updated_at')),
        }
        if extra_keys:
            payload.update(extra_keys)
        return payload

    def _forecast_load_history_by_sales_product(self, conn, sales_product_ids, start_month, end_month):
        out = {}
        if not sales_product_ids or not start_month or not end_month:
            return out
        end_exclusive = self._forecast_history_end_exclusive(end_month)
        if not end_exclusive:
            return out
        placeholders = ','.join(['%s'] * len(sales_product_ids))
        params = list(sales_product_ids) + [start_month, end_exclusive]
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sales_product_id, month_start,
                       sales_qty, net_sales_amount, order_qty, session_total, refund_amount
                FROM sales_perf_agg_month
                WHERE sales_product_id IN ({placeholders})
                  AND month_start >= %s
                  AND month_start < %s
                """,
                tuple(params)
            )
            for row in (cur.fetchall() or []):
                spid = self._parse_int(row.get('sales_product_id'))
                month_str = self._forecast_month_to_str(row.get('month_start'))
                if not spid or not month_str:
                    continue
                out[(spid, month_str)] = {
                    'sales_product_id': spid,
                    'month_start': month_str,
                    'sales_qty': float(row.get('sales_qty') or 0),
                    'net_sales_amount': float(row.get('net_sales_amount') or 0),
                    'order_qty': float(row.get('order_qty') or 0),
                    'session_total': float(row.get('session_total') or 0),
                    'refund_amount': float(row.get('refund_amount') or 0),
                }
        return out

    def _forecast_load_history_by_variant(self, conn, variant_ids, start_month, end_month):
        out = {}
        if not variant_ids or not start_month or not end_month:
            return out
        end_exclusive = self._forecast_history_end_exclusive(end_month)
        if not end_exclusive:
            return out
        placeholders = ','.join(['%s'] * len(variant_ids))
        params = list(variant_ids) + [start_month, end_exclusive]
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sp.variant_id AS variant_id,
                       m.month_start AS month_start,
                       SUM(COALESCE(m.sales_qty, 0)) AS sales_qty,
                       SUM(COALESCE(m.net_sales_amount, 0)) AS net_sales_amount,
                       SUM(COALESCE(m.order_qty, 0)) AS order_qty,
                       SUM(COALESCE(m.session_total, 0)) AS session_total,
                       SUM(COALESCE(m.refund_amount, 0)) AS refund_amount
                FROM sales_perf_agg_month m
                JOIN sales_products sp ON sp.id = m.sales_product_id
                WHERE sp.variant_id IN ({placeholders})
                  AND m.month_start >= %s
                  AND m.month_start < %s
                GROUP BY sp.variant_id, m.month_start
                """,
                tuple(params)
            )
            for row in (cur.fetchall() or []):
                vid = self._parse_int(row.get('variant_id'))
                month_str = self._forecast_month_to_str(row.get('month_start'))
                if not vid or not month_str:
                    continue
                out[(vid, month_str)] = {
                    'variant_id': vid,
                    'month_start': month_str,
                    'sales_qty': float(row.get('sales_qty') or 0),
                    'net_sales_amount': float(row.get('net_sales_amount') or 0),
                    'order_qty': float(row.get('order_qty') or 0),
                    'session_total': float(row.get('session_total') or 0),
                    'refund_amount': float(row.get('refund_amount') or 0),
                }
        return out

    def handle_sales_forecast_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            forecast_mode = self._forecast_normalize_mode((query_params.get('forecast_mode', [''])[0] or ''))

            months_raw = query_params.get('months') or []
            months = self._forecast_parse_months(months_raw)
            if not months:
                months = self._forecast_default_future_months(6)

            hist_start_raw = (query_params.get('history_start', [''])[0] or '').strip()
            hist_end_raw = (query_params.get('history_end', [''])[0] or '').strip()
            hist_start, hist_end = self._forecast_history_month_range(hist_start_raw, hist_end_raw, default_months=12)
            history_months = self._forecast_iter_months(hist_start, hist_end)

            with self._get_db_connection() as conn:
                if forecast_mode == 'platform':
                    rows = self._forecast_build_platform_rows(conn, query_params, months, hist_start, hist_end)
                elif forecast_mode == 'order':
                    rows = self._forecast_build_order_rows(conn, query_params, months, hist_start, hist_end)
                else:
                    rows = self._forecast_build_spec_rows(conn, query_params, months, hist_start, hist_end)

            return self.send_json({
                'status': 'success',
                'forecast_mode': forecast_mode,
                'months': months,
                'history_months': history_months,
                'history_range': {'start': hist_start, 'end': hist_end},
                'rows': rows,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    # ----- 三种模式的行装配 -----

    def _forecast_build_platform_rows(self, conn, query_params, months, hist_start, hist_end):
        dim_rows = self._forecast_load_platform_sku_dim(conn, query_params)
        sales_product_ids = [self._parse_int(r.get('sales_product_id')) for r in dim_rows if self._parse_int(r.get('sales_product_id'))]
        variant_ids = [self._parse_int(r.get('variant_id')) for r in dim_rows if self._parse_int(r.get('variant_id'))]
        thumb_by_variant = self._forecast_load_variant_thumb_b64(conn, variant_ids)
        cells = self._forecast_load_platform_cells(conn, sales_product_ids, months)
        history = self._forecast_load_history_by_sales_product(conn, sales_product_ids, hist_start, hist_end)

        out = []
        for r in dim_rows:
            spid = self._parse_int(r.get('sales_product_id'))
            if not spid:
                continue
            row = {
                'row_key': str(spid),
                'forecast_mode': 'platform',
                'labels': {
                    'sales_product_id': spid,
                    'variant_id': self._parse_int(r.get('variant_id')),
                    'platform_sku': r.get('platform_sku') or '',
                    'shop_name': r.get('shop_name') or '',
                    'sku_family': r.get('sku_family') or '',
                    'spec_name': r.get('spec_name') or '',
                    'fabric_code': r.get('fabric_code') or '',
                    'fabric_name_en': r.get('fabric_name_en') or '',
                    'representative_color': r.get('representative_color') or '',
                    'variant_thumb_b64': thumb_by_variant.get(self._parse_int(r.get('variant_id')) or 0, ''),
                    'product_status': r.get('product_status') or '',
                },
                'history': {},
                'forecasts': {},
            }
            for m in months:
                cell = cells.get((spid, m))
                stored_qty = cell.get('latest_qty') if cell else None
                value_qty = stored_qty or 0
                row['forecasts'][m] = {
                    'stored_qty': stored_qty,
                    'value_qty': value_qty,
                    'is_inherited': False,
                    'source': None,
                    'cell_meta': cell,
                }
            for hm in self._forecast_iter_months(hist_start, hist_end):
                h = history.get((spid, hm))
                row['history'][hm] = h or {'sales_qty': 0, 'net_sales_amount': 0, 'order_qty': 0, 'session_total': 0, 'refund_amount': 0}
            out.append(row)
        return out

    def _forecast_build_spec_rows(self, conn, query_params, months, hist_start, hist_end):
        dim_rows = self._forecast_load_variant_dim(conn, query_params)
        variant_ids = [self._parse_int(r.get('variant_id')) for r in dim_rows if self._parse_int(r.get('variant_id'))]
        thumb_by_variant = self._forecast_load_variant_thumb_b64(conn, variant_ids)
        spec_cells = self._forecast_load_spec_cells(conn, variant_ids, months)
        history = self._forecast_load_history_by_variant(conn, variant_ids, hist_start, hist_end)

        platforms_by_variant = self._forecast_load_variant_platform_skus(conn, variant_ids)
        all_sp_ids = sorted({
            sp.get('sales_product_id')
            for ps in platforms_by_variant.values()
            for sp in ps
            if sp.get('sales_product_id')
        })
        platform_cells = self._forecast_load_platform_cells(conn, all_sp_ids, months)

        out = []
        for r in dim_rows:
            vid = self._parse_int(r.get('variant_id'))
            if not vid:
                continue
            platform_skus = platforms_by_variant.get(vid, [])
            row = {
                'row_key': str(vid),
                'forecast_mode': 'spec',
                'labels': {
                    'variant_id': vid,
                    'sku_family': r.get('sku_family') or '',
                    'spec_name': r.get('spec_name') or '',
                    'fabric_code': r.get('fabric_code') or '',
                    'fabric_name_en': r.get('fabric_name_en') or '',
                    'representative_color': r.get('representative_color') or '',
                    'variant_thumb_b64': thumb_by_variant.get(vid, ''),
                    'platform_skus': platform_skus,
                },
                'history': {},
                'forecasts': {},
            }
            for m in months:
                cell = spec_cells.get((vid, m))
                stored_qty = cell.get('latest_qty') if cell else None

                inherited_items = []
                inherited_total = 0
                for ps in platform_skus:
                    spid = ps.get('sales_product_id')
                    if not spid:
                        continue
                    pc = platform_cells.get((spid, m))
                    pq = pc.get('latest_qty') if pc else 0
                    if pq:
                        inherited_items.append({
                            'id': spid,
                            'label': ps.get('platform_sku') or f'SP#{spid}',
                            'qty': pq,
                        })
                        inherited_total += pq

                if stored_qty is None and inherited_total > 0:
                    row['forecasts'][m] = {
                        'stored_qty': None,
                        'value_qty': inherited_total,
                        'is_inherited': True,
                        'source': {
                            'type': 'platform_sku',
                            'items': inherited_items,
                            'total_qty': inherited_total,
                        },
                        'cell_meta': None,
                    }
                else:
                    row['forecasts'][m] = {
                        'stored_qty': stored_qty,
                        'value_qty': stored_qty or 0,
                        'is_inherited': False,
                        'source': {
                            'type': 'platform_sku',
                            'items': inherited_items,
                            'total_qty': inherited_total,
                        } if inherited_items else None,
                        'cell_meta': cell,
                    }
            for hm in self._forecast_iter_months(hist_start, hist_end):
                h = history.get((vid, hm))
                row['history'][hm] = h or {'sales_qty': 0, 'net_sales_amount': 0, 'order_qty': 0, 'session_total': 0, 'refund_amount': 0}
            out.append(row)
        return out

    def _forecast_build_order_rows(self, conn, query_params, months, hist_start, hist_end):
        dim_rows = self._forecast_load_order_dim(conn, query_params)
        order_ids = [self._parse_int(r.get('order_product_id')) for r in dim_rows if self._parse_int(r.get('order_product_id'))]
        order_cells = self._forecast_load_order_cells(conn, order_ids, months)

        # spec 预测的覆盖（包含继承自 platform 的逻辑），用于推导默认值
        all_variant_ids = sorted({
            vl.get('variant_id')
            for r in dim_rows
            for vl in (r.get('variant_links') or [])
            if vl.get('variant_id')
        })
        spec_cells = self._forecast_load_spec_cells(conn, all_variant_ids, months)
        platforms_by_variant = self._forecast_load_variant_platform_skus(conn, all_variant_ids)
        all_sp_ids = sorted({
            sp.get('sales_product_id')
            for ps in platforms_by_variant.values()
            for sp in ps
            if sp.get('sales_product_id')
        })
        platform_cells = self._forecast_load_platform_cells(conn, all_sp_ids, months)

        def spec_effective_qty(vid, month):
            cell = spec_cells.get((vid, month))
            if cell:
                return cell.get('latest_qty') or 0
            total = 0
            for ps in platforms_by_variant.get(vid, []):
                spid = ps.get('sales_product_id')
                pc = platform_cells.get((spid, month)) if spid else None
                total += (pc.get('latest_qty') or 0) if pc else 0
            return total

        out = []
        for r in dim_rows:
            op_id = self._parse_int(r.get('order_product_id'))
            if not op_id:
                continue
            links = r.get('variant_links') or []
            row = {
                'row_key': str(op_id),
                'forecast_mode': 'order',
                'labels': {
                    'order_product_id': op_id,
                    'sku': r.get('sku') or '',
                    'sku_family': r.get('sku_family') or '',
                    'spec_qty_short': r.get('spec_qty_short') or '',
                    'contents_desc_en': r.get('contents_desc_en') or '',
                    'fabric_code': r.get('fabric_code') or '',
                    'fabric_name_en': r.get('fabric_name_en') or '',
                    'representative_color': r.get('representative_color') or '',
                    'is_on_market': self._parse_int(r.get('is_on_market')) or 0,
                    'variant_links': [
                        {
                            'variant_id': vl.get('variant_id'),
                            'sku_family': vl.get('sku_family'),
                            'spec_name': vl.get('spec_name'),
                            'quantity': vl.get('quantity'),
                        }
                        for vl in links
                    ],
                },
                'history': {},
                'forecasts': {},
            }
            for m in months:
                cell = order_cells.get((op_id, m))
                stored_qty = cell.get('latest_qty') if cell else None

                inherited_items = []
                inherited_total = 0
                for vl in links:
                    vid = vl.get('variant_id')
                    qty_per = max(1, vl.get('quantity') or 1)
                    spec_qty = spec_effective_qty(vid, m)
                    if spec_qty:
                        sub = spec_qty * qty_per
                        inherited_items.append({
                            'id': vid,
                            'label': f"{vl.get('sku_family') or ''} {vl.get('spec_name') or ''}".strip() or f'V#{vid}',
                            'qty': sub,
                            'spec_qty': spec_qty,
                            'ratio': qty_per,
                        })
                        inherited_total += sub

                if stored_qty is None and inherited_total > 0:
                    row['forecasts'][m] = {
                        'stored_qty': None,
                        'value_qty': inherited_total,
                        'is_inherited': True,
                        'source': {
                            'type': 'spec',
                            'items': inherited_items,
                            'total_qty': inherited_total,
                        },
                        'cell_meta': None,
                    }
                else:
                    row['forecasts'][m] = {
                        'stored_qty': stored_qty,
                        'value_qty': stored_qty or 0,
                        'is_inherited': False,
                        'source': {
                            'type': 'spec',
                            'items': inherited_items,
                            'total_qty': inherited_total,
                        } if inherited_items else None,
                        'cell_meta': cell,
                    }
            # 下单SKU 没有自身的销售历史记录；保留空 dict 以保持结构
            for hm in self._forecast_iter_months(hist_start, hist_end):
                row['history'][hm] = {'sales_qty': 0, 'net_sales_amount': 0, 'order_qty': 0, 'session_total': 0, 'refund_amount': 0}
            out.append(row)
        return out

    def _forecast_upsert_cell(self, cur, table, key_cols, key_values, latest_qty):
        """通用 upsert：先 SELECT 看有无记录，再 UPDATE/INSERT。"""
        where_sql = ' AND '.join([f"{c}=%s" for c in key_cols])
        cur.execute(
            f"SELECT id, latest_qty, latest_updated_at FROM {table} WHERE {where_sql} LIMIT 1",
            tuple(key_values)
        )
        row = cur.fetchone() or None
        if row:
            cur.execute(
                f"""
                UPDATE {table}
                SET prev_qty = latest_qty,
                    prev_updated_at = latest_updated_at,
                    latest_qty = %s,
                    latest_updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (latest_qty, self._parse_int(row.get('id')))
            )
            return self._parse_int(row.get('id')), False
        col_list = ','.join(key_cols + ['initial_qty', 'prev_qty', 'latest_qty', 'created_at', 'prev_updated_at', 'latest_updated_at'])
        placeholder_count = len(key_cols)
        placeholders = ','.join(['%s'] * placeholder_count) + ', %s, NULL, %s, CURRENT_TIMESTAMP, NULL, CURRENT_TIMESTAMP'
        cur.execute(
            f"INSERT INTO {table} ({col_list}) VALUES ({placeholders})",
            tuple(list(key_values) + [latest_qty, latest_qty])
        )
        return cur.lastrowid, True

    def _forecast_select_cell(self, cur, table, key_cols, key_values):
        where_sql = ' AND '.join([f"{c}=%s" for c in key_cols])
        select_cols = ['id'] + [c for c in key_cols if c != 'forecast_month'] + [
            'forecast_month', 'initial_qty', 'prev_qty', 'latest_qty',
            'created_at', 'prev_updated_at', 'latest_updated_at'
        ]
        cur.execute(
            f"SELECT {','.join(select_cols)} FROM {table} WHERE {where_sql} LIMIT 1",
            tuple(key_values)
        )
        return cur.fetchone() or None

    def handle_sales_forecast_bulk_update_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            data = self._read_json_body(environ) or {}
            forecast_mode = self._forecast_normalize_mode(data.get('forecast_mode') if isinstance(data, dict) else None)
            cells = data.get('cells') if isinstance(data, dict) else None

            parsed = []
            for item in (cells or []):
                if not isinstance(item, dict):
                    continue
                row_key = self._parse_int(item.get('row_key'))
                month_str = self._forecast_normalize_month(item.get('forecast_month'))
                latest_qty = self._parse_int(item.get('latest_qty'))
                if not row_key or not month_str:
                    continue
                if latest_qty is None:
                    latest_qty = 0
                parsed.append({
                    'row_key': row_key,
                    'forecast_month': month_str,
                    'latest_qty': max(0, latest_qty),
                })

            if not parsed:
                return self.send_json({'status': 'error', 'message': '没有有效的更新数据'}, start_response)

            if forecast_mode == 'platform':
                table = 'sales_forecast_platform_sku_monthly'
                key_cols = ['sales_product_id', 'forecast_month']
            elif forecast_mode == 'order':
                table = 'sales_forecast_order_sku_monthly'
                key_cols = ['order_product_id', 'forecast_month']
            else:
                forecast_mode = 'spec'
                table = 'sales_forecast_spec_monthly'
                key_cols = ['variant_id', 'forecast_month']

            saved_keys = []
            with self._get_db_connection() as conn:
                try:
                    with conn.cursor() as cur:
                        for cell in parsed:
                            self._forecast_upsert_cell(
                                cur, table, key_cols,
                                (cell['row_key'], cell['forecast_month']),
                                cell['latest_qty']
                            )
                            saved_keys.append((cell['row_key'], cell['forecast_month']))
                    conn.commit()
                except Exception as inner:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    return self.send_json({'status': 'error', 'message': str(inner)}, start_response)

                refreshed = []
                with conn.cursor() as cur:
                    for row_key, month_str in saved_keys:
                        row = self._forecast_select_cell(cur, table, key_cols, (row_key, month_str))
                        if not row:
                            continue
                        month_str_out = self._forecast_month_to_str(row.get('forecast_month'), fallback=month_str)
                        refreshed.append({
                            'row_key': str(row_key),
                            'forecast_month': month_str_out,
                            'cell_meta': self._forecast_serialize_cell(row, month_str_out, extra_keys={
                                key_cols[0]: row_key,
                            }),
                        })

            return self.send_json({
                'status': 'success',
                'forecast_mode': forecast_mode,
                'cells': refreshed,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
