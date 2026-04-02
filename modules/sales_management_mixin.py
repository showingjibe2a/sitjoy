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
                    SELECT op.id AS order_product_id, op.sku, spol.quantity
                    FROM sales_product_order_links spol
                    JOIN order_products op ON op.id = spol.order_product_id
                    WHERE spol.sales_product_id=%s
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
                                cur.execute("SELECT id, sku FROM order_products ORDER BY sku ASC LIMIT %s", (limit,))
                                payload['order_products'] = cur.fetchall() or []
                                try:
                                    cur.execute(
                                        """
                                        SELECT ops.id, op.sku AS order_sku, ops.plan_name
                                        FROM order_product_shipping_plans ops
                                        JOIN order_products op ON op.id = ops.order_product_id
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
            from openpyxl.utils import get_column_letter

            wb = Workbook()
            ws = wb.active
            ws.title = 'orders'

            headers = [
                '店铺', '订单号', '订单日期', '订单状态（原运输状态）',
                '销售平台SKU', '实际发货SKU',
                '姓名', '电话(US)', '地址', '城市', '州', '邮编(US)', '跟踪号（可多条）',
                '是否已发物流邮件', '是否邀评', '补偿措施', '备注'
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
                '0', '1', '示例补偿', '示例备注'
            ])
            for cell in ws[3]:
                cell.fill = PatternFill(start_color='ECECEC', end_color='ECECEC', fill_type='solid')
                cell.font = example_font
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

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
                'is_logistics_emailed': ['是否已发物流邮件', '物流已邮件(0/1)'],
                'is_review_invited': ['是否邀评', '邀评(0/1)'],
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

            created = 0
            updated = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, shop_name FROM shops")
                    shop_map = {str(x.get('shop_name') or '').strip(): self._parse_int(x.get('id')) for x in (cur.fetchall() or [])}

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

                        platform_items = [
                            {
                                'sales_product_id': None,
                                'platform_sku': x['sku'],
                                'quantity': x['quantity'],
                                'shipping_plan_id': None
                            }
                            for x in parsed_platform
                        ]
                        shipment_items = [
                            {
                                'order_product_id': None,
                                'order_sku': x['sku'],
                                'quantity': x['quantity'],
                                'source_type': 'manual',
                                'shipping_plan_id': None
                            }
                            for x in self._registration_parse_item_text(shipment_text)
                        ]
                        logistics_items = self._registration_parse_logistics_text(logistics_text)

                        self._registration_fill_item_ids(conn, platform_items, shipment_items)
                        if not shipment_items:
                            shipment_items = self._resolve_registration_auto_shipments(conn, platform_items)

                        with conn.cursor() as cur:
                            if shop_id:
                                cur.execute(
                                    "SELECT id FROM sales_order_registrations WHERE order_no=%s AND shop_id=%s LIMIT 1",
                                    (order_no, shop_id)
                                )
                            else:
                                cur.execute(
                                    "SELECT id FROM sales_order_registrations WHERE order_no=%s AND shop_id IS NULL LIMIT 1",
                                    (order_no,)
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
                                        shop_id, order_date, customer_name, phone, zip_code, address, city, state,
                                        shipping_status, is_review_invited, is_logistics_emailed, compensation_action, remark, existing_id
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
                                        shop_id, order_no, order_date, customer_name, phone, zip_code, address, city, state,
                                        shipping_status, is_review_invited, is_logistics_emailed, compensation_action, remark
                                    )
                                )
                                registration_id = cur.lastrowid
                                created += 1

                        self._registration_save_children(conn, registration_id, platform_items, shipment_items, logistics_items)
                    except Exception as row_error:
                        errors.append({'row': row_idx, 'error': str(row_error)})

            return self.send_json({'status': 'success', 'created': created, 'updated': updated, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
