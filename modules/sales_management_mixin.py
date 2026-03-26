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
        try:
            self._ensure_sales_order_registration_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query_params.get('action', [''])[0] or '').strip().lower()

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
                return self.send_json(payload, start_response)

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
                page = max(1, self._parse_int(query_params.get('page', ['1'])[0]) or 1)
                page_size = max(20, min(self._parse_int(query_params.get('page_size', ['50'])[0]) or 50, 200))
                offset = (page - 1) * page_size

                with self._get_db_connection() as conn:
                    if item_id:
                        item = self._registration_fetch_detail(conn, item_id)
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

                        cur.execute(
                            """
                            SELECT r.id, r.shop_id, r.order_no, r.order_date, r.customer_name, r.shipping_status,
                                   r.created_at, r.updated_at, s.shop_name, s.shop_name AS shop_display_name
                            FROM sales_order_registrations r
                            LEFT JOIN shops s ON s.id = r.shop_id
                            """ + where_sql + " ORDER BY r.id DESC LIMIT %s OFFSET %s",
                            tuple(params + [page_size, offset])
                        )
                        rows = cur.fetchall() or []

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
                    self._registration_fill_item_ids(conn, platform_items, shipment_items)
                    if not shipment_items:
                        shipment_items = self._resolve_registration_auto_shipments(conn, platform_items)

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

                return self.send_json({'status': 'success', 'id': item_id}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM sales_order_registrations WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except ValueError as ve:
            return self.send_json({'status': 'error', 'message': str(ve)}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_sales_order_registration_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            wb = Workbook()
            ws = wb.active
            ws.title = 'orders'
            headers = [
                '店铺', '订单号', '下单日期(YYYY-MM-DD)', '客户姓名', '电话', '邮编', '地址', '城市', '州',
                '发货状态(pending/shipped/delivered/cancelled)', '邀评(0/1)', '物流已邮件(0/1)', '赔偿处理', '备注',
                '平台SKU明细(平台SKU*数量, 用|分隔)',
                '发货SKU明细(下单SKU*数量, 用|分隔, 留空则自动计算)',
                '物流明细(承运商:单号, 用|分隔)'
            ]
            ws.append(headers)
            ws.append([
                '', 'SO-20250101-001', '2025-01-01', 'John Doe', '1234567890', '90001', '123 Main St', 'Los Angeles', 'CA',
                'pending', '0', '0', '', '',
                'MS01-Brown-1A*1|MS01-Gray-1A*1',
                '',
                'UPS:1Z123|FedEx:999'
            ])
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

            self._ensure_sales_order_registration_tables()
            wb = load_workbook(io.BytesIO(file_bytes), data_only=True)
            ws = wb.active
            headers = [str(x.value or '').strip() for x in ws[1]]
            index_map = {name: idx for idx, name in enumerate(headers)}

            def get_val(row_values, key):
                idx = index_map.get(key)
                if idx is None or idx >= len(row_values):
                    return None
                return row_values[idx]

            required = ['订单号', '平台SKU明细(平台SKU*数量, 用|分隔)']
            for col in required:
                if col not in index_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {col}'}, start_response)

            created = 0
            updated = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, shop_name FROM shops")
                    shop_map = {str(x.get('shop_name') or '').strip(): self._parse_int(x.get('id')) for x in (cur.fetchall() or [])}

                for row_idx in range(2, ws.max_row + 1):
                    row_values = [cell.value for cell in ws[row_idx]]
                    if not any(v is not None and str(v).strip() for v in row_values):
                        continue
                    try:
                        shop_name = str(get_val(row_values, '店铺') or '').strip()
                        order_no = str(get_val(row_values, '订单号') or '').strip()
                        if not order_no:
                            raise ValueError('订单号必填')

                        shop_id = shop_map.get(shop_name) if shop_name else None
                        order_date = self._registration_parse_date(get_val(row_values, '下单日期(YYYY-MM-DD)'))
                        customer_name = str(get_val(row_values, '客户姓名') or '').strip() or None
                        phone = str(get_val(row_values, '电话') or '').strip() or None
                        zip_code = str(get_val(row_values, '邮编') or '').strip() or None
                        address = str(get_val(row_values, '地址') or '').strip() or None
                        city = str(get_val(row_values, '城市') or '').strip() or None
                        state = str(get_val(row_values, '州') or '').strip() or None
                        shipping_status = str(get_val(row_values, '发货状态(pending/shipped/delivered/cancelled)') or 'pending').strip() or 'pending'
                        is_review_invited = self._bool_from_any(get_val(row_values, '邀评(0/1)'))
                        is_logistics_emailed = self._bool_from_any(get_val(row_values, '物流已邮件(0/1)'))
                        compensation_action = str(get_val(row_values, '赔偿处理') or '').strip() or None
                        remark = str(get_val(row_values, '备注') or '').strip() or None

                        self._validate_us_phone_zip(phone, zip_code)

                        platform_text = get_val(row_values, '平台SKU明细(平台SKU*数量, 用|分隔)')
                        shipment_text = get_val(row_values, '发货SKU明细(下单SKU*数量, 用|分隔, 留空则自动计算)')
                        logistics_text = get_val(row_values, '物流明细(承运商:单号, 用|分隔)')

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
