# -*- coding: utf-8 -*-
"""支持/配置 Mixin - platform_type/brand/shop/certification 等。"""

import re
from urllib.parse import parse_qs

_SUPPORT_DOMAIN_NAME_TABLES = frozenset({'platform_types', 'brands', 'certifications'})


class SupportDomainMixin:
    """支持域 API 处理器（平台类型、品牌、店铺、认证等）。"""

    # -------------------------------------------------------------------------
    # 简单名称表 CRUD（平台类型 / 品牌 / 认证）
    # -------------------------------------------------------------------------

    def _support_domain_select_name_rows(self, cur, table, keyword):
        if keyword:
            cur.execute(
                f"SELECT id, name, created_at FROM {table} WHERE name LIKE %s ORDER BY id DESC",
                (f"%{keyword}%",),
            )
        else:
            cur.execute(f"SELECT id, name, created_at FROM {table} ORDER BY id ASC")
        return cur.fetchall() or []

    def _handle_support_domain_name_api(self, environ, method, start_response, *, table, log_label):
        if table not in _SUPPORT_DOMAIN_NAME_TABLES:
            return self.send_json({'status': 'error', 'message': 'invalid table'}, start_response)
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        rows = self._support_domain_select_name_rows(cur, table, keyword)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(f"INSERT INTO {table} (name) VALUES (%s)", (name,))
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(f"UPDATE {table} SET name=%s WHERE id=%s", (name, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(f"DELETE FROM {table} WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'{log_label} API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _parse_platform_discount_types_list(self, raw):
        if raw is None:
            return []
        if isinstance(raw, list):
            items = raw
        else:
            items = re.split(r'[,，;；\n\r]+', str(raw))
        out = []
        seen = set()
        for item in items:
            text = str(item or '').strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text[:32])
        return out

    def _encode_platform_discount_types_field(self, raw):
        items = self._parse_platform_discount_types_list(raw)
        return ','.join(items) if items else None

    def _attach_platform_discount_types_list(self, rows):
        for row in rows or []:
            row['discount_types'] = self._parse_platform_discount_types_list(row.get('discount_types'))

    def _support_domain_select_platform_type_rows(self, cur, keyword):
        if keyword:
            cur.execute(
                """
                SELECT id, name, discount_types, created_at
                FROM platform_types
                WHERE name LIKE %s
                ORDER BY id DESC
                """,
                (f"%{keyword}%",),
            )
        else:
            cur.execute(
                """
                SELECT id, name, discount_types, created_at
                FROM platform_types
                ORDER BY id ASC
                """
            )
        rows = cur.fetchall() or []
        self._attach_platform_discount_types_list(rows)
        return rows

    def handle_platform_type_api(self, environ, method, start_response):
        """平台类型管理 API（CRUD，含折扣类型列表）。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        rows = self._support_domain_select_platform_type_rows(cur, keyword)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                discount_types = self._encode_platform_discount_types_field(data.get('discount_types'))
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO platform_types (name, discount_types) VALUES (%s, %s)",
                            (name, discount_types),
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                name = (data.get('name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or name'}, start_response)
                discount_types = self._encode_platform_discount_types_field(data.get('discount_types'))
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE platform_types SET name=%s, discount_types=%s WHERE id=%s",
                            (name, discount_types, item_id),
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM platform_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Platform Type API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_brand_api(self, environ, method, start_response):
        """品牌管理 API（CRUD）。"""
        return self._handle_support_domain_name_api(
            environ, method, start_response, table='brands', log_label='Brand'
        )

    def handle_certification_api(self, environ, method, start_response):
        """认证管理 API（CRUD）。"""
        return self._handle_support_domain_name_api(
            environ, method, start_response, table='certifications', log_label='Certification'
        )

    # -------------------------------------------------------------------------
    # 店铺 API
    # -------------------------------------------------------------------------

    def handle_shop_api(self, environ, method, start_response):
        """店铺管理 API（CRUD）。"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                platform_type_id = self._parse_int(query_params.get('platform_type_id', [''])[0])
                brand_id = self._parse_int(query_params.get('brand_id', [''])[0])
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        where_parts = []
                        params = []
                        if keyword:
                            where_parts.append("(s.shop_name LIKE %s OR pt.name LIKE %s OR b.name LIKE %s)")
                            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
                        if platform_type_id:
                            where_parts.append("s.platform_type_id = %s")
                            params.append(platform_type_id)
                        if brand_id:
                            where_parts.append("s.brand_id = %s")
                            params.append(brand_id)

                        where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
                        handles_select = self._shop_handles_last_mile_select_sql(conn, 's', 'pt')
                        sql = f"""
                            SELECT
                                s.id,
                                s.shop_name,
                                s.platform_type_id,
                                s.brand_id,
                                {handles_select},
                                pt.name AS platform_type_name,
                                b.name AS brand_name,
                                pt.name AS platform_type,
                                b.name AS brand,
                                s.created_at
                            FROM shops s
                            LEFT JOIN platform_types pt ON s.platform_type_id = pt.id
                            LEFT JOIN brands b ON s.brand_id = b.id
                            {where_sql}
                            ORDER BY s.id ASC
                        """
                        cur.execute(sql, tuple(params))
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                shop_name = (data.get('shop_name') or '').strip()
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                brand_id = self._parse_int(data.get('brand_id'))
                handles_last_mile = 1 if data.get('handles_last_mile') in (True, 1, '1', 'true', 'yes') else 0

                if not shop_name or not platform_type_id or not brand_id:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if self._table_has_column(conn, 'shops', 'handles_last_mile'):
                            cur.execute(
                                "INSERT INTO shops (shop_name, platform_type_id, brand_id, handles_last_mile) VALUES (%s, %s, %s, %s)",
                                (shop_name, platform_type_id, brand_id, handles_last_mile),
                            )
                        else:
                            cur.execute(
                                "INSERT INTO shops (shop_name, platform_type_id, brand_id) VALUES (%s, %s, %s)",
                                (shop_name, platform_type_id, brand_id),
                            )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                shop_name = (data.get('shop_name') or '').strip()
                platform_type_id = self._parse_int(data.get('platform_type_id'))
                brand_id = self._parse_int(data.get('brand_id'))
                handles_last_mile = 1 if data.get('handles_last_mile') in (True, 1, '1', 'true', 'yes') else 0

                if not item_id or not shop_name or not platform_type_id or not brand_id:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if self._table_has_column(conn, 'shops', 'handles_last_mile'):
                            cur.execute(
                                "UPDATE shops SET shop_name=%s, platform_type_id=%s, brand_id=%s, handles_last_mile=%s WHERE id=%s",
                                (shop_name, platform_type_id, brand_id, handles_last_mile, item_id),
                            )
                        else:
                            cur.execute(
                                "UPDATE shops SET shop_name=%s, platform_type_id=%s, brand_id=%s WHERE id=%s",
                                (shop_name, platform_type_id, brand_id, item_id),
                            )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM shops WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Shop API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

