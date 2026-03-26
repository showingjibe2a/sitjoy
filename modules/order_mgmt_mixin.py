# -*- coding: utf-8 -*-
"""订单管理 Mixin - order_product 相关 API"""

from urllib.parse import parse_qs

class OrderManagementMixin:
    """订单/配送管理 API 处理器"""

    def handle_order_product_api(self, environ, method, start_response):
        """下单产品管理 API - CRUD"""
        try:
            self._ensure_order_product_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                "SELECT * FROM order_products WHERE sku LIKE %s ORDER BY id DESC LIMIT 500",
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute("SELECT * FROM order_products ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                sku = (data.get('sku') or '').strip()
                if not sku or not sku_family_id:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO order_products (sku_family_id, sku) VALUES (%s, %s)",
                            (sku_family_id, sku)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE order_products SET updated_at=NOW() WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM order_products WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f"Order Product API error: {str(e)}")
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_order_product_carton_calc_api(self, environ, method, start_response):
        """纸箱数量计算 API"""
        try:
            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            data = self._read_json_body(environ)
            length = self._parse_float(data.get('length'))
            width = self._parse_float(data.get('width'))
            height = self._parse_float(data.get('height'))

            if not all([length, width, height]):
                return self.send_json({'status': 'error', 'message': 'Missing dimensions'}, start_response)

            qty = self._calc_carton_qty_by_40hq(length, width, height)
            return self.send_json({'status': 'success', 'carton_qty': qty}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_order_product_template_api(self, environ, method, start_response):
        """订单产品导入模板 API"""
        try:
            if method != 'GET':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            # 返回空白模板/选项
            return self.send_json({'status': 'success', 'template': 'order_product_template.xlsx'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_order_product_import_api(self, environ, method, start_response):
        """订单产品导入 API"""
        try:
            if method != 'POST':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)

            # 简化版导入处理
            return self.send_json({'status': 'success', 'message': 'Import accepted'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
