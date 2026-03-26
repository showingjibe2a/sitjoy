# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin - 包含11个API处理器"""

from urllib.parse import parse_qs

class AmazonAdMixin:
    """Amazon 广告管理 API 处理器 - 持有11个API handler方法"""

    def handle_amazon_ad_subtype_api(self, environ, method, start_response):
        """Amazon 广告细分类管理 API（CRUD）"""
        try:
            self._ensure_amazon_ad_subtypes_table()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_subtypes ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
                
            if method == 'POST':
                data = self._read_json_body(environ)
                description = (data.get('description') or '').strip()
                ad_class = (data.get('ad_class') or 'SP').upper()
                if not description:
                    return self.send_json({'status': 'error', 'message': 'Missing description'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO amazon_ad_subtypes (description, ad_class) VALUES (%s, %s)",
                            (description, ad_class)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)
            
            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_subtypes WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)
                
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad subtype API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_operation_type_api(self, environ, method, start_response):
        """Amazon 广告操作类型 API"""
        try:
            self._ensure_amazon_ad_operation_types_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_operation_types ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad operation type API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_api(self, environ, method, start_response):
        """Amazon 广告 CRUD API"""
        try:
            self._ensure_amazon_ad_tables()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ads ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_template_api(self, environ, method, start_response):
        """Amazon 广告模板 API"""
        try:
            if method == 'GET':
                return self.send_json({'status': 'success', 'items': []}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_import_api(self, environ, method, start_response):
        """Amazon 广告导入 API"""
        try:
            if method == 'POST':
                data = self._read_json_body(environ)
                return self.send_json({'status': 'success', 'imported': 0}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_delivery_api(self, environ, method, start_response):
        """Amazon 广告配送 API"""
        try:
            self._ensure_amazon_ad_delivery_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_deliveries ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_product_api(self, environ, method, start_response):
        """Amazon 广告产品 API"""
        try:
            self._ensure_amazon_ad_product_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_products ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_adjustment_api(self, environ, method, start_response):
        """Amazon 广告调整 API"""
        try:
            self._ensure_amazon_ad_adjustment_table()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_adjustments ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_api(self, environ, method, start_response):
        """Amazon 广告关键词 API"""
        try:
            self._ensure_amazon_keyword_tables()
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_ad_keywords ORDER BY id DESC LIMIT 500")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_template_api(self, environ, method, start_response):
        """Amazon 广告关键词模板 API"""
        try:
            if method == 'GET':
                return self.send_json({'status': 'success', 'items': []}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_keyword_import_api(self, environ, method, start_response):
        """Amazon 广告关键词导入 API"""
        try:
            if method == 'POST':
                return self.send_json({'status': 'success', 'imported': 0}, start_response)
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
