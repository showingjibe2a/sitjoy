# -*- coding: utf-8 -*-
"""工具/仪表盘 Mixin - todo/calendar/feature 等"""

from urllib.parse import parse_qs
from datetime import datetime, timedelta
import calendar
import json

class UtilityMixin:
    """工具/仪表盘 API 处理器"""

    def handle_todo_api(self, environ, method, start_response):
        """待办事项 API（CRUD）"""
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT * FROM todos WHERE created_by=%s ORDER BY due_date ASC LIMIT 300",
                            (user_id,)
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                title = (data.get('title') or '').strip()
                if not title:
                    return self.send_json({'status': 'error', 'message': 'Missing title'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO todos (title, created_by) VALUES (%s, %s)",
                            (title, user_id)
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
                        cur.execute("UPDATE todos SET status=%s WHERE id=%s", ('open', item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM todos WHERE id=%s AND created_by=%s", (item_id, user_id))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Todo API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_calendar_api(self, environ, method, start_response):
        """日历数据 API（按月汇总待办）"""
        try:
            if method != 'GET':
                return self.send_json({'status': 'error', 'message': 'Method not allowed'}, start_response)
            
            now = datetime.now()
            year = now.year
            month = now.month

            days_in_month = calendar.monthrange(year, month)[1]
            start_date = f"{year:04d}-{month:02d}-01"
            end_date = f"{year:04d}-{month:02d}-{days_in_month:02d}"

            days = {}
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id, title, due_date, status FROM todos WHERE due_date BETWEEN %s AND %s",
                        (start_date, end_date)
                    )
                    for row in cur.fetchall() or []:
                        due_date = (row.get('due_date') or '').strip()
                        if due_date not in days:
                            days[due_date] = {'todos': []}
                        days[due_date]['todos'].append(row)

            return self.send_json({'status': 'success', 'days': days}, start_response)
        except Exception as e:
            print(f'Calendar API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_feature_api(self, environ, method, start_response):
        """卖点管理 API（CRUD）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        where_parts = []
                        params = []
                        if keyword:
                            where_parts.append("(f.name LIKE %s OR f.name_en LIKE %s OR pc.category_cn LIKE %s OR pc.category_en LIKE %s)")
                            like_val = f"%{keyword}%"
                            params.extend([like_val, like_val, like_val, like_val])
                        where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
                        sql = f"""
                            SELECT
                                f.id,
                                f.name,
                                f.name_en,
                                f.created_at,
                                GROUP_CONCAT(DISTINCT fc.category_id ORDER BY fc.category_id SEPARATOR ',') AS category_ids_csv,
                                GROUP_CONCAT(DISTINCT pc.category_cn ORDER BY pc.category_cn SEPARATOR ' / ') AS category_cn,
                                GROUP_CONCAT(DISTINCT pc.category_en ORDER BY pc.category_en SEPARATOR ' / ') AS category_en
                            FROM features f
                            LEFT JOIN feature_categories fc ON fc.feature_id = f.id
                            LEFT JOIN product_categories pc ON pc.id = fc.category_id
                            {where_sql}
                            GROUP BY f.id, f.name, f.name_en, f.created_at
                            ORDER BY f.id DESC
                        """
                        cur.execute(sql, tuple(params))
                        rows = cur.fetchall() or []
                        for row in rows:
                            csv = str(row.get('category_ids_csv') or '').strip()
                            row['category_ids'] = [int(v) for v in csv.split(',') if str(v).strip().isdigit()] if csv else []
                            row.pop('category_ids_csv', None)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                category_ids = [self._parse_int(v) for v in (data.get('category_ids') or [])]
                category_ids = [v for v in category_ids if v]
                if not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing name or name_en'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO features (name, name_en) VALUES (%s, %s)", (name, name_en))
                        new_id = cur.lastrowid
                    self._replace_feature_categories(conn, new_id, category_ids)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                category_ids = [self._parse_int(v) for v in (data.get('category_ids') or [])]
                category_ids = [v for v in category_ids if v]
                if not item_id or not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE features SET name=%s, name_en=%s WHERE id=%s", (name, name_en, item_id))
                    self._replace_feature_categories(conn, item_id, category_ids)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM features WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Feature API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _replace_feature_categories(self, conn, feature_id, category_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM feature_categories WHERE feature_id=%s", (feature_id,))
            for category_id in category_ids:
                cur.execute(
                    "INSERT IGNORE INTO feature_categories (feature_id, category_id) VALUES (%s, %s)",
                    (feature_id, category_id)
                )

