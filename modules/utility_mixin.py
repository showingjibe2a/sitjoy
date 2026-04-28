# -*- coding: utf-8 -*-
"""工具/仪表盘 Mixin - todo/calendar/feature 等"""

from urllib.parse import parse_qs
from datetime import datetime, timedelta
import calendar
import json

class UtilityMixin:
    """工具/仪表盘 API 处理器"""

    def _todo_parse_date(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d')
        text = str(value).strip()
        if not text:
            return None
        for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y-%m-%d %H:%M:%S', '%Y/%m/%d %H:%M:%S'):
            try:
                return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
            except Exception:
                continue
        return None

    def _todo_parse_datetime(self, value):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        text = str(value).strip()
        if not text:
            return None
        for fmt in (
            '%Y-%m-%d %H:%M:%S',
            '%Y/%m/%d %H:%M:%S',
            '%Y-%m-%d',
            '%Y/%m/%d',
        ):
            try:
                dt = datetime.strptime(text, fmt)
                if fmt in ('%Y-%m-%d', '%Y/%m/%d'):
                    dt = dt.replace(hour=0, minute=0, second=0)
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                continue
        return None

    def handle_todo_type_api(self, environ, method, start_response):
        """待办类型管理 API（CRUD）"""
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query_params.get('action', [''])[0] or '').strip().lower()

            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, type_name, sort_order, created_at, updated_at
                            FROM todo_types
                            ORDER BY sort_order ASC, id ASC
                            """
                        )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ) or {}
                type_name = (data.get('type_name') or '').strip()
                sort_order = self._parse_int(data.get('sort_order')) or 0
                if not type_name:
                    return self.send_json({'status': 'error', 'message': '缺少类型名称'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO todo_types (type_name, sort_order) VALUES (%s, %s)",
                            (type_name, max(0, sort_order))
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ) or {}
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if action == 'reorder':
                            orders = data.get('orders') if isinstance(data.get('orders'), list) else []
                            pairs = []
                            for row in orders:
                                if not isinstance(row, dict):
                                    continue
                                tid = self._parse_int(row.get('id'))
                                so = self._parse_int(row.get('sort_order'))
                                if tid:
                                    pairs.append((max(0, so or 0), tid))
                            if pairs:
                                cur.executemany("UPDATE todo_types SET sort_order=%s WHERE id=%s", pairs)
                            return self.send_json({'status': 'success'}, start_response)

                        type_name = (data.get('type_name') or '').strip()
                        sort_order = self._parse_int(data.get('sort_order'))
                        sets = []
                        params = []
                        if type_name:
                            sets.append("type_name=%s")
                            params.append(type_name)
                        if sort_order is not None:
                            sets.append("sort_order=%s")
                            params.append(max(0, sort_order))
                        if not sets:
                            return self.send_json({'status': 'error', 'message': '没有可更新字段'}, start_response)
                        params.append(item_id)
                        cur.execute(f"UPDATE todo_types SET {', '.join(sets)} WHERE id=%s", tuple(params))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ) or {}
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        # 保底：不允许删“默认”
                        cur.execute("SELECT type_name FROM todo_types WHERE id=%s LIMIT 1", (item_id,))
                        row = cur.fetchone() or {}
                        if (row.get('type_name') or '').strip() == '默认':
                            return self.send_json({'status': 'error', 'message': '默认类型不可删除'}, start_response)
                        cur.execute("DELETE FROM todo_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Todo type API error: {str(e)}')
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _todo_column_exists(self, conn, column_name):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM information_schema.COLUMNS
                WHERE TABLE_SCHEMA = DATABASE()
                  AND TABLE_NAME = 'todos'
                  AND COLUMN_NAME = %s
                LIMIT 1
                """,
                (str(column_name or '').strip(),)
            )
            return bool(cur.fetchone())

    def _replace_todo_sales_links(self, conn, todo_id, sales_product_ids, sku_family_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM todo_sales_links WHERE todo_id=%s", (todo_id,))
            sp_ids = sorted(set([self._parse_int(x) for x in (sales_product_ids or []) if self._parse_int(x)]))
            sf_ids = sorted(set([self._parse_int(x) for x in (sku_family_ids or []) if self._parse_int(x)]))
            for sp_id in sp_ids:
                cur.execute(
                    "INSERT INTO todo_sales_links (todo_id, sales_product_id) VALUES (%s, %s)",
                    (todo_id, sp_id)
                )
            for sf_id in sf_ids:
                cur.execute(
                    "INSERT INTO todo_sales_links (todo_id, sku_family_id) VALUES (%s, %s)",
                    (todo_id, sf_id)
                )

    def _replace_todo_assignees(self, conn, todo_id, assignee_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM todo_assignments WHERE todo_id=%s", (todo_id,))
            ids = sorted(set([self._parse_int(x) for x in (assignee_ids or []) if self._parse_int(x)]))
            for aid in ids:
                cur.execute(
                    "INSERT INTO todo_assignments (todo_id, assignee_id, assignment_status) VALUES (%s, %s, %s)",
                    (todo_id, aid, 'pending')
                )

    def handle_todo_api(self, environ, method, start_response):
        """待办事项 API（CRUD）"""
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            if method == 'GET':
                query_params = parse_qs(environ.get('QUERY_STRING', ''))
                include_all = str((query_params.get('include_all', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                with_links = str((query_params.get('with_links', ['0'])[0] or '0')).lower() in ('1', 'true', 'yes', 'on')
                todo_type_id = self._parse_int((query_params.get('todo_type_id', [''])[0] or '').strip())
                with self._get_db_connection() as conn:
                    has_created_by = self._todo_column_exists(conn, 'created_by')
                    if not include_all and not has_created_by:
                        return self.send_json({
                            'status': 'error',
                            'message': '数据库表 todos 缺少字段 created_by，请执行 scripts/sql/20260424_02_todos_add_created_by.sql 后重试'
                        }, start_response)
                    with conn.cursor() as cur:
                        params = []
                        where_parts = []
                        if not include_all:
                            where_parts.append('t.created_by=%s')
                            params.append(user_id)
                        if todo_type_id:
                            where_parts.append('t.todo_type_id=%s')
                            params.append(todo_type_id)
                        where_sql = ('WHERE ' + ' AND '.join(where_parts)) if where_parts else ''
                        cur.execute(
                            f"""
                            SELECT t.*, u.name AS creator_name, u.username AS creator_username,
                                   tt.type_name AS todo_type_name
                            FROM todos t
                            LEFT JOIN users u ON u.id = t.created_by
                            LEFT JOIN todo_types tt ON tt.id = t.todo_type_id
                            {where_sql}
                            ORDER BY (t.status='done') ASC, t.due_date ASC, t.id DESC
                            LIMIT 500
                            """,
                            tuple(params)
                        )
                        rows = cur.fetchall() or []

                        if with_links and rows:
                            todo_ids = [self._parse_int(r.get('id')) for r in rows if self._parse_int(r.get('id'))]
                            if todo_ids:
                                placeholders = ','.join(['%s'] * len(todo_ids))
                                cur.execute(
                                    f"""
                                    SELECT tsl.todo_id, tsl.sales_product_id, tsl.sku_family_id,
                                           sp.platform_sku, pf.sku_family
                                    FROM todo_sales_links tsl
                                    LEFT JOIN sales_products sp ON sp.id = tsl.sales_product_id
                                    LEFT JOIN product_families pf ON pf.id = tsl.sku_family_id
                                    WHERE tsl.todo_id IN ({placeholders})
                                    ORDER BY tsl.id ASC
                                    """,
                                    tuple(todo_ids)
                                )
                                link_rows = cur.fetchall() or []
                                link_map = {}
                                for lk in link_rows:
                                    tid = self._parse_int(lk.get('todo_id'))
                                    if not tid:
                                        continue
                                    link_map.setdefault(tid, {
                                        'sales_product_ids': [],
                                        'platform_skus': [],
                                        'sku_family_ids': [],
                                        'sku_families': []
                                    })
                                    sp_id = self._parse_int(lk.get('sales_product_id'))
                                    sf_id = self._parse_int(lk.get('sku_family_id'))
                                    sku = str(lk.get('platform_sku') or '').strip()
                                    sf = str(lk.get('sku_family') or '').strip()
                                    if sp_id and sp_id not in link_map[tid]['sales_product_ids']:
                                        link_map[tid]['sales_product_ids'].append(sp_id)
                                    if sku and sku not in link_map[tid]['platform_skus']:
                                        link_map[tid]['platform_skus'].append(sku)
                                    if sf_id and sf_id not in link_map[tid]['sku_family_ids']:
                                        link_map[tid]['sku_family_ids'].append(sf_id)
                                    if sf and sf not in link_map[tid]['sku_families']:
                                        link_map[tid]['sku_families'].append(sf)

                                cur.execute(
                                    f"""
                                    SELECT ta.todo_id, ta.assignee_id, u.name, u.username
                                    FROM todo_assignments ta
                                    LEFT JOIN users u ON u.id = ta.assignee_id
                                    WHERE ta.todo_id IN ({placeholders})
                                    ORDER BY ta.id ASC
                                    """,
                                    tuple(todo_ids)
                                )
                                ass_rows = cur.fetchall() or []
                                ass_map = {}
                                for ar in ass_rows:
                                    tid = self._parse_int(ar.get('todo_id'))
                                    if not tid:
                                        continue
                                    ass_map.setdefault(tid, []).append({
                                        'assignee_id': self._parse_int(ar.get('assignee_id')),
                                        'name': ar.get('name') or '',
                                        'username': ar.get('username') or ''
                                    })

                                for r in rows:
                                    tid = self._parse_int(r.get('id'))
                                    details = link_map.get(tid, {
                                        'sales_product_ids': [],
                                        'platform_skus': [],
                                        'sku_family_ids': [],
                                        'sku_families': []
                                    })
                                    r.update(details)
                                    r['assignees'] = ass_map.get(tid, [])
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                title = (data.get('title') or '').strip()
                if not title:
                    return self.send_json({'status': 'error', 'message': 'Missing title'}, start_response)

                start_date = self._todo_parse_date(data.get('start_date')) or datetime.now().strftime('%Y-%m-%d')
                due_date = self._todo_parse_date(data.get('due_date')) or start_date
                reminder_interval_days = max(1, self._parse_int(data.get('reminder_interval_days')) or 1)
                is_recurring = 1 if str(data.get('is_recurring', 0)).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                detail = (data.get('detail') or '').strip() or None
                priority = self._parse_int(data.get('priority')) or 2
                todo_type_id = self._parse_int(data.get('todo_type_id')) or 0
                assignee_ids = data.get('assignee_ids') or []
                related_sales_product_ids = data.get('related_sales_product_ids') or []
                related_sku_family_ids = data.get('related_sku_family_ids') or []

                with self._get_db_connection() as conn:
                    has_created_by = self._todo_column_exists(conn, 'created_by')
                    if not has_created_by:
                        return self.send_json({
                            'status': 'error',
                            'message': '数据库表 todos 缺少字段 created_by，请执行 scripts/sql/20260424_02_todos_add_created_by.sql 后重试'
                        }, start_response)
                    has_reminder_interval_days = self._todo_column_exists(conn, 'reminder_interval_days')
                    has_is_recurring = self._todo_column_exists(conn, 'is_recurring')
                    if not todo_type_id:
                        # 默认使用 todo_types 中 sort_order 最小的类型（一般为“默认”）
                        try:
                            with conn.cursor() as cur:
                                cur.execute("SELECT id FROM todo_types ORDER BY sort_order ASC, id ASC LIMIT 1")
                                row = cur.fetchone() or {}
                                todo_type_id = self._parse_int(row.get('id')) or 0
                        except Exception:
                            todo_type_id = 0

                    insert_cols = ['title', 'detail', 'start_date', 'due_date']
                    insert_vals = [title, detail, start_date, due_date]
                    insert_cols.append('todo_type_id')
                    insert_vals.append(todo_type_id)
                    if has_reminder_interval_days:
                        insert_cols.append('reminder_interval_days')
                        insert_vals.append(reminder_interval_days)
                    if has_is_recurring:
                        insert_cols.append('is_recurring')
                        insert_vals.append(is_recurring)
                    insert_cols.extend(['status', 'priority'])
                    insert_vals.extend(['open', priority])
                    if has_created_by:
                        insert_cols.append('created_by')
                        insert_vals.append(user_id)
                    placeholders = ','.join(['%s'] * len(insert_vals))
                    col_sql = ','.join(insert_cols)
                    with conn.cursor() as cur:
                        cur.execute(
                            f'INSERT INTO todos ({col_sql}) VALUES ({placeholders})',
                            tuple(insert_vals)
                        )
                        new_id = cur.lastrowid
                    self._replace_todo_assignees(conn, new_id, assignee_ids)
                    self._replace_todo_sales_links(conn, new_id, related_sales_product_ids, related_sku_family_ids)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                status = str(data.get('status') or '').strip().lower()
                if status not in ('open', 'done'):
                    status = 'open'
                completed_at = self._todo_parse_datetime(data.get('completed_at')) if status == 'done' else None
                if status == 'done' and not completed_at:
                    completed_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                related_sales_product_ids = data.get('related_sales_product_ids') if isinstance(data.get('related_sales_product_ids'), list) else None
                related_sku_family_ids = data.get('related_sku_family_ids') if isinstance(data.get('related_sku_family_ids'), list) else None
                assignee_ids = data.get('assignee_ids') if isinstance(data.get('assignee_ids'), list) else None
                title = (data.get('title') or '').strip() if 'title' in (data or {}) else None
                detail = (data.get('detail') or '').strip() if 'detail' in (data or {}) else None
                start_date = self._todo_parse_date(data.get('start_date')) if 'start_date' in (data or {}) else None
                due_date = self._todo_parse_date(data.get('due_date')) if 'due_date' in (data or {}) else None
                priority = self._parse_int(data.get('priority')) if 'priority' in (data or {}) else None
                reminder_interval_days = self._parse_int(data.get('reminder_interval_days')) if 'reminder_interval_days' in (data or {}) else None
                is_recurring = None
                if 'is_recurring' in (data or {}):
                    is_recurring = 1 if str(data.get('is_recurring', 0)).strip().lower() in ('1', 'true', 'yes', 'on') else 0
                todo_type_id = self._parse_int(data.get('todo_type_id')) if 'todo_type_id' in (data or {}) else None
                
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sets = ['status=%s', 'completed_at=%s']
                        params = [status, completed_at]
                        if title is not None:
                            sets.append('title=%s')
                            params.append(title)
                        if detail is not None:
                            sets.append('detail=%s')
                            params.append(detail or None)
                        if start_date is not None:
                            sets.append('start_date=%s')
                            params.append(start_date or datetime.now().strftime('%Y-%m-%d'))
                        if due_date is not None:
                            sets.append('due_date=%s')
                            params.append(due_date or (start_date or datetime.now().strftime('%Y-%m-%d')))
                        if priority is not None:
                            sets.append('priority=%s')
                            params.append(max(1, min(5, priority or 2)))
                        if reminder_interval_days is not None:
                            sets.append('reminder_interval_days=%s')
                            params.append(max(1, reminder_interval_days or 1))
                        if is_recurring is not None:
                            sets.append('is_recurring=%s')
                            params.append(1 if is_recurring else 0)
                        if todo_type_id is not None:
                            if not todo_type_id:
                                # 兼容：将空值回落到默认类型
                                try:
                                    cur.execute("SELECT id FROM todo_types ORDER BY sort_order ASC, id ASC LIMIT 1")
                                    row = cur.fetchone() or {}
                                    todo_type_id = self._parse_int(row.get('id')) or 0
                                except Exception:
                                    todo_type_id = 0
                            sets.append('todo_type_id=%s')
                            params.append(max(1, todo_type_id or 1))
                        params.append(item_id)
                        cur.execute(f"UPDATE todos SET {', '.join(sets)} WHERE id=%s", tuple(params))
                    if related_sales_product_ids is not None or related_sku_family_ids is not None:
                        self._replace_todo_sales_links(conn, item_id, related_sales_product_ids or [], related_sku_family_ids or [])
                    if assignee_ids is not None:
                        self._replace_todo_assignees(conn, item_id, assignee_ids)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    if not self._todo_column_exists(conn, 'created_by'):
                        return self.send_json({
                            'status': 'error',
                            'message': '数据库表 todos 缺少字段 created_by，请执行 scripts/sql/20260424_02_todos_add_created_by.sql 后重试'
                        }, start_response)
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

