# -*- coding: utf-8 -*-
"""产品管理：货号（SKU 系列）、品类、材料类型、材料及 Listing 目录辅助逻辑。"""
import os
from urllib.parse import parse_qs


class ProductManagementMixin:
    """产品管理 Mixin：SKU（产品系列）、分类、材料和相关辅助方法。"""

    # 材料类型代码与中文名映射（新旧 schema 共用）
    _MATERIAL_TYPE_MAP = {
        'fabric': '面料',
        'filling': '填充',
        'frame': '框架',
        'electronics': '电子元器件',
    }

    # -------------------------------------------------------------------------
    # 查询参数 / SQL 片段
    # -------------------------------------------------------------------------

    def _query_bool_flag(self, query_params, key):
        """解析 URL 查询中的布尔开关（1/true/yes）。"""
        return str(query_params.get(key, [''])[0]).strip().lower() in ('1', 'true', 'yes')

    def _parse_ensure_sku_family_ids(self, query_params):
        """解析 ensure_id / ensure_ids，用于「含下架但强制包含指定货号」场景。"""
        ids = []
        for key in ('ensure_id', 'ensure_ids'):
            for raw in query_params.get(key) or []:
                for part in str(raw or '').split(','):
                    v = self._parse_int(part.strip())
                    if v:
                        ids.append(int(v))
        return sorted(set(ids))

    def _sku_market_filter_clause(self, include_off_market, ensure_ids, table_alias='pf'):
        """生成货号上架状态过滤 SQL 片段；ensure_ids 可强制包含指定 id。"""
        if include_off_market:
            return '', []
        alias = str(table_alias or 'pf').strip() or 'pf'
        if ensure_ids:
            ph = ','.join(['%s'] * len(ensure_ids))
            return (
                f' AND (COALESCE({alias}.is_on_market, 1) = 1 OR {alias}.id IN ({ph}))',
                list(ensure_ids),
            )
        return f' AND COALESCE({alias}.is_on_market, 1) = 1', []

    def _invalidate_template_cache(self, *keys):
        """批量清除模板下拉缓存。"""
        for key in keys:
            self._template_options_cache.pop(key, None)

    def _invalidate_sku_related_cache(self):
        """货号增删改后，联动清除货号/面料列表缓存。"""
        self._invalidate_template_cache('sku_list_all', 'sku_list_on_market', 'fabric_list_all')

    def _handle_product_api_exception(self, e, duplicate_message, log_label, start_response):
        """产品类 API 统一异常出口：业务错误 / 唯一键冲突 / 500。"""
        if isinstance(e, RuntimeError):
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        import pymysql
        if pymysql and isinstance(e, pymysql.err.IntegrityError):
            return self.send_json({'status': 'error', 'message': duplicate_message}, start_response)
        print(f"{log_label}: {e}")
        return self.send_error(500, str(e), start_response)

    def _split_fabric_ids_field(self, rows):
        """将 GROUP_CONCAT 的 fabric_ids 字符串拆成列表。"""
        for row in rows:
            fabric_ids = row.get('fabric_ids')
            row['fabric_ids'] = [v for v in fabric_ids.split(',') if v] if fabric_ids else []
        return rows

    # -------------------------------------------------------------------------
    # 货号（SKU 系列）API
    # -------------------------------------------------------------------------

    def handle_sku_api(self, environ, method, start_response):
        """货号管理 API（CRUD）。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                brief = self._query_bool_flag(query_params, 'brief')
                include_off_market = self._query_bool_flag(query_params, 'include_off_market')
                ensure_ids = self._parse_ensure_sku_family_ids(query_params)
                limit = max(50, min(self._parse_int(query_params.get('limit', ['800'])[0]) or 800, 3000))
                market_clause, market_params = self._sku_market_filter_clause(include_off_market, ensure_ids, 'pf')

                # 简要列表：仅货号基础字段，供下拉/联想
                if brief:
                    select_sql = """
                        SELECT id, sku_family, category, is_on_market, created_at
                        FROM product_families pf
                    """
                    if keyword:
                        where_sql = f" WHERE (sku_family LIKE %s OR category LIKE %s){market_clause}"
                        params = [f"%{keyword}%", f"%{keyword}%"] + market_params + [limit]
                        order_limit = " ORDER BY id DESC LIMIT %s"
                    else:
                        where_sql = f" WHERE 1=1{market_clause}"
                        params = market_params + [limit]
                        order_limit = " ORDER BY id DESC LIMIT %s"
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(select_sql + where_sql + order_limit, tuple(params))
                            rows = cur.fetchall() or []
                    return self.send_json({'status': 'success', 'items': rows}, start_response)

                # 完整列表：附带关联面料；无关键词时走内存缓存
                cache_key = 'sku_list_all' if include_off_market else 'sku_list_on_market'
                if not keyword:
                    cached = self._template_options_cache.get(cache_key)
                    if isinstance(cached, dict) and isinstance(cached.get('items'), list):
                        return self.send_json({'status': 'success', 'items': cached.get('items')}, start_response)

                base_sql = f"""
                    SELECT pf.id, pf.sku_family, pf.category, pf.is_on_market, pf.created_at,
                        GROUP_CONCAT(DISTINCT fm.id ORDER BY fm.id SEPARATOR ',') AS fabric_ids,
                        GROUP_CONCAT(DISTINCT fm.fabric_code ORDER BY fm.fabric_code SEPARATOR ' / ') AS fabric_codes
                    FROM product_families pf
                    LEFT JOIN fabric_product_families fpf ON fpf.sku_family_id = pf.id
                    LEFT JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                """
                if keyword:
                    where_sql = f" WHERE (pf.sku_family LIKE %s OR pf.category LIKE %s){market_clause}"
                    params = [f"%{keyword}%", f"%{keyword}%"] + market_params
                else:
                    where_sql = f" WHERE 1=1{market_clause}"
                    params = list(market_params)
                group_order = """
                    GROUP BY pf.id, pf.sku_family, pf.category, pf.is_on_market, pf.created_at
                    ORDER BY pf.id DESC
                """
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(base_sql + where_sql + group_order, tuple(params))
                        rows = cur.fetchall() or []
                rows = self._split_fabric_ids_field(rows)
                if not keyword:
                    self._template_options_cache[cache_key] = {'items': rows}
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                is_on_market = 1 if self._parse_int(data.get('is_on_market')) != 0 else 0
                fabric_ids = [v for v in (self._parse_int(x) for x in (data.get('fabric_ids') or [])) if v]
                if not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing sku_family or category'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_families (sku_family, category, is_on_market) VALUES (%s, %s, %s)",
                            (sku_family, category, is_on_market),
                        )
                        new_id = cur.lastrowid
                    self._replace_sku_family_fabric_ids(conn, new_id, fabric_ids)
                self._invalidate_sku_related_cache()
                self._ensure_listing_sku_folder(sku_family)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                is_on_market = 1 if self._parse_int(data.get('is_on_market')) != 0 else 0
                fabric_ids = [v for v in (self._parse_int(x) for x in (data.get('fabric_ids') or [])) if v]
                if not item_id or not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'SKU not found'}, start_response)
                        old_sku_family = (row.get('sku_family') or '').strip()

                # 先重命名 Listing 目录，DB 失败时回滚目录名
                rename_result = self._rename_listing_sku_folder(old_sku_family, sku_family)
                if rename_result.get('status') != 'success':
                    return self.send_json({'status': 'error', 'message': rename_result.get('message') or '重命名目录失败'}, start_response)

                db_updated = False
                with self._get_db_connection() as conn:
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE product_families
                                SET sku_family=%s, category=%s, is_on_market=%s
                                WHERE id=%s
                                """,
                                (sku_family, category, is_on_market, item_id),
                            )
                        self._replace_sku_family_fabric_ids(conn, item_id, fabric_ids)
                        db_updated = True
                    except Exception:
                        if rename_result.get('renamed'):
                            self._rename_listing_sku_folder(sku_family, old_sku_family)
                        raise
                if db_updated:
                    self._ensure_listing_sku_folder(sku_family)
                self._invalidate_sku_related_cache()
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM product_families WHERE id=%s", (item_id,))
                self._invalidate_sku_related_cache()
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self._handle_product_api_exception(e, 'SKU 已存在', 'SKU API error', start_response)

    # -------------------------------------------------------------------------
    # 品类 API
    # -------------------------------------------------------------------------

    def handle_category_api(self, environ, method, start_response):
        """品类管理 API（CRUD）；删除被禁用，仅允许编辑维护。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                if not keyword:
                    cached = self._template_options_cache.get('category_list_all')
                    if isinstance(cached, dict) and isinstance(cached.get('items'), list):
                        return self.send_json({'status': 'success', 'items': cached.get('items')}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, category_cn, category_en, category_en_name, created_at
                                FROM product_categories
                                WHERE category_cn LIKE %s OR category_en LIKE %s OR category_en_name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"),
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, category_cn, category_en, category_en_name, created_at
                                FROM product_categories
                                ORDER BY id DESC
                                """
                            )
                        rows = cur.fetchall() or []
                if not keyword:
                    self._template_options_cache['category_list_all'] = {'items': rows}
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                category_cn = (data.get('category_cn') or '').strip()
                category_en = (data.get('category_en') or '').strip()
                category_en_name = (data.get('category_en_name') or '').strip()
                if not category_cn or not category_en or not category_en_name:
                    return self.send_json({'status': 'error', 'message': 'Missing category_cn or category_en or category_en_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_categories (category_cn, category_en, category_en_name) VALUES (%s, %s, %s)",
                            (category_cn, category_en, category_en_name),
                        )
                        new_id = cur.lastrowid
                self._invalidate_template_cache('category_list_all')
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                category_cn = (data.get('category_cn') or '').strip()
                category_en = (data.get('category_en') or '').strip()
                category_en_name = (data.get('category_en_name') or '').strip()
                if not item_id or not category_cn or not category_en or not category_en_name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE product_categories
                            SET category_cn=%s, category_en=%s, category_en_name=%s
                            WHERE id=%s
                            """,
                            (category_cn, category_en, category_en_name, item_id),
                        )
                self._invalidate_template_cache('category_list_all')
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                return self.send_json({'status': 'error', 'message': '不允许删除品类，请使用编辑维护'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self._handle_product_api_exception(e, '品类已存在', 'Category API error', start_response)

    # -------------------------------------------------------------------------
    # 材料类型 API
    # -------------------------------------------------------------------------

    def handle_material_type_api(self, environ, method, start_response):
        """材料类型管理 API（CRUD）。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM material_types
                                WHERE name LIKE %s
                                ORDER BY id DESC
                                """,
                                (f"%{keyword}%",),
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, name, created_at
                                FROM material_types
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall()
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO material_types (name) VALUES (%s)", (name,))
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
                        cur.execute("SELECT id FROM material_types WHERE id=%s", (item_id,))
                        if not cur.fetchone():
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("UPDATE material_types SET name=%s WHERE id=%s", (name, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM material_types WHERE id=%s", (item_id,))
                        if not cur.fetchone():
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("DELETE FROM material_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self._handle_product_api_exception(e, '材料类型已存在或被使用', 'MaterialType API error', start_response)

    # -------------------------------------------------------------------------
    # 材料 API
    # -------------------------------------------------------------------------

    def handle_material_api(self, environ, method, start_response):
        """材料管理 API（CRUD）；兼容 material_type_id 与旧 material_type 字段。"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                type_code = query_params.get('type', [''])[0].strip()
                type_name = query_params.get('type_name', [''])[0].strip()
                type_id = self._parse_int(query_params.get('type_id', [''])[0].strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        has_type_id, _has_parent_id = self._get_material_column_flags(conn)
                        if has_type_id:
                            rows = self._fetch_materials_with_type_id(cur, keyword, type_id, type_name, type_code)
                        else:
                            rows = self._fetch_materials_legacy(cur, keyword, type_name, type_code)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method in ('POST', 'PUT'):
                data = self._read_json_body(environ)
                item_id = data.get('id') if method == 'PUT' else None
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                material_type_id = self._parse_int(data.get('material_type_id'))
                material_type_code = (data.get('material_type') or '').strip()
                parent_id = self._parse_int(data.get('parent_id'))
                if method == 'PUT':
                    if not item_id or not name or not name_en:
                        return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                    if parent_id and int(parent_id) == int(item_id):
                        return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                elif not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing name or name_en'}, start_response)

                with self._get_db_connection() as conn:
                    err, new_id = self._save_material_row(
                        conn, method, item_id, name, name_en,
                        material_type_id, material_type_code, parent_id,
                    )
                    if err:
                        return self.send_json({'status': 'error', 'message': err}, start_response)
                if method == 'POST':
                    return self.send_json({'status': 'success', 'id': new_id}, start_response)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM materials WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self._handle_product_api_exception(e, '材料已存在', 'Material API error', start_response)

    def _fetch_materials_with_type_id(self, cur, keyword, type_id, type_name, type_code):
        """新 schema：materials.material_type_id 关联 material_types。"""
        type_map = self._MATERIAL_TYPE_MAP
        base_sql = """
            SELECT
                m.id, m.name, m.name_en, m.material_type_id,
                m.parent_id, pm.name AS parent_name,
                mt.name AS material_type_name,
                m.created_at
            FROM materials m
            LEFT JOIN materials pm ON m.parent_id = pm.id
            LEFT JOIN material_types mt ON m.material_type_id = mt.id
        """
        filters, params = [], []
        if type_id:
            filters.append("m.material_type_id=%s")
            params.append(type_id)
        elif type_name or type_code:
            resolved_name = type_name or type_map.get(type_code, type_code)
            if resolved_name:
                filters.append("mt.name=%s")
                params.append(resolved_name)
        if keyword:
            filters.append("(m.name LIKE %s OR m.name_en LIKE %s OR mt.name LIKE %s)")
            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
        cur.execute(base_sql + where_sql + " ORDER BY m.id DESC", params)
        return cur.fetchall()

    def _fetch_materials_legacy(self, cur, keyword, type_name, type_code):
        """旧 schema：materials.material_type 存英文代码。"""
        type_map = self._MATERIAL_TYPE_MAP
        resolved_name = type_name or type_map.get(type_code, type_code)
        name_to_code = {v: k for k, v in type_map.items()}
        legacy_code = name_to_code.get(resolved_name) if resolved_name else None
        base_sql = """
            SELECT m.id, m.name, m.name_en, m.material_type, m.parent_id, pm.name AS parent_name, m.created_at
            FROM materials m
            LEFT JOIN materials pm ON m.parent_id = pm.id
        """
        filters, params = [], []
        if legacy_code:
            filters.append("material_type=%s")
            params.append(legacy_code)
        if keyword:
            filters.append("(name LIKE %s OR name_en LIKE %s OR material_type LIKE %s)")
            params.extend([f"%{keyword}%", f"%{keyword}%", f"%{keyword}%"])
        where_sql = (" WHERE " + " AND ".join(filters)) if filters else ""
        cur.execute(base_sql + where_sql + " ORDER BY id DESC", params)
        rows = cur.fetchall()
        cur.execute("SELECT id, name FROM material_types")
        type_lookup = {row['name']: row for row in (cur.fetchall() or [])}
        for row in rows:
            code = row.get('material_type')
            name = type_map.get(code, '')
            mapped = type_lookup.get(name) or {}
            row['material_type_id'] = mapped.get('id')
            row['material_type_name'] = name
        return rows

    def _save_material_row(self, conn, method, item_id, name, name_en, material_type_id, material_type_code, parent_id):
        """材料新增/更新共用逻辑；返回 (错误消息, 新 id)。"""
        has_type_id, has_parent_id = self._get_material_column_flags(conn)
        new_id = None
        with conn.cursor() as cur:
            if not material_type_id and material_type_code:
                material_type_id = self._get_material_type_id(conn, material_type_code)

            parent_row = None
            if parent_id:
                if has_type_id:
                    cur.execute("SELECT id, material_type_id FROM materials WHERE id=%s", (parent_id,))
                else:
                    cur.execute("SELECT id, material_type FROM materials WHERE id=%s", (parent_id,))
                parent_row = cur.fetchone()
                if not parent_row:
                    return 'Invalid parent_id', None

            if has_type_id:
                if not material_type_id:
                    return 'Missing material_type_id', None
                if parent_row and parent_row.get('material_type_id') != material_type_id:
                    return 'Parent type mismatch', None
                if method == 'POST':
                    if has_parent_id:
                        cur.execute(
                            "INSERT INTO materials (name, name_en, material_type_id, parent_id) VALUES (%s, %s, %s, %s)",
                            (name, name_en, material_type_id, parent_id),
                        )
                    else:
                        cur.execute(
                            "INSERT INTO materials (name, name_en, material_type_id) VALUES (%s, %s, %s)",
                            (name, name_en, material_type_id),
                        )
                    new_id = cur.lastrowid
                elif has_parent_id:
                    cur.execute(
                        """
                        UPDATE materials
                        SET name=%s, name_en=%s, material_type_id=%s, parent_id=%s
                        WHERE id=%s
                        """,
                        (name, name_en, material_type_id, parent_id, item_id),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE materials
                        SET name=%s, name_en=%s, material_type_id=%s
                        WHERE id=%s
                        """,
                        (name, name_en, material_type_id, item_id),
                    )
            else:
                if not material_type_code:
                    return 'Missing material_type', None
                if parent_row and parent_row.get('material_type') != material_type_code:
                    return 'Parent type mismatch', None
                if method == 'POST':
                    if has_parent_id:
                        cur.execute(
                            "INSERT INTO materials (name, name_en, material_type, parent_id) VALUES (%s, %s, %s, %s)",
                            (name, name_en, material_type_code, parent_id),
                        )
                    else:
                        cur.execute(
                            "INSERT INTO materials (name, name_en, material_type) VALUES (%s, %s, %s)",
                            (name, name_en, material_type_code),
                        )
                    new_id = cur.lastrowid
                elif has_parent_id:
                    cur.execute(
                        """
                        UPDATE materials
                        SET name=%s, name_en=%s, material_type=%s, parent_id=%s
                        WHERE id=%s
                        """,
                        (name, name_en, material_type_code, parent_id, item_id),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE materials
                        SET name=%s, name_en=%s, material_type=%s
                        WHERE id=%s
                        """,
                        (name, name_en, material_type_code, item_id),
                    )
        return None, new_id

    # -------------------------------------------------------------------------
    # 货号 ↔ 面料关联、Listing 目录
    # -------------------------------------------------------------------------

    def _replace_sku_family_fabric_ids(self, conn, sku_family_id, fabric_ids):
        """全量替换货号关联的面料 id 列表（差量删 + 补缺插）。"""
        sfid = self._parse_int(sku_family_id)
        if not sfid:
            return
        fabric_ids = sorted({int(self._parse_int(x)) for x in (fabric_ids or []) if self._parse_int(x)})
        with conn.cursor() as cur:
            if fabric_ids:
                ph = ','.join(['%s'] * len(fabric_ids))
                cur.execute(
                    f"DELETE FROM fabric_product_families WHERE sku_family_id=%s AND fabric_id NOT IN ({ph})",
                    tuple([sfid] + fabric_ids),
                )
            else:
                cur.execute("DELETE FROM fabric_product_families WHERE sku_family_id=%s", (sfid,))
            cur.execute(
                "SELECT fabric_id FROM fabric_product_families WHERE sku_family_id=%s",
                (sfid,),
            )
            existing = {self._parse_int(r.get('fabric_id')) for r in (cur.fetchall() or [])}
        if not fabric_ids:
            return
        with conn.cursor() as cur:
            for fabric_id in fabric_ids:
                if fabric_id in existing:
                    continue
                cur.execute(
                    "INSERT INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sfid),
                )

    def _ensure_listing_sku_folder(self, sku_family):
        """
        确保 SKU 系列对应的 Listing 目录树完整：
        一级货号目录 + 标准子目录 + 通用/系统占位子目录。
        """
        if not sku_family:
            return

        base_folder = self._ensure_listing_folder()
        enc = self._safe_fsencode
        target = os.path.join(base_folder, enc(sku_family))
        os.makedirs(target, exist_ok=True)

        subdirs = (
            '源文件', '配件图', '配件图（手动上传）', '主图', '主图（手动上传）',
            'A+', 'A+（手动上传）', '关联文件', '视频', '视频（手动上传）', '上传模板',
        )
        for sub in subdirs:
            os.makedirs(os.path.join(target, enc(sub)), exist_ok=True)

        for parent_sub in ('配件图', '主图'):
            parent_path = os.path.join(target, enc(parent_sub))
            os.makedirs(os.path.join(parent_path, enc('通用')), exist_ok=True)
            if parent_sub == '主图':
                os.makedirs(os.path.join(parent_path, enc('通道')), exist_ok=True)

        protected = '#该系统文件夹禁止手动修改任何内容'
        for parent_sub in ('配件图', '主图', 'A+', '视频'):
            parent_path = os.path.join(target, enc(parent_sub))
            os.makedirs(os.path.join(parent_path, enc(protected)), exist_ok=True)

    def _rename_listing_sku_folder(self, old_sku_family, new_sku_family):
        """货号改名时同步重命名 Listing 根目录；旧目录不存在则仅补齐新目录。"""
        old_name = (old_sku_family or '').strip()
        new_name = (new_sku_family or '').strip()
        if (not old_name) or (not new_name) or old_name == new_name:
            return {'status': 'success', 'renamed': False}

        base_folder = self._ensure_listing_folder()
        old_path = os.path.join(base_folder, self._safe_fsencode(old_name))
        new_path = os.path.join(base_folder, self._safe_fsencode(new_name))

        if not os.path.exists(old_path):
            self._ensure_listing_sku_folder(new_name)
            return {'status': 'success', 'renamed': False}

        if os.path.exists(new_path):
            return {'status': 'error', 'message': f'目标目录已存在: {new_name}'}

        try:
            os.rename(old_path, new_path)
            return {'status': 'success', 'renamed': True}
        except Exception as e:
            return {'status': 'error', 'message': f'重命名目录失败: {e}'}

    # -------------------------------------------------------------------------
    # 材料表结构探测（兼容旧库）
    # -------------------------------------------------------------------------

    def _get_material_type_id(self, conn, name_or_code):
        """按中文名或英文代码解析 material_types.id。"""
        resolved_name = self._MATERIAL_TYPE_MAP.get(name_or_code, name_or_code)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM material_types WHERE name=%s", (resolved_name,))
            row = cur.fetchone()
        return self._parse_int(row.get('id')) if row else None

    def _get_material_column_flags(self, conn):
        """一次 DESC 探测 materials 表是否含 material_type_id / parent_id。"""
        with conn.cursor() as cur:
            cur.execute("DESC materials")
            fields = {col.get('Field') for col in (cur.fetchall() or [])}
        return 'material_type_id' in fields, 'parent_id' in fields

    def _materials_has_type_id(self, conn):
        return self._get_material_column_flags(conn)[0]

    def _materials_has_parent_id(self, conn):
        return self._get_material_column_flags(conn)[1]

    def _ensure_listing_folder(self):
        """确保 Listing 资源根目录存在。"""
        folder = self._get_listing_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _get_listing_folder_bytes(self):
        return self._join_resources('')
