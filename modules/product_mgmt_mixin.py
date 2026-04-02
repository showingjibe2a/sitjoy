# -*- coding: utf-8 -*-
import os
import re
from urllib.parse import parse_qs

class ProductManagementMixin:
    """浜у搧绠＄悊 Mixin锛歋KU锛堜骇鍝佺郴鍒楋級銆佸垎绫汇€佹潗鏂欏拰鐩稿叧杈呭姪鏂规硶"""

    def handle_sku_api(self, environ, method, start_response):
        """璐у彿绠＄悊 API锛圕RUD锛?""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                brief = str(query_params.get('brief', [''])[0]).strip().lower() in ('1', 'true', 'yes')
                limit = max(50, min(self._parse_int(query_params.get('limit', ['800'])[0]) or 800, 3000))
                if brief:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            if keyword:
                                cur.execute(
                                    """
                                    SELECT id, sku_family, category, created_at
                                    FROM product_families
                                    WHERE sku_family LIKE %s OR category LIKE %s
                                    ORDER BY id DESC
                                    LIMIT %s
                                    """,
                                    (f"%{keyword}%", f"%{keyword}%", limit)
                                )
                            else:
                                cur.execute(
                                    """
                                    SELECT id, sku_family, category, created_at
                                    FROM product_families
                                    ORDER BY id DESC
                                    LIMIT %s
                                    """,
                                    (limit,)
                                )
                            rows = cur.fetchall() or []
                    return self.send_json({'status': 'success', 'items': rows}, start_response)

                if not keyword:
                    cached = self._template_options_cache.get('sku_list_all')
                    if isinstance(cached, dict) and isinstance(cached.get('items'), list):
                        return self.send_json({'status': 'success', 'items': cached.get('items')}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT pf.id, pf.sku_family, pf.category, pf.created_at,
                                    GROUP_CONCAT(DISTINCT fm.id ORDER BY fm.id SEPARATOR ',') AS fabric_ids,
                                    GROUP_CONCAT(DISTINCT fm.fabric_code ORDER BY fm.fabric_code SEPARATOR ' / ') AS fabric_codes
                                FROM product_families pf
                                LEFT JOIN fabric_product_families fpf ON fpf.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                                WHERE pf.sku_family LIKE %s OR pf.category LIKE %s
                                GROUP BY pf.id, pf.sku_family, pf.category, pf.created_at
                                ORDER BY pf.id DESC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT pf.id, pf.sku_family, pf.category, pf.created_at,
                                    GROUP_CONCAT(DISTINCT fm.id ORDER BY fm.id SEPARATOR ',') AS fabric_ids,
                                    GROUP_CONCAT(DISTINCT fm.fabric_code ORDER BY fm.fabric_code SEPARATOR ' / ') AS fabric_codes
                                FROM product_families pf
                                LEFT JOIN fabric_product_families fpf ON fpf.sku_family_id = pf.id
                                LEFT JOIN fabric_materials fm ON fm.id = fpf.fabric_id
                                GROUP BY pf.id, pf.sku_family, pf.category, pf.created_at
                                ORDER BY pf.id DESC
                                """
                            )
                        rows = cur.fetchall() or []
                for row in rows:
                    fabric_ids = row.get('fabric_ids')
                    if fabric_ids:
                        row['fabric_ids'] = [v for v in fabric_ids.split(',') if v]
                    else:
                        row['fabric_ids'] = []
                if not keyword:
                    self._template_options_cache['sku_list_all'] = {'items': rows}
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                fabric_ids = [self._parse_int(v) for v in (data.get('fabric_ids') or [])]
                fabric_ids = [v for v in fabric_ids if v]
                if not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing sku_family or category'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO product_families (sku_family, category) VALUES (%s, %s)",
                            (sku_family, category)
                        )
                        new_id = cur.lastrowid
                    self._replace_sku_family_fabric_ids(conn, new_id, fabric_ids)
                self._template_options_cache.pop('sku_list_all', None)
                self._template_options_cache.pop('fabric_list_all', None)
                self._ensure_listing_sku_folder(sku_family)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                sku_family = (data.get('sku_family') or '').strip()
                category = (data.get('category') or '').strip()
                fabric_ids = [self._parse_int(v) for v in (data.get('fabric_ids') or [])]
                fabric_ids = [v for v in fabric_ids if v]
                if not item_id or not sku_family or not category:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)

                old_sku_family = None
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT sku_family FROM product_families WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'SKU not found'}, start_response)
                        old_sku_family = (row.get('sku_family') or '').strip()

                rename_result = self._rename_listing_sku_folder(old_sku_family, sku_family)
                if rename_result.get('status') != 'success':
                    return self.send_json({'status': 'error', 'message': rename_result.get('message') or '閲嶅懡鍚嶇洰褰曞け璐?}, start_response)

                db_updated = False
                with self._get_db_connection() as conn:
                    try:
                        with conn.cursor() as cur:
                            cur.execute(
                                """
                                UPDATE product_families
                                SET sku_family=%s, category=%s
                                WHERE id=%s
                                """,
                                (sku_family, category, item_id)
                            )
                        self._replace_sku_family_fabric_ids(conn, item_id, fabric_ids)
                        db_updated = True
                    except Exception:
                        if rename_result.get('renamed'):
                            self._rename_listing_sku_folder(sku_family, old_sku_family)
                        raise
                if db_updated:
                    self._ensure_listing_sku_folder(sku_family)
                self._template_options_cache.pop('sku_list_all', None)
                self._template_options_cache.pop('fabric_list_all', None)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM product_families WHERE id=%s", (item_id,))
                self._template_options_cache.pop('sku_list_all', None)
                self._template_options_cache.pop('fabric_list_all', None)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            import pymysql
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': 'SKU 宸插瓨鍦?}, start_response)
            print("SKU API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_category_api(self, environ, method, start_response):
        """鍝佺被绠＄悊 API锛圕RUD锛?""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

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
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
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
                            (category_cn, category_en, category_en_name)
                        )
                        new_id = cur.lastrowid
                    self._template_options_cache.pop('category_list_all', None)
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
                            (category_cn, category_en, category_en_name, item_id)
                        )
                self._template_options_cache.pop('category_list_all', None)
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                return self.send_json({'status': 'error', 'message': '涓嶅厑璁稿垹闄ゅ搧绫伙紝璇蜂娇鐢ㄧ紪杈戠淮鎶?}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            import pymysql
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '鍝佺被宸插瓨鍦?}, start_response)
            print("Category API error: " + str(e))
            return self.send_error(500, str(e), start_response)

    def handle_material_type_api(self, environ, method, start_response):
        """鏉愭枡绫诲瀷绠＄悊 API锛圕RUD锛?""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

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
                                (f"%{keyword}%",)
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
                        cur.execute(
                            "INSERT INTO material_types (name) VALUES (%s)",
                            (name,)
                        )
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
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute(
                            """
                            UPDATE material_types
                            SET name=%s
                            WHERE id=%s
                            """,
                            (name, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM material_types WHERE id=%s", (item_id,))
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': 'Not found'}, start_response)
                        cur.execute("DELETE FROM material_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            import pymysql
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '鏉愭枡绫诲瀷宸插瓨鍦ㄦ垨琚娇鐢?}, start_response)
            print("MaterialType API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_material_api(self, environ, method, start_response):
        """鏉愭枡绠＄悊 API锛圕RUD锛?""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                type_code = query_params.get('type', [''])[0].strip()
                type_name = query_params.get('type_name', [''])[0].strip()
                type_id = self._parse_int(query_params.get('type_id', [''])[0].strip())
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        type_map = {
                            'fabric': '闈㈡枡',
                            'filling': '濉厖',
                            'frame': '妗嗘灦',
                            'electronics': '鐢靛瓙鍏冨櫒浠?
                        }
                        has_type_id = self._materials_has_type_id(conn)
                        if has_type_id:
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
                            filters = []
                            params = []
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
                            rows = cur.fetchall()
                        else:
                            resolved_name = type_name or type_map.get(type_code, type_code)
                            name_to_code = {v: k for k, v in type_map.items()}
                            legacy_code = name_to_code.get(resolved_name) if resolved_name else None
                            base_sql = """
                                SELECT m.id, m.name, m.name_en, m.material_type, m.parent_id, pm.name AS parent_name, m.created_at
                                FROM materials m
                                LEFT JOIN materials pm ON m.parent_id = pm.id
                            """
                            filters = []
                            params = []
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
                            type_rows = cur.fetchall() or []
                            type_lookup = {row['name']: row for row in type_rows}
                            for row in rows:
                                code = row.get('material_type')
                                name = type_map.get(code, '')
                                mapped = type_lookup.get(name) or {}
                                row['material_type_id'] = mapped.get('id')
                                row['material_type_name'] = name
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                material_type_id = self._parse_int(data.get('material_type_id'))
                material_type_code = (data.get('material_type') or '').strip()
                parent_id = self._parse_int(data.get('parent_id'))
                if not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing name or name_en'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        has_type_id = self._materials_has_type_id(conn)
                        has_parent_id = self._materials_has_parent_id(conn)
                        has_type_id = self._materials_has_type_id(conn)
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
                                return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                        if has_type_id:
                            if not material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type_id'}, start_response)
                            if parent_row and parent_row.get('material_type_id') != material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type_id, parent_id) VALUES (%s, %s, %s, %s)",
                                    (name, name_en, material_type_id, parent_id)
                                )
                            else:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type_id) VALUES (%s, %s, %s)",
                                    (name, name_en, material_type_id)
                                )
                        else:
                            if not material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type'}, start_response)
                            if parent_row and parent_row.get('material_type') != material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type, parent_id) VALUES (%s, %s, %s, %s)",
                                    (name, name_en, material_type_code, parent_id)
                                )
                            else:
                                cur.execute(
                                    "INSERT INTO materials (name, name_en, material_type) VALUES (%s, %s, %s)",
                                    (name, name_en, material_type_code)
                                )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = data.get('id')
                name = (data.get('name') or '').strip()
                name_en = (data.get('name_en') or '').strip()
                material_type_id = self._parse_int(data.get('material_type_id'))
                material_type_code = (data.get('material_type') or '').strip()
                parent_id = self._parse_int(data.get('parent_id'))
                if not item_id or not name or not name_en:
                    return self.send_json({'status': 'error', 'message': 'Missing id or fields'}, start_response)
                if parent_id and int(parent_id) == int(item_id):
                    return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        has_type_id = self._materials_has_type_id(conn)
                        has_parent_id = self._materials_has_parent_id(conn)
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
                                return self.send_json({'status': 'error', 'message': 'Invalid parent_id'}, start_response)
                        if has_type_id:
                            if not material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type_id'}, start_response)
                            if parent_row and parent_row.get('material_type_id') != material_type_id:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type_id=%s, parent_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_id, parent_id, item_id)
                                )
                            else:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_id, item_id)
                                )
                        else:
                            if not material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Missing material_type'}, start_response)
                            if parent_row and parent_row.get('material_type') != material_type_code:
                                return self.send_json({'status': 'error', 'message': 'Parent type mismatch'}, start_response)
                            if has_parent_id:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type=%s, parent_id=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_code, parent_id, item_id)
                                )
                            else:
                                cur.execute(
                                    """
                                    UPDATE materials
                                    SET name=%s, name_en=%s, material_type=%s
                                    WHERE id=%s
                                    """,
                                    (name, name_en, material_type_code, item_id)
                                )
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
        except RuntimeError as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
        except Exception as e:
            import pymysql
            if pymysql and isinstance(e, pymysql.err.IntegrityError):
                return self.send_json({'status': 'error', 'message': '鏉愭枡宸插瓨鍦?}, start_response)
            print("Material API error: " + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def _replace_sku_family_fabric_ids(self, conn, sku_family_id, fabric_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM fabric_product_families WHERE sku_family_id=%s", (sku_family_id,))

        if not fabric_ids:
            return
        with conn.cursor() as cur:
            for fabric_id in fabric_ids:
                cur.execute(
                    "INSERT IGNORE INTO fabric_product_families (fabric_id, sku_family_id) VALUES (%s, %s)",
                    (fabric_id, sku_family_id)
                )

    def _ensure_listing_sku_folder(self, sku_family):
        if not sku_family:
            return
        base_folder = self._ensure_listing_folder()
        try:
            sku_bytes = os.fsencode(sku_family)
        except Exception:
            sku_bytes = str(sku_family).encode('utf-8', errors='surrogatepass')
        target = os.path.join(base_folder, sku_bytes)
        if not os.path.exists(target):
            os.makedirs(target, exist_ok=True)
        # Create standard subfolders for the SKU
        for sub in ('婧愭枃浠?, '涓诲浘', 'A+', '鍏宠仈鏂囦欢', '瑙嗛', '涓婁紶妯℃澘'):
            try:
                sub_bytes = os.fsencode(sub)
            except Exception:
                sub_bytes = str(sub).encode('utf-8', errors='surrogatepass')
            sub_path = os.path.join(target, sub_bytes)
            if not os.path.exists(sub_path):
                os.makedirs(sub_path, exist_ok=True)

        # Ensure default common folders under 涓诲浘 and A+
        for parent_sub in ('涓诲浘', 'A+'):
            try:
                parent_sub_bytes = os.fsencode(parent_sub)
            except Exception:
                parent_sub_bytes = str(parent_sub).encode('utf-8', errors='surrogatepass')
            parent_path = os.path.join(target, parent_sub_bytes)
            try:
                common_sub_bytes = os.fsencode('閫氱敤')
            except Exception:
                common_sub_bytes = '閫氱敤'.encode('utf-8', errors='surrogatepass')
            common_path = os.path.join(parent_path, common_sub_bytes)
            if not os.path.exists(common_path):
                os.makedirs(common_path, exist_ok=True)

    def _rename_listing_sku_folder(self, old_sku_family, new_sku_family):
        old_name = (old_sku_family or '').strip()
        new_name = (new_sku_family or '').strip()
        if (not old_name) or (not new_name) or old_name == new_name:
            return {'status': 'success', 'renamed': False}

        base_folder = self._ensure_listing_folder()
        old_path = os.path.join(base_folder, self._safe_fsencode(old_name))
        new_path = os.path.join(base_folder, self._safe_fsencode(new_name))

        if not os.path.exists(old_path):
            # 鏃х洰褰曚笉瀛樺湪鏃舵寜鏂板悕绉拌ˉ榻愮洰褰?
            self._ensure_listing_sku_folder(new_name)
            return {'status': 'success', 'renamed': False}

        if os.path.exists(new_path):
            return {'status': 'error', 'message': f'鐩爣鐩綍宸插瓨鍦? {new_name}'}

        try:
            os.rename(old_path, new_path)
            return {'status': 'success', 'renamed': True}
        except Exception as e:
            return {'status': 'error', 'message': f'閲嶅懡鍚嶇洰褰曞け璐? {e}'}

    def _get_material_type_id(self, conn, name_or_code):
        type_map = {
            'fabric': '闈㈡枡',
            'filling': '濉厖',
            'frame': '妗嗘灦',
            'electronics': '鐢靛瓙鍏冨櫒浠?
        }
        resolved_name = type_map.get(name_or_code, name_or_code)
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM material_types WHERE name=%s", (resolved_name,))
            row = cur.fetchone()
        return self._parse_int(row.get('id')) if row else None

    def _materials_has_type_id(self, conn):
        with conn.cursor() as cur:
            cur.execute("DESC materials")
            columns = cur.fetchall() or []
        return any(col.get('Field') == 'material_type_id' for col in columns)

    def _materials_has_parent_id(self, conn):
        with conn.cursor() as cur:
            cur.execute("DESC materials")
            columns = cur.fetchall() or []
        return any(col.get('Field') == 'parent_id' for col in columns)

    def _ensure_listing_folder(self):
        folder = self._get_listing_folder_bytes()
        if not os.path.exists(folder):
            os.makedirs(folder, exist_ok=True)
        return folder

    def _get_listing_folder_bytes(self):
        return self._join_resources('')




