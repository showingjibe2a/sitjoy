# -*- coding: utf-8 -*-
"""订单管理 Mixin - order_product 相关 API"""

from urllib.parse import parse_qs
import re

class OrderManagementMixin:
    """订单/配送管理 API 处理器"""

    def handle_order_product_api(self, environ, method, start_response):
        """下单产品管理 API - CRUD"""
        try:
            self._ensure_order_product_tables()
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            action = (query_params.get('action', [''])[0] or '').strip().lower()

            if action == 'shipping_plans':
                return self._handle_order_product_shipping_plans(environ, method, start_response, query_params)

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    rows = self._load_order_product_rows(conn, keyword=keyword)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            if method == 'POST':
                data = self._read_json_body(environ)
                sku_family_id = self._parse_int(data.get('sku_family_id'))
                sku = (data.get('sku') or '').strip()
                fabric_id = self._parse_int(data.get('fabric_id'))
                if not sku or not sku_family_id or not fabric_id:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                filling_material_ids = self._normalize_id_list(data.get('filling_material_ids'))
                frame_material_ids = self._normalize_id_list(data.get('frame_material_ids'))
                feature_ids = self._normalize_id_list(data.get('feature_ids'))
                certification_ids = self._normalize_id_list(data.get('certification_ids'))

                is_iteration = 1 if self._parse_int(data.get('is_iteration')) else 0
                is_on_market = 1 if self._parse_int(data.get('is_on_market')) else 0
                is_dachene_product = 1 if self._parse_int(data.get('is_dachene_product')) else 0

                source_order_product_id = self._parse_int(data.get('source_order_product_id'))
                if not is_iteration:
                    source_order_product_id = None

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO order_products (
                                sku, sku_family_id, version_no, fabric_id,
                                spec_qty_short, contents_desc_en,
                                is_iteration, is_dachene_product, is_on_market,
                                source_order_product_id,
                                finished_length_in, finished_width_in, finished_height_in,
                                net_weight_lbs,
                                package_length_in, package_width_in, package_height_in,
                                gross_weight_lbs,
                                cost_usd, carton_qty, package_size_class, last_mile_avg_freight_usd
                            ) VALUES (
                                %s, %s, %s, %s,
                                %s, %s,
                                %s, %s, %s,
                                %s,
                                %s, %s, %s,
                                %s,
                                %s, %s, %s,
                                %s,
                                %s, %s, %s, %s
                            )
                            """,
                            (
                                sku,
                                sku_family_id,
                                (data.get('version_no') or '').strip(),
                                fabric_id,
                                (data.get('spec_qty_short') or '').strip(),
                                (data.get('contents_desc_en') or '').strip() or None,
                                is_iteration,
                                is_dachene_product,
                                is_on_market,
                                source_order_product_id,
                                self._parse_float(data.get('finished_length_in')),
                                self._parse_float(data.get('finished_width_in')),
                                self._parse_float(data.get('finished_height_in')),
                                self._parse_float(data.get('net_weight_lbs')),
                                self._parse_float(data.get('package_length_in')),
                                self._parse_float(data.get('package_width_in')),
                                self._parse_float(data.get('package_height_in')),
                                self._parse_float(data.get('gross_weight_lbs')),
                                self._parse_float(data.get('cost_usd')),
                                self._parse_int(data.get('carton_qty')),
                                (data.get('package_size_class') or '').strip() or None,
                                self._parse_float(data.get('last_mile_avg_freight_usd')),
                            )
                        )
                        new_id = cur.lastrowid
                    self._replace_order_product_relations(
                        conn,
                        new_id,
                        filling_material_ids,
                        frame_material_ids,
                        feature_ids,
                        certification_ids,
                    )
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                updates = []
                params = []

                text_fields = ['sku', 'version_no', 'spec_qty_short', 'contents_desc_en', 'package_size_class']
                for field in text_fields:
                    if field in data:
                        val = (data.get(field) or '').strip()
                        if field in ('contents_desc_en', 'package_size_class'):
                            val = val or None
                        updates.append(f"{field}=%s")
                        params.append(val)

                int_fields = ['sku_family_id', 'fabric_id', 'source_order_product_id', 'carton_qty']
                for field in int_fields:
                    if field in data:
                        updates.append(f"{field}=%s")
                        params.append(self._parse_int(data.get(field)))

                float_fields = [
                    'finished_length_in', 'finished_width_in', 'finished_height_in', 'net_weight_lbs',
                    'package_length_in', 'package_width_in', 'package_height_in', 'gross_weight_lbs',
                    'cost_usd', 'last_mile_avg_freight_usd'
                ]
                for field in float_fields:
                    if field in data:
                        updates.append(f"{field}=%s")
                        params.append(self._parse_float(data.get(field)))

                bool_fields = ['is_iteration', 'is_dachene_product', 'is_on_market']
                for field in bool_fields:
                    if field in data:
                        updates.append(f"{field}=%s")
                        params.append(1 if self._parse_int(data.get(field)) else 0)

                if 'is_iteration' in data and not (1 if self._parse_int(data.get('is_iteration')) else 0):
                    updates.append("source_order_product_id=%s")
                    params.append(None)

                has_relation_updates = any(
                    key in data for key in ('filling_material_ids', 'frame_material_ids', 'feature_ids', 'certification_ids')
                )

                with self._get_db_connection() as conn:
                    if updates:
                        with conn.cursor() as cur:
                            cur.execute(
                                f"UPDATE order_products SET {', '.join(updates)} WHERE id=%s",
                                tuple(params + [item_id])
                            )

                    if has_relation_updates:
                        filling_material_ids = self._normalize_id_list(data.get('filling_material_ids'))
                        frame_material_ids = self._normalize_id_list(data.get('frame_material_ids'))
                        feature_ids = self._normalize_id_list(data.get('feature_ids'))
                        certification_ids = self._normalize_id_list(data.get('certification_ids'))
                        self._replace_order_product_relations(
                            conn,
                            item_id,
                            filling_material_ids,
                            frame_material_ids,
                            feature_ids,
                            certification_ids,
                        )
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

    def _normalize_id_list(self, value):
        if value is None:
            return []
        items = value if isinstance(value, list) else re.split(r'[\s,，;；]+', str(value))
        out = []
        seen = set()
        for raw in items:
            item_id = self._parse_int(raw)
            if not item_id or item_id in seen:
                continue
            seen.add(item_id)
            out.append(item_id)
        return out

    def _load_order_product_rows(self, conn, keyword=''):
        with conn.cursor() as cur:
            if keyword:
                like_val = f"%{keyword}%"
                cur.execute(
                    """
                    SELECT
                        op.*,
                        pf.sku_family,
                        pf.category,
                        fm.fabric_code,
                        fm.fabric_name_en
                    FROM order_products op
                    LEFT JOIN product_families pf ON pf.id = op.sku_family_id
                    LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                    WHERE op.sku LIKE %s
                       OR pf.sku_family LIKE %s
                       OR fm.fabric_code LIKE %s
                       OR fm.fabric_name_en LIKE %s
                       OR op.version_no LIKE %s
                    ORDER BY op.id DESC
                    LIMIT 1200
                    """,
                    (like_val, like_val, like_val, like_val, like_val)
                )
            else:
                cur.execute(
                    """
                    SELECT
                        op.*,
                        pf.sku_family,
                        pf.category,
                        fm.fabric_code,
                        fm.fabric_name_en
                    FROM order_products op
                    LEFT JOIN product_families pf ON pf.id = op.sku_family_id
                    LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                    ORDER BY op.id DESC
                    LIMIT 1200
                    """
                )
            rows = cur.fetchall() or []

            op_ids = [self._parse_int(row.get('id')) for row in rows if self._parse_int(row.get('id'))]
            material_map = {}
            feature_map = {}
            certification_map = {}

            if op_ids:
                placeholders = ','.join(['%s'] * len(op_ids))

                cur.execute(
                    f"""
                    SELECT opm.order_product_id, opm.material_id, m.name, m.name_en, mt.name AS material_type_name
                    FROM order_product_materials opm
                    JOIN materials m ON m.id = opm.material_id
                    LEFT JOIN material_types mt ON mt.id = m.material_type_id
                    WHERE opm.order_product_id IN ({placeholders})
                    ORDER BY opm.order_product_id ASC, opm.material_id ASC
                    """,
                    tuple(op_ids)
                )
                for rel in (cur.fetchall() or []):
                    order_id = self._parse_int(rel.get('order_product_id'))
                    if not order_id:
                        continue
                    material_map.setdefault(order_id, []).append(rel)

                cur.execute(
                    f"""
                    SELECT opf.order_product_id, opf.feature_id, f.name, f.name_en
                    FROM order_product_features opf
                    JOIN features f ON f.id = opf.feature_id
                    WHERE opf.order_product_id IN ({placeholders})
                    ORDER BY opf.order_product_id ASC, opf.feature_id ASC
                    """,
                    tuple(op_ids)
                )
                for rel in (cur.fetchall() or []):
                    order_id = self._parse_int(rel.get('order_product_id'))
                    if not order_id:
                        continue
                    feature_map.setdefault(order_id, []).append(rel)

                cur.execute(
                    f"""
                    SELECT opc.order_product_id, opc.certification_id, c.name
                    FROM order_product_certifications opc
                    JOIN certifications c ON c.id = opc.certification_id
                    WHERE opc.order_product_id IN ({placeholders})
                    ORDER BY opc.order_product_id ASC, opc.certification_id ASC
                    """,
                    tuple(op_ids)
                )
                for rel in (cur.fetchall() or []):
                    order_id = self._parse_int(rel.get('order_product_id'))
                    if not order_id:
                        continue
                    certification_map.setdefault(order_id, []).append(rel)

            for row in rows:
                order_id = self._parse_int(row.get('id'))
                materials = material_map.get(order_id, []) if order_id else []
                features = feature_map.get(order_id, []) if order_id else []
                certifications = certification_map.get(order_id, []) if order_id else []

                filling_ids = []
                frame_ids = []
                filling_names = []
                frame_names = []
                for material in materials:
                    material_id = self._parse_int(material.get('material_id'))
                    if not material_id:
                        continue
                    material_name = f"{material.get('name') or ''} / {material.get('name_en') or ''}".strip(' /')
                    type_name = str(material.get('material_type_name') or '').strip()
                    if type_name == '填充':
                        filling_ids.append(material_id)
                        if material_name:
                            filling_names.append(material_name)
                    elif type_name == '框架':
                        frame_ids.append(material_id)
                        if material_name:
                            frame_names.append(material_name)

                row['filling_material_ids'] = filling_ids
                row['frame_material_ids'] = frame_ids
                row['filling_material_names'] = filling_names
                row['frame_material_names'] = frame_names

                row['feature_ids'] = [self._parse_int(item.get('feature_id')) for item in features if self._parse_int(item.get('feature_id'))]
                row['feature_names'] = [
                    f"{item.get('name') or ''} / {item.get('name_en') or ''}".strip(' /')
                    for item in features
                    if item.get('name') or item.get('name_en')
                ]

                row['certification_ids'] = [
                    self._parse_int(item.get('certification_id'))
                    for item in certifications
                    if self._parse_int(item.get('certification_id'))
                ]
                row['certification_names'] = [item.get('name') for item in certifications if item.get('name')]

        return rows

    def _replace_order_product_relations(self, conn, order_product_id, filling_material_ids, frame_material_ids, feature_ids, certification_ids):
        material_ids = []
        seen = set()
        for item_id in (filling_material_ids or []) + (frame_material_ids or []):
            if item_id and item_id not in seen:
                seen.add(item_id)
                material_ids.append(item_id)

        with conn.cursor() as cur:
            cur.execute("DELETE FROM order_product_materials WHERE order_product_id=%s", (order_product_id,))
            for material_id in material_ids:
                cur.execute(
                    "INSERT IGNORE INTO order_product_materials (order_product_id, material_id) VALUES (%s, %s)",
                    (order_product_id, material_id)
                )

            cur.execute("DELETE FROM order_product_features WHERE order_product_id=%s", (order_product_id,))
            for feature_id in (feature_ids or []):
                cur.execute(
                    "INSERT IGNORE INTO order_product_features (order_product_id, feature_id) VALUES (%s, %s)",
                    (order_product_id, feature_id)
                )

            cur.execute("DELETE FROM order_product_certifications WHERE order_product_id=%s", (order_product_id,))
            for certification_id in (certification_ids or []):
                cur.execute(
                    "INSERT IGNORE INTO order_product_certifications (order_product_id, certification_id) VALUES (%s, %s)",
                    (order_product_id, certification_id)
                )

    def _handle_order_product_shipping_plans(self, environ, method, start_response, query_params):
        try:
            if method == 'GET':
                order_product_id = self._parse_int(query_params.get('order_product_id', [''])[0])
                if not order_product_id:
                    return self.send_json({'status': 'error', 'message': 'Missing order_product_id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, order_product_id, plan_name, created_at, updated_at
                            FROM order_product_shipping_plans
                            WHERE order_product_id=%s
                            ORDER BY id DESC
                            """,
                            (order_product_id,)
                        )
                        plans = cur.fetchall() or []
                        plan_ids = [self._parse_int(row.get('id')) for row in plans if self._parse_int(row.get('id'))]
                        item_map = {}
                        if plan_ids:
                            placeholders = ','.join(['%s'] * len(plan_ids))
                            cur.execute(
                                f"""
                                SELECT
                                    opsi.id,
                                    opsi.shipping_plan_id,
                                    opsi.substitute_order_product_id,
                                    opsi.quantity,
                                    opsi.sort_order,
                                    op.sku AS substitute_order_sku
                                FROM order_product_shipping_plan_items opsi
                                JOIN order_products op ON op.id = opsi.substitute_order_product_id
                                WHERE opsi.shipping_plan_id IN ({placeholders})
                                ORDER BY opsi.shipping_plan_id ASC, opsi.sort_order ASC, opsi.id ASC
                                """,
                                tuple(plan_ids)
                            )
                            for item in (cur.fetchall() or []):
                                plan_id = self._parse_int(item.get('shipping_plan_id'))
                                if not plan_id:
                                    continue
                                item_map.setdefault(plan_id, []).append(item)

                        for plan in plans:
                            pid = self._parse_int(plan.get('id'))
                            plan['items'] = item_map.get(pid, []) if pid else []

                return self.send_json({'status': 'success', 'items': plans}, start_response)

            data = self._read_json_body(environ)

            if method == 'POST':
                order_product_id = self._parse_int(data.get('order_product_id'))
                plan_name = (data.get('plan_name') or '').strip()
                items = data.get('items') or []
                if not order_product_id or not plan_name:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "INSERT INTO order_product_shipping_plans (order_product_id, plan_name) VALUES (%s, %s)",
                            (order_product_id, plan_name)
                        )
                        plan_id = cur.lastrowid

                        for idx, item in enumerate(items):
                            substitute_order_product_id = self._parse_int(item.get('substitute_order_product_id'))
                            quantity = max(1, self._parse_int(item.get('quantity')) or 1)
                            sort_order = self._parse_int(item.get('sort_order')) or (idx + 1)
                            if not substitute_order_product_id:
                                continue
                            cur.execute(
                                """
                                INSERT INTO order_product_shipping_plan_items
                                    (shipping_plan_id, substitute_order_product_id, quantity, sort_order)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (plan_id, substitute_order_product_id, quantity, sort_order)
                            )
                return self.send_json({'status': 'success', 'id': plan_id}, start_response)

            if method == 'PUT':
                plan_id = self._parse_int(data.get('id'))
                order_product_id = self._parse_int(data.get('order_product_id'))
                plan_name = (data.get('plan_name') or '').strip()
                items = data.get('items') or []
                if not plan_id or not order_product_id or not plan_name:
                    return self.send_json({'status': 'error', 'message': 'Missing fields'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE order_product_shipping_plans
                            SET order_product_id=%s, plan_name=%s
                            WHERE id=%s
                            """,
                            (order_product_id, plan_name, plan_id)
                        )
                        cur.execute("DELETE FROM order_product_shipping_plan_items WHERE shipping_plan_id=%s", (plan_id,))
                        for idx, item in enumerate(items):
                            substitute_order_product_id = self._parse_int(item.get('substitute_order_product_id'))
                            quantity = max(1, self._parse_int(item.get('quantity')) or 1)
                            sort_order = self._parse_int(item.get('sort_order')) or (idx + 1)
                            if not substitute_order_product_id:
                                continue
                            cur.execute(
                                """
                                INSERT INTO order_product_shipping_plan_items
                                    (shipping_plan_id, substitute_order_product_id, quantity, sort_order)
                                VALUES (%s, %s, %s, %s)
                                """,
                                (plan_id, substitute_order_product_id, quantity, sort_order)
                            )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                plan_id = self._parse_int(data.get('id'))
                if not plan_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM order_product_shipping_plans WHERE id=%s", (plan_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
