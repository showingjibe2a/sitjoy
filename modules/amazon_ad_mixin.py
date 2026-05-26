# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin - 包含11个API处理器"""

import cgi
import io
from decimal import Decimal
from urllib.parse import parse_qs

try:
    from openpyxl import Workbook, load_workbook
    _openpyxl_import_error = None
except Exception as e:
    Workbook = None
    load_workbook = None
    _openpyxl_import_error = str(e)


class AmazonAdMixin:
    """Amazon 广告管理 API 处理器 - 持有11个API handler方法"""

    def handle_amazon_ad_subtype_api(self, environ, method, start_response):
        """Amazon 广告细分类管理 API（CRUD）"""
        try:
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

    _AMAZON_AD_ITEM_SELECT = """
        SELECT
            i.id, i.ad_level, i.sku_family_id, i.portfolio_id, i.campaign_id,
            i.strategy_code, i.subtype_id, i.name, i.is_shared_budget, i.status, i.budget,
            i.created_at, i.updated_at,
            pf.sku_family,
            p.name AS portfolio_name,
            c.name AS campaign_name,
            st.description AS subtype_description,
            st.ad_class,
            st.subtype_code
        FROM amazon_ad_items i
        LEFT JOIN amazon_ad_items p ON i.portfolio_id = p.id AND p.ad_level = 'portfolio'
        LEFT JOIN amazon_ad_items c ON i.campaign_id = c.id AND c.ad_level = 'campaign'
        LEFT JOIN amazon_ad_subtypes st ON i.subtype_id = st.id
        LEFT JOIN product_families pf ON i.sku_family_id = pf.id
    """

    def _normalize_shared_budget(self, value):
        if value is None or value == '':
            return None
        if isinstance(value, bool):
            return 1 if value else 0
        text = str(value).strip()
        if text in ('1', '是', 'true', 'True', 'yes', 'Y'):
            return 1
        if text in ('0', '否', 'false', 'False', 'no', 'N'):
            return 0
        parsed = self._parse_int(value)
        return 1 if parsed else 0

    def _parse_budget_value(self, value):
        if value is None or value == '':
            return None
        if isinstance(value, (int, float, Decimal)):
            return float(value)
        text = str(value).strip()
        if not text:
            return None
        return self._parse_float(text)

    def _serialize_amazon_ad_item(self, row):
        if not row:
            return row
        item = dict(row)
        budget = item.get('budget')
        if isinstance(budget, Decimal):
            item['budget'] = float(budget)
        shared = item.get('is_shared_budget')
        if shared is not None:
            item['is_shared_budget'] = int(shared)
        return item

    def _fetch_amazon_ad_item_by_id(self, cur, item_id):
        cur.execute(self._AMAZON_AD_ITEM_SELECT + ' WHERE i.id=%s LIMIT 1', (item_id,))
        row = cur.fetchone()
        return self._serialize_amazon_ad_item(row) if row else None

    def _validate_amazon_ad_parent_refs(self, cur, ad_level, portfolio_id=None, campaign_id=None):
        if portfolio_id:
            cur.execute(
                "SELECT id FROM amazon_ad_items WHERE id=%s AND ad_level='portfolio' LIMIT 1",
                (portfolio_id,)
            )
            if not cur.fetchone():
                return '归属广告组合不存在'
        if campaign_id:
            cur.execute(
                "SELECT id, portfolio_id FROM amazon_ad_items WHERE id=%s AND ad_level='campaign' LIMIT 1",
                (campaign_id,)
            )
            campaign = cur.fetchone()
            if not campaign:
                return '归属广告活动不存在'
            if portfolio_id and int(campaign.get('portfolio_id') or 0) != int(portfolio_id):
                return '广告活动不属于所选广告组合'
        if ad_level == 'campaign' and not portfolio_id:
            return '请选择归属广告组合'
        if ad_level == 'group' and not campaign_id:
            return '请选择归属广告活动'
        return None

    def _build_amazon_ad_write_fields(self, data, ad_level):
        name = (data.get('name') or '').strip()
        status = (data.get('status') or '').strip() or '启动'
        if not name:
            return None, '名称不能为空'

        fields = {
            'ad_level': ad_level,
            'name': name,
            'status': status,
            'sku_family_id': None,
            'portfolio_id': None,
            'campaign_id': None,
            'strategy_code': None,
            'subtype_id': None,
            'is_shared_budget': None,
            'budget': None,
        }

        if ad_level == 'portfolio':
            sku_family_id = self._parse_int(data.get('sku_family_id'))
            fields['sku_family_id'] = sku_family_id if sku_family_id else None
            fields['is_shared_budget'] = self._normalize_shared_budget(data.get('is_shared_budget'))
            if fields['is_shared_budget'] is None:
                return None, '请设置是否共享预算'
        elif ad_level == 'campaign':
            fields['portfolio_id'] = self._parse_int(data.get('portfolio_id'))
            fields['strategy_code'] = (data.get('strategy_code') or '').strip() or None
            fields['subtype_id'] = self._parse_int(data.get('subtype_id'))
            fields['budget'] = self._parse_budget_value(data.get('budget'))
            if not fields['strategy_code']:
                return None, '请选择策略'
            if not fields['subtype_id']:
                return None, '请选择细分类'
        else:
            fields['portfolio_id'] = self._parse_int(data.get('portfolio_id'))
            fields['campaign_id'] = self._parse_int(data.get('campaign_id'))
            if not fields['campaign_id']:
                return None, '请选择归属广告活动'

        return fields, None

    def handle_amazon_ad_api(self, environ, method, start_response):
        """Amazon 广告 CRUD API（amazon_ad_items）"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                level = (query_params.get('level', [''])[0] or '').strip().lower()
                item_id = self._parse_int((query_params.get('id', [''])[0] or '').strip())

                sql = self._AMAZON_AD_ITEM_SELECT + ' WHERE 1=1'
                params = []

                if item_id:
                    sql += ' AND i.id=%s'
                    params.append(item_id)
                if level in ('portfolio', 'campaign', 'group'):
                    sql += ' AND i.ad_level=%s'
                    params.append(level)
                if keyword:
                    like = f'%{keyword}%'
                    sql += (
                        ' AND ('
                        'i.name LIKE %s OR pf.sku_family LIKE %s OR p.name LIKE %s OR c.name LIKE %s '
                        'OR st.description LIKE %s OR st.subtype_code LIKE %s '
                        "OR CONCAT(IFNULL(st.ad_class,''), '-', IFNULL(st.subtype_code,'')) LIKE %s"
                        ')'
                    )
                    params.extend([like] * 7)

                sql += ' ORDER BY i.id DESC LIMIT 500'

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql, tuple(params))
                        rows = [self._serialize_amazon_ad_item(row) for row in (cur.fetchall() or [])]

                if item_id:
                    return self.send_json({'status': 'success', 'item': rows[0] if rows else None}, start_response)
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)

            if method == 'PATCH':
                item_id = self._parse_int(data.get('id'))
                status = (data.get('status') or '').strip()
                if not item_id or not status:
                    return self.send_json({'status': 'error', 'message': 'Missing id or status'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE amazon_ad_items SET status=%s WHERE id=%s",
                            (status, item_id)
                        )
                        if cur.rowcount <= 0:
                            return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)
                        item = self._fetch_amazon_ad_item_by_id(cur, item_id)
                return self.send_json({'status': 'success', 'item': item}, start_response)

            if method == 'POST':
                ad_level = (data.get('ad_level') or '').strip().lower()
                if ad_level not in ('portfolio', 'campaign', 'group'):
                    return self.send_json({'status': 'error', 'message': '无效的广告类型'}, start_response)
                fields, err = self._build_amazon_ad_write_fields(data, ad_level)
                if err:
                    return self.send_json({'status': 'error', 'message': err}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        parent_err = self._validate_amazon_ad_parent_refs(
                            cur, ad_level, fields.get('portfolio_id'), fields.get('campaign_id')
                        )
                        if parent_err:
                            return self.send_json({'status': 'error', 'message': parent_err}, start_response)

                        if ad_level == 'group' and not fields.get('portfolio_id') and fields.get('campaign_id'):
                            cur.execute(
                                "SELECT portfolio_id FROM amazon_ad_items WHERE id=%s AND ad_level='campaign' LIMIT 1",
                                (fields['campaign_id'],)
                            )
                            campaign = cur.fetchone() or {}
                            fields['portfolio_id'] = campaign.get('portfolio_id')

                        cur.execute(
                            """
                            INSERT INTO amazon_ad_items (
                                ad_level, sku_family_id, portfolio_id, campaign_id,
                                strategy_code, subtype_id, name, is_shared_budget, status, budget
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                fields['ad_level'], fields['sku_family_id'], fields['portfolio_id'],
                                fields['campaign_id'], fields['strategy_code'], fields['subtype_id'],
                                fields['name'], fields['is_shared_budget'], fields['status'], fields['budget']
                            )
                        )
                        new_id = cur.lastrowid
                        item = self._fetch_amazon_ad_item_by_id(cur, new_id)
                return self.send_json({'status': 'success', 'id': new_id, 'item': item}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, ad_level FROM amazon_ad_items WHERE id=%s LIMIT 1",
                            (item_id,)
                        )
                        existing = cur.fetchone()
                        if not existing:
                            return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)

                        ad_level = existing.get('ad_level')
                        fields, err = self._build_amazon_ad_write_fields(data, ad_level)
                        if err:
                            return self.send_json({'status': 'error', 'message': err}, start_response)

                        parent_err = self._validate_amazon_ad_parent_refs(
                            cur, ad_level, fields.get('portfolio_id'), fields.get('campaign_id')
                        )
                        if parent_err:
                            return self.send_json({'status': 'error', 'message': parent_err}, start_response)

                        if ad_level == 'group' and not fields.get('portfolio_id') and fields.get('campaign_id'):
                            cur.execute(
                                "SELECT portfolio_id FROM amazon_ad_items WHERE id=%s AND ad_level='campaign' LIMIT 1",
                                (fields['campaign_id'],)
                            )
                            campaign = cur.fetchone() or {}
                            fields['portfolio_id'] = campaign.get('portfolio_id')

                        cur.execute(
                            """
                            UPDATE amazon_ad_items SET
                                sku_family_id=%s, portfolio_id=%s, campaign_id=%s,
                                strategy_code=%s, subtype_id=%s, name=%s,
                                is_shared_budget=%s, status=%s, budget=%s
                            WHERE id=%s
                            """,
                            (
                                fields['sku_family_id'], fields['portfolio_id'], fields['campaign_id'],
                                fields['strategy_code'], fields['subtype_id'], fields['name'],
                                fields['is_shared_budget'], fields['status'], fields['budget'],
                                item_id
                            )
                        )
                        item = self._fetch_amazon_ad_item_by_id(cur, item_id)
                return self.send_json({'status': 'success', 'item': item}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_items WHERE id=%s", (item_id,))
                        if cur.rowcount <= 0:
                            return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad API error: {str(e)}')
            message = str(e)
            if 'foreign key constraint' in message.lower() or '1451' in message:
                message = '无法删除：该广告记录仍被投放/商品/调整记录引用'
            return self.send_json({'status': 'error', 'message': message}, start_response)

    def handle_amazon_ad_template_api(self, environ, method, start_response):
        """Amazon 广告信息批量导入模板下载"""
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json(
                    {'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'},
                    start_response
                )

            from openpyxl.styles import Font, PatternFill, Alignment

            wb = Workbook()
            ws = wb.active
            ws.title = 'amazon_ad_items'
            headers = [
                '广告类型*', '名称*', '状态*',
                '关联货号', '是否共享预算',
                '归属广告组合名称', '策略', '细分类',
                '预算', '归属广告活动名称'
            ]
            ws.append(headers)
            ws.append([
                '广告组合', '示例-Short-SKU01', '启动',
                'SKU01', '是',
                '', '', '',
                '', ''
            ])
            ws.append([
                '广告活动', 'BE-示例组合-SP-KW', '启动',
                '', '',
                '示例-Short-SKU01', 'BE', 'SP-KW',
                '50', ''
            ])
            ws.append([
                '广告组', 'BE-示例组合-SP-KW', '启动',
                '', '',
                '示例-Short-SKU01', '', '',
                '', 'BE-示例组合-SP-KW'
            ])
            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            ws.freeze_panes = 'A2'
            return self._send_excel_workbook(wb, 'amazon_ad_items_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_import_api(self, environ, method, start_response):
        """Amazon 广告信息批量导入"""
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json(
                    {'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'},
                    start_response
                )

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

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active
            headers = [str(cell.value or '').strip() for cell in ws[1]]
            header_map = {name: idx for idx, name in enumerate(headers)}

            def cell_value(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                value = row[idx].value
                return None if value is None else str(value).strip()

            level_map = {
                '广告组合': 'portfolio', 'portfolio': 'portfolio',
                '广告活动': 'campaign', 'campaign': 'campaign',
                '广告组': 'group', 'group': 'group',
            }

            created = updated = unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    portfolio_by_name = {}
                    campaign_by_name = {}
                    cur.execute("SELECT id, name FROM amazon_ad_items WHERE ad_level='portfolio'")
                    for row in cur.fetchall() or []:
                        portfolio_by_name[str(row.get('name') or '').strip()] = row['id']
                    cur.execute("SELECT id, name, portfolio_id FROM amazon_ad_items WHERE ad_level='campaign'")
                    for row in cur.fetchall() or []:
                        campaign_by_name[str(row.get('name') or '').strip()] = row

                    subtype_by_key = {}
                    cur.execute("SELECT id, ad_class, subtype_code, description FROM amazon_ad_subtypes")
                    for row in cur.fetchall() or []:
                        key = f"{row.get('ad_class')}-{row.get('subtype_code')}"
                        subtype_by_key[key] = row['id']
                        subtype_by_key[str(row.get('description') or '').strip()] = row['id']

                    sku_by_family = {}
                    cur.execute("SELECT id, sku_family FROM product_families")
                    for row in cur.fetchall() or []:
                        sku_by_family[str(row.get('sku_family') or '').strip()] = row['id']

                    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=False), start=2):
                        level_raw = cell_value(row, '广告类型*') or ''
                        ad_level = level_map.get(level_raw.lower()) or level_map.get(level_raw)
                        name = cell_value(row, '名称*') or ''
                        status = cell_value(row, '状态*') or '启动'
                        if not level_raw and not name:
                            continue
                        if not ad_level or not name:
                            errors.append({'row': row_idx, 'message': '广告类型或名称为空'})
                            continue

                        payload = {
                            'ad_level': ad_level,
                            'name': name,
                            'status': status,
                        }

                        if ad_level == 'portfolio':
                            sku_family = cell_value(row, '关联货号') or ''
                            if sku_family:
                                payload['sku_family_id'] = sku_by_family.get(sku_family)
                            payload['is_shared_budget'] = cell_value(row, '是否共享预算') or '是'
                        elif ad_level == 'campaign':
                            portfolio_name = cell_value(row, '归属广告组合名称') or ''
                            payload['portfolio_id'] = portfolio_by_name.get(portfolio_name)
                            payload['strategy_code'] = cell_value(row, '策略') or ''
                            subtype_text = cell_value(row, '细分类') or ''
                            payload['subtype_id'] = subtype_by_key.get(subtype_text)
                            payload['budget'] = cell_value(row, '预算') or ''
                            if not payload['portfolio_id']:
                                errors.append({'row': row_idx, 'message': f'未找到广告组合: {portfolio_name}'})
                                continue
                            if not payload['subtype_id']:
                                errors.append({'row': row_idx, 'message': f'未找到细分类: {subtype_text}'})
                                continue
                        else:
                            campaign_name = cell_value(row, '归属广告活动名称') or ''
                            campaign = campaign_by_name.get(campaign_name)
                            if not campaign:
                                errors.append({'row': row_idx, 'message': f'未找到广告活动: {campaign_name}'})
                                continue
                            payload['campaign_id'] = campaign['id']
                            payload['portfolio_id'] = campaign.get('portfolio_id')

                        fields, err = self._build_amazon_ad_write_fields(payload, ad_level)
                        if err:
                            errors.append({'row': row_idx, 'message': err})
                            continue

                        cur.execute(
                            "SELECT id FROM amazon_ad_items WHERE ad_level=%s AND name=%s LIMIT 1",
                            (ad_level, fields['name'])
                        )
                        existing = cur.fetchone()
                        if existing:
                            cur.execute(
                                """
                                UPDATE amazon_ad_items SET
                                    sku_family_id=%s, portfolio_id=%s, campaign_id=%s,
                                    strategy_code=%s, subtype_id=%s,
                                    is_shared_budget=%s, status=%s, budget=%s
                                WHERE id=%s
                                """,
                                (
                                    fields['sku_family_id'], fields['portfolio_id'], fields['campaign_id'],
                                    fields['strategy_code'], fields['subtype_id'],
                                    fields['is_shared_budget'], fields['status'], fields['budget'],
                                    existing['id']
                                )
                            )
                            updated += 1
                        else:
                            cur.execute(
                                """
                                INSERT INTO amazon_ad_items (
                                    ad_level, sku_family_id, portfolio_id, campaign_id,
                                    strategy_code, subtype_id, name, is_shared_budget, status, budget
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                                (
                                    fields['ad_level'], fields['sku_family_id'], fields['portfolio_id'],
                                    fields['campaign_id'], fields['strategy_code'], fields['subtype_id'],
                                    fields['name'], fields['is_shared_budget'], fields['status'], fields['budget']
                                )
                            )
                            new_id = cur.lastrowid
                            created += 1
                            if ad_level == 'portfolio':
                                portfolio_by_name[fields['name']] = new_id
                            elif ad_level == 'campaign':
                                campaign_by_name[fields['name']] = {
                                    'id': new_id,
                                    'portfolio_id': fields['portfolio_id'],
                                }

            return self.send_json(
                {
                    'status': 'success',
                    'created': created,
                    'updated': updated,
                    'unchanged': unchanged,
                    'errors': errors,
                },
                start_response
            )
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_amazon_ad_delivery_api(self, environ, method, start_response):
        """Amazon 广告配送 API"""
        try:
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
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT * FROM amazon_keywords ORDER BY id DESC LIMIT 500")
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

