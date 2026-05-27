# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin - 包含11个API处理器"""

import cgi
import io
from datetime import datetime, timedelta
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

    def _parse_apply_flag(self, value, default=1):
        if value is None or value == '':
            return 1 if default else 0
        if isinstance(value, bool):
            return 1 if value else 0
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'y', '是'):
            return 1
        if text in ('0', 'false', 'no', 'n', '否'):
            return 0
        parsed = self._parse_int(value)
        return 1 if parsed else 0

    def _serialize_operation_type_row(self, row, reasons=None):
        item = dict(row) if row else {}
        item['reasons'] = list(reasons or [])
        for key in ('apply_portfolio', 'apply_campaign', 'apply_group'):
            if key in item and item[key] is not None:
                item[key] = int(item[key])
        return item

    def _fetch_all_operation_types_with_reasons(self, cur):
        cur.execute("SELECT * FROM amazon_ad_operation_types ORDER BY id DESC LIMIT 500")
        rows = cur.fetchall() or []
        if not rows:
            return []
        type_ids = [int(r['id']) for r in rows if r.get('id') is not None]
        reasons_by_type = {tid: [] for tid in type_ids}
        if type_ids:
            placeholders = ','.join(['%s'] * len(type_ids))
            cur.execute(
                "SELECT id, operation_type_id, reason_name FROM amazon_ad_operation_reasons "
                f"WHERE operation_type_id IN ({placeholders}) ORDER BY id ASC",
                tuple(type_ids),
            )
            for rr in cur.fetchall() or []:
                tid = int(rr['operation_type_id'])
                reasons_by_type.setdefault(tid, []).append({
                    'id': rr['id'],
                    'reason_name': rr.get('reason_name') or '',
                })
        return [
            self._serialize_operation_type_row(r, reasons_by_type.get(int(r['id']), []))
            for r in rows
        ]

    def _sync_operation_type_reasons(self, cur, operation_type_id, reasons_payload):
        cur.execute(
            "DELETE FROM amazon_ad_operation_reasons WHERE operation_type_id=%s",
            (operation_type_id,),
        )
        seen = set()
        for raw in reasons_payload or []:
            if isinstance(raw, str):
                name = raw.strip()
            elif isinstance(raw, dict):
                name = (raw.get('reason_name') or '').strip()
            else:
                name = ''
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            cur.execute(
                "INSERT INTO amazon_ad_operation_reasons (operation_type_id, reason_name) VALUES (%s, %s)",
                (operation_type_id, name),
            )

    def handle_amazon_ad_operation_type_api(self, environ, method, start_response):
        """Amazon 广告操作类型 API（含操作原因 CRUD）"""
        try:
            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        items = self._fetch_all_operation_types_with_reasons(cur)
                return self.send_json({'status': 'success', 'items': items}, start_response)

            data = self._read_json_body(environ)

            if method == 'POST':
                name = (data.get('name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': '请填写操作名称'}, start_response)
                apply_portfolio = self._parse_apply_flag(data.get('apply_portfolio'), 1)
                apply_campaign = self._parse_apply_flag(data.get('apply_campaign'), 1)
                apply_group = self._parse_apply_flag(data.get('apply_group'), 1)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_operation_types (
                                name, apply_portfolio, apply_campaign, apply_group
                            ) VALUES (%s, %s, %s, %s)
                            """,
                            (name, apply_portfolio, apply_campaign, apply_group),
                        )
                        new_id = cur.lastrowid
                        self._sync_operation_type_reasons(cur, new_id, data.get('reasons'))
                    conn.commit()
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                batch_items = data.get('items')
                if isinstance(batch_items, list):
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            for it in batch_items:
                                if not isinstance(it, dict):
                                    continue
                                item_id = self._parse_int(it.get('id'))
                                if not item_id:
                                    continue
                                cur.execute(
                                    """
                                    UPDATE amazon_ad_operation_types
                                    SET apply_portfolio=%s, apply_campaign=%s, apply_group=%s
                                    WHERE id=%s
                                    """,
                                    (
                                        self._parse_apply_flag(it.get('apply_portfolio'), 1),
                                        self._parse_apply_flag(it.get('apply_campaign'), 1),
                                        self._parse_apply_flag(it.get('apply_group'), 1),
                                        item_id,
                                    ),
                                )
                        conn.commit()
                    return self.send_json({'status': 'success'}, start_response)

                item_id = self._parse_int(data.get('id'))
                name = (data.get('name') or '').strip()
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                if not name:
                    return self.send_json({'status': 'error', 'message': '请填写操作名称'}, start_response)
                apply_portfolio = self._parse_apply_flag(data.get('apply_portfolio'), 1)
                apply_campaign = self._parse_apply_flag(data.get('apply_campaign'), 1)
                apply_group = self._parse_apply_flag(data.get('apply_group'), 1)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id FROM amazon_ad_operation_types WHERE id=%s LIMIT 1",
                            (item_id,),
                        )
                        if not cur.fetchone():
                            return self.send_json({'status': 'error', 'message': '操作类型不存在'}, start_response)
                        cur.execute(
                            """
                            UPDATE amazon_ad_operation_types
                            SET name=%s, apply_portfolio=%s, apply_campaign=%s, apply_group=%s
                            WHERE id=%s
                            """,
                            (name, apply_portfolio, apply_campaign, apply_group, item_id),
                        )
                        # 仅改操作原因时字段未变，MySQL 可能 rowcount=0，不能据此判不存在
                        self._sync_operation_type_reasons(cur, item_id, data.get('reasons'))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_operation_types WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

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

    def _amazon_ad_items_template_headers(self):
        """导入模板列顺序：归属两列置于最右侧。"""
        return [
            '广告类型*', '名称*', '状态*',
            '关联货号', '是否共享预算',
            '策略', '细分类', '预算',
            '归属广告组合名称', '归属广告活动名称',
        ]

    def _apply_amazon_ad_items_template_formatting(self, ws, last_row=1000):
        """下拉预设 + 按广告类型对不适用字段加灰色底纹（条件格式）。"""
        from openpyxl.styles import Font, PatternFill, Alignment
        from openpyxl.formatting.rule import FormulaRule
        from openpyxl.worksheet.datavalidation import DataValidation

        header_fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
        gray_fill = PatternFill(start_color='E8E8E8', end_color='E8E8E8', fill_type='solid')
        for cell in ws[1]:
            cell.fill = header_fill
            cell.font = Font(bold=True, color='2A2420')
            cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

        data_end = max(2, int(last_row or 1000))
        dv_level = DataValidation(type='list', formula1='"组合,活动,组"', allow_blank=False)
        dv_level.error = '请从列表选择：组合 / 活动 / 组'
        dv_level.errorTitle = '广告类型'
        ws.add_data_validation(dv_level)
        dv_level.add(f'A2:A{data_end}')

        dv_status = DataValidation(type='list', formula1='"启动,暂停,存档"', allow_blank=False)
        dv_status.error = '请从列表选择：启动 / 暂停 / 存档'
        dv_status.errorTitle = '状态'
        ws.add_data_validation(dv_status)
        dv_status.add(f'C2:C{data_end}')

        dv_shared = DataValidation(type='list', formula1='"是,否"', allow_blank=True)
        dv_shared.error = '请从列表选择：是 / 否'
        dv_shared.errorTitle = '是否共享预算'
        ws.add_data_validation(dv_shared)
        dv_shared.add(f'E2:E{data_end}')

        # 条件格式：公式为真时显示灰色（表示当前行广告类型下该列无需填写）
        # 组合：仅 关联货号、是否共享预算；活动：策略/细分类/预算/归属组合；组：仅归属活动
        rules = [
            ('D', 'OR($A2="",$A2<>"组合")'),           # 关联货号
            ('E', 'OR($A2="",$A2<>"组合")'),           # 是否共享预算
            ('F', 'OR($A2="",$A2<>"活动")'),           # 策略
            ('G', 'OR($A2="",$A2<>"活动")'),           # 细分类
            ('H', 'OR($A2="",$A2<>"活动")'),           # 预算
            ('I', 'OR($A2="",$A2<>"活动")'),           # 归属广告组合
            ('J', 'OR($A2="",$A2<>"组")'),              # 归属广告活动
        ]
        for col, formula in rules:
            ws.conditional_formatting.add(
                f'{col}2:{col}{data_end}',
                FormulaRule(formula=[formula], fill=gray_fill),
            )

        ws.freeze_panes = 'A2'
        widths = {
            'A': 11, 'B': 28, 'C': 9, 'D': 14, 'E': 14,
            'F': 8, 'G': 12, 'H': 10, 'I': 22, 'J': 26,
        }
        for col, width in widths.items():
            ws.column_dimensions[col].width = width

    def _build_amazon_ad_items_import_workbook(self):
        from openpyxl import Workbook

        wb = Workbook()
        ws = wb.active
        ws.title = '广告信息'
        headers = self._amazon_ad_items_template_headers()
        ws.append(headers)
        ws.append([
            '组合', '示例-Short-SKU01', '启动',
            'SKU01', '是',
            '', '', '',
            '', '',
        ])
        ws.append([
            '活动', 'BE-示例组合-SP-KW', '启动',
            '', '',
            'BE', 'SP-KW', '50',
            '示例-Short-SKU01', '',
        ])
        ws.append([
            '组', 'BE-示例组合-SP-KW', '启动',
            '', '',
            '', '', '',
            '', 'BE-示例组合-SP-KW',
        ])
        self._apply_amazon_ad_items_template_formatting(ws)

        guide = wb.create_sheet('填写说明')
        guide.append(['字段', '组合', '活动', '组', '说明'])
        guide_rows = [
            ('广告类型*', '必填', '必填', '必填', '下拉：组合 / 活动 / 组'),
            ('名称*', '必填', '必填', '必填', ''),
            ('状态*', '必填', '必填', '必填', '下拉：启动 / 暂停 / 存档'),
            ('关联货号', '选填', '—', '—', '仅组合可填；灰底表示本行不适用'),
            ('是否共享预算', '必填', '—', '—', '仅组合可填；下拉：是 / 否'),
            ('策略', '—', '必填', '—', '仅活动可填'),
            ('细分类', '—', '必填', '—', '仅活动可填（须与系统细分类一致）'),
            ('预算', '—', '必填', '—', '仅活动可填'),
            ('归属广告组合名称', '—', '必填', '—', '仅活动可填（须已存在）'),
            ('归属广告活动名称', '—', '—', '必填', '仅组可填（须已存在）'),
        ]
        for row in guide_rows:
            guide.append(list(row))
        guide.column_dimensions['A'].width = 18
        guide.column_dimensions['B'].width = 8
        guide.column_dimensions['C'].width = 8
        guide.column_dimensions['D'].width = 8
        guide.column_dimensions['E'].width = 42
        return wb

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
            wb = self._build_amazon_ad_items_import_workbook()
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
                '广告组合': 'portfolio', 'portfolio': 'portfolio', '组合': 'portfolio',
                '广告活动': 'campaign', 'campaign': 'campaign', '活动': 'campaign',
                '广告组': 'group', 'group': 'group', '组': 'group',
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

    def _parse_datetime_local_value(self, value):
        text = (value or '').strip()
        if not text:
            return None
        if 'T' in text and len(text) == 16:
            text = text + ':00'
        return text.replace('T', ' ')

    def _serialize_adjustment_ad_list_item(self, row):
        level = row.get('ad_level')
        ad_class = row.get('ad_class') or ''
        subtype_code = row.get('subtype_code') or ''
        if ad_class and subtype_code:
            ad_type_text = f'{ad_class}-{subtype_code}'
        else:
            ad_type_text = row.get('subtype_description') or ''
        name = row.get('name') or ''
        portfolio_name = row.get('portfolio_name') or ''
        campaign_name = row.get('campaign_name') or ''
        return {
            'id': row.get('id'),
            'ad_name': name,
            'ad_level': level,
            'status': row.get('status') or '启动',
            'ad_type_text': ad_type_text,
            'portfolio_name': portfolio_name,
            'campaign_name': campaign_name if level == 'group' else (name if level == 'campaign' else ''),
            'group_name': name if level == 'group' else '',
        }

    def _fetch_adjustment_ad_info(self, cur, ad_item_id):
        cur.execute(self._AMAZON_AD_ITEM_SELECT + ' WHERE i.id=%s LIMIT 1', (ad_item_id,))
        row = cur.fetchone()
        if not row:
            return None, None
        item = self._serialize_amazon_ad_item(row)
        level = item.get('ad_level')
        ad_class = item.get('ad_class') or ''
        subtype_code = item.get('subtype_code') or ''
        if ad_class and subtype_code:
            ad_type_text = f'{ad_class}-{subtype_code}'
        else:
            ad_type_text = item.get('subtype_description') or ''
        ad_info = {
            'ad_type_text': ad_type_text,
            'portfolio_name': item.get('portfolio_name') or '',
            'campaign_name': item.get('campaign_name') if level == 'group' else (item.get('name') if level == 'campaign' else ''),
            'group_name': item.get('name') if level == 'group' else '',
        }
        return item, ad_info

    def _fetch_allowed_operations_for_ad(self, cur, ad_row):
        if not ad_row:
            return []
        level = ad_row.get('ad_level')
        subtype_id = ad_row.get('subtype_id')
        if level == 'group' and ad_row.get('campaign_id'):
            cur.execute(
                "SELECT subtype_id FROM amazon_ad_items WHERE id=%s AND ad_level='campaign' LIMIT 1",
                (ad_row.get('campaign_id'),)
            )
            camp = cur.fetchone() or {}
            subtype_id = camp.get('subtype_id') or subtype_id

        if subtype_id:
            cur.execute(
                """
                SELECT ot.id, ot.name, ot.apply_campaign, ot.apply_group
                FROM amazon_ad_operation_types ot
                INNER JOIN amazon_ad_subtype_operation_types link ON link.operation_type_id = ot.id
                WHERE link.subtype_id = %s
                ORDER BY ot.id ASC
                """,
                (subtype_id,)
            )
        elif level == 'campaign':
            cur.execute(
                "SELECT id, name, apply_campaign, apply_group FROM amazon_ad_operation_types "
                "WHERE apply_campaign=1 ORDER BY id ASC"
            )
        else:
            cur.execute(
                "SELECT id, name, apply_campaign, apply_group FROM amazon_ad_operation_types "
                "WHERE apply_group=1 ORDER BY id ASC"
            )
        ops = cur.fetchall() or []
        result = []
        for op in ops:
            if level == 'campaign' and not int(op.get('apply_campaign') or 0):
                continue
            if level == 'group' and not int(op.get('apply_group') or 0):
                continue
            cur.execute(
                "SELECT id, reason_name FROM amazon_ad_operation_reasons "
                "WHERE operation_type_id=%s ORDER BY id ASC",
                (op['id'],)
            )
            reasons = [
                {'id': r['id'], 'reason_name': r.get('reason_name') or ''}
                for r in (cur.fetchall() or [])
            ]
            result.append({
                'id': op['id'],
                'name': op.get('name') or '',
                'reasons': reasons,
            })
        return result

    def _adjustment_defaults_for_ad(self, cur, ad_item_id):
        now = datetime.now().replace(second=0, microsecond=0)
        cur.execute(
            """
            SELECT adjust_date, end_time FROM amazon_ad_adjustments
            WHERE ad_item_id=%s ORDER BY id DESC LIMIT 1
            """,
            (ad_item_id,)
        )
        last = cur.fetchone() or {}
        end_time = last.get('end_time')
        if end_time and not isinstance(end_time, datetime):
            try:
                end_time = datetime.fromisoformat(str(end_time).replace(' ', 'T', 1))
            except Exception:
                end_time = None
        if isinstance(end_time, datetime):
            start_time = end_time
            end_default = end_time + timedelta(days=7)
        else:
            start_time = now - timedelta(days=7)
            end_default = now
        return {
            'adjust_date': now.strftime('%Y-%m-%d %H:%M:%S'),
            'start_time': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'end_time': end_default.strftime('%Y-%m-%d %H:%M:%S'),
        }

    def handle_amazon_ad_adjustment_api(self, environ, method, start_response):
        """Amazon 广告调整 API（广告搜索 / 默认值 / 调整记录 CRUD）"""
        try:
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query_params.get('action', [''])[0] or '').strip().lower()

            if method == 'GET' and action == 'ad-search':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            self._AMAZON_AD_ITEM_SELECT
                            + " WHERE i.ad_level IN ('campaign', 'group') ORDER BY i.id DESC LIMIT 500"
                        )
                        rows = cur.fetchall() or []
                items = [self._serialize_adjustment_ad_list_item(r) for r in rows]
                return self.send_json({'status': 'success', 'items': items}, start_response)

            if method == 'GET' and action == 'defaults':
                ad_item_id = self._parse_int((query_params.get('ad_item_id', [''])[0] or '').strip())
                if not ad_item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing ad_item_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        ad_row, ad_info = self._fetch_adjustment_ad_info(cur, ad_item_id)
                        if not ad_row:
                            return self.send_json({'status': 'error', 'message': '广告不存在'}, start_response)
                        allowed_operations = self._fetch_allowed_operations_for_ad(cur, ad_row)
                        defaults = self._adjustment_defaults_for_ad(cur, ad_item_id)
                return self.send_json({
                    'status': 'success',
                    'ad_info': ad_info,
                    'allowed_operations': allowed_operations,
                    'defaults': defaults,
                }, start_response)

            if method == 'GET':
                ad_item_id = self._parse_int((query_params.get('ad_item_id', [''])[0] or '').strip())
                sql = """
                    SELECT
                        a.*,
                        i.name AS ad_name,
                        i.ad_level,
                        ot.name AS operation_name,
                        r.reason_name
                    FROM amazon_ad_adjustments a
                    INNER JOIN amazon_ad_items i ON i.id = a.ad_item_id
                    LEFT JOIN amazon_ad_operation_types ot ON ot.id = a.operation_type_id
                    LEFT JOIN amazon_ad_operation_reasons r ON r.id = a.reason_id
                    WHERE 1=1
                """
                params = []
                if ad_item_id:
                    sql += ' AND a.ad_item_id=%s'
                    params.append(ad_item_id)
                sql += ' ORDER BY a.id DESC LIMIT 500'
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(sql, tuple(params))
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)

            if method == 'POST':
                ad_item_id = self._parse_int(data.get('ad_item_id'))
                operation_type_id = self._parse_int(data.get('operation_type_id'))
                reason_id = self._parse_int(data.get('reason_id'))
                target_object = (data.get('target_object') or '').strip()
                is_quick = int(data.get('is_quick_submit') or 0)
                if not ad_item_id or not operation_type_id or not target_object:
                    return self.send_json({'status': 'error', 'message': '缺少必填字段'}, start_response)
                if not is_quick:
                    for field in ('before_value', 'after_value', 'start_time', 'end_time'):
                        if not (data.get(field) or '').strip():
                            return self.send_json({'status': 'error', 'message': '完整提交请填写修改前/后及效果区间时间'}, start_response)

                adjust_date = self._parse_datetime_local_value(data.get('adjust_date')) or datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_adjustments (
                                adjust_date, ad_item_id, operation_type_id, target_object,
                                before_value, after_value, reason_id,
                                start_time, end_time,
                                impressions, clicks, cost, orders, sales,
                                acos, cpc, ctr, cvr, top_of_search_is,
                                attribution_checked, attribution_orders, attribution_sales,
                                remark, is_quick_submit
                            ) VALUES (
                                %s, %s, %s, %s,
                                %s, %s, %s,
                                %s, %s,
                                %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s,
                                %s, %s, %s,
                                %s, %s
                            )
                            """,
                            (
                                adjust_date, ad_item_id, operation_type_id, target_object,
                                (data.get('before_value') or '').strip() or None,
                                (data.get('after_value') or '').strip() or None,
                                reason_id,
                                self._parse_datetime_local_value(data.get('start_time')),
                                self._parse_datetime_local_value(data.get('end_time')),
                                (data.get('impressions') or '').strip() or None,
                                (data.get('clicks') or '').strip() or None,
                                (data.get('cost') or '').strip() or None,
                                (data.get('orders') or '').strip() or None,
                                (data.get('sales') or '').strip() or None,
                                (data.get('acos') or '').strip() or None,
                                (data.get('cpc') or '').strip() or None,
                                (data.get('ctr') or '').strip() or None,
                                (data.get('cvr') or '').strip() or None,
                                (data.get('top_of_search_is') or '').strip() or None,
                                1 if str(data.get('attribution_checked') or '0') == '1' else 0,
                                (data.get('attribution_orders') or '').strip() or None,
                                (data.get('attribution_sales') or '').strip() or None,
                                (data.get('remark') or '').strip() or None,
                                is_quick,
                            )
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM amazon_ad_adjustments WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad adjustment API error: {str(e)}')
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

