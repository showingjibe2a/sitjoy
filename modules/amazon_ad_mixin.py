# -*- coding: utf-8 -*-
"""Amazon 广告管理 Mixin - 包含11个API处理器"""

import cgi
import io
import json
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

    def _parse_subtype_operation_type_ids(self, data):
        raw = data.get('operation_type_ids') if isinstance(data, dict) else None
        if not isinstance(raw, list):
            return []
        out = []
        for x in raw:
            oid = self._parse_int(x)
            if oid and oid > 0:
                out.append(int(oid))
        return sorted(set(out))

    def _sync_amazon_ad_subtype_operation_types(self, cur, subtype_id, operation_type_ids):
        sid = self._parse_int(subtype_id)
        if not sid:
            return
        cur.execute('DELETE FROM amazon_ad_subtype_operation_types WHERE subtype_id=%s', (sid,))
        for oid in operation_type_ids or []:
            cur.execute(
                'INSERT INTO amazon_ad_subtype_operation_types (subtype_id, operation_type_id) VALUES (%s, %s)',
                (sid, int(oid)),
            )

    def _attach_subtype_operation_type_ids(self, cur, rows):
        if not rows:
            return []
        ids = [self._parse_int(r.get('id')) for r in rows if self._parse_int(r.get('id'))]
        if not ids:
            return [dict(r) for r in rows]
        placeholders = ','.join(['%s'] * len(ids))
        cur.execute(
            f'SELECT subtype_id, operation_type_id FROM amazon_ad_subtype_operation_types '
            f'WHERE subtype_id IN ({placeholders})',
            tuple(ids),
        )
        by_subtype = {}
        for row in cur.fetchall() or []:
            sid = self._parse_int(row.get('subtype_id'))
            oid = self._parse_int(row.get('operation_type_id'))
            if sid and oid:
                by_subtype.setdefault(sid, []).append(oid)
        out = []
        for r in rows:
            item = dict(r)
            sid = self._parse_int(item.get('id'))
            item['operation_type_ids'] = by_subtype.get(sid, [])
            out.append(item)
        return out

    def _validate_amazon_ad_subtype_payload(self, cur, description, ad_class, subtype_code, exclude_id=None):
        description = (description or '').strip()
        ad_class = (ad_class or 'SP').strip().upper() or 'SP'
        subtype_code = (subtype_code or '').strip()
        if not description:
            return None, '请填写描述'
        if not subtype_code:
            return None, '请填写细分简称'
        sql = (
            'SELECT id FROM amazon_ad_subtypes WHERE ad_class=%s AND subtype_code=%s'
        )
        params = [ad_class, subtype_code]
        if exclude_id:
            sql += ' AND id<>%s'
            params.append(int(exclude_id))
        sql += ' LIMIT 1'
        cur.execute(sql, tuple(params))
        if cur.fetchone():
            return None, f'该广告大类（{ad_class}）下细分简称「{subtype_code}」已存在'
        return {
            'description': description,
            'ad_class': ad_class,
            'subtype_code': subtype_code,
        }, None

    def handle_amazon_ad_subtype_api(self, environ, method, start_response):
        """Amazon 广告细分类管理 API（CRUD）"""
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            
            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = 'SELECT * FROM amazon_ad_subtypes WHERE 1=1'
                        params = []
                        if keyword:
                            like = f'%{keyword}%'
                            sql += (
                                ' AND (description LIKE %s OR ad_class LIKE %s OR subtype_code LIKE %s'
                                " OR CONCAT(ad_class, '-', subtype_code) LIKE %s)"
                            )
                            params.extend([like, like, like, like])
                        sql += ' ORDER BY id DESC LIMIT 500'
                        cur.execute(sql, tuple(params))
                        rows = self._attach_subtype_operation_type_ids(cur, cur.fetchall() or [])
                return self.send_json({'status': 'success', 'items': rows}, start_response)
                
            if method == 'POST':
                data = self._read_json_body(environ) or {}
                op_ids = self._parse_subtype_operation_type_ids(data)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        fields, err = self._validate_amazon_ad_subtype_payload(
                            cur,
                            data.get('description'),
                            data.get('ad_class'),
                            data.get('subtype_code'),
                        )
                        if err:
                            return self.send_json({'status': 'error', 'message': err}, start_response)
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_subtypes (description, ad_class, subtype_code)
                            VALUES (%s, %s, %s)
                            """,
                            (fields['description'], fields['ad_class'], fields['subtype_code']),
                        )
                        new_id = cur.lastrowid
                        self._sync_amazon_ad_subtype_operation_types(cur, new_id, op_ids)
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ) or {}
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                op_ids = self._parse_subtype_operation_type_ids(data)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute('SELECT id FROM amazon_ad_subtypes WHERE id=%s LIMIT 1', (item_id,))
                        if not cur.fetchone():
                            return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)
                        fields, err = self._validate_amazon_ad_subtype_payload(
                            cur,
                            data.get('description'),
                            data.get('ad_class'),
                            data.get('subtype_code'),
                            exclude_id=item_id,
                        )
                        if err:
                            return self.send_json({'status': 'error', 'message': err}, start_response)
                        cur.execute(
                            """
                            UPDATE amazon_ad_subtypes
                            SET description=%s, ad_class=%s, subtype_code=%s
                            WHERE id=%s
                            """,
                            (
                                fields['description'],
                                fields['ad_class'],
                                fields['subtype_code'],
                                item_id,
                            ),
                        )
                        self._sync_amazon_ad_subtype_operation_types(cur, item_id, op_ids)
                return self.send_json({'status': 'success', 'id': item_id}, start_response)
            
            if method == 'DELETE':
                data = self._read_json_body(environ) or {}
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute('DELETE FROM amazon_ad_subtypes WHERE id=%s', (item_id,))
                        if cur.rowcount <= 0:
                            return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)
                return self.send_json({'status': 'success'}, start_response)
                
            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            print(f'Amazon ad subtype API error: {str(e)}')
            message = str(e)
            if 'uniq_ad_subtype' in message.lower() or 'duplicate' in message.lower():
                message = '该广告大类下细分简称已存在'
            return self.send_json({'status': 'error', 'message': message}, start_response)

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

    def _parse_operation_type_reason_names(self, value):
        if value is None or value == '':
            return []
        if isinstance(value, list):
            names = value
        else:
            text = str(value).strip()
            if not text:
                return []
            try:
                parsed = json.loads(text)
                names = parsed if isinstance(parsed, list) else []
            except Exception:
                names = [part.strip() for part in text.split('\n') if part.strip()]
        out = []
        seen = set()
        for raw in names:
            name = (raw if isinstance(raw, str) else (raw.get('reason_name') if isinstance(raw, dict) else ''))
            name = str(name or '').strip()
            if not name:
                continue
            key = name.lower()
            if key in seen:
                continue
            seen.add(key)
            out.append(name)
        return out

    def _normalize_operation_type_reasons_payload(self, payload):
        if payload is None:
            return []
        if isinstance(payload, list):
            return self._parse_operation_type_reason_names(payload)
        return []

    def _encode_operation_type_reason_names(self, names):
        cleaned = self._parse_operation_type_reason_names(names)
        return json.dumps(cleaned, ensure_ascii=False) if cleaned else None

    def _serialize_operation_type_row(self, row):
        item = dict(row) if row else {}
        reason_names = self._parse_operation_type_reason_names(item.pop('reason_names', None))
        item['reasons'] = [{'reason_name': name} for name in reason_names]
        for key in ('apply_portfolio', 'apply_campaign', 'apply_group'):
            if key in item and item[key] is not None:
                item[key] = int(item[key])
        return item

    def _fetch_all_operation_types_with_reasons(self, cur):
        cur.execute("SELECT * FROM amazon_ad_operation_types ORDER BY id DESC LIMIT 500")
        return [self._serialize_operation_type_row(r) for r in (cur.fetchall() or [])]

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
                reason_names = self._encode_operation_type_reason_names(
                    self._normalize_operation_type_reasons_payload(data.get('reasons'))
                )
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO amazon_ad_operation_types (
                                name, apply_portfolio, apply_campaign, apply_group, reason_names
                            ) VALUES (%s, %s, %s, %s, %s)
                            """,
                            (name, apply_portfolio, apply_campaign, apply_group, reason_names),
                        )
                        new_id = cur.lastrowid
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
                reason_names = self._encode_operation_type_reason_names(
                    self._normalize_operation_type_reasons_payload(data.get('reasons'))
                )
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
                            SET name=%s, apply_portfolio=%s, apply_campaign=%s, apply_group=%s,
                                reason_names=%s
                            WHERE id=%s
                            """,
                            (name, apply_portfolio, apply_campaign, apply_group, reason_names, item_id),
                        )
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
            i.id, i.ad_level, i.sku_family_id, i.shop_id, i.portfolio_id, i.campaign_id,
            i.strategy_code, i.subtype_id, i.name, i.is_shared_budget, i.status, i.budget,
            i.created_at, i.updated_at,
            pf.sku_family,
            sh.shop_name,
            p.name AS portfolio_name,
            c.name AS campaign_name,
            st.description AS subtype_description,
            st.ad_class,
            st.subtype_code
        FROM amazon_ad_items i
        LEFT JOIN amazon_ad_items c ON i.campaign_id = c.id AND c.ad_level = 'campaign'
        LEFT JOIN amazon_ad_items p ON p.id = COALESCE(NULLIF(i.portfolio_id, 0), c.portfolio_id)
            AND p.ad_level = 'portfolio'
        LEFT JOIN amazon_ad_subtypes st ON i.subtype_id = st.id
        LEFT JOIN product_families pf ON i.sku_family_id = pf.id
        LEFT JOIN shops sh ON sh.id = i.shop_id
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

    def _inherit_campaign_fields_from_portfolio(self, cur, fields):
        """广告活动从归属组合继承 sku_family_id。"""
        if fields.get('ad_level') != 'campaign':
            return
        portfolio_id = fields.get('portfolio_id')
        if not portfolio_id:
            return
        cur.execute(
            """
            SELECT sku_family_id
            FROM amazon_ad_items WHERE id=%s AND ad_level='portfolio' LIMIT 1
            """,
            (portfolio_id,),
        )
        portfolio = cur.fetchone() or {}
        if portfolio.get('sku_family_id'):
            fields['sku_family_id'] = portfolio.get('sku_family_id')

    def _inherit_campaign_fields_from_portfolio_record(self, fields, portfolio_row):
        if fields.get('ad_level') != 'campaign' or not portfolio_row:
            return
        if portfolio_row.get('sku_family_id'):
            fields['sku_family_id'] = portfolio_row.get('sku_family_id')

    def _inherit_group_fields_from_campaign(self, cur, fields):
        """广告组从归属活动继承 portfolio_id / strategy_code / subtype_id / sku_family_id。"""
        if fields.get('ad_level') != 'group':
            return
        campaign_id = fields.get('campaign_id')
        if not campaign_id:
            return
        cur.execute(
            """
            SELECT portfolio_id, strategy_code, subtype_id, sku_family_id
            FROM amazon_ad_items WHERE id=%s AND ad_level='campaign' LIMIT 1
            """,
            (campaign_id,),
        )
        campaign = cur.fetchone() or {}
        if campaign.get('portfolio_id'):
            fields['portfolio_id'] = campaign.get('portfolio_id')
        fields['strategy_code'] = campaign.get('strategy_code')
        fields['subtype_id'] = campaign.get('subtype_id')
        if campaign.get('sku_family_id'):
            fields['sku_family_id'] = campaign.get('sku_family_id')

    def _inherit_group_fields_from_campaign_record(self, fields, campaign_row):
        """广告组从内存中的活动记录继承字段（导入批处理用）。"""
        if fields.get('ad_level') != 'group' or not campaign_row:
            return
        if campaign_row.get('portfolio_id'):
            fields['portfolio_id'] = campaign_row.get('portfolio_id')
        fields['strategy_code'] = campaign_row.get('strategy_code')
        fields['subtype_id'] = campaign_row.get('subtype_id')
        if campaign_row.get('sku_family_id'):
            fields['sku_family_id'] = campaign_row.get('sku_family_id')

    def _apply_amazon_ad_campaign_shop_id(self, fields, data, *, is_create=False, existing_shop_id=None):
        if fields.get('ad_level') != 'campaign':
            fields['shop_id'] = None
            return
        shop_id = self._parse_int((data or {}).get('shop_id'))
        if shop_id:
            fields['shop_id'] = shop_id
        elif is_create:
            fields['shop_id'] = 1
        elif existing_shop_id is not None:
            fields['shop_id'] = existing_shop_id

    def _validate_amazon_ad_shop_ref(self, cur, shop_id):
        if not shop_id:
            return None
        cur.execute("SELECT id FROM shops WHERE id=%s LIMIT 1", (shop_id,))
        if not cur.fetchone():
            return '关联店铺不存在'
        return None

    def _load_amazon_ad_import_context(self, cur):
        """一次性加载导入索引，避免逐行 SELECT。"""
        portfolio_by_name = {}
        campaign_by_key = {}
        campaign_by_id = {}
        campaign_by_name = {}
        existing_portfolio_by_name = {}
        existing_campaign_by_key = {}
        existing_group_by_key = {}

        shop_by_name = {}
        shop_rows = []
        cur.execute("SELECT id, shop_name FROM shops ORDER BY id ASC")
        shop_rows = cur.fetchall() or []
        for row in shop_rows:
            name = str(row.get('shop_name') or '').strip()
            if name:
                shop_by_name[name] = row['id']
        default_shop_id = shop_rows[0]['id'] if shop_rows else 1

        cur.execute(
            """
            SELECT id, ad_level, name, portfolio_id, campaign_id, shop_id,
                   sku_family_id, strategy_code, subtype_id, is_shared_budget, status, budget
            FROM amazon_ad_items
            WHERE ad_level IN ('portfolio', 'campaign', 'group')
            """
        )
        for row in cur.fetchall() or []:
            level = row.get('ad_level')
            name = str(row.get('name') or '').strip()
            if not name:
                continue
            if level == 'portfolio':
                portfolio_by_name[name] = row['id']
                existing_portfolio_by_name[name] = row
            elif level == 'campaign':
                pid = int(self._parse_int(row.get('portfolio_id')) or 0)
                campaign_by_key[(pid, name)] = row
                campaign_by_id[int(row['id'])] = row
                campaign_by_name.setdefault(name, []).append(row)
                existing_campaign_by_key[(pid, name)] = row
            else:
                cid = int(self._parse_int(row.get('campaign_id')) or 0)
                existing_group_by_key[(cid, name)] = row

        subtype_by_key = {}
        cur.execute("SELECT id, ad_class, subtype_code, description FROM amazon_ad_subtypes")
        for row in cur.fetchall() or []:
            key = f"{row.get('ad_class')}-{row.get('subtype_code')}"
            subtype_by_key[key] = row['id']
            subtype_by_key[str(row.get('description') or '').strip()] = row['id']
            code = str(row.get('subtype_code') or '').strip()
            if code:
                subtype_by_key[code] = row['id']

        sku_by_family = {}
        cur.execute("SELECT id, sku_family FROM product_families")
        for row in cur.fetchall() or []:
            sku_by_family[str(row.get('sku_family') or '').strip()] = row['id']

        return {
            'portfolio_by_name': portfolio_by_name,
            'campaign_by_key': campaign_by_key,
            'campaign_by_id': campaign_by_id,
            'campaign_by_name': campaign_by_name,
            'existing_portfolio_by_name': existing_portfolio_by_name,
            'existing_campaign_by_key': existing_campaign_by_key,
            'existing_group_by_key': existing_group_by_key,
            'subtype_by_key': subtype_by_key,
            'sku_by_family': sku_by_family,
            'shop_by_name': shop_by_name,
            'default_shop_id': default_shop_id or 1,
        }

    def _find_amazon_ad_import_existing(self, ad_level, name, ctx, portfolio_id=None, campaign_id=None):
        name = (name or '').strip()
        if not name:
            return None
        if ad_level == 'portfolio':
            return ctx['existing_portfolio_by_name'].get(name)
        if ad_level == 'campaign':
            pid = self._parse_int(portfolio_id)
            if not pid:
                return None
            return ctx['existing_campaign_by_key'].get((int(pid), name))
        cid = self._parse_int(campaign_id)
        if not cid:
            return None
        return ctx['existing_group_by_key'].get((int(cid), name))

    def _register_amazon_ad_import_row(self, ctx, fields, row_id):
        level = fields['ad_level']
        name = fields['name']
        row = {
            'id': row_id,
            'ad_level': level,
            'name': name,
            'portfolio_id': fields.get('portfolio_id'),
            'campaign_id': fields.get('campaign_id'),
            'shop_id': fields.get('shop_id'),
            'sku_family_id': fields.get('sku_family_id'),
            'strategy_code': fields.get('strategy_code'),
            'subtype_id': fields.get('subtype_id'),
            'is_shared_budget': fields.get('is_shared_budget'),
            'status': fields.get('status'),
            'budget': fields.get('budget'),
        }
        if level == 'portfolio':
            ctx['portfolio_by_name'][name] = row_id
            ctx['existing_portfolio_by_name'][name] = row
        elif level == 'campaign':
            pid = int(self._parse_int(fields.get('portfolio_id')) or 0)
            ctx['campaign_by_key'][(pid, name)] = row
            ctx['campaign_by_id'][int(row_id)] = row
            ctx['campaign_by_name'].setdefault(name, []).append(row)
            ctx['existing_campaign_by_key'][(pid, name)] = row
        else:
            cid = int(self._parse_int(fields.get('campaign_id')) or 0)
            ctx['existing_group_by_key'][(cid, name)] = row

    def _find_amazon_ad_item_by_scoped_name(self, cur, ad_level, name, portfolio_id=None, campaign_id=None, exclude_id=None):
        """按同层级作用域查找：组合全局唯一；活动在同一组合下唯一；组在同一活动下唯一。"""
        name = (name or '').strip()
        if not name:
            return None
        sql = "SELECT id FROM amazon_ad_items WHERE ad_level=%s AND name=%s"
        params = [ad_level, name]
        if ad_level == 'campaign':
            pid = self._parse_int(portfolio_id)
            if not pid:
                return None
            sql += ' AND portfolio_id=%s'
            params.append(pid)
        elif ad_level == 'group':
            cid = self._parse_int(campaign_id)
            if not cid:
                return None
            sql += ' AND campaign_id=%s'
            params.append(cid)
        if exclude_id:
            sql += ' AND id<>%s'
            params.append(int(exclude_id))
        sql += ' LIMIT 1'
        cur.execute(sql, tuple(params))
        return cur.fetchone()

    def _validate_amazon_ad_name_unique(self, cur, ad_level, name, portfolio_id=None, campaign_id=None, exclude_id=None):
        row = self._find_amazon_ad_item_by_scoped_name(
            cur, ad_level, name, portfolio_id=portfolio_id, campaign_id=campaign_id, exclude_id=exclude_id
        )
        if not row:
            return None
        if ad_level == 'portfolio':
            return '广告组合名称已存在，请勿重复'
        if ad_level == 'campaign':
            return '该广告组合下已存在同名广告活动'
        return '该广告活动下已存在同名广告组'

    def _amazon_ad_batch_scope_key(self, ad_level, name, portfolio_id=None, campaign_id=None):
        name = (name or '').strip()
        if ad_level == 'portfolio':
            return ('portfolio', name)
        if ad_level == 'campaign':
            return ('campaign', int(self._parse_int(portfolio_id) or 0), name)
        return ('group', int(self._parse_int(campaign_id) or 0), name)

    def _validate_amazon_ad_name_unique_in_batch(self, ad_level, name, portfolio_id=None, campaign_id=None, batch_seen=None):
        key = self._amazon_ad_batch_scope_key(ad_level, name, portfolio_id, campaign_id)
        if key in (batch_seen or set()):
            if ad_level == 'portfolio':
                return '本批导入中广告组合名称重复'
            if ad_level == 'campaign':
                return '本批导入中该广告组合下广告活动名称重复'
            return '本批导入中该广告活动下广告组名称重复'
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

                        if ad_level == 'campaign':
                            self._inherit_campaign_fields_from_portfolio(cur, fields)
                            self._apply_amazon_ad_campaign_shop_id(fields, data, is_create=True)
                        elif ad_level == 'group':
                            self._inherit_group_fields_from_campaign(cur, fields)

                        if ad_level == 'campaign':
                            shop_err = self._validate_amazon_ad_shop_ref(cur, fields.get('shop_id'))
                            if shop_err:
                                return self.send_json({'status': 'error', 'message': shop_err}, start_response)

                        dup_err = self._validate_amazon_ad_name_unique(
                            cur, ad_level, fields['name'],
                            portfolio_id=fields.get('portfolio_id'),
                            campaign_id=fields.get('campaign_id'),
                        )
                        if dup_err:
                            return self.send_json({'status': 'error', 'message': dup_err}, start_response)

                        cur.execute(
                            """
                            INSERT INTO amazon_ad_items (
                                ad_level, sku_family_id, shop_id, portfolio_id, campaign_id,
                                strategy_code, subtype_id, name, is_shared_budget, status, budget
                            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                            """,
                            (
                                fields['ad_level'], fields['sku_family_id'], fields.get('shop_id'),
                                fields['portfolio_id'], fields['campaign_id'], fields['strategy_code'],
                                fields['subtype_id'], fields['name'], fields['is_shared_budget'],
                                fields['status'], fields['budget']
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
                            "SELECT id, ad_level, shop_id FROM amazon_ad_items WHERE id=%s LIMIT 1",
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

                        if ad_level == 'campaign':
                            self._inherit_campaign_fields_from_portfolio(cur, fields)
                            self._apply_amazon_ad_campaign_shop_id(
                                fields, data, is_create=False, existing_shop_id=existing.get('shop_id')
                            )
                        elif ad_level == 'group':
                            self._inherit_group_fields_from_campaign(cur, fields)

                        if ad_level == 'campaign':
                            shop_err = self._validate_amazon_ad_shop_ref(cur, fields.get('shop_id'))
                            if shop_err:
                                return self.send_json({'status': 'error', 'message': shop_err}, start_response)

                        dup_err = self._validate_amazon_ad_name_unique(
                            cur, ad_level, fields['name'],
                            portfolio_id=fields.get('portfolio_id'),
                            campaign_id=fields.get('campaign_id'),
                            exclude_id=item_id,
                        )
                        if dup_err:
                            return self.send_json({'status': 'error', 'message': dup_err}, start_response)

                        cur.execute(
                            """
                            UPDATE amazon_ad_items SET
                                sku_family_id=%s, shop_id=%s, portfolio_id=%s, campaign_id=%s,
                                strategy_code=%s, subtype_id=%s, name=%s,
                                is_shared_budget=%s, status=%s, budget=%s
                            WHERE id=%s
                            """,
                            (
                                fields['sku_family_id'], fields.get('shop_id'), fields['portfolio_id'],
                                fields['campaign_id'], fields['strategy_code'], fields['subtype_id'],
                                fields['name'], fields['is_shared_budget'], fields['status'], fields['budget'],
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
            '策略', '细分类', '预算', '关联店铺',
            '归属广告组合名称', '归属广告活动名称',
        ]

    def _load_amazon_ad_items_template_options(self):
        """模板下拉：货号、细分类、店铺（与导入解析键一致）。"""
        sku_families = []
        subtype_labels = []
        shop_names = []
        with self._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sku_family FROM product_families
                    WHERE sku_family IS NOT NULL AND TRIM(sku_family) <> ''
                    ORDER BY sku_family ASC
                    """
                )
                sku_families = [
                    str(row.get('sku_family') or '').strip()
                    for row in (cur.fetchall() or [])
                    if str(row.get('sku_family') or '').strip()
                ]
                cur.execute(
                    """
                    SELECT ad_class, subtype_code, description
                    FROM amazon_ad_subtypes
                    ORDER BY ad_class ASC, subtype_code ASC, id ASC
                    """
                )
                seen = set()
                for row in cur.fetchall() or []:
                    ad_class = str(row.get('ad_class') or '').strip()
                    code = str(row.get('subtype_code') or '').strip()
                    desc = str(row.get('description') or '').strip()
                    composite = f'{ad_class}-{code}' if ad_class and code else ''
                    for label in (desc, composite, code):
                        if label and label not in seen:
                            seen.add(label)
                            subtype_labels.append(label)
                cur.execute(
                    """
                    SELECT shop_name FROM shops
                    WHERE shop_name IS NOT NULL AND TRIM(shop_name) <> ''
                    ORDER BY id ASC
                    """
                )
                shop_names = [
                    str(row.get('shop_name') or '').strip()
                    for row in (cur.fetchall() or [])
                    if str(row.get('shop_name') or '').strip()
                ]
        return sku_families, subtype_labels, shop_names

    def _style_amazon_ad_items_template_example_rows(self, ws):
        """第 2–4 行为示例行，使用不同底色区分（导入时跳过）。"""
        from openpyxl.styles import Font, PatternFill, Alignment

        example_font = Font(italic=True, color='7B8088')
        example_align = Alignment(horizontal='center', vertical='center', wrap_text=True)
        fills = [
            PatternFill(start_color='E8F0E8', end_color='E8F0E8', fill_type='solid'),
            PatternFill(start_color='E8EEF6', end_color='E8EEF6', fill_type='solid'),
            PatternFill(start_color='F6EEE8', end_color='F6EEE8', fill_type='solid'),
        ]
        for row_idx, fill in enumerate(fills, start=2):
            for cell in ws[row_idx]:
                cell.fill = fill
                cell.font = example_font
                cell.alignment = example_align

    def _apply_amazon_ad_items_template_formatting(
        self,
        ws,
        *,
        options_ws=None,
        sku_families=None,
        subtype_labels=None,
        shop_names=None,
        first_data_row=5,
        last_row=1000,
    ):
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

        first_data_row = max(5, int(first_data_row or 5))
        data_end = max(first_data_row, int(last_row or 1000))
        anchor = first_data_row

        dv_level = DataValidation(type='list', formula1='"组合,活动,组"', allow_blank=False)
        dv_level.error = '请从列表选择：组合 / 活动 / 组'
        dv_level.errorTitle = '广告类型'
        ws.add_data_validation(dv_level)
        dv_level.add(f'A{first_data_row}:A{data_end}')

        dv_status = DataValidation(type='list', formula1='"启动,暂停,存档"', allow_blank=False)
        dv_status.error = '请从列表选择：启动 / 暂停 / 存档'
        dv_status.errorTitle = '状态'
        ws.add_data_validation(dv_status)
        dv_status.add(f'C{first_data_row}:C{data_end}')

        dv_shared = DataValidation(type='list', formula1='"是,否"', allow_blank=True)
        dv_shared.error = '请从列表选择：是 / 否'
        dv_shared.errorTitle = '是否共享预算'
        ws.add_data_validation(dv_shared)
        dv_shared.add(f'E{first_data_row}:E{data_end}')

        dv_strategy = DataValidation(type='list', formula1='"BE,BD,PC"', allow_blank=True)
        dv_strategy.error = '请从列表选择：BE / BD / PC'
        dv_strategy.errorTitle = '策略'
        ws.add_data_validation(dv_strategy)
        dv_strategy.add(f'F{first_data_row}:F{data_end}')

        sku_families = list(sku_families or [])
        subtype_labels = list(subtype_labels or [])
        shop_names = list(shop_names or [])
        if options_ws is not None and sku_families:
            opt_end = len(sku_families) + 1
            dv_sku = DataValidation(
                type='list',
                formula1=f"='_options'!$A$2:$A${opt_end}",
                allow_blank=True,
            )
            dv_sku.error = '请从列表选择货号'
            dv_sku.errorTitle = '关联货号'
            ws.add_data_validation(dv_sku)
            dv_sku.add(f'D{first_data_row}:D{data_end}')
        if options_ws is not None and subtype_labels:
            opt_end = len(subtype_labels) + 1
            dv_subtype = DataValidation(
                type='list',
                formula1=f"='_options'!$B$2:$B${opt_end}",
                allow_blank=True,
            )
            dv_subtype.error = '请从列表选择细分类'
            dv_subtype.errorTitle = '细分类'
            ws.add_data_validation(dv_subtype)
            dv_subtype.add(f'G{first_data_row}:G{data_end}')
        if options_ws is not None and shop_names:
            opt_end = len(shop_names) + 1
            dv_shop = DataValidation(
                type='list',
                formula1=f"='_options'!$C$2:$C${opt_end}",
                allow_blank=True,
            )
            dv_shop.error = '请从列表选择店铺'
            dv_shop.errorTitle = '关联店铺'
            ws.add_data_validation(dv_shop)
            dv_shop.add(f'I{first_data_row}:I{data_end}')

        # 条件格式：公式为真时显示灰色（表示当前行广告类型下该列无需填写）
        rules = [
            ('D', f'OR($A{anchor}="",$A{anchor}<>"组合")'),
            ('E', f'OR($A{anchor}="",$A{anchor}<>"组合")'),
            ('F', f'OR($A{anchor}="",$A{anchor}<>"活动")'),
            ('G', f'OR($A{anchor}="",$A{anchor}<>"活动")'),
            ('H', f'OR($A{anchor}="",$A{anchor}<>"活动")'),
            ('I', f'OR($A{anchor}="",$A{anchor}<>"活动")'),
            ('J', f'OR($A{anchor}="",$A{anchor}<>"活动")'),
            ('K', f'OR($A{anchor}="",$A{anchor}<>"组")'),
        ]
        for col, formula in rules:
            ws.conditional_formatting.add(
                f'{col}{first_data_row}:{col}{data_end}',
                FormulaRule(formula=[formula], fill=gray_fill),
            )

        ws.freeze_panes = f'A{first_data_row}'
        widths = {
            'A': 11, 'B': 28, 'C': 9, 'D': 14, 'E': 14,
            'F': 8, 'G': 12, 'H': 10, 'I': 16, 'J': 22, 'K': 26,
        }
        for col, width in widths.items():
            ws.column_dimensions[col].width = width

    def _is_amazon_ad_template_sample_row(self, row_idx, name):
        if row_idx <= 4:
            return True
        text = str(name or '').strip()
        return ('示例' in text) or ('请勿导入' in text)

    def _build_amazon_ad_items_import_workbook(self):
        from openpyxl import Workbook

        sku_families, subtype_labels, shop_names = self._load_amazon_ad_items_template_options()
        example_shop = shop_names[0] if shop_names else ''

        wb = Workbook()
        ws = wb.active
        ws.title = '广告信息'
        headers = self._amazon_ad_items_template_headers()
        ws.append(headers)
        ws.append([
            '组合', '示例-Short-SKU01', '启动',
            'SKU01', '是',
            '', '', '', '',
            '', '',
        ])
        ws.append([
            '活动', 'BE-示例组合-SP-KW', '启动',
            '', '',
            'BE', 'SP-KW', '50', example_shop,
            '示例-Short-SKU01', '',
        ])
        ws.append([
            '组', 'BE-示例组合-SP-KW', '启动',
            '', '',
            '', '', '', '',
            '', 'BE-示例组合-SP-KW',
        ])
        self._style_amazon_ad_items_template_example_rows(ws)

        options_ws = wb.create_sheet('_options')
        options_ws.sheet_state = 'hidden'
        options_ws.append(['sku_family', 'subtype', 'shop_name'])
        opt_rows = max(len(sku_families), len(subtype_labels), len(shop_names), 1)
        for i in range(opt_rows):
            options_ws.append([
                sku_families[i] if i < len(sku_families) else '',
                subtype_labels[i] if i < len(subtype_labels) else '',
                shop_names[i] if i < len(shop_names) else '',
            ])

        self._apply_amazon_ad_items_template_formatting(
            ws,
            options_ws=options_ws,
            sku_families=sku_families,
            subtype_labels=subtype_labels,
            shop_names=shop_names,
            first_data_row=5,
            last_row=1200,
        )

        guide = wb.create_sheet('填写说明')
        guide.append(['字段', '组合', '活动', '组', '说明'])
        guide_rows = [
            ('广告类型*', '必填', '必填', '必填', '下拉：组合 / 活动 / 组'),
            ('名称*', '必填', '必填', '必填', ''),
            ('状态*', '必填', '必填', '必填', '下拉：启动 / 暂停 / 存档'),
            ('关联货号', '选填', '—', '—', '仅组合可填；下拉为系统货号；灰底表示本行不适用'),
            ('是否共享预算', '必填', '—', '—', '仅组合可填；下拉：是 / 否'),
            ('策略', '—', '必填', '—', '仅活动可填；下拉：BE / BD / PC'),
            ('细分类', '—', '必填', '—', '仅活动可填；下拉为系统细分类'),
            ('预算', '—', '必填', '—', '仅活动可填'),
            ('关联店铺', '—', '选填', '—', '仅活动可填；下拉为系统店铺；留空默认 id=1'),
            ('归属广告组合名称', '—', '必填', '—', '仅活动可填（须已存在）'),
            ('归属广告活动名称', '—', '—', '必填', '仅组可填（须已存在）'),
            ('', '', '', '', '第2–4行为示例（彩色底纹），导入时自动跳过；请从第5行填写'),
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
            skipped_sample_rows = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    ctx = self._load_amazon_ad_import_context(cur)
                    portfolio_by_name = ctx['portfolio_by_name']
                    campaign_by_key = ctx['campaign_by_key']
                    campaign_by_name = ctx['campaign_by_name']
                    subtype_by_key = ctx['subtype_by_key']
                    sku_by_family = ctx['sku_by_family']
                    shop_by_name = ctx['shop_by_name']
                    default_shop_id = ctx['default_shop_id']
                    batch_seen_names = set()

                    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=False), start=2):
                        name = cell_value(row, '名称*') or ''
                        if self._is_amazon_ad_template_sample_row(row_idx, name):
                            skipped_sample_rows += 1
                            continue
                        level_raw = cell_value(row, '广告类型*') or ''
                        ad_level = level_map.get(level_raw.lower()) or level_map.get(level_raw)
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
                            shop_name = cell_value(row, '关联店铺') or ''
                            if shop_name:
                                payload['shop_id'] = shop_by_name.get(shop_name)
                                if not payload['shop_id']:
                                    errors.append({'row': row_idx, 'message': f'未找到店铺: {shop_name}'})
                                    continue
                            if not payload['portfolio_id']:
                                errors.append({'row': row_idx, 'message': f'未找到广告组合: {portfolio_name}'})
                                continue
                            if not payload['subtype_id']:
                                errors.append({'row': row_idx, 'message': f'未找到细分类: {subtype_text}'})
                                continue
                        else:
                            campaign_name = cell_value(row, '归属广告活动名称') or ''
                            portfolio_name = cell_value(row, '归属广告组合名称') or ''
                            portfolio_id_for_group = portfolio_by_name.get(portfolio_name) if portfolio_name else None
                            campaign = None
                            if portfolio_id_for_group is not None:
                                campaign = campaign_by_key.get(
                                    (int(portfolio_id_for_group), campaign_name.strip())
                                )
                            if not campaign and campaign_name:
                                matches = campaign_by_name.get(campaign_name.strip(), [])
                                if len(matches) == 1:
                                    campaign = matches[0]
                                elif len(matches) > 1:
                                    errors.append({
                                        'row': row_idx,
                                        'message': (
                                            f'广告活动「{campaign_name}」在多个广告组合中存在，'
                                            '请填写归属广告组合名称'
                                        ),
                                    })
                                    continue
                            if not campaign:
                                errors.append({'row': row_idx, 'message': f'未找到广告活动: {campaign_name}'})
                                continue
                            payload['campaign_id'] = campaign['id']
                            payload['portfolio_id'] = campaign.get('portfolio_id')

                        fields, err = self._build_amazon_ad_write_fields(payload, ad_level)
                        if err:
                            errors.append({'row': row_idx, 'message': err})
                            continue
                        if ad_level == 'campaign':
                            portfolio_name = cell_value(row, '归属广告组合名称') or ''
                            portfolio_row = ctx['existing_portfolio_by_name'].get(portfolio_name)
                            self._inherit_campaign_fields_from_portfolio_record(fields, portfolio_row)
                            if payload.get('shop_id'):
                                fields['shop_id'] = payload['shop_id']
                        elif ad_level == 'group':
                            campaign_row = None
                            if fields.get('campaign_id'):
                                campaign_row = ctx['campaign_by_id'].get(int(fields['campaign_id']))
                            self._inherit_group_fields_from_campaign_record(fields, campaign_row)

                        existing = self._find_amazon_ad_import_existing(
                            ad_level, fields['name'], ctx,
                            portfolio_id=fields.get('portfolio_id'),
                            campaign_id=fields.get('campaign_id'),
                        )
                        if ad_level == 'campaign' and not fields.get('shop_id'):
                            fields['shop_id'] = (
                                existing.get('shop_id') if existing else None
                            ) or default_shop_id
                        if existing:
                            cur.execute(
                                """
                                UPDATE amazon_ad_items SET
                                    sku_family_id=%s, shop_id=%s, portfolio_id=%s, campaign_id=%s,
                                    strategy_code=%s, subtype_id=%s,
                                    is_shared_budget=%s, status=%s, budget=%s
                                WHERE id=%s
                                """,
                                (
                                    fields['sku_family_id'], fields.get('shop_id'),
                                    fields['portfolio_id'], fields['campaign_id'],
                                    fields['strategy_code'], fields['subtype_id'],
                                    fields['is_shared_budget'], fields['status'], fields['budget'],
                                    existing['id']
                                )
                            )
                            updated += 1
                            self._register_amazon_ad_import_row(ctx, fields, existing['id'])
                        else:
                            batch_dup_err = self._validate_amazon_ad_name_unique_in_batch(
                                ad_level, fields['name'],
                                portfolio_id=fields.get('portfolio_id'),
                                campaign_id=fields.get('campaign_id'),
                                batch_seen=batch_seen_names,
                            )
                            if batch_dup_err:
                                errors.append({'row': row_idx, 'message': batch_dup_err})
                                continue
                            cur.execute(
                                """
                                INSERT INTO amazon_ad_items (
                                    ad_level, sku_family_id, shop_id, portfolio_id, campaign_id,
                                    strategy_code, subtype_id, name, is_shared_budget, status, budget
                                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                                """,
                                (
                                    fields['ad_level'], fields['sku_family_id'], fields.get('shop_id'),
                                    fields['portfolio_id'], fields['campaign_id'], fields['strategy_code'],
                                    fields['subtype_id'], fields['name'], fields['is_shared_budget'],
                                    fields['status'], fields['budget']
                                )
                            )
                            new_id = cur.lastrowid
                            created += 1
                            batch_seen_names.add(self._amazon_ad_batch_scope_key(
                                ad_level, fields['name'],
                                portfolio_id=fields.get('portfolio_id'),
                                campaign_id=fields.get('campaign_id'),
                            ))
                            self._register_amazon_ad_import_row(ctx, fields, new_id)

            return self.send_json(
                {
                    'status': 'success',
                    'created': created,
                    'updated': updated,
                    'unchanged': unchanged,
                    'skipped_sample_rows': skipped_sample_rows,
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

    def _adjustment_portfolio_name_from_row(self, row):
        if not row:
            return ''
        text = (row.get('portfolio_name') or '').strip()
        if text:
            return text
        if row.get('ad_level') == 'portfolio':
            return (row.get('name') or '').strip()
        return ''

    def _serialize_adjustment_ad_list_item(self, row):
        level = row.get('ad_level')
        ad_class = row.get('ad_class') or ''
        subtype_code = row.get('subtype_code') or ''
        if ad_class and subtype_code:
            ad_type_text = f'{ad_class}-{subtype_code}'
        else:
            ad_type_text = row.get('subtype_description') or ''
        name = row.get('name') or ''
        portfolio_name = self._adjustment_portfolio_name_from_row(row)
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
            'portfolio_name': self._adjustment_portfolio_name_from_row(item),
            'campaign_name': item.get('campaign_name') if level == 'group' else (item.get('name') if level == 'campaign' else ''),
            'group_name': item.get('name') if level == 'group' else '',
        }
        if level == 'portfolio':
            ad_info['portfolio_name'] = item.get('name') or ad_info['portfolio_name']
            ad_info['campaign_name'] = ''
            ad_info['group_name'] = ''
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
                SELECT ot.id, ot.name, ot.apply_portfolio, ot.apply_campaign, ot.apply_group, ot.reason_names
                FROM amazon_ad_operation_types ot
                INNER JOIN amazon_ad_subtype_operation_types link ON link.operation_type_id = ot.id
                WHERE link.subtype_id = %s
                ORDER BY ot.id ASC
                """,
                (subtype_id,)
            )
        elif level == 'portfolio':
            cur.execute(
                "SELECT id, name, apply_portfolio, apply_campaign, apply_group, reason_names "
                "FROM amazon_ad_operation_types WHERE apply_portfolio=1 ORDER BY id ASC"
            )
        elif level == 'campaign':
            cur.execute(
                "SELECT id, name, apply_portfolio, apply_campaign, apply_group, reason_names "
                "FROM amazon_ad_operation_types WHERE apply_campaign=1 ORDER BY id ASC"
            )
        else:
            cur.execute(
                "SELECT id, name, apply_portfolio, apply_campaign, apply_group, reason_names "
                "FROM amazon_ad_operation_types WHERE apply_group=1 ORDER BY id ASC"
            )
        ops = cur.fetchall() or []
        result = []
        for op in ops:
            if level == 'portfolio' and not int(op.get('apply_portfolio') or 0):
                continue
            if level == 'campaign' and not int(op.get('apply_campaign') or 0):
                continue
            if level == 'group' and not int(op.get('apply_group') or 0):
                continue
            reason_names = self._parse_operation_type_reason_names(op.get('reason_names'))
            result.append({
                'id': op['id'],
                'name': op.get('name') or '',
                'reasons': [{'reason_name': name} for name in reason_names],
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
                            + " WHERE i.ad_level IN ('portfolio', 'campaign', 'group') "
                            + " ORDER BY FIELD(i.ad_level, 'portfolio', 'campaign', 'group'), i.id DESC LIMIT 500"
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
                        ot.name AS operation_name
                    FROM amazon_ad_adjustments a
                    INNER JOIN amazon_ad_items i ON i.id = a.ad_item_id
                    LEFT JOIN amazon_ad_operation_types ot ON ot.id = a.operation_type_id
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
                reason_name = (data.get('reason_name') or '').strip() or None
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
                                before_value, after_value, reason_name,
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
                                reason_name,
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

