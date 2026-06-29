# -*- coding: utf-8 -*-
"""销售佣金：平台 × 佣金大类规则 + 货号细分类目映射，统一 unit/period 计算。"""

import json


class CommissionCalcMixin:
    """佣金规则解析与应用（无 priority：仅精确匹配或平台级 product_category='*'）。"""

    COMMISSION_UNAVAILABLE_LABEL = '无法计算'

    # -------------------------------------------------------------------------
    # 规则缓存与解析
    # -------------------------------------------------------------------------

    def _commission_rules_tables_ready(self, conn):
        return (
            self._table_exists_simple(conn, 'commission_calc_rules')
            and self._table_exists_simple(conn, 'commission_product_category_mappings')
        )

    def _commission_load_rules_cache(self, conn):
        """一次请求内复用：mappings (pt,细分类)→group；rules (pt,group)→rule。"""
        empty = {'mappings': {}, 'rules': {}, 'ready': False}
        if not self._commission_rules_tables_ready(conn):
            return empty
        mappings = {}
        rules = {}
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT platform_type_id, product_category, commission_group
                FROM commission_product_category_mappings
                """
            )
            for row in cur.fetchall() or []:
                pt_id = self._parse_int(row.get('platform_type_id'))
                cat = str(row.get('product_category') or '').strip()
                grp = str(row.get('commission_group') or '').strip()
                if pt_id and cat and grp:
                    mappings[(int(pt_id), cat)] = grp
            cur.execute(
                """
                SELECT platform_type_id, commission_group, calc_method, params_json
                FROM commission_calc_rules
                """
            )
            for row in cur.fetchall() or []:
                pt_id = self._parse_int(row.get('platform_type_id'))
                grp = str(row.get('commission_group') or '').strip()
                if not pt_id or not grp:
                    continue
                params = row.get('params_json')
                if isinstance(params, (bytes, bytearray)):
                    params = params.decode('utf-8', errors='replace')
                if isinstance(params, str):
                    try:
                        params = json.loads(params) if params.strip() else {}
                    except Exception:
                        params = {}
                if not isinstance(params, dict):
                    params = {}
                rules[(int(pt_id), grp)] = {
                    'calc_method': str(row.get('calc_method') or '').strip().lower(),
                    'params_json': params,
                    'commission_group': grp,
                }
        return {'mappings': mappings, 'rules': rules, 'ready': True}

    def _commission_resolve_group(self, cache, platform_type_id, product_category):
        """细分类→佣金大类；无映射返回 (None, reason)。"""
        pt_id = self._parse_int(platform_type_id)
        if not pt_id:
            return None, '缺少平台类型'
        cat = str(product_category or '').strip()
        if not cat:
            return None, '缺少货号细分类目'
        if not cache or not cache.get('ready'):
            return None, '佣金规则表未就绪'
        mappings = cache.get('mappings') or {}
        grp = mappings.get((int(pt_id), cat))
        if not grp:
            grp = mappings.get((int(pt_id), '*'))
        if not grp:
            return None, f'未维护类目映射（{cat}）'
        return str(grp).strip(), None

    def _commission_resolve_rule(self, cache, platform_type_id, product_category):
        """返回 rule dict 或 None；附带 commission_group / unavailable_reason。"""
        grp, err = self._commission_resolve_group(cache, platform_type_id, product_category)
        if not grp:
            return None, None, err or self.COMMISSION_UNAVAILABLE_LABEL
        pt_id = int(self._parse_int(platform_type_id))
        rule = (cache.get('rules') or {}).get((pt_id, grp))
        if not rule:
            return None, grp, f'未维护佣金规则（{grp}）'
        return rule, grp, None

    # -------------------------------------------------------------------------
    # 金额计算（unit=单件净收入 period=周期净销售额合计）
    # -------------------------------------------------------------------------

    @staticmethod
    def _commission_parse_tiers(params):
        tiers = []
        for item in (params or {}).get('tiers') or []:
            if not isinstance(item, dict):
                continue
            rate = item.get('rate')
            try:
                rate_f = float(rate)
            except Exception:
                continue
            up_to = item.get('up_to')
            if up_to is None or str(up_to).strip() == '':
                tiers.append({'up_to': None, 'rate': rate_f})
            else:
                try:
                    tiers.append({'up_to': float(up_to), 'rate': rate_f})
                except Exception:
                    continue
        return tiers

    def _commission_apply_tiered(self, amount, params):
        tiers = self._commission_parse_tiers(params)
        if not tiers:
            return None
        s = max(0.0, float(amount or 0))
        if s <= 1e-12:
            return 0.0
        total = 0.0
        prev_cap = 0.0
        for tier in tiers:
            cap = tier.get('up_to')
            rate = float(tier.get('rate') or 0)
            if cap is None:
                seg = max(0.0, s - prev_cap)
            else:
                cap_f = float(cap)
                seg = max(0.0, min(s, cap_f) - prev_cap)
                prev_cap = cap_f
            total += seg * rate
            if cap is None:
                break
            if s <= float(cap):
                break
        return round(total, 2)

    def _commission_apply_flat(self, amount, params):
        try:
            rate = float((params or {}).get('rate'))
        except Exception:
            return None
        s = max(0.0, float(amount or 0))
        if s <= 1e-12:
            return 0.0
        return round(s * rate, 2)

    def _commission_apply_rule_amount(self, amount, rule):
        if not rule:
            return None
        method = str(rule.get('calc_method') or '').strip().lower()
        params = rule.get('params_json') or {}
        if method == 'flat':
            return self._commission_apply_flat(amount, params)
        if method == 'tiered':
            return self._commission_apply_tiered(amount, params)
        return None

    def _commission_apply_period(self, net_sales_total, rule):
        """周期净销售额 → 佣金 USD。"""
        comm = self._commission_apply_rule_amount(net_sales_total, rule)
        if comm is None:
            return None, None
        net = max(0.0, float(net_sales_total or 0))
        if net <= 1e-12:
            return 0.0, 0.0
        rate = round(float(comm) / net, 6)
        return comm, rate

    def _commission_apply_unit(self, net_price, rule):
        """单件折后净收入 → 佣金 USD 与费率。"""
        return self._commission_apply_period(net_price, rule)

    def _commission_compute_for_context(self, cache, platform_type_id, product_category, amount, *, mode='period'):
        """统一入口：成功返回 dict；失败 commission_status=unavailable。"""
        rule, grp, err = self._commission_resolve_rule(cache, platform_type_id, product_category)
        if not rule:
            return {
                'commission_status': 'unavailable',
                'commission_message': err or self.COMMISSION_UNAVAILABLE_LABEL,
                'commission_group': grp,
                'est_referral_commission_usd': None,
                'commission_rate': None,
            }
        apply_fn = self._commission_apply_unit if mode == 'unit' else self._commission_apply_period
        comm, rate = apply_fn(amount, rule)
        if comm is None:
            return {
                'commission_status': 'unavailable',
                'commission_message': self.COMMISSION_UNAVAILABLE_LABEL,
                'commission_group': grp,
                'est_referral_commission_usd': None,
                'commission_rate': None,
            }
        return {
            'commission_status': 'ok',
            'commission_message': None,
            'commission_group': grp,
            'est_referral_commission_usd': comm,
            'commission_rate': rate,
        }

    # -------------------------------------------------------------------------
    # 销售产品上下文批量加载
    # -------------------------------------------------------------------------

    def _commission_load_sp_context_map(self, conn, sales_product_ids):
        ids = sorted({int(x) for x in (sales_product_ids or []) if self._parse_int(x)})
        out = {}
        if not ids:
            return out
        ph = ','.join(['%s'] * len(ids))
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT sp.id AS sales_product_id,
                       sh.platform_type_id,
                       TRIM(COALESCE(pf.category, '')) AS product_category
                FROM sales_products sp
                LEFT JOIN shops sh ON sh.id = sp.shop_id
                LEFT JOIN sales_product_variants v ON v.id = sp.variant_id
                LEFT JOIN product_families pf ON pf.id = v.sku_family_id
                WHERE sp.id IN ({ph})
                """,
                tuple(ids),
            )
            for row in cur.fetchall() or []:
                spid = self._parse_int(row.get('sales_product_id'))
                if not spid:
                    continue
                out[int(spid)] = {
                    'platform_type_id': self._parse_int(row.get('platform_type_id')),
                    'product_category': str(row.get('product_category') or '').strip(),
                }
        return out

    def _commission_perf_derived_with_commission(
        self, bom, lm, net, ad_spend, refund_amt, gross_sales, comm_result,
    ):
        """与产品表现货号分组一致的衍生字段（佣金不可算时利润/净利率亦为 null）。"""
        bom_f = float(bom or 0)
        lm_f = float(lm or 0)
        net_f = float(net or 0)
        ad_f = float(ad_spend or 0)
        ref_f = float(refund_amt or 0)
        gross_f = float(gross_sales or 0)
        total = round(bom_f + lm_f, 2)
        base = {
            'estimated_total_cost_usd': total,
            'commission_status': (comm_result or {}).get('commission_status'),
            'commission_message': (comm_result or {}).get('commission_message'),
            'commission_group': (comm_result or {}).get('commission_group'),
        }
        if (comm_result or {}).get('commission_status') != 'ok':
            base.update({
                'est_referral_commission_usd': None,
                'commission_rate': None,
                'estimated_net_profit_usd': None,
                'net_margin_rate': None,
            })
            return base
        comm_f = float(comm_result.get('est_referral_commission_usd') or 0)
        rate = comm_result.get('commission_rate')
        profit = round(net_f - comm_f - total - ad_f - ref_f, 2)
        nmr = round((profit / gross_f), 6) if gross_f else 0.0
        base.update({
            'est_referral_commission_usd': round(comm_f, 2),
            'commission_rate': rate,
            'estimated_net_profit_usd': profit,
            'net_margin_rate': nmr,
        })
        return base

    # -------------------------------------------------------------------------
    # HTTP API：前端 bootstrap（规则 + 映射，体量小可全量下发）
    # -------------------------------------------------------------------------

    def handle_commission_rules_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            with self._get_db_connection() as conn:
                cache = self._commission_load_rules_cache(conn)
                if not cache.get('ready'):
                    return self.send_json({
                        'status': 'success',
                        'ready': False,
                        'rules': [],
                        'mappings': [],
                    }, start_response)
                rules_out = []
                mappings_out = []
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT r.id, r.platform_type_id, pt.name AS platform_type_name,
                               r.commission_group, r.calc_method, r.params_json
                        FROM commission_calc_rules r
                        INNER JOIN platform_types pt ON pt.id = r.platform_type_id
                        ORDER BY pt.name ASC, r.commission_group ASC
                        """
                    )
                    for row in cur.fetchall() or []:
                        params = row.get('params_json')
                        if isinstance(params, (bytes, bytearray)):
                            params = params.decode('utf-8', errors='replace')
                        if isinstance(params, str):
                            try:
                                params = json.loads(params) if params.strip() else {}
                            except Exception:
                                params = {}
                        rules_out.append({
                            'id': self._parse_int(row.get('id')),
                            'platform_type_id': self._parse_int(row.get('platform_type_id')),
                            'platform_type_name': row.get('platform_type_name') or '',
                            'commission_group': row.get('commission_group') or '',
                            'calc_method': row.get('calc_method') or '',
                            'params_json': params if isinstance(params, dict) else {},
                        })
                    cur.execute(
                        """
                        SELECT m.id, m.platform_type_id, pt.name AS platform_type_name,
                               m.product_category, m.commission_group
                        FROM commission_product_category_mappings m
                        INNER JOIN platform_types pt ON pt.id = m.platform_type_id
                        ORDER BY pt.name ASC, m.product_category ASC
                        """
                    )
                    for row in cur.fetchall() or []:
                        mappings_out.append({
                            'id': self._parse_int(row.get('id')),
                            'platform_type_id': self._parse_int(row.get('platform_type_id')),
                            'platform_type_name': row.get('platform_type_name') or '',
                            'product_category': row.get('product_category') or '',
                            'commission_group': row.get('commission_group') or '',
                        })
            return self.send_json({
                'status': 'success',
                'ready': True,
                'rules': rules_out,
                'mappings': mappings_out,
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
