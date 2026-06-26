"""钉钉群机器人 Webhook：数据库群聊配置 + 通知功能绑定；文件配置为回退。"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from urllib.parse import parse_qs


class DingTalkNotifyMixin:
    DINGTALK_KEYWORD = '【SITJOY】'
    DINGTALK_COLOR_NEGATIVE = '#c91d1d'
    DINGTALK_COLOR_POSITIVE = '#2d7d4a'
    DINGTALK_COLOR_MUTED = '#9aa0a6'

    # 新增通知功能时在此注册，配置页会自动出现对应绑定项
    DINGTALK_NOTIFY_FEATURES = (
        {
            'notify_key': 'overseas_stockout',
            'label': '海外仓缺货提醒',
            'page_key': 'logistics_warehouse_inventory_management',
        },
        {
            'notify_key': 'overseas_restock',
            'label': '海外仓重新上架提醒',
            'page_key': 'logistics_warehouse_inventory_management',
        },
        {
            'notify_key': 'transit_eta_delay',
            'label': '在途物流到货延迟',
            'page_key': 'logistics_in_transit_management',
        },
        {
            'notify_key': 'transit_listed_available',
            'label': '在途物流上架可售',
            'page_key': 'logistics_in_transit_management',
        },
        {
            'notify_key': 'amazon_account_health_alert',
            'label': 'Amazon账户健康提醒',
            'page_key': 'amazon_account_health_management',
        },
    )

    def _dingtalk_table_missing(self, exc):
        message = str(exc or '').lower()
        return (
            "doesn't exist" in message
            or 'does not exist' in message
            or 'unknown table' in message
        )

    def _mask_dingtalk_secret(self, secret):
        text = str(secret or '').strip()
        if not text:
            return ''
        if len(text) <= 4:
            return '****'
        return f"****{text[-4:]}"

    def _serialize_dingtalk_group(self, row, reveal_secrets=False):
        if not row:
            return None
        secret = str(row.get('secret') or '')
        webhook = str(row.get('webhook_url') or '')
        item = {
            'id': int(row.get('id') or 0),
            'group_name': str(row.get('group_name') or '').strip(),
            'webhook_url': webhook if reveal_secrets else self._mask_webhook_url(webhook),
            'secret': secret if reveal_secrets else self._mask_dingtalk_secret(secret),
            'remark': str(row.get('remark') or '').strip(),
            'is_enabled': int(row.get('is_enabled') or 0),
            'created_at': str(row.get('created_at') or ''),
            'updated_at': str(row.get('updated_at') or ''),
        }
        return item

    def _mask_webhook_url(self, url):
        text = str(url or '').strip()
        if not text:
            return ''
        if len(text) <= 24:
            return text[:8] + '...'
        return f"{text[:20]}...{text[-8:]}"

    def _dingtalk_page_label(self, page_key):
        key = str(page_key or '').strip()
        labels = getattr(self, 'PAGE_PERMISSION_LABELS', None) or {}
        return str(labels.get(key) or key or '未知页面')

    def _dingtalk_notify_feature_map(self):
        items = getattr(self, 'DINGTALK_NOTIFY_FEATURES', None) or ()
        return {
            str(row.get('notify_key') or '').strip(): row
            for row in items
            if isinstance(row, dict) and str(row.get('notify_key') or '').strip()
        }

    def _dingtalk_notify_feature(self, notify_key):
        key = str(notify_key or '').strip()
        return self._dingtalk_notify_feature_map().get(key)

    def _dingtalk_notify_feature_label(self, notify_key):
        feature = self._dingtalk_notify_feature(notify_key)
        if feature:
            return str(feature.get('label') or notify_key or '未知通知')
        return str(notify_key or '未知通知')

    def _dingtalk_notify_feature_options(self):
        labels = getattr(self, 'PAGE_PERMISSION_LABELS', None) or {}
        items = []
        for feature in getattr(self, 'DINGTALK_NOTIFY_FEATURES', None) or ():
            if not isinstance(feature, dict):
                continue
            notify_key = str(feature.get('notify_key') or '').strip()
            if not notify_key:
                continue
            page_key = str(feature.get('page_key') or '').strip()
            items.append({
                'notify_key': notify_key,
                'notify_label': str(feature.get('label') or notify_key).strip(),
                'page_key': page_key,
                'page_label': labels.get(page_key) or self._dingtalk_page_label(page_key),
            })
        return items

    def _require_dingtalk_admin(self, user_id, start_response):
        if not user_id:
            return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
        if not self._user_has_page_access(user_id, 'system_dingtalk_notify_management'):
            return self.send_json({'status': 'error', 'message': '无权限'}, start_response)
        return None

    def _get_dingtalk_notify_config(self):
        webhook = (os.environ.get('SITJOY_DINGTALK_WEBHOOK') or '').strip()
        secret = (os.environ.get('SITJOY_DINGTALK_SECRET') or '').strip()
        try:
            file_cfg = self._load_local_db_config() or {}
        except Exception:
            file_cfg = {}
        dt_cfg = file_cfg.get('dingtalk') if isinstance(file_cfg.get('dingtalk'), dict) else {}
        if not webhook:
            webhook = str(dt_cfg.get('webhook_url') or dt_cfg.get('webhook') or '').strip()
        if not secret:
            secret = str(dt_cfg.get('secret') or '').strip()
        return {
            'webhook_url': webhook,
            'secret': secret,
            'keyword': self.DINGTALK_KEYWORD,
        }

    def _resolve_dingtalk_delivery_config(self, notify_key=None):
        notify_key = str(notify_key or '').strip()
        if notify_key:
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT g.id, g.group_name, g.webhook_url, g.secret
                            FROM dingtalk_notify_bindings b
                            JOIN dingtalk_groups g ON g.id = b.dingtalk_group_id
                            WHERE b.notify_key=%s
                              AND COALESCE(b.is_enabled, 1) = 1
                              AND COALESCE(g.is_enabled, 1) = 1
                            LIMIT 1
                            """,
                            (notify_key,),
                        )
                        row = cur.fetchone()
                        if row:
                            webhook = str(row.get('webhook_url') or '').strip()
                            secret = str(row.get('secret') or '').strip()
                            if webhook and secret:
                                return {
                                    'source': 'database',
                                    'notify_key': notify_key,
                                    'group_id': int(row.get('id') or 0),
                                    'group_name': str(row.get('group_name') or '').strip(),
                                    'webhook_url': webhook,
                                    'secret': secret,
                                }, None
            except Exception as exc:
                if not self._dingtalk_table_missing(exc):
                    return None, str(exc)
        file_cfg = self._get_dingtalk_notify_config()
        webhook = str(file_cfg.get('webhook_url') or '').strip()
        secret = str(file_cfg.get('secret') or '').strip()
        if webhook and secret:
            return {
                'source': 'file',
                'webhook_url': webhook,
                'secret': secret,
            }, None
        if notify_key:
            return None, (
                f'通知功能「{self._dingtalk_notify_feature_label(notify_key)}」未绑定启用的钉钉群，'
                '请先在系统管理 → 钉钉通知配置中维护'
            )
        return None, '未配置钉钉通知（请维护群聊绑定或 db_config.json）'

    def _build_dingtalk_signed_webhook_url(self, webhook_url, secret):
        url = (webhook_url or '').strip()
        sec = (secret or '').strip()
        if not url or not sec:
            return url
        timestamp = str(round(time.time() * 1000))
        string_to_sign = f'{timestamp}\n{sec}'
        digest = hmac.new(
            sec.encode('utf-8'),
            string_to_sign.encode('utf-8'),
            digestmod=hashlib.sha256,
        ).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest))
        joiner = '&' if '?' in url else '?'
        return f'{url}{joiner}timestamp={timestamp}&sign={sign}'

    def _ensure_dingtalk_keyword(self, text):
        body = (text or '').strip()
        keyword = self.DINGTALK_KEYWORD
        if keyword not in body:
            body = f'{keyword}\n\n{body}' if body else keyword
        return body

    def _prepare_dingtalk_text(self, text, delivery_cfg=None):
        body = (text or '').strip()
        cfg = delivery_cfg if isinstance(delivery_cfg, dict) else self._get_dingtalk_notify_config()
        if (cfg.get('secret') or '').strip():
            return body
        return self._ensure_dingtalk_keyword(body)

    def _post_dingtalk_payload(self, payload, notify_key=None):
        delivery_cfg, err = self._resolve_dingtalk_delivery_config(notify_key=notify_key)
        if err:
            return False, err
        webhook = str(delivery_cfg.get('webhook_url') or '').strip()
        secret = str(delivery_cfg.get('secret') or '').strip()
        if not webhook:
            return False, '未配置钉钉 Webhook'
        if not secret:
            return False, '未配置钉钉加签 Secret'
        url = self._build_dingtalk_signed_webhook_url(webhook, secret)
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json; charset=utf-8'},
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                raw = resp.read().decode('utf-8', errors='replace')
            try:
                result = json.loads(raw) if raw else {}
            except Exception:
                result = {}
            if isinstance(result, dict) and int(result.get('errcode') or 0) != 0:
                return False, str(result.get('errmsg') or raw or '钉钉返回错误')
            return True, None
        except urllib.error.HTTPError as e:
            detail = ''
            try:
                detail = e.read().decode('utf-8', errors='replace')
            except Exception:
                detail = str(e)
            return False, f'钉钉请求失败 HTTP {e.code}: {detail or e.reason}'
        except Exception as e:
            return False, f'钉钉请求失败: {e}'

    def _dingtalk_user_display_name(self, user_id):
        uid = self._parse_int(user_id) or 0
        if not uid:
            return ''
        try:
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        'SELECT username, name FROM users WHERE id=%s LIMIT 1',
                        (uid,),
                    )
                    row = cur.fetchone() or {}
            name = str(row.get('name') or '').strip()
            if name:
                return name
            username = str(row.get('username') or '').strip()
            if username:
                return username
        except Exception:
            pass
        return f'用户{uid}'

    def _dingtalk_markdown_colored_text(self, text, color):
        body = (text or '').strip()
        hex_color = str(color or '').strip()
        if not body or not hex_color:
            return body
        if not hex_color.startswith('#'):
            hex_color = f'#{hex_color}'
        return f'<font color="{hex_color}">{body}</font>'

    def _dingtalk_markdown_muted_text(self, text):
        body = (text or '').strip()
        if not body:
            return body
        return f'<font color="{self.DINGTALK_COLOR_MUTED}" size="2">{body}</font>'

    def _dingtalk_notify_tone_color(self, tone):
        if tone == 'positive':
            return self.DINGTALK_COLOR_POSITIVE
        if tone == 'negative':
            return self.DINGTALK_COLOR_NEGATIVE
        return ''

    def _build_dingtalk_markdown_message(self, title, detail_lines, user_id=None, title_tone=None, include_summary_line=True):
        """组装钉钉 Markdown 正文：列表明细 + 分隔线 + 通知人/时间。"""
        lines = [str(line).strip() for line in (detail_lines or []) if str(line or '').strip()]
        if not lines:
            return ''
        count = len(lines)
        sections = []
        if include_summary_line:
            sections.extend([
                f'本次共 **{count}** 条：',
                '',
            ])
        sections.extend([
            '\n'.join(lines),
            '',
            '---',
        ])
        footer_bits = []
        notifier = self._dingtalk_user_display_name(user_id)
        if notifier:
            footer_bits.append(f'通知人：**{notifier}**')
        footer_bits.append(f'时间：{datetime.now().strftime("%Y-%m-%d %H:%M")}')
        sections.append('> ' + ' · '.join(footer_bits))
        body = '\n'.join(sections)
        title_text = str(title or '').strip() or '系统通知'
        title_color = self._dingtalk_notify_tone_color(title_tone)
        if title_color:
            title_text = self._dingtalk_markdown_colored_text(title_text, title_color)
        return f'### {title_text}\n\n{body}'

    def _format_overseas_inventory_notify_blocks(self, items, event_kind):
        grouped = {}
        order = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            warehouse_name = str(row.get('warehouse_name') or '').strip()
            if not sku or not warehouse_name:
                continue
            if sku not in grouped:
                grouped[sku] = {
                    'rows': [],
                    'us_remaining_qty': self._parse_int(row.get('us_remaining_qty')),
                }
                order.append(sku)
            grouped[sku]['rows'].append(row)
            if grouped[sku]['us_remaining_qty'] is None and row.get('us_remaining_qty') is not None:
                grouped[sku]['us_remaining_qty'] = self._parse_int(row.get('us_remaining_qty')) or 0

        missing_skus = [sku for sku in order if grouped[sku].get('us_remaining_qty') is None]
        if missing_skus:
            try:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        totals = self._load_us_remaining_qty_by_skus(cur, missing_skus)
                for sku in missing_skus:
                    grouped[sku]['us_remaining_qty'] = totals.get(sku, 0)
            except Exception:
                for sku in missing_skus:
                    grouped[sku]['us_remaining_qty'] = 0

        color = self.DINGTALK_COLOR_NEGATIVE if event_kind == 'stockout' else self.DINGTALK_COLOR_POSITIVE
        blocks = []
        for sku in order:
            entry = grouped.get(sku) or {}
            rows = entry.get('rows') or []
            if not rows:
                continue
            us_total = entry.get('us_remaining_qty')
            if us_total is None:
                us_total = 0
            header = f'**{sku}**（全美库存：{us_total}）<br/>'
            detail_parts = []
            for row in rows:
                wh = str(row.get('warehouse_name') or '').strip()
                if not wh:
                    continue
                if event_kind == 'stockout':
                    prev_qty = self._parse_int(row.get('previous_qty')) or 0
                    new_qty = 0
                else:
                    prev_qty = 0
                    new_qty = self._parse_int(row.get('available_qty')) or 0
                detail_parts.append(f'{wh}：{prev_qty} → {new_qty}')
            if not detail_parts:
                continue
            detail_block = '<br/>'.join(detail_parts)
            blocks.append('\n'.join([
                f'- {self._dingtalk_markdown_colored_text(header, color)}',
                self._dingtalk_markdown_muted_text(f'  {detail_block}'),
            ]))
        return blocks

    def _format_overseas_stockout_lines(self, items):
        return self._format_overseas_inventory_notify_blocks(items, 'stockout')

    def _format_overseas_restock_lines(self, items):
        return self._format_overseas_inventory_notify_blocks(items, 'restock')

    def _send_dingtalk_overseas_markdown(self, title, lines, notify_key=None, user_id=None, title_tone=None, include_summary_line=True):
        formatted = [line for line in (lines or []) if line]
        if not formatted:
            return False, '没有可发送的记录'
        delivery_cfg, _err = self._resolve_dingtalk_delivery_config(notify_key=notify_key)
        markdown_text = self._build_dingtalk_markdown_message(
            title, formatted, user_id=user_id, title_tone=title_tone, include_summary_line=include_summary_line,
        )
        text = self._prepare_dingtalk_text(markdown_text, delivery_cfg=delivery_cfg)
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'title': title,
                'text': text,
            },
        }
        return self._post_dingtalk_payload(payload, notify_key=notify_key)

    def _format_transit_listed_sku_block_text(self, sku_lines):
        rows = sku_lines if isinstance(sku_lines, list) else []
        parts = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            if not sku:
                continue
            qty = self._parse_int(row.get('qty'))
            if qty is not None and qty > 0:
                parts.append(f'<br>{sku} × {qty}')
            else:
                parts.append(sku)
        return '<br/><br/>'.join(parts)

    def _format_transit_sku_detail_lines(self, sku_lines):
        rows = sku_lines if isinstance(sku_lines, list) else []
        lines = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            if not sku:
                continue
            qty = self._parse_int(row.get('qty'))
            if qty is not None and qty > 0:
                lines.append(f'{sku} × {qty}')
            else:
                lines.append(sku)
        return lines

    def _transit_eta_delay_detail_label(self, field_key, field_label):
        key = str(field_key or '').strip()
        if key == 'eta_latest':
            return 'ETA'
        if key == 'expected_listed_date_latest':
            return '预计上架时间'
        label = str(field_label or '').strip()
        if label.upper().startswith('ETA'):
            return 'ETA'
        if '预计上架' in label:
            return '预计上架时间'
        return label or '预计到货'

    def _format_transit_eta_delay_lines(self, items):
        grouped = {}
        order = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            transit_id = self._parse_int(row.get('transit_id'))
            if not transit_id:
                continue
            if transit_id not in grouped:
                grouped[transit_id] = {'meta': row, 'changes': []}
                order.append(transit_id)
            grouped[transit_id]['changes'].append(row)

        blocks = []
        for transit_id in order:
            entry = grouped.get(transit_id) or {}
            meta = entry.get('meta') or {}
            changes = entry.get('changes') or []
            box = str(meta.get('logistics_box_no') or '').strip() or '-'
            bl = str(meta.get('bill_of_lading_no') or '').strip()
            bl_text = f' · 提单 {bl}' if bl else ''
            header = f'**{box}**{bl_text}<br/>'
            detail_parts = []
            seen_fields = set()
            for row in changes:
                field = str(row.get('field') or '').strip()
                if field and field in seen_fields:
                    continue
                if field:
                    seen_fields.add(field)
                label = self._transit_eta_delay_detail_label(field, row.get('field_label'))
                old_date = str(row.get('previous_date') or '').strip() or '-'
                new_date = str(row.get('new_date') or '').strip() or '-'
                detail_parts.append(f'{label} {old_date} → {new_date}')
            if not detail_parts:
                continue
            detail_block = '<br/>'.join(detail_parts)
            block_lines = [
                f'- {self._dingtalk_markdown_colored_text(header, self.DINGTALK_COLOR_NEGATIVE)}',
                self._dingtalk_markdown_muted_text(f'  {detail_block}'),
            ]
            blocks.append('\n'.join(block_lines))
        return blocks

    def _format_transit_listed_available_lines(self, items):
        blocks = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            event_kind = str(row.get('event_kind') or 'registered').strip()
            if event_kind != 'registered':
                continue
            box = str(row.get('logistics_box_no') or '').strip() or '-'
            wh = str(row.get('warehouse_name') or '').strip() or '-'
            sku_block = self._format_transit_listed_sku_block_text(row.get('sku_lines'))
            if not sku_block:
                continue
            header = f'**{box}** · {wh}'
            block_lines = [
                f'- {self._dingtalk_markdown_colored_text(header, self.DINGTALK_COLOR_POSITIVE)}',
                self._dingtalk_markdown_muted_text(f'  {sku_block}'),
            ]
            blocks.append('\n'.join(block_lines))
        return blocks

    def _format_account_health_alert_datetime(self, value):
        text = ('' if value is None else str(value)).strip()
        if not text:
            return ''
        for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M'):
            try:
                return datetime.strptime(text, fmt).strftime('%Y-%m-%d %H:%M')
            except Exception:
                continue
        return text[:16]

    def _format_amazon_account_health_alert_lines(self, items):
        blocks = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            shop = str(row.get('shop_name') or '').strip() or '-'
            dt = self._format_account_health_alert_datetime(row.get('record_datetime')) or '-'
            breaches = row.get('breaches') if isinstance(row.get('breaches'), list) else []
            worses = row.get('worses') if isinstance(row.get('worses'), list) else []
            header = f'**{shop}** · {dt}'
            block_lines = [
                f'- {self._dingtalk_markdown_colored_text(header, self.DINGTALK_COLOR_NEGATIVE)}',
            ]
            detail_lines = []
            for metric in breaches:
                if not isinstance(metric, dict):
                    continue
                label = str(metric.get('label') or '').strip()
                if not label:
                    continue
                value = str(metric.get('value') or '').strip()
                detail_lines.append(f'异常 · {label} · {value}' if value else f'异常 · {label}')
            for metric in worses:
                if not isinstance(metric, dict):
                    continue
                label = str(metric.get('label') or '').strip()
                if not label:
                    continue
                value = str(metric.get('value') or '').strip()
                detail_lines.append(f'变差 · {label} · {value}' if value else f'变差 · {label}')
            if not detail_lines:
                detail_lines.append('指标 · 当前无异常或变差')
            block_lines.extend(self._dingtalk_markdown_muted_text(line) for line in detail_lines)
            remark = str(row.get('remark') or '').strip()
            if remark:
                block_lines.append(self._dingtalk_markdown_muted_text(f'备注 · {remark}'))
            blocks.append('\n'.join(block_lines))
        return blocks

    def _send_dingtalk_amazon_account_health_alert(self, items, notify_key=None, user_id=None):
        key = notify_key or 'amazon_account_health_alert'
        lines = self._format_amazon_account_health_alert_lines(items)
        return self._send_dingtalk_transit_markdown(
            '账户健康提醒', lines, notify_key=key, user_id=user_id, title_tone='negative',
        )

    def _send_dingtalk_transit_markdown(self, title, lines, notify_key=None, user_id=None, title_tone=None, include_summary_line=True):
        formatted = [line for line in (lines or []) if line]
        if not formatted:
            return False, '没有可发送的记录'
        delivery_cfg, _err = self._resolve_dingtalk_delivery_config(notify_key=notify_key)
        markdown_text = self._build_dingtalk_markdown_message(
            title, formatted, user_id=user_id, title_tone=title_tone, include_summary_line=include_summary_line,
        )
        text = self._prepare_dingtalk_text(markdown_text, delivery_cfg=delivery_cfg)
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'title': title,
                'text': text,
            },
        }
        return self._post_dingtalk_payload(payload, notify_key=notify_key)

    def _send_dingtalk_transit_eta_delay(self, items, notify_key=None, user_id=None):
        key = notify_key or 'transit_eta_delay'
        lines = self._format_transit_eta_delay_lines(items)
        if not lines:
            return False, '没有可发送的记录'
        count = len(lines)
        title = f'在途物流到货延迟提醒（{count}条）'
        return self._send_dingtalk_transit_markdown(
            title, lines, notify_key=key, user_id=user_id, title_tone='negative', include_summary_line=False,
        )

    def _send_dingtalk_transit_listed_available(self, items, notify_key=None, user_id=None):
        key = notify_key or 'transit_listed_available'
        lines = self._format_transit_listed_available_lines(items)
        if not lines:
            return False, '没有可发送的记录'
        count = len(lines)
        title = f'在途物流上架可售提醒（{count}条）'
        return self._send_dingtalk_transit_markdown(
            title, lines, notify_key=key, user_id=user_id, title_tone='positive', include_summary_line=False,
        )

    def _send_dingtalk_overseas_stockout(self, items, notify_key=None, user_id=None):
        key = notify_key or 'overseas_stockout'
        lines = self._format_overseas_stockout_lines(items)
        if not lines:
            return False, '没有可发送的记录'
        count = len(lines)
        title = f'海外仓缺货提醒（{count}条）'
        return self._send_dingtalk_overseas_markdown(
            title, lines, notify_key=key, user_id=user_id, title_tone='negative', include_summary_line=False,
        )

    def _send_dingtalk_overseas_restock(self, items, notify_key=None, user_id=None):
        key = notify_key or 'overseas_restock'
        lines = self._format_overseas_restock_lines(items)
        if not lines:
            return False, '没有可发送的记录'
        count = len(lines)
        title = f'海外仓重新上架提醒（{count}条）'
        return self._send_dingtalk_overseas_markdown(
            title, lines, notify_key=key, user_id=user_id, title_tone='positive', include_summary_line=False,
        )

    def _validate_dingtalk_notify_access(self, user_id, notify_key):
        notify_key = str(notify_key or '').strip()
        if not notify_key:
            return False, '缺少 notify_key'
        feature = self._dingtalk_notify_feature(notify_key)
        if not feature:
            return False, f'未知的通知功能：{notify_key}'
        page_key = str(feature.get('page_key') or '').strip()
        if not page_key:
            return False, f'通知功能「{self._dingtalk_notify_feature_label(notify_key)}」未配置来源页面'
        if not self._user_has_page_access(user_id, page_key):
            return False, (
                f'无权限发送「{self._dingtalk_notify_feature_label(notify_key)}」通知'
                f'（需 {self._dingtalk_page_label(page_key)} 页面权限）'
            )
        return True, None

    def handle_dingtalk_group_api(self, environ, method, start_response):
        try:
            user_id = self._get_session_user(environ)
            denied = self._require_dingtalk_admin(user_id, start_response)
            if denied:
                return denied

            query = parse_qs(environ.get('QUERY_STRING', ''))
            item_id = self._parse_int((query.get('id', [''])[0] or '').strip())

            if method == 'GET':
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if item_id:
                            cur.execute(
                                """
                                SELECT id, group_name, webhook_url, secret, remark, is_enabled,
                                       created_at, updated_at
                                FROM dingtalk_groups
                                WHERE id=%s
                                LIMIT 1
                                """,
                                (item_id,),
                            )
                            row = cur.fetchone()
                            if not row:
                                return self.send_json({'status': 'error', 'message': '记录不存在'}, start_response)
                            return self.send_json({
                                'status': 'success',
                                'item': self._serialize_dingtalk_group(row, reveal_secrets=True),
                            }, start_response)
                        cur.execute(
                            """
                            SELECT id, group_name, webhook_url, secret, remark, is_enabled,
                                   created_at, updated_at
                            FROM dingtalk_groups
                            ORDER BY id ASC
                            """
                        )
                        rows = cur.fetchall() or []
                return self.send_json({
                    'status': 'success',
                    'items': [self._serialize_dingtalk_group(row) for row in rows],
                }, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                group_name = str(data.get('group_name') or '').strip()
                webhook_url = str(data.get('webhook_url') or '').strip()
                secret = str(data.get('secret') or '').strip()
                remark = str(data.get('remark') or '').strip() or None
                is_enabled = 1 if str(data.get('is_enabled', 1)).strip().lower() not in ('0', 'false', 'no') else 0
                if not group_name:
                    return self.send_json({'status': 'error', 'message': '请填写群聊名称'}, start_response)
                if not webhook_url:
                    return self.send_json({'status': 'error', 'message': '请填写 Webhook URL'}, start_response)
                if not secret:
                    return self.send_json({'status': 'error', 'message': '请填写加签 Secret'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO dingtalk_groups
                            (group_name, webhook_url, secret, remark, is_enabled)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (group_name, webhook_url, secret, remark, is_enabled),
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': int(new_id or 0)}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                group_name = str(data.get('group_name') or '').strip()
                webhook_url = str(data.get('webhook_url') or '').strip()
                secret = str(data.get('secret') or '').strip()
                remark = str(data.get('remark') or '').strip() or None
                is_enabled = 1 if str(data.get('is_enabled', 1)).strip().lower() not in ('0', 'false', 'no') else 0
                if not group_name:
                    return self.send_json({'status': 'error', 'message': '请填写群聊名称'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT webhook_url, secret FROM dingtalk_groups WHERE id=%s LIMIT 1", (item_id,))
                        existing = cur.fetchone() or {}
                        final_webhook = webhook_url or str(existing.get('webhook_url') or '').strip()
                        final_secret = secret or str(existing.get('secret') or '').strip()
                        if not final_webhook:
                            return self.send_json({'status': 'error', 'message': '请填写 Webhook URL'}, start_response)
                        if not final_secret:
                            return self.send_json({'status': 'error', 'message': '请填写加签 Secret'}, start_response)
                        cur.execute(
                            """
                            UPDATE dingtalk_groups
                            SET group_name=%s, webhook_url=%s, secret=%s, remark=%s, is_enabled=%s
                            WHERE id=%s
                            """,
                            (group_name, final_webhook, final_secret, remark, is_enabled, item_id),
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT COUNT(*) AS cnt FROM dingtalk_notify_bindings WHERE dingtalk_group_id=%s",
                            (item_id,),
                        )
                        bound = int((cur.fetchone() or {}).get('cnt') or 0)
                        if bound > 0:
                            return self.send_json({
                                'status': 'error',
                                'message': f'该群聊仍被 {bound} 个通知功能绑定，请先解除绑定',
                            }, start_response)
                        cur.execute("DELETE FROM dingtalk_groups WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as exc:
            if self._dingtalk_table_missing(exc):
                return self.send_json({
                    'status': 'error',
                    'message': '钉钉配置表未初始化，请先执行 scripts/sql/20260621_01_dingtalk_notify_config.sql',
                }, start_response)
            return self.send_json({'status': 'error', 'message': str(exc)}, start_response)

    def handle_dingtalk_notify_binding_api(self, environ, method, start_response):
        try:
            user_id = self._get_session_user(environ)
            denied = self._require_dingtalk_admin(user_id, start_response)
            if denied:
                return denied

            if method == 'GET':
                feature_options = self._dingtalk_notify_feature_options()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, group_name, is_enabled
                            FROM dingtalk_groups
                            ORDER BY id ASC
                            """
                        )
                        groups = cur.fetchall() or []
                        cur.execute(
                            """
                            SELECT b.id, b.notify_key, b.dingtalk_group_id, b.is_enabled,
                                   g.group_name
                            FROM dingtalk_notify_bindings b
                            LEFT JOIN dingtalk_groups g ON g.id = b.dingtalk_group_id
                            ORDER BY b.notify_key ASC
                            """
                        )
                        bindings = cur.fetchall() or []
                binding_map = {str(r.get('notify_key') or '').strip(): r for r in bindings}
                rows = []
                for opt in feature_options:
                    notify_key = opt['notify_key']
                    bound = binding_map.get(notify_key) or {}
                    rows.append({
                        'id': int(bound.get('id') or 0) or None,
                        'notify_key': notify_key,
                        'notify_label': opt['notify_label'],
                        'page_key': opt.get('page_key'),
                        'page_label': opt.get('page_label'),
                        'dingtalk_group_id': int(bound.get('dingtalk_group_id') or 0) or None,
                        'group_name': str(bound.get('group_name') or '').strip(),
                        'is_enabled': int(bound.get('is_enabled') or 0) if bound else 0,
                        'is_bound': bool(bound),
                    })
                return self.send_json({
                    'status': 'success',
                    'feature_options': feature_options,
                    'groups': [
                        {
                            'id': int(g.get('id') or 0),
                            'group_name': str(g.get('group_name') or '').strip(),
                            'is_enabled': int(g.get('is_enabled') or 0),
                        }
                        for g in groups
                    ],
                    'bindings': rows,
                }, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                notify_key = str(data.get('notify_key') or '').strip()
                group_id = self._parse_int(data.get('dingtalk_group_id'))
                is_enabled = 1 if str(data.get('is_enabled', 1)).strip().lower() not in ('0', 'false', 'no') else 0
                if not notify_key:
                    return self.send_json({'status': 'error', 'message': '缺少 notify_key'}, start_response)
                if not group_id:
                    return self.send_json({'status': 'error', 'message': '请选择钉钉群聊'}, start_response)
                if not self._dingtalk_notify_feature(notify_key):
                    return self.send_json({'status': 'error', 'message': '无效的通知功能'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT id FROM dingtalk_groups WHERE id=%s LIMIT 1", (group_id,))
                        if not cur.fetchone():
                            return self.send_json({'status': 'error', 'message': '群聊不存在'}, start_response)
                        cur.execute(
                            """
                            INSERT INTO dingtalk_notify_bindings
                            (notify_key, dingtalk_group_id, is_enabled)
                            VALUES (%s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                dingtalk_group_id=VALUES(dingtalk_group_id),
                                is_enabled=VALUES(is_enabled)
                            """,
                            (notify_key, group_id, is_enabled),
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                notify_key = str(data.get('notify_key') or '').strip()
                item_id = self._parse_int(data.get('id'))
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if item_id:
                            cur.execute("DELETE FROM dingtalk_notify_bindings WHERE id=%s", (item_id,))
                        elif notify_key:
                            cur.execute("DELETE FROM dingtalk_notify_bindings WHERE notify_key=%s", (notify_key,))
                        else:
                            return self.send_json({'status': 'error', 'message': '缺少 id 或 notify_key'}, start_response)
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as exc:
            if self._dingtalk_table_missing(exc):
                return self.send_json({
                    'status': 'error',
                    'message': '钉钉配置表未初始化，请先执行 scripts/sql/20260621_01_dingtalk_notify_config.sql 与 20260622_01_dingtalk_notify_feature_bindings.sql',
                }, start_response)
            return self.send_json({'status': 'error', 'message': str(exc)}, start_response)

    def handle_dingtalk_page_notify_binding_api(self, environ, method, start_response):
        """兼容旧 API 路径。"""
        return self.handle_dingtalk_notify_binding_api(environ, method, start_response)

    def handle_dingtalk_notify_api(self, environ, method, start_response):
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)

            query = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query.get('action', [''])[0] or '').strip().lower()
            data = self._read_json_body(environ)
            notify_key = str(data.get('notify_key') or action or '').strip()

            if action == 'overseas_stockout':
                ok_access, access_err = self._validate_dingtalk_notify_access(user_id, notify_key)
                if not ok_access:
                    return self.send_json({'status': 'error', 'message': access_err}, start_response)
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_overseas_stockout(items, notify_key=notify_key, user_id=user_id)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_overseas_stockout_lines(items)),
                }, start_response)

            if action == 'overseas_restock':
                ok_access, access_err = self._validate_dingtalk_notify_access(user_id, notify_key)
                if not ok_access:
                    return self.send_json({'status': 'error', 'message': access_err}, start_response)
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_overseas_restock(items, notify_key=notify_key, user_id=user_id)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_overseas_restock_lines(items)),
                }, start_response)

            if action == 'transit_eta_delay':
                ok_access, access_err = self._validate_dingtalk_notify_access(user_id, notify_key)
                if not ok_access:
                    return self.send_json({'status': 'error', 'message': access_err}, start_response)
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_transit_eta_delay(items, notify_key=notify_key, user_id=user_id)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_transit_eta_delay_lines(items)),
                }, start_response)

            if action == 'transit_listed_available':
                ok_access, access_err = self._validate_dingtalk_notify_access(user_id, notify_key)
                if not ok_access:
                    return self.send_json({'status': 'error', 'message': access_err}, start_response)
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_transit_listed_available(items, notify_key=notify_key, user_id=user_id)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_transit_listed_available_lines(items)),
                }, start_response)

            if action == 'amazon_account_health_alert':
                ok_access, access_err = self._validate_dingtalk_notify_access(user_id, notify_key)
                if not ok_access:
                    return self.send_json({'status': 'error', 'message': access_err}, start_response)
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_amazon_account_health_alert(items, notify_key=notify_key, user_id=user_id)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_amazon_account_health_alert_lines(items)),
                }, start_response)

            return self.send_json({'status': 'error', 'message': '未知 action'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
