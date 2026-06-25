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

    def _dingtalk_notify_tone_color(self, tone):
        if tone == 'positive':
            return self.DINGTALK_COLOR_POSITIVE
        if tone == 'negative':
            return self.DINGTALK_COLOR_NEGATIVE
        return ''

    def _build_dingtalk_markdown_message(self, title, detail_lines, user_id=None, title_tone=None):
        """组装钉钉 Markdown 正文：列表明细 + 分隔线 + 通知人/时间。"""
        lines = [str(line).strip() for line in (detail_lines or []) if str(line or '').strip()]
        if not lines:
            return ''
        count = len(lines)
        sections = [
            f'本次共 **{count}** 条：',
            '',
            '\n'.join(lines),
            '',
            '---',
        ]
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

    def _format_overseas_inventory_notify_lines(self, items, event_kind):
        lines = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            warehouse_name = str(row.get('warehouse_name') or '').strip()
            if not sku or not warehouse_name:
                continue
            if event_kind == 'restock':
                qty = self._parse_int(row.get('available_qty'))
                qty_text = f' · 在库 **{qty}**' if qty is not None and qty > 0 else ''
                line = f'**{sku}** · {warehouse_name} · **重新上架**{qty_text}'
                color = self.DINGTALK_COLOR_POSITIVE
            else:
                prev_qty = self._parse_int(row.get('previous_qty'))
                prev_text = f' · 原库存 **{prev_qty}**' if prev_qty is not None and prev_qty > 0 else ''
                line = f'**{sku}** · {warehouse_name} · **缺货**{prev_text}'
                color = self.DINGTALK_COLOR_NEGATIVE
            lines.append(f'- {self._dingtalk_markdown_colored_text(line, color)}')
        return lines

    def _format_overseas_stockout_lines(self, items):
        return self._format_overseas_inventory_notify_lines(items, 'stockout')

    def _format_overseas_restock_lines(self, items):
        return self._format_overseas_inventory_notify_lines(items, 'restock')

    def _send_dingtalk_overseas_markdown(self, title, lines, notify_key=None, user_id=None, title_tone=None):
        formatted = [line for line in (lines or []) if line]
        if not formatted:
            return False, '没有可发送的记录'
        delivery_cfg, _err = self._resolve_dingtalk_delivery_config(notify_key=notify_key)
        markdown_text = self._build_dingtalk_markdown_message(
            title, formatted, user_id=user_id, title_tone=title_tone,
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

    def _format_transit_sku_summary(self, sku_lines, max_items=6):
        rows = sku_lines if isinstance(sku_lines, list) else []
        parts = []
        for row in rows[:max_items]:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            if not sku:
                continue
            qty = self._parse_int(row.get('qty'))
            qty_text = f'×**{qty}**' if qty is not None and qty > 0 else ''
            parts.append(f'{sku}{qty_text}')
        if len(rows) > max_items:
            parts.append(f'…等 {len(rows)} 个 SKU')
        return '、'.join(parts)

    def _format_transit_eta_delay_lines(self, items):
        lines = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            box = str(row.get('logistics_box_no') or '').strip() or '-'
            wh = str(row.get('warehouse_name') or '').strip() or '-'
            label = str(row.get('field_label') or '预计到货').strip()
            old_date = str(row.get('previous_date') or '').strip() or '-'
            new_date = str(row.get('new_date') or '').strip() or '-'
            bl = str(row.get('bill_of_lading_no') or '').strip()
            bl_text = f' · 提单 {bl}' if bl else ''
            line = f'**{box}**{bl_text} · {wh} · {label} **{old_date} → {new_date}**'
            lines.append(f'- {self._dingtalk_markdown_colored_text(line, self.DINGTALK_COLOR_NEGATIVE)}')
        return lines

    def _format_transit_listed_available_lines(self, items):
        lines = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            box = str(row.get('logistics_box_no') or '').strip() or '-'
            wh = str(row.get('warehouse_name') or '').strip() or '-'
            listed_date = str(row.get('listed_date') or '').strip()
            sku_summary = self._format_transit_sku_summary(row.get('sku_lines'))
            if not sku_summary:
                continue
            event_kind = str(row.get('event_kind') or 'registered').strip()
            if event_kind == 'stock_applied':
                action = '上架可售入仓'
            else:
                action = '物流上架可售'
            date_text = f' · 上架日 **{listed_date}**' if listed_date else ''
            line = f'**{box}** · {wh} · **{action}**{date_text} · {sku_summary}'
            lines.append(f'- {self._dingtalk_markdown_colored_text(line, self.DINGTALK_COLOR_POSITIVE)}')
        return lines

    def _send_dingtalk_transit_markdown(self, title, lines, notify_key=None, user_id=None, title_tone=None):
        formatted = [line for line in (lines or []) if line]
        if not formatted:
            return False, '没有可发送的记录'
        delivery_cfg, _err = self._resolve_dingtalk_delivery_config(notify_key=notify_key)
        markdown_text = self._build_dingtalk_markdown_message(
            title, formatted, user_id=user_id, title_tone=title_tone,
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
        return self._send_dingtalk_transit_markdown(
            '在途物流到货延迟提醒', lines, notify_key=key, user_id=user_id, title_tone='negative',
        )

    def _send_dingtalk_transit_listed_available(self, items, notify_key=None, user_id=None):
        key = notify_key or 'transit_listed_available'
        lines = self._format_transit_listed_available_lines(items)
        return self._send_dingtalk_transit_markdown(
            '在途物流上架可售提醒', lines, notify_key=key, user_id=user_id, title_tone='positive',
        )

    def _send_dingtalk_overseas_stockout(self, items, notify_key=None, user_id=None):
        key = notify_key or 'overseas_stockout'
        lines = self._format_overseas_stockout_lines(items)
        return self._send_dingtalk_overseas_markdown(
            '海外仓缺货提醒', lines, notify_key=key, user_id=user_id, title_tone='negative',
        )

    def _send_dingtalk_overseas_restock(self, items, notify_key=None, user_id=None):
        key = notify_key or 'overseas_restock'
        lines = self._format_overseas_restock_lines(items)
        return self._send_dingtalk_overseas_markdown(
            '海外仓重新上架提醒', lines, notify_key=key, user_id=user_id, title_tone='positive',
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

            return self.send_json({'status': 'error', 'message': '未知 action'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
