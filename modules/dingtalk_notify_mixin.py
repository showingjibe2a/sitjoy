"""钉钉群机器人 Webhook 通知（关键词安全设置须包含【SITJOY】）。"""

import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import parse_qs


class DingTalkNotifyMixin:
    DINGTALK_KEYWORD = '【SITJOY】'

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

    def _post_dingtalk_payload(self, payload):
        cfg = self._get_dingtalk_notify_config()
        webhook = cfg.get('webhook_url') or ''
        if not webhook:
            return False, '未配置钉钉 Webhook（环境变量 SITJOY_DINGTALK_WEBHOOK 或 db_config.json → dingtalk.webhook_url）'
        url = self._build_dingtalk_signed_webhook_url(webhook, cfg.get('secret'))
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

    def _format_overseas_stockout_lines(self, items):
        lines = []
        for row in items or []:
            if not isinstance(row, dict):
                continue
            sku = str(row.get('sku') or '').strip()
            warehouse_name = str(row.get('warehouse_name') or '').strip()
            if not sku or not warehouse_name:
                continue
            lines.append(f'{sku} 在 {warehouse_name} 缺货')
        return lines

    def _send_dingtalk_overseas_stockout(self, items):
        lines = self._format_overseas_stockout_lines(items)
        if not lines:
            return False, '没有可发送的缺货记录'
        title = '海外仓缺货提醒'
        text = self._ensure_dingtalk_keyword('\n'.join(lines))
        payload = {
            'msgtype': 'markdown',
            'markdown': {
                'title': title,
                'text': f'### {title}\n\n{text}',
            },
        }
        return self._post_dingtalk_payload(payload)

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

            if action == 'overseas_stockout':
                items = data.get('items') if isinstance(data.get('items'), list) else []
                ok, err = self._send_dingtalk_overseas_stockout(items)
                if not ok:
                    return self.send_json({'status': 'error', 'message': err or '发送失败'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'sent_count': len(self._format_overseas_stockout_lines(items)),
                }, start_response)

            return self.send_json({'status': 'error', 'message': '未知 action'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
