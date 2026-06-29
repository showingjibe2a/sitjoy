# -*- coding: utf-8 -*-
"""WSGI 应用入口：请求路径规范化与 page/api 分发。"""

import json
import traceback
from datetime import datetime
from urllib.parse import parse_qs


class AppEntryMixin:
    """WSGI 入口：权限校验 → 页面 → API。"""

    @staticmethod
    def _normalize_request_path(path):
        p = str(path or '/').strip()
        if not p.startswith('/'):
            p = '/' + p
        if len(p) > 1 and p.endswith('/'):
            p = p.rstrip('/')
        return p

    def __call__(self, environ, start_response):
        """WSGI 主入口。"""
        try:
            path = self._normalize_request_path(environ.get('PATH_INFO'))
            environ['PATH_INFO'] = path
            method = (environ.get('REQUEST_METHOD') or 'GET').upper()
            environ['REQUEST_METHOD'] = method

            cache_body = getattr(self, '_audit_cache_request_body', None)
            if callable(cache_body):
                cache_body(environ, path, method)

            permission_result = self._validate_api_permission(path, environ, start_response)
            if permission_result is not None:
                return permission_result

            page_result = self._dispatch_page_request(path, environ, start_response)
            if page_result is not None:
                return page_result

            api_result = self._dispatch_api_request(path, environ, method, start_response)
            if api_result is not None:
                log_op = getattr(self, '_audit_try_log_operation', None)
                if callable(log_op):
                    log_op(environ, path, method)
                return api_result

            if path.startswith('/static/'):
                return self.serve_static(path, start_response)

            return self.send_error(404, 'Not Found', start_response)
        except Exception as e:
            print(f"WSGI 错误: {str(e)}")
            traceback.print_exc()
            if str(environ.get('PATH_INFO') or '').startswith('/api/'):
                return self.send_json({'status': 'error', 'message': f'服务器错误: {str(e)}', 'path': environ.get('PATH_INFO', '')}, start_response)
            return self.send_error(500, f'服务器错误: {str(e)}', start_response)

    def handle_hello_api(self, environ, path, method, start_response):
        try:
            if method == 'POST':
                content_length = int(environ.get('CONTENT_LENGTH', 0))
                body = environ['wsgi.input'].read(content_length)
                try:
                    text = body.decode('utf-8', errors='surrogateescape')
                except Exception:
                    text = body.decode('utf-8', errors='replace')
                data = json.loads(text)
                name = data.get('name', '访客')
            else:
                query_string = environ.get('QUERY_STRING', '')
                query_params = parse_qs(query_string)
                name = query_params.get('name', ['访客'])[0]

            response = {
                'message': f'你好，{name}！',
                'timestamp': datetime.now().isoformat(),
                'status': 'success'
            }
            return self.send_json(response, start_response)
        except Exception as e:
            return self.send_error(500, str(e), start_response)

    def handle_status(self, start_response):
        response = {
            'status': 'running',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat()
        }
        return self.send_json(response, start_response)