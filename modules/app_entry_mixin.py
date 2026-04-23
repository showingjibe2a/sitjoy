import json
import traceback
from datetime import datetime
from urllib.parse import parse_qs


class AppEntryMixin:
    """WSGI 入口相关能力。"""

    def __call__(self, environ, start_response):
        try:
            path = environ['PATH_INFO']
            method = environ['REQUEST_METHOD']

            permission_result = self._validate_api_permission(path, environ, start_response)
            if permission_result is not None:
                return permission_result

            page_result = self._dispatch_page_request(path, environ, start_response)
            if page_result is not None:
                return page_result

            api_result = self._dispatch_api_request(path, environ, method, start_response)
            if api_result is not None:
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