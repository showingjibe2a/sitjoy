import json
import traceback
from datetime import datetime
from urllib.parse import parse_qs


class AppEntryMixin:
    """WSGI 鍏ュ彛鐩稿叧鑳藉姏銆?""

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
            print(f"WSGI 閿欒: {str(e)}")
            traceback.print_exc()
            return self.send_error(500, f'鏈嶅姟鍣ㄩ敊璇? {str(e)}', start_response)

    def handle_hello_api(self, environ, path, method, start_response):
        try:
            if method == 'POST':
                content_length = int(environ.get('CONTENT_LENGTH', 0))
                body = environ['wsgi.input'].read(content_length)
                data = json.loads(body.decode('utf-8'))
                name = data.get('name', '璁垮')
            else:
                query_string = environ.get('QUERY_STRING', '')
                query_params = parse_qs(query_string)
                name = query_params.get('name', ['璁垮'])[0]

            response = {
                'message': f'浣犲ソ锛寋name}锛?,
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


