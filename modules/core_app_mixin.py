import json
import mimetypes
import os
import re
import time
from datetime import datetime

try:
    import pymysql
    _pymysql_import_error = None
except Exception as e:
    pymysql = None
    _pymysql_import_error = str(e)


class CoreAppMixin:
    """应用通用能力：缓存、响应、静态文件、DB连接、基础解析。"""

    def _get_cached_template_options(self, cache_key, loader, ttl_seconds=120):
        try:
            now = time.time()
            cached = self._template_options_cache.get(cache_key)
            if cached and (now - cached.get('ts', 0) <= ttl_seconds):
                return cached.get('data')

            cache_dir = os.path.join(self.base_path, '__pycache__')
            os.makedirs(cache_dir, exist_ok=True)
            cache_file = os.path.join(cache_dir, f'opt_cache_{cache_key}.json')
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        disk_cached = json.load(f)
                    if isinstance(disk_cached, dict) and (now - float(disk_cached.get('ts') or 0) <= ttl_seconds):
                        data = disk_cached.get('data')
                        self._template_options_cache[cache_key] = {'ts': now, 'data': data}
                        return data
                except Exception:
                    pass

            data = loader()
            self._template_options_cache[cache_key] = {'ts': now, 'data': data}
            try:
                with open(cache_file, 'w', encoding='utf-8') as f:
                    json.dump({'ts': now, 'data': data}, f, ensure_ascii=False)
            except Exception:
                pass
            return data
        except Exception:
            return loader()

    def send_json(self, data, start_response, status='200 OK'):
        payload = json.dumps(data, ensure_ascii=False, default=str).encode('utf-8')
        start_response(status, [
            ('Content-Type', 'application/json; charset=utf-8'),
            ('Content-Length', str(len(payload)))
        ])
        return [payload]

    def send_error(self, code, message, start_response):
        code_int = int(code)
        status_text = {
            400: 'Bad Request',
            401: 'Unauthorized',
            403: 'Forbidden',
            404: 'Not Found',
            405: 'Method Not Allowed',
            409: 'Conflict',
            500: 'Internal Server Error'
        }.get(code_int, 'Error')
        return self.send_json({'status': 'error', 'message': str(message)}, start_response, f'{code_int} {status_text}')

    def serve_file(self, relative_path, content_type, start_response):
        file_path = os.path.join(self.base_path, relative_path)
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.send_error(404, 'File not found', start_response)
        with open(file_path, 'rb') as f:
            content = f.read()
        start_response('200 OK', [
            ('Content-Type', content_type),
            ('Content-Length', str(len(content)))
        ])
        return [content]

    def serve_static(self, path, start_response):
        rel_path = (path or '').lstrip('/')
        static_root = os.path.join(self.base_path, 'static')
        file_path = os.path.normpath(os.path.join(self.base_path, rel_path))
        static_root_norm = os.path.normpath(static_root)
        if not file_path.startswith(static_root_norm):
            return self.send_error(403, 'Invalid path', start_response)
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self.send_error(404, 'File not found', start_response)
        mime_type, _ = mimetypes.guess_type(file_path)
        if not mime_type:
            mime_type = 'application/octet-stream'
        with open(file_path, 'rb') as f:
            content = f.read()
        start_response('200 OK', [
            ('Content-Type', mime_type),
            ('Content-Length', str(len(content))),
            ('Cache-Control', 'public, max-age=300')
        ])
        return [content]

    def _read_json_body(self, environ):
        content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
        if content_length <= 0:
            return {}
        body = environ['wsgi.input'].read(content_length)
        if not body:
            return {}
        return json.loads(body.decode('utf-8'))

    def _get_db_config(self):
        config = {
            'host': os.environ.get('SITJOY_DB_HOST', '127.0.0.1'),
            'user': os.environ.get('SITJOY_DB_USER', 'root'),
            'password': os.environ.get('SITJOY_DB_PASSWORD', ''),
            'database': os.environ.get('SITJOY_DB_NAME', 'sitjoy'),
            'port': int(os.environ.get('SITJOY_DB_PORT', '3306')),
            'charset': 'utf8mb4'
        }
        file_cfg = self._load_local_db_config()
        if file_cfg:
            for key in ['host', 'user', 'password', 'database', 'port', 'charset']:
                if key in file_cfg and file_cfg[key] not in (None, ''):
                    if key == 'port':
                        try:
                            config[key] = int(file_cfg[key])
                        except Exception:
                            continue
                    else:
                        config[key] = file_cfg[key]
        return config

    def _load_local_db_config(self):
        try:
            cfg_path = os.path.join(self.base_path, 'db_config.json')
            if not os.path.exists(cfg_path):
                return None
            with open(cfg_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return None

    def _get_db_connection(self):
        if not pymysql:
            raise RuntimeError(f"PyMySQL not available: {_pymysql_import_error}")
        cfg = self._get_db_config()
        return pymysql.connect(
            host=cfg['host'],
            user=cfg['user'],
            password=cfg['password'],
            database=cfg['database'],
            port=cfg['port'],
            charset=cfg['charset'],
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
            connect_timeout=3,
            read_timeout=12,
            write_timeout=12
        )

    def _split_multi_values(self, value):
        if value is None:
            return []
        if isinstance(value, list):
            raw_items = value
        else:
            raw_items = re.split(r'[\n,，;；/]+', str(value))

        seen = set()
        result = []
        for item in raw_items:
            text = str(item).strip()
            if not text:
                continue
            if text in seen:
                continue
            seen.add(text)
            result.append(text)
        return result

    def _parse_float(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return float(text)
        except Exception:
            return None

    def _parse_int(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            return int(float(text))
        except Exception:
            return None

    def _calc_carton_qty_by_40hq(self, package_length_in, package_width_in, package_height_in):
        length_in = self._parse_float(package_length_in)
        width_in = self._parse_float(package_width_in)
        height_in = self._parse_float(package_height_in)
        if length_in is None or width_in is None or height_in is None:
            return None
        if length_in <= 0 or width_in <= 0 or height_in <= 0:
            return None
        inch_to_meter = 0.0254
        volume_m3 = length_in * inch_to_meter * width_in * inch_to_meter * height_in * inch_to_meter
        if volume_m3 <= 0:
            return None
        qty = int(69.0 / volume_m3)
        return qty if qty >= 0 else None

    def _parse_date_str(self, value):
        if value is None:
            return None
        text = str(value).strip()
        if text == '':
            return None
        try:
            dt = datetime.strptime(text, '%Y-%m-%d')
            return dt.strftime('%Y-%m-%d')
        except Exception:
            return None
