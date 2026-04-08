import base64
import hashlib
import hmac
import json
import time
import uuid
from urllib.parse import parse_qs


class AuthEmployeeMixin:
    def _get_session_id(self, environ):
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == 'session_id'), None)

    def _get_cookie_value(self, environ, name):
        cookie = environ.get('HTTP_COOKIE', '')
        pairs = [p.strip().split('=', 1) for p in cookie.split(';') if '=' in p]
        return next((v for k, v in pairs if k == name), None)

    def _get_auth_secret(self):
        env_secret = __import__('os').environ.get('SITJOY_AUTH_SECRET')
        if env_secret:
            return env_secret.encode('utf-8', errors='ignore')
        cfg = self._get_db_config() or {}
        seed = f"{cfg.get('host','')}|{cfg.get('user','')}|{cfg.get('password','')}|{cfg.get('database','')}"
        return hashlib.sha256(seed.encode('utf-8', errors='ignore')).digest()

    def _b64url_encode(self, raw):
        return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

    def _b64url_decode(self, text):
        pad = '=' * (-len(text) % 4)
        return base64.urlsafe_b64decode((text + pad).encode('ascii'))

    def _make_stateless_token(self, user_id, ttl_seconds=7 * 24 * 3600):
        exp = int(time.time()) + int(ttl_seconds)
        payload = f"{user_id}|{exp}".encode('utf-8', errors='surrogatepass')
        sig = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
        return self._b64url_encode(payload + b'|' + sig)

    def _verify_stateless_token(self, token):
        if not token:
            return None
        try:
            raw = self._b64url_decode(token)
            parts = raw.split(b'|')
            if len(parts) != 3:
                return None
            user_id_b, exp_b, sig_b = parts
            payload = user_id_b + b'|' + exp_b
            expected = hmac.new(self._get_auth_secret(), payload, hashlib.sha256).hexdigest().encode('ascii')
            if not hmac.compare_digest(sig_b, expected):
                return None
            exp = int(exp_b.decode('utf-8', errors='ignore') or '0')
            if exp < int(time.time()):
                return None
            return int(user_id_b.decode('utf-8', errors='ignore'))
        except Exception:
            return None

    def _get_session_user(self, environ):
        session_id = self._get_session_id(environ)
        token = self._get_cookie_value(environ, 'session_token')
        token_user = self._verify_stateless_token(token)
        if token_user:
            if session_id and session_id not in self._user_session:
                self._user_session[session_id] = token_user
            return token_user
        if session_id:
            if session_id in self._user_session:
                return self._user_session[session_id]
            try:
                cfg = self._get_db_config()
                if cfg:
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT employee_id FROM sessions WHERE session_id=%s AND (expires_at IS NULL OR expires_at>NOW())",
                                (session_id,)
                            )
                            row = cur.fetchone()
                            if row and row.get('employee_id'):
                                self._user_session[session_id] = row['employee_id']
                                return row['employee_id']
            except Exception as e:
                print(f"Session DB lookup failed: {type(e).__name__}: {e}")
            if token_user:
                return token_user
        return None

    def _set_session_user(self, user_id):
        session_id = str(uuid.uuid4())
        self._user_session[session_id] = user_id
        try:
            cfg = self._get_db_config()
            if cfg:
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "REPLACE INTO sessions (session_id, employee_id, expires_at) VALUES (%s, %s, DATE_ADD(NOW(), INTERVAL 7 DAY))",
                            (session_id, user_id)
                        )
        except Exception as e:
            print(f"Session DB write failed: {type(e).__name__}: {e}")
        return session_id

    def _parse_factory_scope_payload(self, data):
        mode_raw = str((data or {}).get('factory_scope_mode') or 'all').strip().lower()
        mode = 'custom' if mode_raw == 'custom' else 'all'
        ids_raw = (data or {}).get('factory_scope_ids') or []
        if not isinstance(ids_raw, list):
            ids_raw = []
        ids = []
        for value in ids_raw:
            try:
                number = int(value)
            except Exception:
                number = 0
            if number > 0:
                ids.append(number)
        return mode, sorted(set(ids))

    def _replace_user_factory_scopes(self, conn, user_id, scope_mode, factory_ids):
        with conn.cursor() as cur:
            cur.execute("DELETE FROM user_factory_scopes WHERE user_id=%s", (user_id,))
            if scope_mode != 'custom':
                return
            for factory_id in sorted(set(factory_ids or [])):
                cur.execute(
                    "INSERT INTO user_factory_scopes (user_id, factory_id) VALUES (%s, %s)",
                    (user_id, factory_id)
                )

    def handle_auth_api(self, environ, method, start_response):
        try:
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            action = query_params.get('action', [''])[0]

            if method == 'POST' and action == 'login':
                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '用户名密码不能为空'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT u.id, u.password_hash, u.name, u.username,
                                   COALESCE(u.is_approved, 1) AS is_approved
                            FROM users u
                            WHERE u.username=%s
                            """,
                            (username,)
                        )
                        row = cur.fetchone()
                        if not row:
                            return self.send_json({'status': 'error', 'message': '用户不存在'}, start_response)

                        pwd_hash = hashlib.sha256(password.encode('utf-8', errors='surrogatepass')).hexdigest()
                        if row['password_hash'] != pwd_hash:
                            return self.send_json({'status': 'error', 'message': '密码错误'}, start_response)

                        if not int(row.get('is_approved') or 0):
                            return self.send_json({'status': 'error', 'message': '账号待审核，请等待管理员批准后再登录'}, start_response)

                        session_id = self._set_session_user(row['id'])
                        token = self._make_stateless_token(row['id'])
                        headers = [
                            ('Content-Type', 'application/json; charset=utf-8'),
                            ('Set-Cookie', f'session_id={session_id}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax'),
                            ('Set-Cookie', f'session_token={token}; Path=/; Max-Age=604800; HttpOnly; SameSite=Lax')
                        ]
                        response_body = json.dumps({
                            'status': 'success',
                            'session_id': session_id,
                            'employee_id': row['id'],
                            'name': row.get('name') or row.get('username')
                        }).encode('utf-8', errors='surrogatepass')
                        start_response('200 OK', headers)
                        return [response_body]

            elif method == 'POST' and action == 'logout':
                user = self._get_session_user(environ)
                session_id = self._get_session_id(environ)
                if user:
                    for sid, uid in list(self._user_session.items()):
                        if uid == user:
                            del self._user_session[sid]
                if session_id:
                    try:
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute("DELETE FROM sessions WHERE session_id=%s", (session_id,))
                    except Exception as e:
                        print(f"Session DB delete failed: {type(e).__name__}: {e}")
                headers = [
                    ('Content-Type', 'application/json; charset=utf-8'),
                    ('Set-Cookie', 'session_id=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax'),
                    ('Set-Cookie', 'session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
                ]
                start_response('200 OK', headers)
                return [json.dumps({'status': 'success'}).encode('utf-8', errors='surrogatepass')]

            elif method == 'GET' and action == 'current':
                user_id = self._get_session_user(environ)
                if not user_id:
                    return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT id, username, name, phone, birthday, is_admin,
                                   COALESCE(can_grant_admin, 0) AS can_grant_admin,
                                   page_permissions
                            FROM users WHERE id=%s
                            """,
                            (user_id,)
                        )
                        row = cur.fetchone()
                        if row:
                            page_permissions = self._normalize_page_permissions(row.get('page_permissions'))
                            return self.send_json({
                                'status': 'success',
                                'id': row['id'],
                                'name': row.get('name') or row.get('username'),
                                'phone': row['phone'],
                                'birthday': row['birthday'],
                                'is_admin': row['is_admin'],
                                'can_grant_admin': row.get('can_grant_admin', 0),
                                'page_permissions': page_permissions,
                                'page_permission_labels': getattr(self, 'PAGE_PERMISSION_LABELS', {}),
                                'page_permission_groups': getattr(self, 'PAGE_PERMISSION_GROUPS', [])
                            }, start_response)
                        return self.send_json({'status': 'error', 'message': '用户信息未找到'}, start_response)

            elif method == 'GET' and action == 'debug':
                session_id = self._get_session_id(environ)
                db_found = False
                employee_id = None
                if session_id:
                    try:
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute(
                                    "SELECT employee_id FROM sessions WHERE session_id=%s AND (expires_at IS NULL OR expires_at>NOW())",
                                    (session_id,)
                                )
                                row = cur.fetchone()
                                if row and row.get('employee_id'):
                                    db_found = True
                                    employee_id = row['employee_id']
                    except Exception as e:
                        return self.send_json({'status': 'error', 'message': str(e)}, start_response)
                return self.send_json({
                    'status': 'success',
                    'session_id': session_id,
                    'db_session_found': db_found,
                    'employee_id': employee_id
                }, start_response)

            elif method == 'POST' and action == 'register':
                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '缺少必要字段'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        try:
                            pwd_hash = hashlib.sha256(password.encode('utf-8', errors='surrogatepass')).hexdigest()
                            cur.execute(
                                """
                                INSERT INTO users (username, password_hash, name, phone, birthday, is_approved)
                                VALUES (%s, %s, %s, %s, %s, 0)
                                """,
                                (username, pwd_hash, name or None, phone or None, birthday)
                            )
                            return self.send_json({
                                'status': 'pending',
                                'message': '注册申请已提交，请等待管理员审核后方可登录'
                            }, start_response)
                        except Exception as e:
                            if 'Duplicate' in str(e):
                                return self.send_json({'status': 'error', 'message': '用户名已存在'}, start_response)
                            raise

            elif method == 'GET' and action == 'pending_users':
                user_id = self._get_session_user(environ)
                if not user_id:
                    return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, is_admin, COALESCE(can_grant_admin, 0) AS can_grant_admin FROM users WHERE id=%s",
                            (user_id,)
                        )
                        actor_row = cur.fetchone()
                        if not actor_row or not actor_row.get('is_admin'):
                            return self.send_json({'status': 'error', 'message': '无权限'}, start_response)
                        cur.execute(
                            """
                            SELECT id, username, name, phone, created_at,
                                   is_admin, COALESCE(can_grant_admin, 0) AS can_grant_admin,
                                   page_permissions
                            FROM users
                            WHERE COALESCE(is_approved, 1) = 0
                            ORDER BY created_at DESC
                            """
                        )
                        rows = cur.fetchall() or []
                        items = []
                        for r in rows:
                            items.append({
                                'id': r['id'],
                                'username': r['username'],
                                'name': r.get('name') or '',
                                'phone': r.get('phone') or '',
                                'created_at': str(r['created_at']) if r.get('created_at') else '',
                                'is_admin': int(r.get('is_admin') or 0),
                                'can_grant_admin': int(r.get('can_grant_admin') or 0),
                                'page_permissions': self._normalize_page_permissions(r.get('page_permissions'))
                            })
                return self.send_json({'status': 'success', 'items': items}, start_response)

            elif method == 'POST' and action == 'approve_user':
                user_id = self._get_session_user(environ)
                if not user_id:
                    return self.send_json({'status': 'error', 'message': '未登录'}, start_response)
                data = self._read_json_body(environ)
                target_id = self._parse_int(data.get('id'))
                approved = 1 if data.get('approve', True) else 0
                if not target_id:
                    return self.send_json({'status': 'error', 'message': '缺少用户ID'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, is_admin, COALESCE(can_grant_admin, 0) AS can_grant_admin FROM users WHERE id=%s",
                            (user_id,)
                        )
                        actor_row = cur.fetchone()
                        if not actor_row or not actor_row.get('is_admin'):
                            return self.send_json({'status': 'error', 'message': '无权限'}, start_response)
                        if approved:
                            desired_is_admin = 1 if data.get('is_admin') else 0
                            desired_can_grant_admin = 1 if data.get('can_grant_admin') else 0
                            if desired_is_admin and not self._can_manage_admin_permission(actor_row):
                                return self.send_json({'status': 'error', 'message': '无权限授予管理员'}, start_response)
                            if desired_can_grant_admin and int(user_id or 0) != 1:
                                return self.send_json({'status': 'error', 'message': '仅ID=1可设置管理员授权权限'}, start_response)
                            page_permissions = self._serialize_page_permissions(data.get('page_permissions'))
                            cur.execute(
                                """
                                UPDATE users
                                SET is_approved=1,
                                    is_admin=%s,
                                    can_grant_admin=%s,
                                    page_permissions=%s
                                WHERE id=%s
                                """,
                                (desired_is_admin, desired_can_grant_admin, page_permissions, target_id)
                            )
                        else:
                            cur.execute(
                                "DELETE FROM users WHERE id=%s AND COALESCE(is_approved,1)=0",
                                (target_id,)
                            )
                return self.send_json({'status': 'success'}, start_response)

            return self.send_json({'status': 'error', 'message': '不支持的操作'}, start_response)
        except Exception as e:
            print('Auth API error: ' + str(e))
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_employee_api(self, environ, method, start_response):
        try:
            user_id = self._get_session_user(environ)
            query_string = environ.get('QUERY_STRING', '')
            query_params = parse_qs(query_string)
            actor_record = self._get_user_permission_record(user_id) if user_id else None
            user_is_admin = bool(actor_record and actor_record.get('is_admin'))

            if method == 'GET':
                keyword = query_params.get('q', [''])[0].strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT id, username, name, phone, birthday, is_admin,
                                       COALESCE(can_grant_admin, 0) AS can_grant_admin,
                                       page_permissions, COALESCE(is_approved, 1) AS is_approved, created_at
                                FROM users
                                WHERE name LIKE %s OR username LIKE %s OR phone LIKE %s
                                ORDER BY id ASC
                                """,
                                (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT id, username, name, phone, birthday, is_admin,
                                       COALESCE(can_grant_admin, 0) AS can_grant_admin,
                                       page_permissions, COALESCE(is_approved, 1) AS is_approved, created_at
                                FROM users
                                ORDER BY id ASC
                                """
                            )
                        rows = cur.fetchall() or []
                        user_ids = [int(r.get('id')) for r in rows if r.get('id')]
                        scope_map = {}
                        if user_ids:
                            try:
                                placeholders = ','.join(['%s'] * len(user_ids))
                                cur.execute(
                                    f"SELECT user_id, factory_id FROM user_factory_scopes WHERE user_id IN ({placeholders}) ORDER BY user_id ASC, factory_id ASC",
                                    tuple(user_ids)
                                )
                                for rel in (cur.fetchall() or []):
                                    uid = int(rel.get('user_id') or 0)
                                    fid = int(rel.get('factory_id') or 0)
                                    if uid > 0 and fid > 0:
                                        scope_map.setdefault(uid, []).append(fid)
                            except Exception as e:
                                message = str(e).lower()
                                if not ("doesn't exist" in message or 'does not exist' in message or 'unknown table' in message):
                                    raise
                items = []
                for row in rows:
                    uid = int(row.get('id') or 0)
                    factory_scope_ids = sorted(set(scope_map.get(uid, [])))
                    items.append({
                        'id': row['id'],
                        'username': row['username'],
                        'name': row.get('name') or '',
                        'phone': row.get('phone') or '',
                        'birthday': row.get('birthday'),
                        'is_admin': int(row.get('is_admin') or 0),
                        'can_grant_admin': int(row.get('can_grant_admin') or 0),
                        'is_approved': int(row.get('is_approved') or 0),
                        'page_permissions': self._normalize_page_permissions(row.get('page_permissions')),
                        'factory_scope_mode': 'custom' if factory_scope_ids else 'all',
                        'factory_scope_ids': factory_scope_ids,
                        'created_at': row.get('created_at')
                    })
                return self.send_json({'status': 'success', 'items': items}, start_response)

            if method == 'POST':
                if not user_is_admin:
                    return self.send_json({'status': 'error', 'message': '仅管理员可新增账号'}, start_response)

                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                password = (data.get('password') or '').strip()
                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                target_is_admin = 1 if data.get('is_admin') else 0
                target_can_grant_admin = 1 if data.get('can_grant_admin') else 0
                if target_is_admin and not self._can_manage_admin_permission(actor_record):
                    return self.send_json({'status': 'error', 'message': '无权限授予管理员'}, start_response)
                if target_can_grant_admin and int(user_id or 0) != 1:
                    return self.send_json({'status': 'error', 'message': '仅ID=1可设置管理员授权权限'}, start_response)
                if not username or not password:
                    return self.send_json({'status': 'error', 'message': '缺少必要字段'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        pwd_hash = hashlib.sha256(password.encode('utf-8', errors='surrogatepass')).hexdigest()
                        cur.execute(
                            """
                            INSERT INTO users (
                                username, password_hash, name, phone, birthday,
                                is_admin, can_grant_admin, page_permissions, is_approved
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 1)
                            """,
                            (
                                username,
                                pwd_hash,
                                name or None,
                                phone or None,
                                birthday,
                                target_is_admin,
                                target_can_grant_admin,
                                self._serialize_page_permissions(data.get('page_permissions'))
                            )
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少员工ID'}, start_response)

                if not user_is_admin and item_id != user_id:
                    return self.send_json({'status': 'error', 'message': '无权修改其他员工信息'}, start_response)

                if not user_is_admin and ('name' in data or 'birthday' in data or 'username' in data):
                    return self.send_json({'status': 'error', 'message': '仅管理员可修改账号、姓名或生日'}, start_response)

                username = (data.get('username') or '').strip()
                name = (data.get('name') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                target_is_admin = self._parse_int(data.get('is_admin'))
                target_can_grant_admin = self._parse_int(data.get('can_grant_admin'))
                has_factory_scope_payload = ('factory_scope_mode' in data) or ('factory_scope_ids' in data)
                factory_scope_mode, factory_scope_ids = self._parse_factory_scope_payload(data)

                if has_factory_scope_payload and not user_is_admin:
                    return self.send_json({'status': 'error', 'message': '仅管理员可修改工厂范围权限'}, start_response)
                if has_factory_scope_payload and factory_scope_mode == 'custom' and not factory_scope_ids:
                    return self.send_json({'status': 'error', 'message': '自定义工厂范围至少选择一个工厂'}, start_response)

                updates = []
                params = []

                if 'username' in data:
                    if not username:
                        return self.send_json({'status': 'error', 'message': '账号不能为空'}, start_response)
                    updates.append('username=%s')
                    params.append(username)
                if 'name' in data:
                    updates.append('name=%s')
                    params.append(name or None)
                if 'phone' in data:
                    updates.append('phone=%s')
                    params.append(phone or None)
                if 'birthday' in data:
                    updates.append('birthday=%s')
                    params.append(birthday)

                if 'page_permissions' in data:
                    if not user_is_admin:
                        return self.send_json({'status': 'error', 'message': '仅管理员可修改页面访问权限'}, start_response)
                    updates.append('page_permissions=%s')
                    params.append(self._serialize_page_permissions(data.get('page_permissions')))

                if user_is_admin and target_is_admin is not None:
                    if int(item_id) == 1 and int(target_is_admin) == 0:
                        return self.send_json({'status': 'error', 'message': 'ID=1管理员不可取消管理员身份'}, start_response)
                    if int(target_is_admin) == 1 and not self._can_manage_admin_permission(actor_record):
                        return self.send_json({'status': 'error', 'message': '无权限授予管理员'}, start_response)
                    updates.append('is_admin=%s')
                    params.append(1 if target_is_admin else 0)

                if user_is_admin and target_can_grant_admin is not None:
                    if int(user_id or 0) != 1:
                        return self.send_json({'status': 'error', 'message': '仅ID=1可设置管理员授权权限'}, start_response)
                    updates.append('can_grant_admin=%s')
                    params.append(1 if target_can_grant_admin else 0)

                if not updates:
                    if not has_factory_scope_payload:
                        return self.send_json({'status': 'error', 'message': '无可更新字段'}, start_response)

                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "SELECT id, is_admin, page_permissions FROM users WHERE id=%s",
                            (item_id,)
                        )
                        target_row = cur.fetchone() or {}
                        if not target_row:
                            return self.send_json({'status': 'error', 'message': '用户不存在'}, start_response)

                        if 'username' in data:
                            cur.execute(
                                "SELECT id FROM users WHERE username=%s AND id<>%s LIMIT 1",
                                (username, item_id)
                            )
                            if cur.fetchone():
                                return self.send_json({'status': 'error', 'message': '账号已存在，请更换名称'}, start_response)

                        # If factory scope is customized, default-disable factory master module for non-admin targets.
                        effective_is_admin = int(target_is_admin if target_is_admin is not None else (target_row.get('is_admin') or 0))
                        if has_factory_scope_payload and factory_scope_mode == 'custom' and effective_is_admin == 0:
                            current_permissions = self._normalize_page_permissions(target_row.get('page_permissions'))
                            if 'page_permissions' in data:
                                current_permissions = self._normalize_page_permissions(data.get('page_permissions'))
                            current_permissions['logistics_factory_management'] = 0
                            serialized_permissions = self._serialize_page_permissions(current_permissions)
                            if 'page_permissions=%s' in updates:
                                idx = updates.index('page_permissions=%s')
                                params[idx] = serialized_permissions
                            else:
                                updates.append('page_permissions=%s')
                                params.append(serialized_permissions)

                        if updates:
                            params.append(item_id)
                            cur.execute(
                                f"UPDATE users SET {', '.join(updates)} WHERE id=%s",
                                tuple(params)
                            )

                    if has_factory_scope_payload:
                        try:
                            self._replace_user_factory_scopes(conn, item_id, factory_scope_mode, factory_scope_ids)
                        except Exception as e:
                            message = str(e).lower()
                            if "doesn't exist" in message or 'does not exist' in message or 'unknown table' in message:
                                return self.send_json({'status': 'error', 'message': '缺少 user_factory_scopes 表，请先执行 SQL 脚本 20260408_01_user_factory_scopes.sql'}, start_response)
                            raise
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                if not user_is_admin:
                    return self.send_json({'status': 'error', 'message': '仅管理员可删除员工'}, start_response)

                data = self._read_json_body(environ)
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少员工ID'}, start_response)
                if int(item_id) == 1:
                    return self.send_json({'status': 'error', 'message': 'ID=1管理员不可删除'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM users WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            message = str(e)
            if 'Duplicate' in message or 'duplicate' in message:
                return self.send_json({'status': 'error', 'message': '账号已存在，请更换名称'}, start_response)
            print('Employee API error: ' + message)
            return self.send_json({'status': 'error', 'message': message}, start_response)
