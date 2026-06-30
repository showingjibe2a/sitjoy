# -*- coding: utf-8 -*-
"""首页个人信息与头像（data/user_avatars，与上架资源目录分离）。"""

import cgi
import os
import uuid
from urllib.parse import parse_qs

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
USER_AVATARS_REL_DIR = 'user_avatars'
USER_AVATARS_ABS_DIR = os.path.join(_PROJECT_ROOT, 'data', USER_AVATARS_REL_DIR)
_AVATAR_ALLOWED_EXT = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
_AVATAR_MAX_BYTES = 2 * 1024 * 1024


class ProfileMixin:
    """个人资料 API：基本信息、改密、头像上传/删除。"""

    # -------------------------------------------------------------------------
    # 头像存储路径
    # -------------------------------------------------------------------------

    def _user_avatars_abs_dir(self):
        path = USER_AVATARS_ABS_DIR
        os.makedirs(path, exist_ok=True)
        return path

    def _avatar_abs_path_from_rel(self, rel_path):
        rel = str(rel_path or '').strip().replace('\\', '/').lstrip('/')
        if not rel or '..' in rel.split('/'):
            return None
        if not rel.startswith(USER_AVATARS_REL_DIR + '/'):
            return None
        abs_path = os.path.normpath(os.path.join(_PROJECT_ROOT, 'data', rel))
        base = os.path.normpath(os.path.join(_PROJECT_ROOT, 'data'))
        if not abs_path.startswith(base + os.sep) and abs_path != base:
            return None
        return abs_path

    def _delete_user_avatar_file(self, rel_path):
        abs_path = self._avatar_abs_path_from_rel(rel_path)
        if abs_path and os.path.isfile(abs_path):
            try:
                os.remove(abs_path)
            except OSError:
                pass

    def _avatar_ext_from_filename(self, filename):
        base = os.path.basename(str(filename or ''))
        _, ext = os.path.splitext(base.lower())
        return ext if ext in _AVATAR_ALLOWED_EXT else ''

    def _avatar_ext_from_content_type(self, content_type):
        ct = str(content_type or '').split(';')[0].strip().lower()
        mapping = {
            'image/jpeg': '.jpg',
            'image/png': '.png',
            'image/webp': '.webp',
            'image/gif': '.gif',
        }
        return mapping.get(ct, '')

    # -------------------------------------------------------------------------
    # 资料序列化与 DB 读取
    # -------------------------------------------------------------------------

    def _format_profile_date(self, value):
        if value is None:
            return None
        if hasattr(value, 'strftime'):
            return value.strftime('%Y-%m-%d')
        text = str(value).strip()
        return text[:10] if text else None

    def _format_system_permission_label(self, row):
        if not row or not int(row.get('is_admin') or 0):
            return ''
        if int(row.get('can_grant_admin') or 0):
            return '管理员（可授权管理员）'
        return '管理员'

    def _format_supervisor_label(self, row):
        if not row:
            return ''
        sid = int(row.get('direct_supervisor_id') or 0)
        if sid <= 0:
            return ''
        name = (row.get('supervisor_name') or '').strip()
        username = (row.get('supervisor_username') or '').strip()
        if name and username:
            return f'{name}（{username}）'
        return name or username or ''

    def _serialize_user_profile_row(self, row):
        if not row:
            return None
        uid = int(row.get('id') or 0)
        avatar_path = (row.get('avatar_path') or '').strip() or None
        created = row.get('created_at')
        created_at = ''
        if created is not None:
            try:
                created_at = created.isoformat(sep=' ', timespec='seconds') if hasattr(created, 'isoformat') else str(created)
            except Exception:
                created_at = str(created)
        return {
            'id': uid,
            'username': row.get('username') or '',
            'name': row.get('name') or '',
            'phone': row.get('phone') or '',
            'birthday': self._format_profile_date(row.get('birthday')),
            'hire_date': self._format_profile_date(row.get('hire_date')),
            'job_title': (row.get('job_title') or '').strip(),
            'direct_supervisor_id': int(row['direct_supervisor_id']) if row.get('direct_supervisor_id') else None,
            'direct_supervisor_label': self._format_supervisor_label(row),
            'is_admin': int(row.get('is_admin') or 0),
            'can_grant_admin': int(row.get('can_grant_admin') or 0),
            'system_permission_label': self._format_system_permission_label(row),
            'avatar_path': avatar_path,
            'avatar_url': f'/api/profile/avatar?user_id={uid}' if avatar_path else None,
            'created_at': created_at,
            'display_name': (row.get('name') or '').strip() or (row.get('username') or '').strip(),
            'role_label': '管理员' if int(row.get('is_admin') or 0) else '员工',
        }

    def _load_user_profile_row(self, conn, user_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.username, u.name, u.phone, u.birthday, u.hire_date, u.job_title,
                       u.direct_supervisor_id, u.is_admin,
                       COALESCE(u.can_grant_admin, 0) AS can_grant_admin,
                       u.page_permissions, u.avatar_path, u.created_at,
                       s.name AS supervisor_name, s.username AS supervisor_username
                FROM users u
                LEFT JOIN users s ON s.id = u.direct_supervisor_id
                WHERE u.id=%s
                LIMIT 1
                """,
                (int(user_id),),
            )
            return cur.fetchone()

    def _load_supervisor_candidates(self, conn, user_id):
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, name
                FROM users
                WHERE COALESCE(is_approved, 1) = 1 AND id <> %s
                ORDER BY COALESCE(NULLIF(TRIM(name), ''), username) ASC, id ASC
                """,
                (int(user_id),),
            )
            rows = cur.fetchall() or []
        items = []
        for row in rows:
            uid = int(row.get('id') or 0)
            if uid <= 0:
                continue
            name = (row.get('name') or '').strip()
            username = (row.get('username') or '').strip()
            label = f'{name}（{username}）' if name and username else (name or username or f'#{uid}')
            items.append({'id': uid, 'label': label})
        return items

    def _parse_profile_multipart_avatar(self, environ):
        content_type = str(environ.get('CONTENT_TYPE') or '')
        if 'multipart/form-data' not in content_type.lower():
            return None
        try:
            form = cgi.FieldStorage(fp=environ.get('wsgi.input'), environ=environ, keep_blank_values=True)
        except Exception:
            return None
        item = form['avatar'] if 'avatar' in form else None
        if item is None or not getattr(item, 'file', None) or not getattr(item, 'filename', None):
            return None
        filename = item.filename
        file_bytes = item.file.read()
        if not file_bytes:
            return None, None
        if len(file_bytes) > _AVATAR_MAX_BYTES:
            raise ValueError('头像文件不能超过 2MB')
        ext = self._avatar_ext_from_filename(filename) or self._avatar_ext_from_content_type(getattr(item, 'type', None))
        if not ext:
            raise ValueError('仅支持 JPG / PNG / WebP / GIF')
        return filename, file_bytes, ext

    # -------------------------------------------------------------------------
    # 个人资料 API
    # -------------------------------------------------------------------------
    def handle_profile_api(self, environ, method, start_response):
        """GET 资料 / PUT 更新 / 改密 / 头像上传与删除。"""
        try:
            user_id = self._get_session_user(environ)
            if not user_id:
                return self.send_json({'status': 'error', 'message': '未登录'}, start_response)

            query = parse_qs(environ.get('QUERY_STRING', '') or '')
            action = (query.get('action', [''])[0] or '').strip().lower()
            path = str(environ.get('PATH_INFO') or '')

            if path.rstrip('/') == '/api/profile/avatar' or action == 'avatar':
                target_id = self._parse_int((query.get('user_id', [''])[0] or '').strip()) or int(user_id)
                if int(target_id) != int(user_id):
                    return self.send_json({'status': 'error', 'message': '无权查看他人头像'}, start_response)
                with self._get_db_connection() as conn:
                    row = self._load_user_profile_row(conn, target_id)
                rel = (row or {}).get('avatar_path') if row else None
                if not rel:
                    return self.send_error(404, '无头像', start_response)
                abs_path = self._avatar_abs_path_from_rel(rel)
                if not abs_path or not os.path.isfile(abs_path):
                    return self.send_error(404, '头像文件不存在', start_response)
                import mimetypes
                mime, _ = mimetypes.guess_type(abs_path)
                if not mime:
                    mime = 'image/jpeg'
                with open(abs_path, 'rb') as f:
                    data = f.read()
                headers = [
                    ('Content-Type', mime),
                    ('Content-Length', str(len(data))),
                    ('Cache-Control', 'private, max-age=300'),
                ]
                start_response('200 OK', headers)
                return [data]

            if method == 'GET':
                with self._get_db_connection() as conn:
                    row = self._load_user_profile_row(conn, user_id)
                    candidates = self._load_supervisor_candidates(conn, user_id)
                profile = self._serialize_user_profile_row(row)
                if not profile:
                    return self.send_json({'status': 'error', 'message': '用户不存在'}, start_response)
                return self.send_json({
                    'status': 'success',
                    'profile': profile,
                    'supervisor_candidates': candidates,
                }, start_response)

            if method == 'POST' and action == 'change_password':
                data = self._read_json_body(environ)
                password = (data.get('password') or '').strip()
                password_confirm = (data.get('password_confirm') or '').strip()
                if len(password) < 6:
                    return self.send_json({'status': 'error', 'message': '新密码至少 6 位'}, start_response)
                if password != password_confirm:
                    return self.send_json({'status': 'error', 'message': '两次输入的密码不一致'}, start_response)
                pwd_hash = self._hash_user_password(password)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            'UPDATE users SET password_hash=%s WHERE id=%s',
                            (pwd_hash, int(user_id)),
                        )
                return self.send_json({'status': 'success', 'message': '密码已修改'}, start_response)

            if method == 'PUT' or (method == 'POST' and action == 'update'):
                data = self._read_json_body(environ)
                username = (data.get('username') or '').strip()
                phone = (data.get('phone') or '').strip()
                birthday_raw = (data.get('birthday') or '').strip()
                birthday = self._parse_date_str(birthday_raw) if birthday_raw else None
                if not username:
                    return self.send_json({'status': 'error', 'message': '登录账号不能为空'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            'SELECT id FROM users WHERE username=%s AND id<>%s LIMIT 1',
                            (username, int(user_id)),
                        )
                        if cur.fetchone():
                            return self.send_json({'status': 'error', 'message': '登录账号已存在，请更换'}, start_response)
                        cur.execute(
                            """
                            UPDATE users
                            SET username=%s, phone=%s, birthday=%s
                            WHERE id=%s
                            """,
                            (
                                username,
                                phone or None,
                                birthday,
                                int(user_id),
                            ),
                        )
                    row = self._load_user_profile_row(conn, user_id)
                profile = self._serialize_user_profile_row(row)
                return self.send_json({'status': 'success', 'profile': profile, 'message': '已保存'}, start_response)

            if method == 'POST' and action == 'upload_avatar':
                try:
                    parsed = self._parse_profile_multipart_avatar(environ)
                except ValueError as ve:
                    return self.send_json({'status': 'error', 'message': str(ve)}, start_response)
                if not parsed:
                    return self.send_json({'status': 'error', 'message': '请选择头像图片'}, start_response)
                _filename, file_bytes, ext = parsed
                rel_path = f'{USER_AVATARS_REL_DIR}/{int(user_id)}_{uuid.uuid4().hex[:10]}{ext}'
                abs_path = self._avatar_abs_path_from_rel(rel_path)
                if not abs_path:
                    return self.send_json({'status': 'error', 'message': '无效存储路径'}, start_response)
                os.makedirs(os.path.dirname(abs_path), exist_ok=True)
                with open(abs_path, 'wb') as f:
                    f.write(file_bytes)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute('SELECT avatar_path FROM users WHERE id=%s', (int(user_id),))
                        old = cur.fetchone()
                        old_rel = (old or {}).get('avatar_path') if old else None
                        cur.execute('UPDATE users SET avatar_path=%s WHERE id=%s', (rel_path, int(user_id)))
                    if old_rel and old_rel != rel_path:
                        self._delete_user_avatar_file(old_rel)
                    row = self._load_user_profile_row(conn, user_id)
                profile = self._serialize_user_profile_row(row)
                return self.send_json({'status': 'success', 'profile': profile, 'message': '头像已更新'}, start_response)

            if method == 'DELETE' or (method == 'POST' and action == 'delete_avatar'):
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute('SELECT avatar_path FROM users WHERE id=%s', (int(user_id),))
                        old = cur.fetchone()
                        old_rel = (old or {}).get('avatar_path') if old else None
                        cur.execute('UPDATE users SET avatar_path=NULL WHERE id=%s', (int(user_id),))
                    if old_rel:
                        self._delete_user_avatar_file(old_rel)
                    row = self._load_user_profile_row(conn, user_id)
                profile = self._serialize_user_profile_row(row)
                return self.send_json({'status': 'success', 'profile': profile, 'message': '头像已移除'}, start_response)

            return self.send_json({'status': 'error', 'message': '不支持的请求'}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
