import os
import re
from datetime import datetime
from urllib.parse import parse_qs

try:
    from openpyxl import Workbook, load_workbook
    from openpyxl.styles import PatternFill, Font, Alignment, Border, Side
    from openpyxl.worksheet.datavalidation import DataValidation
    _openpyxl_import_error = None
except Exception as _e:
    Workbook = None
    load_workbook = None
    PatternFill = None
    Font = None
    Alignment = None
    Border = None
    Side = None
    DataValidation = None
    _openpyxl_import_error = _e


class LogisticsWarehouseMixin:

    def handle_factory_stock_api(self, environ, method, start_response):
        """工厂在库库存 CRUD"""
        try:
            self._ensure_factory_inventory_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                action = (query_params.get('action', [''])[0] or '').strip().lower()
                if action == 'options':
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, factory_name FROM logistics_factories ORDER BY factory_name ASC")
                            factories = cur.fetchall() or []
                            cur.execute("SELECT id, sku FROM order_products ORDER BY sku ASC")
                            order_products = cur.fetchall() or []
                    return self.send_json({'status': 'success', 'factories': factories, 'order_products': order_products}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT fs.id, fs.order_product_id, fs.factory_id, fs.quantity, fs.notes, fs.updated_at,
                                       op.sku, f.factory_name
                                FROM factory_stock_inventory fs
                                JOIN order_products op ON op.id = fs.order_product_id
                                JOIN logistics_factories f ON f.id = fs.factory_id
                                WHERE op.sku LIKE %s OR f.factory_name LIKE %s
                                ORDER BY op.sku ASC, f.factory_name ASC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT fs.id, fs.order_product_id, fs.factory_id, fs.quantity, fs.notes, fs.updated_at,
                                       op.sku, f.factory_name
                                FROM factory_stock_inventory fs
                                JOIN order_products op ON op.id = fs.order_product_id
                                JOIN logistics_factories f ON f.id = fs.factory_id
                                ORDER BY op.sku ASC, f.factory_name ASC
                                """
                            )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                op_id = self._parse_int(data.get('order_product_id'))
                factory_id = self._parse_int(data.get('factory_id'))
                quantity = max(0, self._parse_int(data.get('quantity')) or 0)
                notes = (data.get('notes') or '').strip() or None
                if not op_id or not factory_id:
                    return self.send_json({'status': 'error', 'message': '缺少 order_product_id 或 factory_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO factory_stock_inventory (order_product_id, factory_id, quantity, notes)
                            VALUES (%s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE quantity=%s, notes=%s
                            """,
                            (op_id, factory_id, quantity, notes, quantity, notes)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                quantity = max(0, self._parse_int(data.get('quantity')) or 0)
                notes = (data.get('notes') or '').strip() or None
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE factory_stock_inventory SET quantity=%s, notes=%s WHERE id=%s",
                            (quantity, notes, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM factory_stock_inventory WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_factory_wip_api(self, environ, method, start_response):
        """工厂在制库存 CRUD"""
        try:
            self._ensure_factory_inventory_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            def _parse_yes_no(value):
                text = str(value if value is not None else '').strip().lower()
                if text in ('1', 'true', 'yes', 'y', '是'):
                    return 1
                return 0

            def _parse_date_text(value):
                text = (value or '').strip()
                if not text:
                    return None
                for fmt in ('%Y-%m-%d', '%Y/%m/%d'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return None

            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                action = (query_params.get('action', [''])[0] or '').strip().lower()
                if action == 'options':
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, factory_name FROM logistics_factories ORDER BY factory_name ASC")
                            factories = cur.fetchall() or []
                            cur.execute("SELECT id, sku FROM order_products ORDER BY sku ASC")
                            order_products = cur.fetchall() or []
                    return self.send_json({'status': 'success', 'factories': factories, 'order_products': order_products}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                """
                                SELECT fw.id, fw.order_product_id, fw.factory_id, fw.quantity,
                                        fw.expected_completion_date, fw.is_completed, fw.actual_completion_date,
                                        fw.notes, fw.created_at, fw.updated_at,
                                       op.sku, f.factory_name
                                FROM factory_wip_inventory fw
                                JOIN order_products op ON op.id = fw.order_product_id
                                JOIN logistics_factories f ON f.id = fw.factory_id
                                WHERE op.sku LIKE %s OR f.factory_name LIKE %s
                                ORDER BY op.sku ASC, f.factory_name ASC, fw.expected_completion_date ASC
                                """,
                                (f"%{keyword}%", f"%{keyword}%")
                            )
                        else:
                            cur.execute(
                                """
                                SELECT fw.id, fw.order_product_id, fw.factory_id, fw.quantity,
                                        fw.expected_completion_date, fw.is_completed, fw.actual_completion_date,
                                        fw.notes, fw.created_at, fw.updated_at,
                                       op.sku, f.factory_name
                                FROM factory_wip_inventory fw
                                JOIN order_products op ON op.id = fw.order_product_id
                                JOIN logistics_factories f ON f.id = fw.factory_id
                                ORDER BY op.sku ASC, f.factory_name ASC, fw.expected_completion_date ASC
                                """
                            )
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                op_id = self._parse_int(data.get('order_product_id'))
                factory_id = self._parse_int(data.get('factory_id'))
                quantity = max(0, self._parse_int(data.get('quantity')) or 0)
                notes = (data.get('notes') or '').strip() or None
                expected_date = _parse_date_text(data.get('expected_completion_date'))
                is_completed = _parse_yes_no(data.get('is_completed'))
                actual_completion_date = _parse_date_text(data.get('actual_completion_date'))
                if is_completed and not actual_completion_date:
                    actual_completion_date = datetime.now().strftime('%Y-%m-%d')
                if not is_completed:
                    actual_completion_date = None
                if not op_id or not factory_id:
                    return self.send_json({'status': 'error', 'message': '缺少 order_product_id 或 factory_id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO factory_wip_inventory (order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                            """,
                            (op_id, factory_id, quantity, expected_date, is_completed, actual_completion_date, notes)
                        )
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                quantity = max(0, self._parse_int(data.get('quantity')) or 0)
                notes = (data.get('notes') or '').strip() or None
                expected_date = _parse_date_text(data.get('expected_completion_date'))
                is_completed = _parse_yes_no(data.get('is_completed'))
                actual_completion_date = _parse_date_text(data.get('actual_completion_date'))
                if is_completed and not actual_completion_date:
                    actual_completion_date = datetime.now().strftime('%Y-%m-%d')
                if not is_completed:
                    actual_completion_date = None
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE factory_wip_inventory SET quantity=%s, expected_completion_date=%s, is_completed=%s, actual_completion_date=%s, notes=%s WHERE id=%s",
                            (quantity, expected_date, is_completed, actual_completion_date, notes, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': '缺少 id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM factory_wip_inventory WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_factory_stock_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            self._ensure_factory_inventory_tables()
            wb = Workbook()
            ws = wb.active
            ws.title = 'factory_stock'

            headers = ['SKU', '工厂', '数量', '备注']
            ws.append(headers)
            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            widths = [24, 24, 10, 28]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width

            option_sheet = wb.create_sheet('_options')
            option_sheet.sheet_state = 'hidden'
            option_sheet.append(['factory_name', 'sku'])

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT factory_name FROM logistics_factories ORDER BY factory_name ASC")
                    factories = [str(r.get('factory_name') or '').strip() for r in (cur.fetchall() or []) if r.get('factory_name')]
                    cur.execute("SELECT sku FROM order_products ORDER BY sku ASC")
                    skus = [str(r.get('sku') or '').strip() for r in (cur.fetchall() or []) if r.get('sku')]

            max_len = max(len(factories), len(skus), 1)
            for i in range(max_len):
                option_sheet.append([
                    factories[i] if i < len(factories) else '',
                    skus[i] if i < len(skus) else ''
                ])

            max_row = 400
            if factories:
                dv_factory = DataValidation(type='list', formula1=f"='_options'!$A$2:$A${len(factories) + 1}", allow_blank=False)
                ws.add_data_validation(dv_factory)
                for row in range(2, max_row + 1):
                    dv_factory.add(f'B{row}')
            if skus:
                dv_sku = DataValidation(type='list', formula1=f"='_options'!$B$2:$B${len(skus) + 1}", allow_blank=False)
                ws.add_data_validation(dv_sku)
                for row in range(2, max_row + 1):
                    dv_sku.add(f'A{row}')

            ws.freeze_panes = 'A2'
            return self._send_excel_workbook(wb, 'factory_stock_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_factory_stock_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
            ws = wb.active
            header_values = next(ws.iter_rows(min_row=1, max_row=1, values_only=True), tuple())
            headers = [str(value or '').strip() for value in header_values]
            header_map = {name: idx for idx, name in enumerate(headers)}

            for required in ('SKU', '工厂', '数量'):
                if required not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {required}'}, start_response)

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx]

            self._ensure_factory_inventory_tables()
            created = 0
            updated = 0
            unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, sku FROM order_products")
                    sku_map = {str(r.get('sku') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}
                    cur.execute("SELECT id, factory_name FROM logistics_factories")
                    factory_map = {str(r.get('factory_name') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}

                    normalized_rows = []
                    pair_keys = set()
                    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                        if not any(value is not None and str(value).strip() for value in row):
                            continue
                        try:
                            sku = str(get_cell(row, 'SKU') or '').strip()
                            factory_name = str(get_cell(row, '工厂') or '').strip()
                            quantity = self._parse_int(get_cell(row, '数量'))
                            notes = str(get_cell(row, '备注') or '').strip() or None
                            if not sku or not factory_name or quantity is None:
                                raise ValueError('SKU/工厂/数量不能为空，且数量需为整数')
                            order_product_id = sku_map.get(sku)
                            factory_id = factory_map.get(factory_name)
                            if not order_product_id:
                                raise ValueError(f'未找到SKU: {sku}')
                            if not factory_id:
                                raise ValueError(f'未找到工厂: {factory_name}')
                            quantity = max(0, int(quantity))
                            normalized_rows.append((order_product_id, factory_id, quantity, notes))
                            pair_keys.add((order_product_id, factory_id))
                        except Exception as row_error:
                            errors.append({'row': row_idx, 'error': str(row_error)})

                    existing_map = {}
                    if pair_keys:
                        op_ids = sorted({k[0] for k in pair_keys})
                        factory_ids = sorted({k[1] for k in pair_keys})
                        op_placeholders = ','.join(['%s'] * len(op_ids))
                        fa_placeholders = ','.join(['%s'] * len(factory_ids))
                        cur.execute(
                            f"""
                            SELECT id, order_product_id, factory_id, quantity, notes
                            FROM factory_stock_inventory
                            WHERE order_product_id IN ({op_placeholders})
                              AND factory_id IN ({fa_placeholders})
                            """,
                            tuple(op_ids) + tuple(factory_ids)
                        )
                        for ex in (cur.fetchall() or []):
                            key = (int(ex.get('order_product_id')), int(ex.get('factory_id')))
                            existing_map[key] = {
                                'id': int(ex.get('id')),
                                'quantity': int(ex.get('quantity') or 0),
                                'notes': (ex.get('notes') or '').strip() or None
                            }

                    for order_product_id, factory_id, quantity, notes in normalized_rows:
                        key = (order_product_id, factory_id)
                        ex = existing_map.get(key)
                        if ex:
                            if ex.get('quantity') == quantity and (ex.get('notes') or None) == (notes or None):
                                unchanged += 1
                                continue
                            cur.execute(
                                "UPDATE factory_stock_inventory SET quantity=%s, notes=%s WHERE id=%s",
                                (quantity, notes, ex['id'])
                            )
                            updated += 1
                        else:
                            cur.execute(
                                "INSERT INTO factory_stock_inventory (order_product_id, factory_id, quantity, notes) VALUES (%s, %s, %s, %s)",
                                (order_product_id, factory_id, quantity, notes)
                            )
                            created += 1

            return self.send_json({'status': 'success', 'created': created, 'updated': updated, 'unchanged': unchanged, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_factory_wip_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.worksheet.datavalidation import DataValidation
            from openpyxl.utils import get_column_letter

            self._ensure_factory_inventory_tables()
            wb = Workbook()
            ws = wb.active
            ws.title = 'factory_wip'

            headers = ['SKU', '工厂', '数量', '预计完工日期', '是否完工(是/否)', '实际完工时间', '备注']
            ws.append(headers)
            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            widths = [24, 24, 10, 16, 14, 16, 28]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width

            option_sheet = wb.create_sheet('_options')
            option_sheet.sheet_state = 'hidden'
            option_sheet.append(['factory_name', 'sku'])

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT factory_name FROM logistics_factories ORDER BY factory_name ASC")
                    factories = [str(r.get('factory_name') or '').strip() for r in (cur.fetchall() or []) if r.get('factory_name')]
                    cur.execute("SELECT sku FROM order_products ORDER BY sku ASC")
                    skus = [str(r.get('sku') or '').strip() for r in (cur.fetchall() or []) if r.get('sku')]

            max_len = max(len(factories), len(skus), 1)
            for i in range(max_len):
                option_sheet.append([
                    factories[i] if i < len(factories) else '',
                    skus[i] if i < len(skus) else ''
                ])

            max_row = 400
            if factories:
                dv_factory = DataValidation(type='list', formula1=f"='_options'!$A$2:$A${len(factories) + 1}", allow_blank=False)
                ws.add_data_validation(dv_factory)
                for row in range(2, max_row + 1):
                    dv_factory.add(f'B{row}')
            if skus:
                dv_sku = DataValidation(type='list', formula1=f"='_options'!$B$2:$B${len(skus) + 1}", allow_blank=False)
                ws.add_data_validation(dv_sku)
                for row in range(2, max_row + 1):
                    dv_sku.add(f'A{row}')
            dv_completed = DataValidation(type='list', formula1='"否,是"', allow_blank=True)
            ws.add_data_validation(dv_completed)
            for row in range(2, max_row + 1):
                dv_completed.add(f'E{row}')

            ws.freeze_panes = 'A2'
            return self._send_excel_workbook(wb, 'factory_wip_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_factory_wip_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
            ws = wb.active
            header_values = next(ws.iter_rows(min_row=1, max_row=1, values_only=True), tuple())
            headers = [str(value or '').strip() for value in header_values]
            header_map = {name: idx for idx, name in enumerate(headers)}

            for required in ('SKU', '工厂', '数量'):
                if required not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {required}'}, start_response)

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx]

            def parse_date(value):
                text = str(value or '').strip()
                if not text:
                    return None
                for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y.%m.%d'):
                    try:
                        return datetime.strptime(text, fmt).strftime('%Y-%m-%d')
                    except Exception:
                        continue
                return None

            def parse_yes_no(value):
                text = str(value or '').strip().lower()
                return 1 if text in ('1', 'true', 'yes', 'y', '是') else 0

            self._ensure_factory_inventory_tables()
            created = 0
            updated = 0
            unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, sku FROM order_products")
                    sku_map = {str(r.get('sku') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}
                    cur.execute("SELECT id, factory_name FROM logistics_factories")
                    factory_map = {str(r.get('factory_name') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}

                    normalized_rows = []
                    pair_keys = set()
                    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                        if not any(value is not None and str(value).strip() for value in row):
                            continue
                        try:
                            sku = str(get_cell(row, 'SKU') or '').strip()
                            factory_name = str(get_cell(row, '工厂') or '').strip()
                            quantity = self._parse_int(get_cell(row, '数量'))
                            expected_completion_date = parse_date(get_cell(row, '预计完工日期'))
                            is_completed = parse_yes_no(get_cell(row, '是否完工(是/否)'))
                            actual_completion_date = parse_date(get_cell(row, '实际完工时间'))
                            notes = str(get_cell(row, '备注') or '').strip() or None
                            if not sku or not factory_name or quantity is None:
                                raise ValueError('SKU/工厂/数量不能为空，且数量需为整数')
                            if is_completed and not actual_completion_date:
                                actual_completion_date = datetime.now().strftime('%Y-%m-%d')
                            if not is_completed:
                                actual_completion_date = None
                            order_product_id = sku_map.get(sku)
                            factory_id = factory_map.get(factory_name)
                            if not order_product_id:
                                raise ValueError(f'未找到SKU: {sku}')
                            if not factory_id:
                                raise ValueError(f'未找到工厂: {factory_name}')
                            quantity = max(0, int(quantity))
                            normalized_rows.append((order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes))
                            pair_keys.add((order_product_id, factory_id))
                        except Exception as row_error:
                            errors.append({'row': row_idx, 'error': str(row_error)})

                    existing_map = {}
                    if pair_keys:
                        op_ids = sorted({k[0] for k in pair_keys})
                        factory_ids = sorted({k[1] for k in pair_keys})
                        op_placeholders = ','.join(['%s'] * len(op_ids))
                        fa_placeholders = ','.join(['%s'] * len(factory_ids))
                        cur.execute(
                            f"""
                            SELECT id, order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes
                            FROM factory_wip_inventory
                            WHERE order_product_id IN ({op_placeholders})
                              AND factory_id IN ({fa_placeholders})
                            ORDER BY id DESC
                            """,
                            tuple(op_ids) + tuple(factory_ids)
                        )
                        for ex in (cur.fetchall() or []):
                            key = (int(ex.get('order_product_id')), int(ex.get('factory_id')))
                            if key in existing_map:
                                continue
                            existing_map[key] = {
                                'id': int(ex.get('id')),
                                'quantity': int(ex.get('quantity') or 0),
                                'expected_completion_date': (str(ex.get('expected_completion_date') or '').strip() or None),
                                'is_completed': int(ex.get('is_completed') or 0),
                                'actual_completion_date': (str(ex.get('actual_completion_date') or '').strip() or None),
                                'notes': (ex.get('notes') or '').strip() or None
                            }

                    for order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes in normalized_rows:
                        key = (order_product_id, factory_id)
                        ex = existing_map.get(key)
                        if ex:
                            same = (
                                ex.get('quantity') == quantity and
                                (ex.get('expected_completion_date') or None) == (expected_completion_date or None) and
                                int(ex.get('is_completed') or 0) == int(is_completed or 0) and
                                (ex.get('actual_completion_date') or None) == (actual_completion_date or None) and
                                (ex.get('notes') or None) == (notes or None)
                            )
                            if same:
                                unchanged += 1
                                continue
                            cur.execute(
                                """
                                UPDATE factory_wip_inventory
                                SET quantity=%s, expected_completion_date=%s, is_completed=%s, actual_completion_date=%s, notes=%s
                                WHERE id=%s
                                """,
                                (quantity, expected_completion_date, is_completed, actual_completion_date, notes, ex['id'])
                            )
                            updated += 1
                        else:
                            cur.execute(
                                """
                                INSERT INTO factory_wip_inventory
                                  (order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes)
                                VALUES (%s, %s, %s, %s, %s, %s, %s)
                                """,
                                (order_product_id, factory_id, quantity, expected_completion_date, is_completed, actual_completion_date, notes)
                            )
                            created += 1

            return self.send_json({'status': 'success', 'created': created, 'updated': updated, 'unchanged': unchanged, 'errors': errors}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_factory_api(self, environ, method, start_response):
        try:
            self._ensure_logistics_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                "SELECT id, factory_name, created_at, updated_at FROM logistics_factories WHERE factory_name LIKE %s ORDER BY id DESC",
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute("SELECT id, factory_name, created_at, updated_at FROM logistics_factories ORDER BY id DESC")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                name = (data.get('factory_name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing factory_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO logistics_factories (factory_name) VALUES (%s)", (name,))
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                name = (data.get('factory_name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or factory_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE logistics_factories SET factory_name=%s WHERE id=%s", (name, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM logistics_factories WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_forwarder_api(self, environ, method, start_response):
        try:
            self._ensure_logistics_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                "SELECT id, forwarder_name, created_at, updated_at FROM logistics_forwarders WHERE forwarder_name LIKE %s ORDER BY id DESC",
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute("SELECT id, forwarder_name, created_at, updated_at FROM logistics_forwarders ORDER BY id DESC")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                name = (data.get('forwarder_name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing forwarder_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO logistics_forwarders (forwarder_name) VALUES (%s)", (name,))
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                name = (data.get('forwarder_name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or forwarder_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE logistics_forwarders SET forwarder_name=%s WHERE id=%s", (name, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM logistics_forwarders WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_supplier_api(self, environ, method, start_response):
        try:
            self._ensure_logistics_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            if method == 'GET':
                keyword = (query_params.get('q', [''])[0] or '').strip()
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        if keyword:
                            cur.execute(
                                "SELECT id, supplier_name, created_at, updated_at FROM logistics_suppliers WHERE supplier_name LIKE %s ORDER BY id DESC",
                                (f"%{keyword}%",)
                            )
                        else:
                            cur.execute("SELECT id, supplier_name, created_at, updated_at FROM logistics_suppliers ORDER BY id DESC")
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                name = (data.get('supplier_name') or '').strip()
                if not name:
                    return self.send_json({'status': 'error', 'message': 'Missing supplier_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("INSERT INTO logistics_suppliers (supplier_name) VALUES (%s)", (name,))
                        new_id = cur.lastrowid
                return self.send_json({'status': 'success', 'id': new_id}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                name = (data.get('supplier_name') or '').strip()
                if not item_id or not name:
                    return self.send_json({'status': 'error', 'message': 'Missing id or supplier_name'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE logistics_suppliers SET supplier_name=%s WHERE id=%s", (name, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM logistics_suppliers WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_api(self, environ, method, start_response):
        try:
            self._ensure_logistics_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            allowed_regions = {'美西', '美中', '美东南', '美东'}

            def _resolve_name_short(conn, supplier_id, warehouse_name, warehouse_short_name):
                with conn.cursor() as cur:
                    cur.execute("SELECT supplier_name FROM logistics_suppliers WHERE id=%s", (supplier_id,))
                    supplier = cur.fetchone()
                if not supplier:
                    return None, None, '供应商不存在'
                supplier_name = (supplier.get('supplier_name') or '').strip()
                name = (warehouse_name or '').strip()
                short_name = (warehouse_short_name or '').strip()

                if name and not short_name:
                    if name.startswith(supplier_name + ' '):
                        short_name = name[len(supplier_name) + 1:].strip()
                    elif ' ' in name:
                        parts = [p for p in name.split(' ') if p]
                        if len(parts) >= 2:
                            short_name = ' '.join(parts[1:]).strip() if parts[0] == supplier_name else parts[-1].strip()
                if short_name and not name:
                    name = f"{supplier_name} {short_name}".strip()

                if not name or not short_name:
                    return None, None, '仓库名称和仓库简称至少需要一个完整可推导'
                return name, short_name, None

            if method == 'GET':
                action = (query_params.get('action', [''])[0] or '').strip().lower()
                if action == 'options':
                    with self._get_db_connection() as conn:
                        with conn.cursor() as cur:
                            cur.execute("SELECT id, supplier_name FROM logistics_suppliers ORDER BY id DESC")
                            suppliers = cur.fetchall() or []
                    return self.send_json({'status': 'success', 'suppliers': suppliers, 'regions': sorted(list(allowed_regions))}, start_response)

                keyword = (query_params.get('q', [''])[0] or '').strip()
                supplier_id = self._parse_int(query_params.get('supplier_id', [''])[0])
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = """
                            SELECT w.id, w.warehouse_name, w.supplier_id, w.warehouse_short_name, w.is_enabled, w.region,
                                   w.created_at, w.updated_at, s.supplier_name
                            FROM logistics_overseas_warehouses w
                            JOIN logistics_suppliers s ON s.id = w.supplier_id
                        """
                        filters = []
                        params = []
                        if supplier_id:
                            filters.append("w.supplier_id=%s")
                            params.append(supplier_id)
                        if keyword:
                            like = f"%{keyword}%"
                            filters.append("(w.warehouse_name LIKE %s OR s.supplier_name LIKE %s OR w.warehouse_short_name LIKE %s OR w.region LIKE %s)")
                            params.extend([like, like, like, like])
                        where_sql = (' WHERE ' + ' AND '.join(filters)) if filters else ''
                        cur.execute(sql + where_sql + " ORDER BY w.id DESC", params)
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            action = (query_params.get('action', [''])[0] or '').strip().lower()

            if method == 'PUT' and action == 'toggle_enabled':
                item_id = self._parse_int(data.get('id'))
                is_enabled = 1 if self._parse_int(data.get('is_enabled')) else 0
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE logistics_overseas_warehouses SET is_enabled=%s WHERE id=%s", (is_enabled, item_id))
                return self.send_json({'status': 'success'}, start_response)

            if method in ('POST', 'PUT'):
                supplier_id = self._parse_int(data.get('supplier_id'))
                region = (data.get('region') or '').strip()
                is_enabled = 1 if self._parse_int(data.get('is_enabled', 1)) else 0
                if not supplier_id or region not in allowed_regions:
                    return self.send_json({'status': 'error', 'message': '供应商和区域必填且区域需为指定选项'}, start_response)
                with self._get_db_connection() as conn:
                    name, short_name, err = _resolve_name_short(conn, supplier_id, data.get('warehouse_name'), data.get('warehouse_short_name'))
                    if err:
                        return self.send_json({'status': 'error', 'message': err}, start_response)
                    with conn.cursor() as cur:
                        if method == 'POST':
                            cur.execute(
                                """
                                INSERT INTO logistics_overseas_warehouses
                                (warehouse_name, supplier_id, warehouse_short_name, is_enabled, region)
                                VALUES (%s, %s, %s, %s, %s)
                                """,
                                (name, supplier_id, short_name, is_enabled, region)
                            )
                            return self.send_json({'status': 'success', 'id': cur.lastrowid}, start_response)
                        item_id = self._parse_int(data.get('id'))
                        if not item_id:
                            return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                        cur.execute(
                            """
                            UPDATE logistics_overseas_warehouses
                            SET warehouse_name=%s, supplier_id=%s, warehouse_short_name=%s, is_enabled=%s, region=%s
                            WHERE id=%s
                            """,
                            (name, supplier_id, short_name, is_enabled, region, item_id)
                        )
                        return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM logistics_overseas_warehouses WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            self._ensure_logistics_tables()
            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.utils import get_column_letter
            from openpyxl.worksheet.datavalidation import DataValidation

            allowed_regions = ['美西', '美中', '美东南', '美东']
            supplier_names = []
            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT supplier_name FROM logistics_suppliers ORDER BY supplier_name ASC")
                    supplier_names = [str(r.get('supplier_name') or '').strip() for r in (cur.fetchall() or []) if str(r.get('supplier_name') or '').strip()]

            wb = Workbook()
            ws = wb.active
            ws.title = 'warehouse_import'
            headers = ['仓库名称', '供应商', '仓库简称', '区域']
            ws.append(headers)

            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)

            widths = [28, 22, 18, 12]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width
            ws.freeze_panes = 'A2'

            option_ws = wb.create_sheet('_options')
            option_ws.append(['supplier_options', 'region_options'])
            max_len = max(len(supplier_names), len(allowed_regions))
            for i in range(max_len):
                option_ws.append([
                    supplier_names[i] if i < len(supplier_names) else None,
                    allowed_regions[i] if i < len(allowed_regions) else None
                ])
            option_ws.sheet_state = 'hidden'

            if supplier_names:
                supplier_end_row = 1 + len(supplier_names)
                dv_supplier = DataValidation(type='list', formula1=f"='_options'!$A$2:$A${supplier_end_row}", allow_blank=False)
                ws.add_data_validation(dv_supplier)
                dv_supplier.add('B2:B1000')

            region_end_row = 1 + len(allowed_regions)
            dv_region = DataValidation(type='list', formula1=f"='_options'!$B$2:$B${region_end_row}", allow_blank=False)
            ws.add_data_validation(dv_region)
            dv_region.add('D2:D1000')

            return self._send_excel_workbook(wb, 'logistics_warehouse_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            self._ensure_logistics_tables()
            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)

            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes))
            ws = wb.active
            headers = [str(cell.value or '').strip() for cell in ws[1]]
            header_map = {name: idx for idx, name in enumerate(headers)}
            required_headers = ['仓库名称', '供应商', '仓库简称', '区域']
            for col_name in required_headers:
                if col_name not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {col_name}'}, start_response)

            allowed_regions = {'美西', '美中', '美东南', '美东'}
            created = 0
            updated = 0
            unchanged = 0
            errors = []

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx].value

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT id, supplier_name FROM logistics_suppliers")
                    supplier_rows = cur.fetchall() or []
                    supplier_map = {str(r.get('supplier_name') or '').strip(): int(r.get('id')) for r in supplier_rows if r.get('id') and str(r.get('supplier_name') or '').strip()}

                for row_idx in range(2, ws.max_row + 1):
                    row = ws[row_idx]
                    if not any(cell.value is not None and str(cell.value).strip() for cell in row):
                        continue
                    try:
                        warehouse_name = str(get_cell(row, '仓库名称') or '').strip()
                        supplier_name = str(get_cell(row, '供应商') or '').strip()
                        warehouse_short_name = str(get_cell(row, '仓库简称') or '').strip()
                        region = str(get_cell(row, '区域') or '').strip()

                        if supplier_name not in supplier_map:
                            raise ValueError(f'供应商必须为系统可选项: {supplier_name or "[空]"}')
                        if region not in allowed_regions:
                            raise ValueError(f'区域必须为系统可选项: {region or "[空]"}')

                        supplier_id = supplier_map.get(supplier_name)
                        if not warehouse_name and warehouse_short_name:
                            warehouse_name = f"{supplier_name} {warehouse_short_name}".strip()
                        if warehouse_name and not warehouse_short_name:
                            if warehouse_name.startswith(supplier_name + ' '):
                                warehouse_short_name = warehouse_name[len(supplier_name) + 1:].strip()
                        if not warehouse_name or not warehouse_short_name:
                            raise ValueError('仓库名称/仓库简称无效，至少需形成可推导的完整名称')

                        with conn.cursor() as cur:
                            cur.execute(
                                "SELECT id, supplier_id, warehouse_short_name, region FROM logistics_overseas_warehouses WHERE warehouse_name=%s LIMIT 1",
                                (warehouse_name,)
                            )
                            existing = cur.fetchone()
                            if existing:
                                if int(existing.get('supplier_id') or 0) == int(supplier_id or 0) and str(existing.get('warehouse_short_name') or '').strip() == warehouse_short_name and str(existing.get('region') or '').strip() == region:
                                    unchanged += 1
                                else:
                                    cur.execute(
                                        "UPDATE logistics_overseas_warehouses SET supplier_id=%s, warehouse_short_name=%s, region=%s WHERE id=%s",
                                        (supplier_id, warehouse_short_name, region, existing.get('id'))
                                    )
                                    updated += 1
                            else:
                                cur.execute(
                                    "INSERT INTO logistics_overseas_warehouses (warehouse_name, supplier_id, warehouse_short_name, region) VALUES (%s, %s, %s, %s)",
                                    (warehouse_name, supplier_id, warehouse_short_name, region)
                                )
                                created += 1
                    except Exception as row_error:
                        errors.append({'row': row_idx, 'error': str(row_error)})

            return self.send_json({
                'status': 'success',
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'errors': errors
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_inventory_api(self, environ, method, start_response):
        try:
            self._ensure_logistics_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))

            if method == 'GET':
                action = (query_params.get('action', [''])[0] or '').strip().lower()
                if action == 'options':
                    option_limit = max(100, min(self._parse_int(query_params.get('order_product_limit', ['800'])[0]) or 800, 2000))
                    include_order_products = str(query_params.get('include_order_products', ['1'])[0]).strip().lower() in ('1', 'true', 'yes')

                    def _load_options_payload():
                        with self._get_db_connection() as conn:
                            with conn.cursor() as cur:
                                cur.execute("SELECT id, warehouse_name FROM logistics_overseas_warehouses WHERE COALESCE(is_enabled,1)=1 ORDER BY warehouse_name ASC")
                                warehouses = cur.fetchall() or []
                                order_products = []
                                if include_order_products:
                                    cur.execute("SELECT id, sku FROM order_products ORDER BY sku ASC LIMIT %s", (option_limit,))
                                    order_products = cur.fetchall() or []
                        return {'status': 'success', 'warehouses': warehouses, 'order_products': order_products}

                    cache_key = f'logistics_wh_inventory_options_{1 if include_order_products else 0}_{option_limit}'
                    payload = self._get_cached_template_options(cache_key, _load_options_payload, ttl_seconds=1800)
                    return self.send_json(payload, start_response)

                keyword = (query_params.get('q', [''])[0] or '').strip()
                warehouse_id = self._parse_int(query_params.get('warehouse_id', [''])[0])
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        sql = """
                            SELECT i.id, i.warehouse_id, i.order_product_id, i.available_qty,
                                   i.updated_at, w.warehouse_name, op.sku
                            FROM logistics_overseas_inventory i
                            JOIN logistics_overseas_warehouses w ON w.id = i.warehouse_id
                            JOIN order_products op ON op.id = i.order_product_id
                        """
                        filters = ["COALESCE(w.is_enabled,1)=1"]
                        params = []
                        if warehouse_id:
                            filters.append("i.warehouse_id=%s")
                            params.append(warehouse_id)
                        if keyword:
                            filters.append("(op.sku LIKE %s OR w.warehouse_name LIKE %s)")
                            like = f"%{keyword}%"
                            params.extend([like, like])
                        where_sql = (' WHERE ' + ' AND '.join(filters)) if filters else ''
                        cur.execute(sql + where_sql + " ORDER BY i.id DESC", params)
                        rows = cur.fetchall() or []
                return self.send_json({'status': 'success', 'items': rows}, start_response)

            data = self._read_json_body(environ)
            if method == 'POST':
                warehouse_id = self._parse_int(data.get('warehouse_id'))
                order_product_id = self._parse_int(data.get('order_product_id'))
                available_qty = self._parse_int(data.get('available_qty'))
                if not warehouse_id or not order_product_id or available_qty is None:
                    return self.send_json({'status': 'error', 'message': 'Missing warehouse_id/order_product_id/available_qty'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO logistics_overseas_inventory (warehouse_id, order_product_id, available_qty, in_transit_qty)
                            VALUES (%s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE
                                available_qty=VALUES(available_qty)
                            """,
                            (warehouse_id, order_product_id, available_qty, 0)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'PUT':
                item_id = self._parse_int(data.get('id'))
                warehouse_id = self._parse_int(data.get('warehouse_id'))
                order_product_id = self._parse_int(data.get('order_product_id'))
                available_qty = self._parse_int(data.get('available_qty'))
                if not item_id or not warehouse_id or not order_product_id or available_qty is None:
                    return self.send_json({'status': 'error', 'message': 'Missing required fields'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            UPDATE logistics_overseas_inventory
                            SET warehouse_id=%s, order_product_id=%s, available_qty=%s
                            WHERE id=%s
                            """,
                            (warehouse_id, order_product_id, available_qty, item_id)
                        )
                return self.send_json({'status': 'success'}, start_response)

            if method == 'DELETE':
                item_id = self._parse_int(data.get('id'))
                if not item_id:
                    return self.send_json({'status': 'error', 'message': 'Missing id'}, start_response)
                with self._get_db_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM logistics_overseas_inventory WHERE id=%s", (item_id,))
                return self.send_json({'status': 'success'}, start_response)

            return self.send_error(405, 'Method not allowed', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_inventory_template_api(self, environ, method, start_response):
        try:
            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)
            if Workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            from openpyxl.styles import PatternFill, Font, Alignment
            from openpyxl.utils import get_column_letter

            wb = Workbook()
            ws = wb.active
            ws.title = 'warehouse_inventory'
            headers = ['SKU', '仓库', '可用量']
            ws.append(headers)
            for cell in ws[1]:
                cell.fill = PatternFill(start_color='D3D3D3', end_color='D3D3D3', fill_type='solid')
                cell.font = Font(bold=True, color='2A2420')
                cell.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
            widths = [24, 28, 12]
            for idx, width in enumerate(widths, start=1):
                ws.column_dimensions[get_column_letter(idx)].width = width
            ws.freeze_panes = 'A2'
            return self._send_excel_workbook(wb, 'warehouse_inventory_template.xlsx', start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_inventory_import_api(self, environ, method, start_response):
        try:
            if method != 'POST':
                return self.send_error(405, 'Method not allowed', start_response)
            if load_workbook is None:
                return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)

            content_type = environ.get('CONTENT_TYPE', '')
            if 'multipart/form-data' not in content_type:
                return self.send_json({'status': 'error', 'message': 'Invalid content type'}, start_response)

            content_length = int(environ.get('CONTENT_LENGTH', 0) or 0)
            raw_body = environ['wsgi.input'].read(content_length) if content_length > 0 else b''
            env_copy = dict(environ)
            env_copy['CONTENT_LENGTH'] = str(len(raw_body))
            form = cgi.FieldStorage(fp=io.BytesIO(raw_body), environ=env_copy, keep_blank_values=True)
            file_item = form['file'] if 'file' in form else None
            if file_item is None or getattr(file_item, 'file', None) is None:
                return self.send_json({'status': 'error', 'message': 'Missing file'}, start_response)
            file_bytes = file_item.file.read() or b''
            if not file_bytes:
                return self.send_json({'status': 'error', 'message': 'Empty file'}, start_response)

            wb = load_workbook(io.BytesIO(file_bytes), read_only=True, data_only=True)
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            import_mode = (query_params.get('mode', ['partial'])[0] or 'partial').strip().lower()
            if import_mode not in ('partial', 'replace_all'):
                import_mode = 'partial'
            ws = wb.active
            header_rows = ws.iter_rows(min_row=1, max_row=1, values_only=True)
            header_values = next(header_rows, tuple())
            headers = [str(value or '').strip() for value in header_values]
            header_map = {name: idx for idx, name in enumerate(headers)}
            required_headers = ['SKU', '仓库', '可用量']
            for col_name in required_headers:
                if col_name not in header_map:
                    return self.send_json({'status': 'error', 'message': f'模板缺少列: {col_name}'}, start_response)

            def get_cell(row, name):
                idx = header_map.get(name)
                if idx is None or idx >= len(row):
                    return None
                return row[idx]

            self._ensure_logistics_tables()
            created = 0
            updated = 0
            unchanged = 0
            errors = []

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    raw_rows = []
                    sku_names = set()
                    warehouse_names = set()
                    warehouse_ids = set()
                    order_product_ids = set()
                    for row_idx, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                        if not any(value is not None and str(value).strip() for value in row):
                            continue
                        try:
                            sku = str(get_cell(row, 'SKU') or '').strip()
                            warehouse_name = str(get_cell(row, '仓库') or '').strip()
                            available_qty = self._parse_int(get_cell(row, '可用量'))
                            if not sku or not warehouse_name or available_qty is None:
                                raise ValueError('SKU、仓库、可用量不能为空且可用量需为整数')
                            raw_rows.append((row_idx, sku, warehouse_name, available_qty))
                            sku_names.add(sku)
                            warehouse_names.add(warehouse_name)
                        except Exception as row_error:
                            errors.append({'row': row_idx, 'error': str(row_error)})

                    sku_map = {}
                    wh_map = {}
                    if sku_names:
                        sku_list = sorted(sku_names)
                        sku_placeholders = ','.join(['%s'] * len(sku_list))
                        cur.execute(
                            f"SELECT id, sku FROM order_products WHERE sku IN ({sku_placeholders})",
                            tuple(sku_list)
                        )
                        sku_map = {str(r.get('sku') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}
                    if warehouse_names:
                        wh_list = sorted(warehouse_names)
                        wh_placeholders = ','.join(['%s'] * len(wh_list))
                        cur.execute(
                            f"SELECT id, warehouse_name FROM logistics_overseas_warehouses WHERE COALESCE(is_enabled,1)=1 AND warehouse_name IN ({wh_placeholders})",
                            tuple(wh_list)
                        )
                        wh_map = {str(r.get('warehouse_name') or '').strip(): int(r.get('id')) for r in (cur.fetchall() or []) if r.get('id')}

                    normalized_map = {}
                    for row_idx, sku, warehouse_name, available_qty in raw_rows:
                        order_product_id = sku_map.get(sku)
                        warehouse_id = wh_map.get(warehouse_name)
                        if not order_product_id:
                            errors.append({'row': row_idx, 'error': f'未找到SKU: {sku}'})
                            continue
                        if not warehouse_id:
                            errors.append({'row': row_idx, 'error': f'未找到仓库: {warehouse_name}'})
                            continue
                        warehouse_ids.add(warehouse_id)
                        order_product_ids.add(order_product_id)
                        normalized_map[(warehouse_id, order_product_id)] = available_qty

                    if import_mode == 'replace_all':
                        cur.execute("UPDATE logistics_overseas_inventory SET available_qty=0 WHERE available_qty<>0")

                    existing_map = {}
                    if warehouse_ids and order_product_ids:
                        wh_placeholders = ','.join(['%s'] * len(warehouse_ids))
                        op_placeholders = ','.join(['%s'] * len(order_product_ids))
                        cur.execute(
                            f"""
                            SELECT id, warehouse_id, order_product_id, available_qty
                            FROM logistics_overseas_inventory
                            WHERE warehouse_id IN ({wh_placeholders})
                              AND order_product_id IN ({op_placeholders})
                            """,
                            tuple(warehouse_ids) + tuple(order_product_ids)
                        )
                        for existing in (cur.fetchall() or []):
                            key = (self._parse_int(existing.get('warehouse_id')), self._parse_int(existing.get('order_product_id')))
                            if key[0] and key[1]:
                                existing_map[key] = {
                                    'id': self._parse_int(existing.get('id')),
                                    'available_qty': self._parse_int(existing.get('available_qty')),
                                }

                    to_upsert = []
                    to_insert = []
                    for (warehouse_id, order_product_id), available_qty in normalized_map.items():
                        key = (warehouse_id, order_product_id)
                        existing = existing_map.get(key)
                        if existing:
                            if (existing.get('available_qty') or 0) != available_qty:
                                to_upsert.append((warehouse_id, order_product_id, available_qty, 0))
                            else:
                                unchanged += 1
                        else:
                            to_insert.append((warehouse_id, order_product_id, available_qty, 0))
                            to_upsert.append((warehouse_id, order_product_id, available_qty, 0))

                    if to_upsert:
                        cur.executemany(
                            """
                            INSERT INTO logistics_overseas_inventory (warehouse_id, order_product_id, available_qty, in_transit_qty)
                            VALUES (%s, %s, %s, %s)
                            ON DUPLICATE KEY UPDATE available_qty=VALUES(available_qty)
                            """,
                            to_upsert
                        )
                    updated += len([1 for t in to_upsert if (t[0], t[1]) in existing_map and (existing_map[(t[0], t[1])].get('available_qty') or 0) != t[2]])
                    created += len(to_insert)

            return self.send_json({
                'status': 'success',
                'created': created,
                'updated': updated,
                'unchanged': unchanged,
                'mode': import_mode,
                'errors': errors
            }, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)

    def handle_logistics_warehouse_dashboard_api(self, environ, method, start_response):
        """仓储看板：SKU库存聚合 + 仓库分列 + 在途角标（只读，工厂库存从独立表读取）"""
        try:
            self._ensure_logistics_tables()
            self._ensure_factory_inventory_tables()
            self._ensure_order_product_tables()
            query_params = parse_qs(environ.get('QUERY_STRING', ''))
            action = (query_params.get('action', [''])[0] or '').strip().lower()

            if method != 'GET':
                return self.send_error(405, 'Method not allowed', start_response)

            region_order = {'美西': 1, '美中': 2, '美东南': 3, '美东': 4}

            def _region_rank(region_name):
                text = str(region_name or '').strip()
                for key, rank in region_order.items():
                    if key in text:
                        return rank
                return 99

            with self._get_db_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT w.id, w.warehouse_name, w.warehouse_short_name, w.region, s.supplier_name
                        FROM logistics_overseas_warehouses w
                        JOIN logistics_suppliers s ON s.id = w.supplier_id
                        WHERE COALESCE(w.is_enabled,1)=1
                        """
                    )
                    warehouse_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT op.id, op.sku, pf.sku_family, op.is_iteration, op.is_on_market, op.source_order_product_id,
                               fm.fabric_name_en, fm.representative_color
                        FROM order_products op
                        LEFT JOIN product_families pf ON pf.id = op.sku_family_id
                        LEFT JOIN fabric_materials fm ON fm.id = op.fabric_id
                        ORDER BY op.sku DESC
                        """
                    )
                    sku_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT order_product_id, warehouse_id, SUM(available_qty) AS qty
                        FROM logistics_overseas_inventory
                        GROUP BY order_product_id, warehouse_id
                        """
                    )
                    inv_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT
                            li.order_product_id,
                            t.destination_warehouse_id AS warehouse_id,
                            w.region,
                            t.logistics_box_no,
                            COALESCE(t.expected_warehouse_date, t.eta_latest, t.expected_listed_date_latest) AS expected_arrival_date,
                            SUM(li.shipped_qty) AS qty
                        FROM logistics_in_transit_items li
                        JOIN logistics_in_transit t ON t.id = li.transit_id
                        LEFT JOIN logistics_overseas_warehouses w ON w.id = t.destination_warehouse_id
                        WHERE t.listed_date IS NULL
                                                    AND COALESCE(w.is_enabled,1)=1
                        GROUP BY li.order_product_id, t.destination_warehouse_id, w.region, t.logistics_box_no, COALESCE(t.expected_warehouse_date, t.eta_latest, t.expected_listed_date_latest)
                        """
                    )
                    transit_rows = cur.fetchall() or []

                    cur.execute("SELECT id, factory_name FROM logistics_factories ORDER BY factory_name ASC")
                    factory_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT order_product_id, factory_id, quantity
                        FROM factory_stock_inventory
                        """
                    )
                    fstock_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT order_product_id, factory_id, SUM(quantity) AS quantity,
                               MIN(expected_completion_date) AS earliest_date
                        FROM factory_wip_inventory
                        WHERE COALESCE(is_completed, 0) = 0
                        GROUP BY order_product_id, factory_id
                        """
                    )
                    fwip_rows = cur.fetchall() or []

                    cur.execute(
                        """
                        SELECT id, order_product_id, factory_id, quantity, expected_completion_date
                        FROM factory_wip_inventory
                        WHERE COALESCE(is_completed, 0) = 0
                        ORDER BY expected_completion_date ASC, id ASC
                        """
                    )
                    fwip_detail_rows = cur.fetchall() or []

            factories = [
                {'id': int(r['id']), 'factory_name': r['factory_name'] or ''}
                for r in factory_rows if r.get('id')
            ]
            factory_ids = [f['id'] for f in factories]

            warehouses = sorted(
                [
                    {
                        'id': int(w.get('id')),
                        'warehouse_name': w.get('warehouse_name') or '',
                        'warehouse_short_name': w.get('warehouse_short_name') or '',
                        'region': w.get('region') or '',
                        'supplier_name': w.get('supplier_name') or ''
                    }
                    for w in warehouse_rows if w.get('id')
                ],
                key=lambda x: (_region_rank(x.get('region')), str(x.get('warehouse_name') or ''))
            )

            inv_map = {}
            for row in inv_rows:
                op_id = self._parse_int(row.get('order_product_id'))
                wh_id = self._parse_int(row.get('warehouse_id'))
                qty = self._parse_int(row.get('qty')) or 0
                if not op_id or not wh_id:
                    continue
                inv_map[(op_id, wh_id)] = qty

            transit_total_map = {}
            transit_wh_map = {}
            transit_region_map = {}
            transit_tip_map = {}
            transit_wh_tip_map = {}
            for row in transit_rows:
                op_id = self._parse_int(row.get('order_product_id'))
                wh_id = self._parse_int(row.get('warehouse_id'))
                region = (row.get('region') or '').strip()
                box_no = (row.get('logistics_box_no') or '').strip()
                arrival_date = row.get('expected_arrival_date')
                arrival_text = str(arrival_date)[:10] if arrival_date else '未知'
                qty = self._parse_int(row.get('qty')) or 0
                if not op_id or qty <= 0:
                    continue
                transit_total_map[op_id] = transit_total_map.get(op_id, 0) + qty
                tip_text = f"{box_no or '批次'}: {qty}（预计到货 {arrival_text}）"
                transit_tip_map.setdefault(op_id, []).append(tip_text)
                if wh_id:
                    transit_wh_map[(op_id, wh_id)] = transit_wh_map.get((op_id, wh_id), 0) + qty
                    transit_wh_tip_map.setdefault((op_id, wh_id), []).append(tip_text)
                if region:
                    region_key = None
                    for r in ('美西', '美中', '美东南', '美东'):
                        if r in region:
                            region_key = r
                            break
                    if region_key:
                        transit_region_map.setdefault(op_id, {})
                        transit_region_map[op_id][region_key] = transit_region_map[op_id].get(region_key, 0) + qty

            fstock_map = {}
            for row in fstock_rows:
                op_id = self._parse_int(row.get('order_product_id'))
                f_id = self._parse_int(row.get('factory_id'))
                qty = self._parse_int(row.get('quantity')) or 0
                if op_id and f_id:
                    fstock_map.setdefault(op_id, {})[f_id] = qty

            fwip_map = {}
            for row in fwip_rows:
                op_id = self._parse_int(row.get('order_product_id'))
                f_id = self._parse_int(row.get('factory_id'))
                qty = self._parse_int(row.get('quantity')) or 0
                date_val = row.get('earliest_date')
                if op_id and f_id:
                    fwip_map.setdefault(op_id, {})[f_id] = {
                        'quantity': qty,
                        'earliest_date': str(date_val) if date_val else None
                    }

            fwip_tip_map = {}
            for row in fwip_detail_rows:
                op_id = self._parse_int(row.get('order_product_id'))
                f_id = self._parse_int(row.get('factory_id'))
                row_id = self._parse_int(row.get('id'))
                qty = self._parse_int(row.get('quantity')) or 0
                date_val = row.get('expected_completion_date')
                if not op_id or not f_id or qty <= 0:
                    continue
                date_text = str(date_val)[:10] if date_val else '未知'
                tip_text = f"批次#{row_id}: {qty}（预计完工 {date_text}）"
                fwip_tip_map.setdefault((op_id, f_id), []).append(tip_text)

            raw_row_map = {}
            for row in sku_rows:
                op_id = self._parse_int(row.get('id'))
                if not op_id:
                    continue
                warehouse_qty = {}
                available_total = 0
                for wh in warehouses:
                    wh_id = wh['id']
                    qty = inv_map.get((op_id, wh_id), 0)
                    warehouse_qty[str(wh_id)] = qty
                    available_total += qty
                op_fstock = fstock_map.get(op_id, {})
                op_fwip = fwip_map.get(op_id, {})
                raw_row_map[op_id] = {
                    'order_product_id': op_id,
                    'sku_family': row.get('sku_family') or '',
                    'sku': row.get('sku') or '',
                    'fabric_name_en': row.get('fabric_name_en') or '',
                    'representative_color': row.get('representative_color') or '',
                    'available_total': available_total,
                    'in_transit_total': transit_total_map.get(op_id, 0),
                    'factory_stock_total': sum(op_fstock.values()),
                    'factory_stock_by_factory': {str(fid): qty for fid, qty in op_fstock.items()},
                    'factory_wip_total': sum(v['quantity'] for v in op_fwip.values()),
                    'factory_wip_by_factory': {
                        str(fid): {'quantity': v['quantity'], 'earliest_date': v['earliest_date']}
                        for fid, v in op_fwip.items()
                    },
                    'in_transit_by_region': transit_region_map.get(op_id, {}),
                    'is_iteration': 1 if self._parse_int(row.get('is_iteration')) else 0,
                    'is_on_market': 1 if self._parse_int(row.get('is_on_market', 1)) else 0,
                    'source_order_product_id': self._parse_int(row.get('source_order_product_id')),
                    'warehouse_qty': warehouse_qty,
                    'in_transit_by_warehouse': {
                        str(wh['id']): transit_wh_map.get((op_id, wh['id']), 0) for wh in warehouses
                    },
                    'in_transit_tip_by_warehouse': {
                        str(wh['id']): '\n'.join(transit_wh_tip_map.get((op_id, wh['id']), [])) for wh in warehouses
                    },
                    'factory_wip_tip_by_factory': {
                        str(fid): '\n'.join(fwip_tip_map.get((op_id, fid), [])) for fid in factory_ids
                    },
                    'in_transit_tip': '\n'.join(transit_tip_map.get(op_id, [])),
                    'iteration_children': []
                }

            def _resolve_source_root(op_id):
                visited = set()
                current_id = op_id
                while current_id and current_id not in visited:
                    visited.add(current_id)
                    current = raw_row_map.get(current_id)
                    if not current:
                        return op_id
                    source_id = self._parse_int(current.get('source_order_product_id'))
                    if not current.get('is_iteration') or not source_id or source_id == current_id or source_id not in raw_row_map:
                        return current_id
                    current_id = source_id
                return op_id

            top_level_ids = []
            seen_top_level = set()
            for row in sku_rows:
                op_id = self._parse_int(row.get('id'))
                if not op_id or op_id not in raw_row_map:
                    continue
                root_id = _resolve_source_root(op_id)
                if root_id == op_id:
                    if op_id not in seen_top_level:
                        seen_top_level.add(op_id)
                        top_level_ids.append(op_id)
                    continue
                parent = raw_row_map.get(root_id)
                child = raw_row_map.get(op_id)
                if not parent or not child:
                    if op_id not in seen_top_level:
                        seen_top_level.add(op_id)
                        top_level_ids.append(op_id)
                    continue
                parent['available_total'] += child.get('available_total', 0)
                parent['in_transit_total'] += child.get('in_transit_total', 0)
                parent['factory_stock_total'] += child.get('factory_stock_total', 0)
                parent['factory_wip_total'] += child.get('factory_wip_total', 0)
                for region_key, rqty in (child.get('in_transit_by_region') or {}).items():
                    parent['in_transit_by_region'][region_key] = parent['in_transit_by_region'].get(region_key, 0) + rqty
                for fid_str, qty in (child.get('factory_stock_by_factory') or {}).items():
                    parent['factory_stock_by_factory'][fid_str] = parent['factory_stock_by_factory'].get(fid_str, 0) + qty
                for fid_str, wip_val in (child.get('factory_wip_by_factory') or {}).items():
                    if fid_str in parent['factory_wip_by_factory']:
                        parent['factory_wip_by_factory'][fid_str]['quantity'] += wip_val.get('quantity', 0)
                    else:
                        parent['factory_wip_by_factory'][fid_str] = dict(wip_val)
                if child.get('in_transit_tip'):
                    parent['in_transit_tip'] = '\n'.join(filter(None, [parent.get('in_transit_tip') or '', child.get('in_transit_tip') or '']))
                for wh in warehouses:
                    wh_key = str(wh['id'])
                    parent['warehouse_qty'][wh_key] = (parent['warehouse_qty'].get(wh_key) or 0) + (child.get('warehouse_qty', {}).get(wh_key) or 0)
                    parent['in_transit_by_warehouse'][wh_key] = (parent['in_transit_by_warehouse'].get(wh_key) or 0) + (child.get('in_transit_by_warehouse', {}).get(wh_key) or 0)
                    child_tip = (child.get('in_transit_tip_by_warehouse', {}) or {}).get(wh_key) or ''
                    parent_tip = (parent.get('in_transit_tip_by_warehouse', {}) or {}).get(wh_key) or ''
                    merged_tip = '\n'.join([text for text in [parent_tip, child_tip] if text])
                    parent.setdefault('in_transit_tip_by_warehouse', {})[wh_key] = merged_tip
                for fid in factory_ids:
                    f_key = str(fid)
                    child_tip = (child.get('factory_wip_tip_by_factory', {}) or {}).get(f_key) or ''
                    parent_tip = (parent.get('factory_wip_tip_by_factory', {}) or {}).get(f_key) or ''
                    merged_tip = '\n'.join([text for text in [parent_tip, child_tip] if text])
                    parent.setdefault('factory_wip_tip_by_factory', {})[f_key] = merged_tip
                parent['iteration_children'].append({
                    'order_product_id': child.get('order_product_id'),
                    'sku': child.get('sku') or '',
                    'fabric_name_en': child.get('fabric_name_en') or '',
                    'representative_color': child.get('representative_color') or '',
                    'is_on_market': 1 if self._parse_int(child.get('is_on_market', 1)) else 0,
                    'available_total': child.get('available_total', 0) or 0,
                    'in_transit_total': child.get('in_transit_total', 0) or 0,
                    'warehouse_qty': dict(child.get('warehouse_qty') or {}),
                    'in_transit_by_warehouse': dict(child.get('in_transit_by_warehouse') or {}),
                    'in_transit_tip': child.get('in_transit_tip') or '',
                    'factory_stock_total': child.get('factory_stock_total', 0) or 0,
                    'factory_wip_total': child.get('factory_wip_total', 0) or 0,
                    'in_transit_tip_by_warehouse': dict(child.get('in_transit_tip_by_warehouse') or {}),
                    'factory_wip_tip_by_factory': dict(child.get('factory_wip_tip_by_factory') or {}),
                    'factory_stock_by_factory': dict(child.get('factory_stock_by_factory') or {}),
                    'factory_wip_by_factory': {
                        str(fid): {
                            'quantity': int((val or {}).get('quantity') or 0),
                            'earliest_date': (val or {}).get('earliest_date')
                        }
                        for fid, val in (child.get('factory_wip_by_factory') or {}).items()
                    }
                })

            rows = []
            for op_id in top_level_ids:
                item = raw_row_map.get(op_id)
                if not item:
                    continue
                item['iteration_children'] = sorted(item.get('iteration_children') or [], key=lambda x: str(x.get('sku') or ''))
                rows.append(item)

            if action == 'export':
                if Workbook is None:
                    return self.send_json({'status': 'error', 'message': f'openpyxl not available: {_openpyxl_import_error}'}, start_response)
                wb = Workbook()
                ws = wb.active
                ws.title = 'warehouse_dashboard'
                factory_headers = [f['factory_name'] for f in factories]
                headers = (
                    ['SKU', '现货库存', '在途数量']
                    + [w['warehouse_short_name'] or w['warehouse_name'] for w in warehouses]
                    + [f'工厂在库-{fn}' for fn in factory_headers]
                    + [f'工厂在制-{fn}' for fn in factory_headers]
                )
                for idx, title in enumerate(headers, start=1):
                    ws.cell(row=1, column=idx, value=title)
                line = 2
                for item in rows:
                    data_line = [
                        item.get('sku') or '',
                        item.get('available_total') or 0,
                        item.get('in_transit_total') or 0,
                    ]
                    for wh in warehouses:
                        data_line.append((item.get('warehouse_qty') or {}).get(str(wh['id']), 0))
                    fstock_bf = item.get('factory_stock_by_factory') or {}
                    for f in factories:
                        data_line.append(fstock_bf.get(str(f['id']), 0))
                    fwip_bf = item.get('factory_wip_by_factory') or {}
                    for f in factories:
                        wip_val = fwip_bf.get(str(f['id'])) or {}
                        data_line.append(wip_val.get('quantity', 0))
                    for col, value in enumerate(data_line, start=1):
                        ws.cell(row=line, column=col, value=value)
                    line += 1
                return self._send_excel_workbook(wb, 'logistics_warehouse_dashboard.xlsx', start_response)

            return self.send_json({'status': 'success', 'warehouses': warehouses, 'factories': factories, 'items': rows}, start_response)
        except Exception as e:
            return self.send_json({'status': 'error', 'message': str(e)}, start_response)
